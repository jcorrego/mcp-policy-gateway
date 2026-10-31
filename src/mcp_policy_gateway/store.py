"""Durable approval, idempotency and audit state for the reference gateway.

SQLite keeps the reference runnable without infrastructure. Every state change uses a
write transaction plus a compare-and-set on the expected prior state, and the matching
audit event commits in the same transaction. See docs/adr/003-durable-approvals.md.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from .models import AuditEvent


class ApprovalState(StrEnum):
    REQUESTED = "requested"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    EXECUTING = "executing"
    EXECUTED = "executed"


# The only legal edges. Anything else is refused by the store, not just by callers.
TRANSITIONS: dict[ApprovalState, frozenset[ApprovalState]] = {
    ApprovalState.REQUESTED: frozenset(
        {ApprovalState.APPROVED, ApprovalState.REJECTED, ApprovalState.EXPIRED}
    ),
    ApprovalState.APPROVED: frozenset({ApprovalState.EXECUTING}),
    ApprovalState.EXECUTING: frozenset({ApprovalState.EXECUTED}),
    ApprovalState.REJECTED: frozenset(),
    ApprovalState.EXPIRED: frozenset(),
    ApprovalState.EXECUTED: frozenset(),
}

_STATES_SQL = ", ".join(f"'{state.value}'" for state in ApprovalState)

SCHEMA = f"""
CREATE TABLE IF NOT EXISTS approval_requests (
    request_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    action TEXT NOT NULL,
    requester TEXT NOT NULL,
    account_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ({_STATES_SQL})),
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    approver TEXT,
    decision_note TEXT,
    decided_at REAL,
    executed_at REAL,
    UNIQUE (tenant_id, requester, action, idempotency_key)
);
CREATE TABLE IF NOT EXISTS audit_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at REAL NOT NULL,
    correlation_id TEXT NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    metadata TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_by_correlation ON audit_events (correlation_id, seq);
CREATE TRIGGER IF NOT EXISTS audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events_append_only'); END;
CREATE TRIGGER IF NOT EXISTS audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events_append_only'); END;
"""


class StoreError(RuntimeError):
    """The state store cannot be opened or used safely."""


class TransitionConflict(RuntimeError):
    """The request is no longer in the state this transition expects."""


@dataclass(frozen=True)
class ApprovalRequest:
    request_id: str
    tenant_id: str
    action: str
    requester: str
    account_id: str
    reason: str
    idempotency_key: str
    payload_digest: str
    policy_version: str
    state: ApprovalState
    created_at: float
    expires_at: float
    approver: str | None
    decision_note: str | None
    decided_at: float | None
    executed_at: float | None

    def public_view(self) -> dict[str, Any]:
        """Fields an agent or operator may see; the digest is an internal detail."""
        return {
            "request_id": self.request_id,
            "action": self.action,
            "account_id": self.account_id,
            "requester": self.requester,
            "reason": self.reason,
            "state": self.state.value,
            "policy_version": self.policy_version,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "approver": self.approver,
            "decided_at": self.decided_at,
            "executed_at": self.executed_at,
        }


def _connect(path: str | Path) -> sqlite3.Connection:
    try:
        connection = sqlite3.connect(str(path), isolation_level=None, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        if str(path) != ":memory:":
            connection.execute("PRAGMA journal_mode = WAL")
        return connection
    except sqlite3.Error as exc:
        raise StoreError("invalid_state_store") from exc


class ApprovalStore:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self._db = _connect(path)
        try:
            self._db.executescript(SCHEMA)
        except sqlite3.Error as exc:
            raise StoreError("invalid_state_store") from exc

    def close(self) -> None:
        self._db.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Serialize writers; a request transition and its audit event commit together."""
        self._db.execute("BEGIN IMMEDIATE")
        try:
            yield self._db
        except BaseException:
            self._db.execute("ROLLBACK")
            raise
        self._db.execute("COMMIT")

    def get(self, request_id: str) -> ApprovalRequest | None:
        row = self._db.execute(
            "SELECT * FROM approval_requests WHERE request_id = ?", (request_id,)
        ).fetchone()
        return _request(row) if row else None

    def find_by_idempotency(
        self, tenant_id: str, requester: str, action: str, idempotency_key: str
    ) -> ApprovalRequest | None:
        row = self._db.execute(
            "SELECT * FROM approval_requests WHERE tenant_id = ? AND requester = ? "
            "AND action = ? AND idempotency_key = ?",
            (tenant_id, requester, action, idempotency_key),
        ).fetchone()
        return _request(row) if row else None

    def insert(self, request: ApprovalRequest) -> None:
        self._db.execute(
            "INSERT INTO approval_requests (request_id, tenant_id, action, requester, "
            "account_id, reason, idempotency_key, payload_digest, policy_version, state, "
            "created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                request.request_id, request.tenant_id, request.action, request.requester,
                request.account_id, request.reason, request.idempotency_key,
                request.payload_digest, request.policy_version, request.state.value,
                request.created_at, request.expires_at,
            ),
        )

    def transition(
        self,
        request_id: str,
        expected: ApprovalState,
        target: ApprovalState,
        **fields: Any,
    ) -> None:
        """Compare-and-set; refuse illegal edges and lost races alike."""
        if target not in TRANSITIONS[expected]:
            raise TransitionConflict(f"illegal_transition:{expected}->{target}")
        allowed = {"approver", "decision_note", "decided_at", "executed_at"}
        if not set(fields) <= allowed:
            raise ValueError("unexpected transition fields")
        assignments = "".join(f", {name} = ?" for name in fields)
        cursor = self._db.execute(
            f"UPDATE approval_requests SET state = ?{assignments} "
            "WHERE request_id = ? AND state = ?",
            (target.value, *fields.values(), request_id, expected.value),
        )
        if cursor.rowcount != 1:
            raise TransitionConflict("state_changed")

    def append_audit(self, event: AuditEvent, recorded_at: float) -> None:
        self._db.execute(
            "INSERT INTO audit_events (recorded_at, correlation_id, action, actor, tenant_id, "
            "decision, reason, policy_version, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                recorded_at, event.correlation_id, event.action, event.actor, event.tenant_id,
                str(event.decision), event.reason, event.policy_version,
                json.dumps(event.metadata, sort_keys=True),
            ),
        )

    def audit_events(self, correlation_id: str | None = None) -> list[dict[str, Any]]:
        if correlation_id is None:
            rows = self._db.execute("SELECT * FROM audit_events ORDER BY seq").fetchall()
        else:
            rows = self._db.execute(
                "SELECT * FROM audit_events WHERE correlation_id = ? ORDER BY seq",
                (correlation_id,),
            ).fetchall()
        return [{**dict(row), "metadata": json.loads(row["metadata"])} for row in rows]


def _request(row: sqlite3.Row) -> ApprovalRequest:
    data = dict(row)
    data["state"] = ApprovalState(data["state"])
    return ApprovalRequest(**data)


def new_request_id() -> str:
    return f"apr_{uuid.uuid4().hex}"


class SyntheticFreezeUpstream:
    """Stand-in for an external account system that honours an idempotency token.

    It is deliberately separate from ApprovalStore: the gateway cannot assume the
    upstream effect and its own `executed` record commit atomically.
    """

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._db = _connect(path)
        try:
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS upstream_freezes (request_id TEXT PRIMARY KEY, "
                "account_id TEXT NOT NULL, apply_calls INTEGER NOT NULL)"
            )
        except sqlite3.Error as exc:
            raise StoreError("invalid_state_store") from exc

    def apply_freeze(self, request_id: str, account_id: str) -> None:
        """Apply once per token; repeated calls with the same token add no new effect."""
        self._db.execute(
            "INSERT INTO upstream_freezes (request_id, account_id, apply_calls) "
            "VALUES (?, ?, 1) ON CONFLICT (request_id) DO UPDATE SET "
            "apply_calls = apply_calls + 1",
            (request_id, account_id),
        )

    def is_frozen(self, account_id: str) -> bool:
        return self.effect_count(account_id) > 0

    def effect_count(self, account_id: str) -> int:
        return self._db.execute(
            "SELECT COUNT(*) FROM upstream_freezes WHERE account_id = ?", (account_id,)
        ).fetchone()[0]

    def apply_calls(self, request_id: str) -> int:
        row = self._db.execute(
            "SELECT apply_calls FROM upstream_freezes WHERE request_id = ?", (request_id,)
        ).fetchone()
        return row[0] if row else 0
