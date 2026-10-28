"""Durable approval workflow: separate approver, idempotency, transitions and recovery.

All principals, accounts and requests are synthetic.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp_policy_gateway.models import Decision, Principal
from mcp_policy_gateway.service import GatewayService
from mcp_policy_gateway.store import (
    ApprovalState,
    ApprovalStore,
    SyntheticFreezeUpstream,
    TransitionConflict,
)

REQUEST = "gateway:request_account_freeze"
APPROVE = "gateway:approve_account_freeze"
AGENT = Principal("agent-01", "tenant_red", frozenset({REQUEST, "gateway:get_account_summary"}))
HUMAN = Principal("human-approver-01", "tenant_red", frozenset({APPROVE}))


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


class TimeoutAfterApply(SyntheticFreezeUpstream):
    """Upstream applies the effect, then the response is lost on the way back."""

    def __init__(self, path, failures: int = 1) -> None:
        super().__init__(path)
        self.failures = failures

    def apply_freeze(self, request_id: str, account_id: str) -> None:
        super().apply_freeze(request_id, account_id)
        if self.failures:
            self.failures -= 1
            raise TimeoutError("synthetic response timeout")


@pytest.fixture
def db(tmp_path):
    return tmp_path / "gateway.sqlite3"


def gateway(db, clock=None, upstream=None) -> GatewayService:
    return GatewayService(
        store=ApprovalStore(db),
        upstream=upstream or SyntheticFreezeUpstream(db),
        clock=clock or Clock(),
    )


def request(service, key="freeze-001", reason="synthetic card-theft report", account="acct_red"):
    return service.request_account_freeze(AGENT, account, reason, key)


def test_request_is_persisted_and_survives_a_new_process(db):
    first = request(gateway(db))
    assert first["decision"] == Decision.REQUIRE_APPROVAL
    assert first["state"] == "requested"
    assert first["replayed"] is False
    assert "No state was changed" in first["message"]

    restarted = gateway(db)
    view = restarted.get_freeze_request(
        Principal("agent-01", "tenant_red", frozenset({"gateway:get_freeze_request"})),
        first["request_id"],
    )
    assert view["ok"] is True
    assert view["request"]["state"] == "requested"
    assert view["request"]["requester"] == "agent-01"
    assert restarted.upstream.is_frozen("acct_red") is False


def test_idempotent_replay_returns_same_request_and_conflict_is_denied(db):
    service = gateway(db)
    first = request(service)
    replay = request(service)
    assert replay["request_id"] == first["request_id"]
    assert replay["replayed"] is True
    count = sqlite3.connect(db).execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0]
    assert count == 1

    conflict = request(service, reason="a different synthetic reason")
    assert conflict["decision"] == Decision.DENY
    assert conflict["reason"] == "idempotency_key_conflict"

    # Keys are scoped to the verified requester: another agent's key cannot collide.
    other = Principal("agent-02", "tenant_red", frozenset({REQUEST}))
    separate = service.request_account_freeze(
        other, "acct_red", "synthetic card-theft report", "freeze-001"
    )
    assert separate["request_id"] != first["request_id"]
    reasons = [event["reason"] for event in service.audit_log(first["request_id"])]
    assert reasons == ["human_approval_required", "idempotent_replay", "idempotency_key_conflict"]


@pytest.mark.parametrize(
    ("principal", "reason"),
    [
        # The agent cannot approve its own request even if it somehow holds approver scope.
        (Principal("agent-01", "tenant_red", frozenset({REQUEST, APPROVE})),
         "self_approval_forbidden"),
        # Holding the tool scope is not approval authority.
        (Principal("agent-02", "tenant_red", frozenset({REQUEST})), "missing_approver_scope"),
        (Principal("human-approver-02", "tenant_blue", frozenset({APPROVE})),
         "cross_tenant_access"),
    ],
)
def test_only_a_separate_same_tenant_approver_can_decide(db, principal, reason):
    service = gateway(db)
    pending = request(service)
    denied = service.decide_freeze(principal, pending["request_id"], approve=True, note="ok")
    assert denied == {
        "ok": False, "decision": Decision.DENY, "reason": reason,
        "policy_version": service.policy.version,
    }
    assert service.store.get(pending["request_id"]).state is ApprovalState.REQUESTED
    assert service.audit_log(pending["request_id"])[-1]["reason"] == reason


def test_decision_requires_note_and_unknown_request_is_denied(db):
    service = gateway(db)
    pending = request(service)
    blank = service.decide_freeze(HUMAN, pending["request_id"], approve=True, note="  ")
    assert blank["reason"] == "decision_note_required"
    missing = service.decide_freeze(HUMAN, "apr_missing", approve=True, note="ok")
    assert missing["reason"] == "unknown_request"


def test_happy_path_executes_exactly_once(db):
    service = gateway(db)
    pending = request(service)
    request_id = pending["request_id"]
    early = service.execute_freeze(HUMAN, request_id)
    assert (early["reason"], early["state"]) == ("invalid_transition", "requested")

    approved = service.decide_freeze(HUMAN, request_id, approve=True, note="verified by phone")
    assert approved["ok"] is True
    assert approved["request"]["state"] == "approved"
    assert approved["request"]["approver"] == "human-approver-01"

    executed = service.execute_freeze(HUMAN, request_id)
    assert executed["reason"] == "executed"
    assert executed["request"]["state"] == "executed"
    again = service.execute_freeze(HUMAN, request_id)
    assert again["reason"] == "already_executed"
    assert service.upstream.apply_calls(request_id) == 1
    assert service.upstream.effect_count("acct_red") == 1
    summary = service.get_account_summary(AGENT, "acct_red")
    assert summary["account"]["status"] == "frozen"

    # A replay after execution returns the executed request and creates nothing new.
    replay = request(service)
    assert (replay["request_id"], replay["state"]) == (request_id, "executed")
    assert service.upstream.effect_count("acct_red") == 1


def test_rejected_and_decided_requests_cannot_transition_again(db):
    service = gateway(db)
    request_id = request(service)["request_id"]
    assert service.decide_freeze(HUMAN, request_id, approve=False, note="not verified")["ok"]
    second = service.decide_freeze(HUMAN, request_id, approve=True, note="changed mind")
    assert (second["reason"], second["state"]) == ("invalid_transition", "rejected")
    blocked = service.execute_freeze(HUMAN, request_id)
    assert (blocked["reason"], blocked["state"]) == ("invalid_transition", "rejected")
    assert service.upstream.is_frozen("acct_red") is False


def test_expired_request_cannot_be_approved(db):
    clock = Clock()
    service = gateway(db, clock=clock)
    pending = request(service)
    clock.now = pending["expires_at"]
    expired = service.decide_freeze(HUMAN, pending["request_id"], approve=True, note="late")
    assert (expired["reason"], expired["state"]) == ("approval_expired", "expired")
    later = service.decide_freeze(HUMAN, pending["request_id"], approve=True, note="later")
    assert (later["reason"], later["state"]) == ("invalid_transition", "expired")
    assert service.execute_freeze(HUMAN, pending["request_id"])["reason"] == "invalid_transition"


def test_timeout_after_upstream_execution_recovers_without_duplicate_effect(db):
    upstream = TimeoutAfterApply(db)
    service = gateway(db, upstream=upstream)
    request_id = request(service)["request_id"]
    service.decide_freeze(HUMAN, request_id, approve=True, note="verified")

    lost = service.execute_freeze(HUMAN, request_id)
    assert lost["ok"] is False
    assert lost["reason"] == "upstream_outcome_unknown"
    assert lost["request"]["state"] == "executing"
    # The effect happened even though the gateway could not record success.
    assert upstream.effect_count("acct_red") == 1

    # A fresh process resumes from durable state and finishes without a second effect.
    resumed = gateway(db, upstream=SyntheticFreezeUpstream(db))
    done = resumed.execute_freeze(HUMAN, request_id)
    assert done["reason"] == "executed"
    assert done["request"]["state"] == "executed"
    assert resumed.upstream.apply_calls(request_id) == 2
    assert resumed.upstream.effect_count("acct_red") == 1

    trail = resumed.audit_log(request_id)
    assert [(e["action"], e["reason"]) for e in trail] == [
        ("request_account_freeze", "human_approval_required"),
        ("approve_account_freeze", "approved"),
        ("execute_account_freeze", "execution_started"),
        ("execute_account_freeze", "upstream_outcome_unknown"),
        ("execute_account_freeze", "execution_resumed"),
        ("execute_account_freeze", "executed"),
    ]
    assert {e["correlation_id"] for e in trail} == {request_id}
    assert trail[3]["metadata"]["error"] == "TimeoutError"


def test_concurrent_approvers_produce_exactly_one_decision(db):
    request_id = request(gateway(db))["request_id"]
    barrier = threading.Barrier(6)
    results: list[dict] = []

    def decide(index: int) -> None:
        service = gateway(db)  # one connection per thread, like separate operator processes
        approver = Principal(f"human-approver-{index}", "tenant_red", frozenset({APPROVE}))
        barrier.wait()
        results.append(
            service.decide_freeze(approver, request_id, approve=index % 2 == 0, note="race")
        )

    threads = [threading.Thread(target=decide, args=(i,)) for i in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    winners = [result for result in results if result["ok"]]
    assert len(winners) == 1
    assert sorted(r["reason"] for r in results if not r["ok"]) == ["invalid_transition"] * 5
    final = gateway(db).store.get(request_id)
    assert final.state.value == winners[0]["request"]["state"]
    assert final.approver == winners[0]["request"]["approver"]


def test_store_refuses_illegal_edges_and_lost_races(db):
    service = gateway(db)
    request_id = request(service)["request_id"]
    with pytest.raises(TransitionConflict, match="illegal_transition"):
        service.store.transition(request_id, ApprovalState.REQUESTED, ApprovalState.EXECUTED)
    with pytest.raises(TransitionConflict, match="state_changed"):
        service.store.transition(request_id, ApprovalState.APPROVED, ApprovalState.EXECUTING)


def test_audit_log_is_append_only(db):
    request(gateway(db))
    connection = sqlite3.connect(db)
    with pytest.raises(sqlite3.DatabaseError, match="audit_events_append_only"):
        connection.execute("UPDATE audit_events SET decision = 'allow'")
    with pytest.raises(sqlite3.DatabaseError, match="audit_events_append_only"):
        connection.execute("DELETE FROM audit_events")


def test_agent_cannot_read_other_tenant_request(db):
    service = gateway(db)
    request_id = request(service)["request_id"]
    blue = Principal("agent-blue", "tenant_blue", frozenset({"gateway:get_freeze_request"}))
    assert service.get_freeze_request(blue, request_id)["reason"] == "cross_tenant_access"
    assert service.get_freeze_request(AGENT, request_id)["reason"] == "missing_scope"


# ---------------------------------------------------------------- operator CLI

ISSUER = "https://issuer.example.test"
AUDIENCE = "mcp-policy-gateway"


@pytest.fixture
def issuer(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = tmp_path / "issuer.pem"
    public.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    return key, public


def cli(issuer, db, subject, scope, *args):
    key, public = issuer
    now = datetime.now(UTC)
    token = jwt.encode({
        "iss": ISSUER, "aud": AUDIENCE, "sub": subject, "tenant_id": "tenant_red",
        "scope": scope, "iat": now, "exp": now + timedelta(minutes=5),
    }, key, algorithm="RS256")
    env = {k: v for k, v in os.environ.items() if not k.startswith("GATEWAY_")}
    env.update({
        "GATEWAY_ID_TOKEN": token, "GATEWAY_JWT_PUBLIC_KEY_FILE": str(public),
        "GATEWAY_ISSUER": ISSUER, "GATEWAY_AUDIENCE": AUDIENCE,
    })
    if db is not None:
        env["GATEWAY_STATE_DB"] = str(db)
    return subprocess.run(
        [sys.executable, "-m", "mcp_policy_gateway.approvals", *args],
        capture_output=True, text=True, env=env, timeout=20,
    )


def test_operator_cli_uses_verified_identity_and_durable_store(issuer, db):
    # The CLI runs on wall-clock time, so the request must too.
    request_id = request(gateway(db, clock=time.time))["request_id"]
    selfish = cli(issuer, db, "agent-01", APPROVE, "approve", request_id, "--note", "mine")
    assert selfish.returncode == 1
    assert json.loads(selfish.stdout)["reason"] == "self_approval_forbidden"

    approved = cli(issuer, db, "human-approver-01", APPROVE, "approve", request_id, "--note", "ok")
    assert approved.returncode == 0, approved.stderr
    assert json.loads(approved.stdout)["request"]["state"] == "approved"
    executed = cli(issuer, db, "human-approver-01", APPROVE, "execute", request_id)
    assert json.loads(executed.stdout)["request"]["state"] == "executed"
    audit = json.loads(cli(issuer, db, "human-approver-01", APPROVE, "audit", request_id).stdout)
    assert [event["reason"] for event in audit["audit"]] == [
        "human_approval_required", "self_approval_forbidden", "approved",
        "execution_started", "executed",
    ]

    no_store = cli(issuer, None, "human-approver-01", APPROVE, "execute", request_id)
    assert no_store.returncode != 0
    assert "invalid_state_store" in no_store.stderr


def test_demo_runs_agent_and_operator_over_real_processes():
    import asyncio

    from mcp_policy_gateway.demo import run_demo

    results = asyncio.run(run_demo())
    assert results["replay"]["request_id"] == results["approval"]["request_id"]
    assert results["self_approval"]["reason"] == "self_approval_forbidden"
    assert results["execution"]["request"]["state"] == "executed"
    assert results["agent_view"]["request"]["state"] == "executed"
    assert results["summary_after"]["account"]["status"] == "frozen"
    assert [e["reason"] for e in results["audit_trail"]][:6] == [
        "human_approval_required", "idempotent_replay", "self_approval_forbidden",
        "approved", "execution_started", "executed",
    ]


def test_lock_wait_that_crosses_expiry_expires_instead_of_approving(db):
    """Regression: time must be sampled after the write lock is acquired."""
    clock = Clock()
    service = gateway(db, clock=clock)
    pending = request(service)
    clock.now = pending["expires_at"] - 1  # still valid when the approver starts
    locked, release = threading.Event(), threading.Event()

    def hold_write_lock() -> None:
        other = sqlite3.connect(db, isolation_level=None)
        other.execute("BEGIN IMMEDIATE")
        locked.set()
        release.wait(timeout=5)
        clock.now = pending["expires_at"]  # expiry passes while the approver waits
        other.execute("COMMIT")
        other.close()

    holder = threading.Thread(target=hold_write_lock)
    holder.start()
    locked.wait(timeout=5)
    timer = threading.Timer(0.3, release.set)
    timer.start()
    result = service.decide_freeze(HUMAN, pending["request_id"], approve=True, note="late")
    holder.join()
    timer.join()
    assert (result["reason"], result["state"]) == ("approval_expired", "expired")
    stored = service.store.get(pending["request_id"])
    assert stored.state is ApprovalState.EXPIRED
    assert stored.decided_at == pending["expires_at"]
    assert service.execute_freeze(HUMAN, pending["request_id"])["reason"] == "invalid_transition"
