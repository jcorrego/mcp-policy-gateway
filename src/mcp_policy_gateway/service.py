from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from collections.abc import Callable
from dataclasses import asdict
from typing import Any

from .data import ACCOUNTS, CASES
from .models import AuditEvent, Decision, PolicyDecision, Principal
from .policy import PolicyEngine
from .store import (
    ApprovalRequest,
    ApprovalState,
    ApprovalStore,
    SyntheticFreezeUpstream,
    new_request_id,
)

FREEZE = "request_account_freeze"
MAX_TEXT = 500
IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
NO_CHANGE = (
    "No state was changed. Route this request to an authorized human approver; "
    "the agent cannot approve or execute it."
)


class GatewayService:
    """Application service behind MCP tools and the approver CLI; transport-free."""

    def __init__(
        self,
        policy: PolicyEngine | None = None,
        store: ApprovalStore | None = None,
        upstream: SyntheticFreezeUpstream | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.policy = policy or PolicyEngine()
        self.store = store if store is not None else ApprovalStore()
        self.upstream = upstream if upstream is not None else SyntheticFreezeUpstream()
        self.clock = clock

    # ----------------------------------------------------------------- agent tools

    def get_case(self, principal: Principal, case_id: str) -> dict[str, Any]:
        case = CASES.get(case_id)
        if case is None:
            return self._deny(principal, "get_case", "unknown_case", {})

        decision = self.policy.authorize(
            principal,
            action="get_case",
            resource_tenant=case.tenant_id,
        )
        if decision.decision is not Decision.ALLOW:
            return self._decision(principal, "get_case", decision, {"case_id": case_id})

        return self._allow(principal, "get_case", {"case": asdict(case)})

    def get_account_summary(self, principal: Principal, account_id: str) -> dict[str, Any]:
        account = ACCOUNTS.get(account_id)
        if account is None:
            return self._deny(principal, "get_account_summary", "unknown_account", {})

        decision = self.policy.authorize(
            principal,
            action="get_account_summary",
            resource_tenant=account.tenant_id,
        )
        if decision.decision is not Decision.ALLOW:
            return self._decision(
                principal,
                "get_account_summary",
                decision,
                {"account_id": account_id},
            )

        # Data minimization: this tool intentionally never returns owner name or email.
        payload = {
            "account_id": account.account_id,
            "status": "frozen" if self.upstream.is_frozen(account.account_id) else account.status,
            "balance_cents": account.balance_cents,
        }
        return self._allow(principal, "get_account_summary", {"account": payload})

    def request_account_freeze(
        self,
        principal: Principal,
        account_id: str,
        reason: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Persist an approval request. Replays with the same key return the same request."""
        account = ACCOUNTS.get(account_id)
        if account is None:
            return self._deny(principal, FREEZE, "unknown_account", {})
        if not reason.strip() or not idempotency_key.strip():
            return self._deny(principal, FREEZE, "reason_and_idempotency_key_required", {})
        if len(reason) > MAX_TEXT or not IDEMPOTENCY_KEY.fullmatch(idempotency_key):
            return self._deny(principal, FREEZE, "invalid_request_fields", {})

        decision = self.policy.authorize(
            principal,
            action=FREEZE,
            resource_tenant=account.tenant_id,
        )
        metadata: dict[str, Any] = {"account_id": account_id, "idempotency_key": idempotency_key}
        if decision.decision is not Decision.REQUIRE_APPROVAL:
            return self._decision(principal, FREEZE, decision, metadata)

        rule = self.policy.rule(FREEZE)
        if rule is None or rule.approval_ttl_seconds is None:
            return self._deny(principal, FREEZE, "unknown_action", metadata)
        digest = hashlib.sha256(
            json.dumps({"account_id": account_id, "reason": reason}, sort_keys=True).encode()
        ).hexdigest()
        with self.store.transaction():
            now = self.clock()  # after the write lock, so lock waits cannot skew timestamps
            existing = self.store.find_by_idempotency(
                principal.tenant_id, principal.subject, FREEZE, idempotency_key
            )
            if existing is not None:
                metadata["request_id"] = existing.request_id
                if existing.payload_digest != digest:
                    return self._deny(
                        principal, FREEZE, "idempotency_key_conflict", metadata,
                        correlation_id=existing.request_id,
                    )
                self._audit(
                    principal, FREEZE, Decision.REQUIRE_APPROVAL, "idempotent_replay", metadata,
                    correlation_id=existing.request_id,
                )
                return self._approval_pending(existing, decision, replayed=True)

            request = ApprovalRequest(
                request_id=new_request_id(),
                tenant_id=principal.tenant_id,
                action=FREEZE,
                requester=principal.subject,
                account_id=account_id,
                reason=reason,
                idempotency_key=idempotency_key,
                payload_digest=digest,
                policy_version=self.policy.version,
                state=ApprovalState.REQUESTED,
                created_at=now,
                expires_at=now + rule.approval_ttl_seconds,
                approver=None,
                decision_note=None,
                decided_at=None,
                executed_at=None,
            )
            self.store.insert(request)
            metadata["request_id"] = request.request_id
            self._audit(
                principal, FREEZE, decision.decision, decision.reason, metadata,
                correlation_id=request.request_id,
            )
        return self._approval_pending(request, decision, replayed=False)

    def get_freeze_request(self, principal: Principal, request_id: str) -> dict[str, Any]:
        request = self.store.get(request_id)
        if request is None:
            return self._deny(principal, "get_freeze_request", "unknown_request", {})
        decision = self.policy.authorize(
            principal, action="get_freeze_request", resource_tenant=request.tenant_id
        )
        metadata = {"request_id": request_id}
        if decision.decision is not Decision.ALLOW:
            return self._decision(
                principal, "get_freeze_request", decision, metadata, correlation_id=request_id
            )
        self._audit(
            principal, "get_freeze_request", Decision.ALLOW, "policy_satisfied", metadata,
            correlation_id=request_id,
        )
        return {
            "ok": True, "decision": Decision.ALLOW, "policy_version": self.policy.version,
            "request": request.public_view(),
        }

    # ------------------------------------------------------------- operator actions

    def decide_freeze(
        self, principal: Principal, request_id: str, *, approve: bool, note: str
    ) -> dict[str, Any]:
        """A separate human identity approves or rejects; never reachable via MCP tools."""
        action = "approve_account_freeze" if approve else "reject_account_freeze"
        request = self.store.get(request_id)
        if request is None:
            return self._deny(principal, action, "unknown_request", {})
        metadata = {"request_id": request_id}
        decision = self.policy.authorize_operator(
            principal, action=request.action, resource_tenant=request.tenant_id,
            requester=request.requester,
        )
        if decision.decision is not Decision.ALLOW:
            return self._decision(principal, action, decision, metadata, correlation_id=request_id)
        if not note.strip() or len(note) > MAX_TEXT:
            return self._deny(
                principal, action, "decision_note_required", metadata, correlation_id=request_id
            )

        with self.store.transaction():
            # Sample time only once the write lock is held: a lock wait that crosses
            # expires_at must expire the request, not approve it with a stale timestamp.
            now = self.clock()
            current = self._stored(request_id)
            if current.state is ApprovalState.REQUESTED and now >= current.expires_at:
                self.store.transition(
                    request_id, ApprovalState.REQUESTED, ApprovalState.EXPIRED, decided_at=now
                )
                return self._deny(
                    principal, action, "approval_expired", metadata,
                    correlation_id=request_id, state=ApprovalState.EXPIRED,
                )
            if current.state is not ApprovalState.REQUESTED:
                return self._deny(
                    principal, action, "invalid_transition", metadata,
                    correlation_id=request_id, state=current.state,
                )
            target = ApprovalState.APPROVED if approve else ApprovalState.REJECTED
            self.store.transition(
                request_id, ApprovalState.REQUESTED, target,
                approver=principal.subject, decision_note=note, decided_at=now,
            )
            self._audit(
                principal, action, Decision.ALLOW, target.value, metadata,
                correlation_id=request_id,
            )
        return self._operator_result(request_id, target.value)

    def execute_freeze(self, principal: Principal, request_id: str) -> dict[str, Any]:
        """Apply an approved freeze exactly once, resuming safely after an unknown outcome."""
        action = "execute_account_freeze"
        request = self.store.get(request_id)
        if request is None:
            return self._deny(principal, action, "unknown_request", {})
        metadata = {"request_id": request_id, "account_id": request.account_id}
        decision = self.policy.authorize_operator(
            principal, action=request.action, resource_tenant=request.tenant_id, requester=None
        )
        if decision.decision is not Decision.ALLOW:
            return self._decision(principal, action, decision, metadata, correlation_id=request_id)

        with self.store.transaction():
            current = self._stored(request_id)
            if current.state is ApprovalState.EXECUTED:
                self._audit(
                    principal, action, Decision.ALLOW, "already_executed", metadata,
                    correlation_id=request_id,
                )
                return self._operator_result(request_id, "already_executed")
            if current.state is ApprovalState.APPROVED:
                self.store.transition(request_id, ApprovalState.APPROVED, ApprovalState.EXECUTING)
                step = "execution_started"
            elif current.state is ApprovalState.EXECUTING:
                # A previous attempt may or may not have reached the upstream system.
                step = "execution_resumed"
            else:
                return self._deny(
                    principal, action, "invalid_transition", metadata,
                    correlation_id=request_id, state=current.state,
                )
            self._audit(principal, action, Decision.ALLOW, step, metadata, request_id)

        try:
            # The request id is the upstream idempotency token, so a retry adds no effect.
            self.upstream.apply_freeze(request_id, current.account_id)
        except Exception as exc:  # any failure leaves the upstream outcome unknown
            self._audit(
                principal, action, Decision.ALLOW, "upstream_outcome_unknown",
                {**metadata, "error": type(exc).__name__}, correlation_id=request_id,
            )
            result = self._operator_result(request_id, "upstream_outcome_unknown")
            result["ok"] = False
            result["message"] = "Retry execute with the same request_id; upstream is idempotent."
            return result

        with self.store.transaction():
            latest = self._stored(request_id)
            outcome = "already_executed"
            if latest.state is ApprovalState.EXECUTING:
                self.store.transition(
                    request_id, ApprovalState.EXECUTING, ApprovalState.EXECUTED,
                    executed_at=self.clock(),
                )
                outcome = "executed"
            self._audit(principal, action, Decision.ALLOW, outcome, metadata, request_id)
        return self._operator_result(request_id, outcome)

    # ---------------------------------------------------------------------- audit

    def _stored(self, request_id: str) -> ApprovalRequest:
        request = self.store.get(request_id)
        if request is None:  # rows are never deleted; treat a vanished row as corruption
            raise RuntimeError("approval_request_missing")
        return request

    def audit_log(self, correlation_id: str | None = None) -> list[dict[str, Any]]:
        return self.store.audit_events(correlation_id)

    def _approval_pending(
        self, request: ApprovalRequest, decision: PolicyDecision, *, replayed: bool
    ) -> dict[str, Any]:
        return {
            "ok": False,
            "decision": Decision.REQUIRE_APPROVAL,
            "reason": decision.reason,
            "policy_version": decision.policy_version,
            "request_id": request.request_id,
            "state": request.state.value,
            "expires_at": request.expires_at,
            "replayed": replayed,
            "message": NO_CHANGE,
        }

    def _operator_result(self, request_id: str, reason: str) -> dict[str, Any]:
        request = self._stored(request_id)
        return {
            "ok": True, "decision": Decision.ALLOW, "reason": reason,
            "policy_version": self.policy.version, "request": request.public_view(),
        }

    def _allow(self, principal: Principal, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        self._audit(principal, action, Decision.ALLOW, "policy_satisfied", payload)
        return {
            "ok": True, "decision": Decision.ALLOW,
            "policy_version": self.policy.version, **payload,
        }

    def _deny(
        self,
        principal: Principal,
        action: str,
        reason: str,
        metadata: dict[str, Any],
        correlation_id: str | None = None,
        state: ApprovalState | None = None,
    ) -> dict[str, Any]:
        self._audit(principal, action, Decision.DENY, reason, metadata, correlation_id)
        result: dict[str, Any] = {
            "ok": False, "decision": Decision.DENY, "reason": reason,
            "policy_version": self.policy.version,
        }
        if state is not None:
            result["state"] = state.value
        return result

    def _decision(
        self,
        principal: Principal,
        action: str,
        decision: PolicyDecision,
        metadata: dict[str, Any],
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        self._audit(principal, action, decision.decision, decision.reason, metadata, correlation_id)
        return {
            "ok": False, "decision": Decision.DENY, "reason": decision.reason,
            "policy_version": decision.policy_version,
        }

    def _audit(
        self,
        principal: Principal,
        action: str,
        decision: Decision,
        reason: str,
        metadata: dict[str, Any],
        correlation_id: str | None = None,
    ) -> None:
        self.store.append_audit(
            AuditEvent(
                action=action,
                actor=principal.subject,
                tenant_id=principal.tenant_id,
                decision=decision,
                reason=reason,
                policy_version=self.policy.version,
                metadata=metadata,
                correlation_id=correlation_id or f"call_{uuid.uuid4().hex}",
            ),
            recorded_at=self.clock(),
        )
