from __future__ import annotations

from dataclasses import asdict
from typing import Any

from .data import ACCOUNTS, CASES
from .models import AuditEvent, Decision, Principal, RiskLevel
from .policy import PolicyEngine


class GatewayService:
    """Application service behind MCP tools; easy to test without a transport."""

    def __init__(self, policy: PolicyEngine | None = None) -> None:
        self.policy = policy or PolicyEngine()
        self.audit_events: list[AuditEvent] = []

    def get_case(self, principal: Principal, case_id: str) -> dict[str, Any]:
        case = CASES.get(case_id)
        if case is None:
            return self._deny(principal, "get_case", "unknown_case", {})

        decision = self.policy.authorize(
            principal,
            action="get_case",
            resource_tenant=case.tenant_id,
            risk=RiskLevel.READ,
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
            risk=RiskLevel.READ,
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
            "status": account.status,
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
        account = ACCOUNTS.get(account_id)
        if account is None:
            return self._deny(principal, "request_account_freeze", "unknown_account", {})
        if not reason.strip() or not idempotency_key.strip():
            return self._deny(
                principal,
                "request_account_freeze",
                "reason_and_idempotency_key_required",
                {},
            )

        decision = self.policy.authorize(
            principal,
            action="request_account_freeze",
            resource_tenant=account.tenant_id,
            risk=RiskLevel.MUTATION,
        )
        metadata = {"account_id": account_id, "idempotency_key": idempotency_key}
        return self._decision(principal, "request_account_freeze", decision, metadata)

    def audit_log(self) -> list[dict[str, Any]]:
        return [event.to_dict() for event in self.audit_events]

    def _allow(self, principal: Principal, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        self._audit(principal, action, Decision.ALLOW, "policy_satisfied", payload)
        return {"ok": True, "decision": Decision.ALLOW, **payload}

    def _deny(
        self,
        principal: Principal,
        action: str,
        reason: str,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        self._audit(principal, action, Decision.DENY, reason, metadata)
        return {"ok": False, "decision": Decision.DENY, "reason": reason}

    def _decision(
        self,
        principal: Principal,
        action: str,
        decision: Any,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        self._audit(principal, action, decision.decision, decision.reason, metadata)
        if decision.decision is Decision.REQUIRE_APPROVAL:
            return {
                "ok": False,
                "decision": Decision.REQUIRE_APPROVAL,
                "reason": decision.reason,
                "message": (
                    "No state was changed. Route this request to an authorized human approver."
                ),
            }
        return {"ok": False, "decision": Decision.DENY, "reason": decision.reason}

    def _audit(
        self,
        principal: Principal,
        action: str,
        decision: Decision,
        reason: str,
        metadata: dict[str, Any],
    ) -> None:
        self.audit_events.append(
            AuditEvent(
                action=action,
                actor=principal.subject,
                tenant_id=principal.tenant_id,
                decision=decision,
                reason=reason,
                metadata=metadata,
            )
        )
