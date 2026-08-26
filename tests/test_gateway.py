from mcp_policy_gateway.models import Decision, Principal
from mcp_policy_gateway.service import GatewayService


def red_principal(*scopes: str) -> Principal:
    return Principal(subject="agent-01", tenant_id="tenant_red", scopes=frozenset(scopes))


def test_summary_is_minimized_and_audited() -> None:
    gateway = GatewayService()
    result = gateway.get_account_summary(red_principal("gateway:get_account_summary"), "acct_red")

    assert result["ok"] is True
    assert result["account"] == {
        "account_id": "acct_red",
        "status": "active",
        "balance_cents": 12_500,
    }
    assert "email" not in result["account"]
    assert "owner_name" not in result["account"]
    assert gateway.audit_log()[-1]["decision"] == Decision.ALLOW


def test_cross_tenant_read_is_denied() -> None:
    gateway = GatewayService()
    result = gateway.get_account_summary(red_principal("gateway:get_account_summary"), "acct_blue")

    assert result == {"ok": False, "decision": Decision.DENY, "reason": "cross_tenant_access"}
    assert gateway.audit_log()[-1]["reason"] == "cross_tenant_access"


def test_missing_scope_is_denied() -> None:
    gateway = GatewayService()
    result = gateway.get_case(red_principal(), "case_red_01")

    assert result == {"ok": False, "decision": Decision.DENY, "reason": "missing_scope"}


def test_high_impact_action_cannot_mutate_without_approval() -> None:
    gateway = GatewayService()
    result = gateway.request_account_freeze(
        red_principal("gateway:request_account_freeze"),
        "acct_red",
        "customer reported card theft",
        "freeze-2026-001",
    )

    assert result["ok"] is False
    assert result["decision"] == Decision.REQUIRE_APPROVAL
    assert result["reason"] == "human_approval_required"
    assert "No state was changed" in result["message"]


def test_mutation_requires_reason_and_idempotency_key() -> None:
    gateway = GatewayService()
    result = gateway.request_account_freeze(
        red_principal("gateway:request_account_freeze"), "acct_red", "", ""
    )

    assert result == {
        "ok": False,
        "decision": Decision.DENY,
        "reason": "reason_and_idempotency_key_required",
    }
