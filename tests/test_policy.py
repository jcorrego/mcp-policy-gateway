"""Versioned policy must fail closed on incomplete or unsafe configurations."""

import json

import pytest

from mcp_policy_gateway.models import Decision, Principal
from mcp_policy_gateway.policy import PolicyConfigError, PolicyEngine, load_policy
from mcp_policy_gateway.service import GatewayService


def red(*scopes: str) -> Principal:
    return Principal("synthetic-actor", "tenant_red", frozenset(scopes))


def configuration() -> dict:
    return {
        "version": "test-v2",
        "actions": {
            "get_case": {"scope": "gateway:cases.read", "risk": "read"},
            "get_account_summary": {"scope": "gateway:accounts.read", "risk": "read"},
            "request_account_freeze": {"scope": "gateway:freeze.request", "risk": "mutation"},
        },
    }


def write_config(tmp_path, data):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_configured_scopes_and_version_apply_to_allow_deny_and_approval(tmp_path):
    policy = PolicyEngine(load_policy(write_config(tmp_path, configuration())))
    gateway = GatewayService(policy)
    assert gateway.get_case(red("gateway:get_case"), "case_red_01")["reason"] == "missing_scope"
    assert gateway.get_case(red("gateway:cases.read"), "case_red_01")["ok"] is True
    assert gateway.get_case(red("gateway:cases.read"), "case_blue_01")["reason"] == (
        "cross_tenant_access"
    )
    approval = gateway.request_account_freeze(
        red("gateway:freeze.request"), "acct_red", "synthetic request", "test-001"
    )
    assert approval["decision"] == Decision.REQUIRE_APPROVAL
    assert gateway.get_case(red(), "missing")["reason"] == "unknown_case"
    assert {event["policy_version"] for event in gateway.audit_log()} == {"test-v2"}
    assert policy.authorize(red(), action="not_a_tool", resource_tenant="tenant_red").reason == (
        "unknown_action"
    )


@pytest.mark.parametrize(
    "edit",
    [
        lambda d: d.update(version=""),
        lambda d: d.update(version="bad\nlabel"),
        lambda d: d.update(version=12),
        lambda d: d["actions"].pop("get_case"),
        lambda d: d["actions"].update(extra={"scope": "gateway:extra", "risk": "read"}),
        lambda d: d["actions"]["request_account_freeze"].update(risk="read"),
        lambda d: d["actions"]["get_case"].update(risk="mutation"),
        lambda d: d["actions"]["get_case"].update(scope=""),
        lambda d: d["actions"]["get_case"].update(scope="gateway:cases.read other"),
        lambda d: d["actions"]["get_case"].update(unexpected="allow"),
    ],
)
def test_unsafe_configs_fail_closed(tmp_path, edit):
    data = configuration()
    edit(data)
    with pytest.raises(PolicyConfigError, match="invalid_policy_config"):
        load_policy(write_config(tmp_path, data))


def test_missing_and_malformed_configs_fail_closed(tmp_path):
    with pytest.raises(PolicyConfigError, match="invalid_policy_config"):
        load_policy(tmp_path / "missing.json")
    path = tmp_path / "malformed.json"
    path.write_text("not-json", encoding="utf-8")
    with pytest.raises(PolicyConfigError, match="invalid_policy_config"):
        load_policy(path)


@pytest.mark.parametrize(
    "raw",
    [
        '{"version":"one","version":"two","actions":{}}',
        '{"version":"one","actions":{"get_case":{"scope":"gateway:get_case",'
        '"scope":"gateway:other","risk":"read"}}}',
    ],
)
def test_duplicate_keys_fail_before_rule_validation(tmp_path, raw):
    path = tmp_path / "duplicate.json"
    path.write_text(raw, encoding="utf-8")
    with pytest.raises(PolicyConfigError, match="invalid_policy_config"):
        load_policy(path)


def test_config_is_snapshotted_not_reloaded_mid_session(tmp_path):
    path = write_config(tmp_path, configuration())
    gateway = GatewayService(PolicyEngine(load_policy(path)))
    changed = configuration()
    changed["version"] = "test-v3"
    changed["actions"]["get_case"]["scope"] = "gateway:other"
    write_config(tmp_path, changed)
    assert gateway.get_case(red("gateway:cases.read"), "case_red_01")["ok"] is True
    assert gateway.audit_log()[-1]["policy_version"] == "test-v2"
