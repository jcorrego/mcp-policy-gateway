"""Immutable, validated policy loaded before MCP serves any tool calls."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from types import MappingProxyType

from .models import Decision, PolicyDecision, Principal, RiskLevel

DEFAULT_POLICY_FILE = "policy-v2.json"


@dataclass(frozen=True)
class ActionRule:
    scope: str
    risk: RiskLevel
    approver_scope: str | None = None
    approval_ttl_seconds: int | None = None


class PolicyConfigError(ValueError):
    """A policy cannot safely be used; abort startup rather than fall back."""


# The tool contract fixes the risk class. Config may alter scopes but cannot downgrade
# the approval gate, add unknown actions or silently remove coverage for a tool.
TOOL_RISKS = MappingProxyType({
    "get_case": RiskLevel.READ,
    "get_account_summary": RiskLevel.READ,
    "get_freeze_request": RiskLevel.READ,
    "request_account_freeze": RiskLevel.MUTATION,
})

_READ_KEYS = frozenset({"scope", "risk"})
_MUTATION_KEYS = frozenset({"scope", "risk", "approver_scope", "approval_ttl_seconds"})
_MIN_TTL, _MAX_TTL = 60, 86_400


@dataclass(frozen=True)
class PolicyConfig:
    version: str
    actions: Mapping[str, ActionRule]


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate policy key")
        result[key] = value
    return result


def _valid_scope(scope: object) -> bool:
    return (
        isinstance(scope, str)
        and scope.startswith("gateway:")
        and bool(scope[8:])
        and not any(char.isspace() for char in scope)
    )


def load_policy(path: str | Path | None = None) -> PolicyConfig:
    try:
        text = (
            Path(path).read_text(encoding="utf-8")
            if path is not None
            else files("mcp_policy_gateway").joinpath(DEFAULT_POLICY_FILE).read_text(
                encoding="utf-8"
            )
        )
        data = json.loads(text, object_pairs_hook=_unique_object)
        if not isinstance(data, dict) or set(data) != {"version", "actions"}:
            raise ValueError("expected version and actions")
        version = data["version"]
        if not isinstance(version, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", version
        ):
            raise ValueError("invalid version")
        actions = data["actions"]
        if not isinstance(actions, dict) or set(actions) != set(TOOL_RISKS):
            raise ValueError("policy must cover exactly the exposed tools")
        parsed: dict[str, ActionRule] = {}
        for action, rule in actions.items():
            risk = TOOL_RISKS[action]
            expected_keys = _MUTATION_KEYS if risk is RiskLevel.MUTATION else _READ_KEYS
            if not isinstance(rule, dict) or set(rule) != expected_keys:
                raise ValueError(f"invalid rule for {action}")
            if not _valid_scope(rule["scope"]) or rule["risk"] != risk.value:
                raise ValueError(f"invalid scope or risk for {action}")
            if risk is RiskLevel.MUTATION:
                ttl = rule["approval_ttl_seconds"]
                if (
                    not _valid_scope(rule["approver_scope"])
                    or isinstance(ttl, bool)
                    or not isinstance(ttl, int)
                    or not _MIN_TTL <= ttl <= _MAX_TTL
                ):
                    raise ValueError(f"invalid approval rule for {action}")
                parsed[action] = ActionRule(rule["scope"], risk, rule["approver_scope"], ttl)
            else:
                parsed[action] = ActionRule(rule["scope"], risk)
        # An approver scope must never double as an ordinary tool scope; otherwise a token
        # minted for an agent's tool use could also act as the human approval credential.
        tool_scopes = {rule.scope for rule in parsed.values()}
        if any(rule.approver_scope in tool_scopes for rule in parsed.values()):
            raise ValueError("approver scope overlaps a tool scope")
        return PolicyConfig(version, MappingProxyType(parsed))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        raise PolicyConfigError("invalid_policy_config") from exc


class PolicyEngine:
    """Deterministic policy layer. The model never decides authorization."""

    def __init__(self, config: PolicyConfig | None = None) -> None:
        self.config = config if config is not None else load_policy()

    @property
    def version(self) -> str:
        return self.config.version

    def rule(self, action: str) -> ActionRule | None:
        return self.config.actions.get(action)

    def authorize(
        self,
        principal: Principal,
        *,
        action: str,
        resource_tenant: str,
    ) -> PolicyDecision:
        rule = self.config.actions.get(action)
        if rule is None:
            return PolicyDecision(Decision.DENY, "unknown_action", RiskLevel.MUTATION, self.version)
        if principal.tenant_id != resource_tenant:
            return PolicyDecision(Decision.DENY, "cross_tenant_access", rule.risk, self.version)
        if rule.scope not in principal.scopes:
            return PolicyDecision(Decision.DENY, "missing_scope", rule.risk, self.version)
        if rule.risk is RiskLevel.MUTATION:
            return PolicyDecision(
                Decision.REQUIRE_APPROVAL, "human_approval_required", rule.risk, self.version
            )
        return PolicyDecision(Decision.ALLOW, "policy_satisfied", rule.risk, self.version)

    def authorize_operator(
        self,
        principal: Principal,
        *,
        action: str,
        resource_tenant: str,
        requester: str | None,
    ) -> PolicyDecision:
        """Authorize a human decision on, or execution of, an approval request.

        Pass `requester` to forbid the principal that created the request from deciding it.
        """
        rule = self.config.actions.get(action)
        if rule is None or rule.approver_scope is None:
            return PolicyDecision(Decision.DENY, "unknown_action", RiskLevel.MUTATION, self.version)
        if principal.tenant_id != resource_tenant:
            return PolicyDecision(Decision.DENY, "cross_tenant_access", rule.risk, self.version)
        if rule.approver_scope not in principal.scopes:
            return PolicyDecision(Decision.DENY, "missing_approver_scope", rule.risk, self.version)
        if requester is not None and principal.subject == requester:
            return PolicyDecision(
                Decision.DENY, "self_approval_forbidden", rule.risk, self.version
            )
        return PolicyDecision(Decision.ALLOW, "approver_authorized", rule.risk, self.version)
