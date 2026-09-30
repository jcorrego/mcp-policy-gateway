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


@dataclass(frozen=True)
class ActionRule:
    scope: str
    risk: RiskLevel


class PolicyConfigError(ValueError):
    """A policy cannot safely be used; abort startup rather than fall back."""


# The tool contract fixes the risk class. Config may alter scopes but cannot downgrade
# the approval gate, add unknown actions or silently remove coverage for a tool.
TOOL_RISKS = MappingProxyType({
    "get_case": RiskLevel.READ,
    "get_account_summary": RiskLevel.READ,
    "request_account_freeze": RiskLevel.MUTATION,
})


@dataclass(frozen=True)
class PolicyConfig:
    version: str
    actions: Mapping[str, ActionRule]


def load_policy(path: str | Path | None = None) -> PolicyConfig:
    try:
        text = (
            Path(path).read_text(encoding="utf-8")
            if path is not None
            else files("mcp_policy_gateway").joinpath("policy-v1.json").read_text(encoding="utf-8")
        )
        data = json.loads(text)
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
            if not isinstance(rule, dict) or set(rule) != {"scope", "risk"}:
                raise ValueError(f"invalid rule for {action}")
            scope, risk = rule["scope"], rule["risk"]
            if (
                not isinstance(scope, str)
                or not scope.startswith("gateway:")
                or not scope[8:]
                or any(char.isspace() for char in scope)
                or risk != TOOL_RISKS[action].value
            ):
                raise ValueError(f"invalid scope or risk for {action}")
            parsed[action] = ActionRule(scope, TOOL_RISKS[action])
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
