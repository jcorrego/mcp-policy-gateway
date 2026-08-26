from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any


class RiskLevel(StrEnum):
    READ = "read"
    SENSITIVE_READ = "sensitive_read"
    MUTATION = "mutation"


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True)
class Principal:
    subject: str
    tenant_id: str
    scopes: frozenset[str]


@dataclass(frozen=True)
class Account:
    account_id: str
    tenant_id: str
    owner_name: str
    email: str
    status: str
    balance_cents: int


@dataclass(frozen=True)
class Case:
    case_id: str
    tenant_id: str
    account_id: str
    summary: str
    status: str


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    reason: str
    risk: RiskLevel


@dataclass(frozen=True)
class AuditEvent:
    action: str
    actor: str
    tenant_id: str
    decision: Decision
    reason: str
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
