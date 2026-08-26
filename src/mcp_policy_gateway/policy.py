from .models import Decision, PolicyDecision, Principal, RiskLevel


class PolicyEngine:
    """Deterministic policy layer. The model never decides authorization."""

    def authorize(
        self,
        principal: Principal,
        *,
        action: str,
        resource_tenant: str,
        risk: RiskLevel,
    ) -> PolicyDecision:
        if principal.tenant_id != resource_tenant:
            return PolicyDecision(Decision.DENY, "cross_tenant_access", risk)

        required_scope = f"gateway:{action}"
        if required_scope not in principal.scopes:
            return PolicyDecision(Decision.DENY, "missing_scope", risk)

        if risk is RiskLevel.MUTATION:
            return PolicyDecision(Decision.REQUIRE_APPROVAL, "human_approval_required", risk)

        return PolicyDecision(Decision.ALLOW, "policy_satisfied", risk)
