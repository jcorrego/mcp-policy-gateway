# Threat model

## Assets to protect

- Tenant-scoped account and case data.
- Direct identifiers such as names and email addresses.
- State-changing operations such as account freezes.
- The integrity of the audit record.

## Trust boundaries

1. **Model output is untrusted.** It may be wrong, manipulated by retrieved text, or prompt-injected.
2. **Tool arguments are untrusted.** They do not establish identity, tenant membership, authorization, or approval.
3. **The MCP adapter is a transport boundary, not a policy engine.** It passes a verified principal to application code.
4. **The policy engine is authoritative.** It determines allow, deny or require-approval deterministically.

## Controls implemented here

| Threat | Control |
| --- | --- |
| Cross-tenant access | Compare verified principal tenant with resource tenant before data is returned. |
| Over-broad model access | Check a narrowly named action scope for every tool. |
| PII disclosure | Return a minimized view; direct fields never enter the tool response. |
| Unsafe mutation | Policy emits `require_approval`; the gateway makes no state change. |
| Duplicate request | Require a non-empty idempotency key at the gateway boundary. |
| Missing evidence | Require a reason for a state-changing request. |
| Silent authorization failure | Emit structured audit events for allow, deny and approval outcomes. |

## Deliberate non-goals

This reference implementation does **not** claim to provide:

- OAuth/OIDC verification, session management or mTLS;
- persistent or tamper-evident audit storage;
- a real approval workflow, payments system, PCI environment or production data source;
- DLP classification beyond the explicit minimized response; or
- protection against a compromised runtime or authorized human operator.

Production hardening would add identity-token verification, a policy decision point with centrally managed policies, encrypted append-only audit storage, rate limits, anomaly detection, secret management, monitoring, and integration tests against the real upstream system.
