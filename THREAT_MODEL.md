# Threat model

## Assets to protect

- Tenant-scoped account and case data.
- Direct identifiers such as names and email addresses.
- State-changing operations such as account freezes.
- The integrity of the audit record.

## Trust boundaries

1. **Model output is untrusted.** It may be wrong, manipulated by retrieved text, or prompt-injected.
2. **Tool arguments are untrusted.** They do not establish identity, tenant membership, authorization, or approval.
3. **The MCP adapter authenticates a launch-bound session.** It validates a signed JWT with a pinned issuer public key at startup and again before each tool call, then passes a verified principal to application code.
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
| Spoofed principal in model arguments | The MCP tool schema has no identity fields; the adapter derives a principal only from the verified launch token. |
| Expired or wrong-audience token | JWT checks issuer, audience, expiry, issuance and signature; invalid startup fails closed and each call revalidates. |

## Deliberate non-goals

This reference implementation does **not** claim to provide:

- OIDC discovery, JWKS rotation, revocation, remote per-request authentication or mTLS;
- persistent or tamper-evident audit storage;
- a real approval workflow, payments system, PCI environment or production data source;
- DLP classification beyond the explicit minimized response; or
- protection against a compromised runtime or authorized human operator.

Production hardening would add key rotation and revocation, per-request authentication for remote transport, centrally managed policies, encrypted append-only audit storage, rate limits, anomaly detection, secret management, monitoring, and integration tests against the real upstream system.
