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
| Invalid or incomplete policy config | Parse and validate every rule before serving; fix tool risk classes in code and deny unknown actions. |
| Agent approves its own mutation | Approve/reject/execute are not MCP tools; the operator CLI requires a separately verified principal with a distinct approver scope and refuses the requester's subject. |
| Approver token minted from agent scopes | Policy loading fails if the approver scope equals any tool scope. |
| Duplicate or replayed request | Idempotency keys are unique per tenant, requester and action; a same-payload replay returns the existing request, and a different payload is denied. |
| Stale or raced decision | Requests expire at their policy TTL; transitions are compare-and-set under a write lock, so only one decision wins. |
| Timeout after upstream execution | The request stays `executing`; a retry reuses the request ID as the upstream idempotency token, so no second effect occurs. |
| Audit rewriting by the application | SQLite triggers abort `UPDATE` and `DELETE` on audit events; transitions and their audit events commit atomically. |

Policy is an immutable startup snapshot. Decision and audit records carry its version label and explicit reason, but the label is not a content hash. The operator controls the launch environment and must review configuration changes.

## Deliberate non-goals

This reference implementation does **not** claim to provide:

- OIDC discovery, JWKS rotation, revocation, remote per-request authentication or mTLS;
- tamper-evident audit storage (the append-only triggers do not stop someone with write access to the database file);
- a production approval interface, PostgreSQL deployment, payments system, PCI environment or production data source;
- DLP classification beyond the explicit minimized response; or
- protection against a compromised runtime or authorized human operator.

Production hardening would add key rotation and revocation, per-request authentication for remote transport, centrally managed policies, encrypted append-only audit storage, rate limits, anomaly detection, secret management, monitoring, and integration tests against the real upstream system.
