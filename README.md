# mcp-policy-gateway

A **policy-first MCP server** reference implementation. It shows how to give an agent useful tools without allowing the model to decide authorization, cross tenant boundaries, leak direct PII, or execute high-impact mutations on its own.

> This is a portfolio/reference implementation. Every record is synthetic; it is not production software and does not claim to integrate with a bank, payment processor, or customer system.

## Why this exists

A common MCP demo exposes a raw API to a model and treats a successful tool call as a security model. This project takes the opposite position:

- **Policy is deterministic.** The model cannot authorize itself.
- **Tenant boundary is enforced server-side.** A tool argument cannot switch tenant.
- **Tool output is minimized.** The account summary intentionally excludes owner name and email.
- **High-impact actions stop at an approval gate.** A freeze request produces no state change.
- **Every decision is auditable.** Allow, deny and approval-required outcomes create structured audit events.
- **Mutation requests require a reason and idempotency key.**

## Architecture

```text
MCP client / agent
       │ tool call
       ▼
FastMCP stdio adapter
       │ JWT verified with operator-pinned public key (at startup and per call)
       ▼
GatewayService ──► PolicyEngine ──► allow / deny / require approval
       │                 │
       ▼                 ▼
synthetic domain data   structured audit event
```

The launcher supplies a JWT, issuer, audience and pinned public key through its environment. The adapter derives the principal from the verified session, outside model-controlled arguments. The bundled test issuer exists only for synthetic tests and the demo; it is not an OIDC provider. See [ADR 001](docs/adr/001-verified-session.md).

## Tools

| Tool | Risk | Behaviour |
| --- | --- | --- |
| `get_case(case_id)` | Read | Allows only cases in the caller's tenant with the right scope. |
| `get_account_summary(account_id)` | Read | Returns a minimized summary; never direct PII. |
| `request_account_freeze(...)` | Mutation | Requires a scope, reason and idempotency key, then **always requires human approval**. |

## Quickstart

Requires Python 3.11+.

```bash
python -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
.venv/bin/ruff check .
.venv/bin/python -m mcp_policy_gateway.demo
```

The demo generates a temporary RSA keypair and JWT, starts a real MCP stdio subprocess, and prints an allowed read, cross-tenant denial and approval-required response. Run as an MCP stdio server with your trusted launcher:

```bash
.venv/bin/mcp-policy-gateway
```

The launcher must set `GATEWAY_ID_TOKEN`, `GATEWAY_JWT_PUBLIC_KEY_FILE`, `GATEWAY_ISSUER` and `GATEWAY_AUDIENCE`. The key file contains only the issuer's public key. The JWT must be signed with RS256 and contain `iss`, `aud`, `sub`, `tenant_id`, a space-delimited `scope`, `iat` and `exp`. Missing or invalid settings fail startup. Never pass the token as a tool argument or commit it to this repository. These launch variables are for a one-identity stdio process, not multi-tenant remote transport.

## Demonstrated abuse controls

The tests prove the gateway:

1. denies an agent from `tenant_red` trying to read `tenant_blue` data;
2. denies a tool call without its required scope;
3. does not return owner name or email through the summary tool;
4. returns `require_approval` rather than mutating account state; and
5. rejects state-changing requests that omit a reason or idempotency key.

The identity tests also exercise expired/wrong-audience tokens, bad signatures, malformed claims, untrusted tenant/scope arguments and a real MCP client/server exchange.

## Threat model and non-goals

See [THREAT_MODEL.md](THREAT_MODEL.md). This is a pinned-key JWT verification seam, not full OIDC discovery, key rotation, revocation, durable audit storage, secrets management or a payment/ledger system.

## Interview walkthrough

A concise way to explain the project:

> I designed the MCP boundary so the model can reason over safe, scoped data but cannot decide access or execute high-impact actions. Authorization is deterministic, tenant isolation is enforced server-side, the tool surface minimizes PII, and sensitive mutations terminate in an auditable human approval gate.

## Development

```bash
.venv/bin/pytest
.venv/bin/ruff check .
```

CI runs both checks on pushes and pull requests.

## License

MIT. See [LICENSE](LICENSE).
