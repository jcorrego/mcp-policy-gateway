# mcp-policy-gateway

A **policy-first MCP server** reference implementation. It shows how to give an agent useful tools without allowing the model to decide authorization, cross tenant boundaries, leak direct PII, or execute high-impact mutations on its own.

> This is a portfolio/reference implementation. Every record is synthetic; it is not production software and does not claim to integrate with a bank, payment processor, or customer system.

## Why this exists

A common MCP demo exposes a raw API to a model and treats a successful tool call as a security model. This project takes the opposite position:

- **Policy is deterministic.** The model cannot authorize itself.
- **Tenant boundary is enforced server-side.** A tool argument cannot switch tenant.
- **Tool output is minimized.** The account summary intentionally excludes owner name and email.
- **High-impact actions stop at an approval gate.** A freeze request is stored as a pending approval and changes no account state. Only a different, human approver identity can approve it, and only through the operator CLI. MCP has no approve tool.
- **Approved actions execute once.** A store-enforced state machine, idempotent replays and an idempotent upstream token mean that a timeout after execution resumes the request without freezing the account twice.
- **Every decision is auditable.** Allow, deny, approval and execution outcomes go to an append-only audit table, with a correlation ID per request.
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
synthetic domain data   ApprovalStore (SQLite): approval requests + append-only audit
                                 ▲
human approver ──► operator CLI ─┘  approve / reject / execute ──► synthetic upstream
  (own verified JWT, approver scope, never the requester)          (idempotent on request ID)
```

The launcher supplies a JWT, issuer, audience and pinned public key through its environment. The adapter derives the principal from the verified session, outside model-controlled arguments. The bundled test issuer exists only for synthetic tests and the demo; it is not an OIDC provider. The policy engine loads a versioned configuration snapshot at startup. See [ADR 001](docs/adr/001-verified-session.md), [ADR 002](docs/adr/002-versioned-policy.md) and [ADR 003](docs/adr/003-durable-approvals.md).

## Tools

| Tool | Risk | Behaviour |
| --- | --- | --- |
| `get_case(case_id)` | Read | Allows only cases in the caller's tenant with the right scope. |
| `get_account_summary(account_id)` | Read | Returns a minimized summary; never direct PII. |
| `request_account_freeze(...)` | Mutation | Requires a scope, reason and idempotency key, then stores a pending request that **always requires human approval**. A retry with the same key returns the same request. |
| `get_freeze_request(request_id)` | Read | Returns a request's state inside the caller's tenant. |

Operator-only commands, deliberately not exposed over MCP:

```bash
mcp-policy-gateway-approvals approve REQUEST_ID --note "why"
mcp-policy-gateway-approvals reject  REQUEST_ID --note "why"
mcp-policy-gateway-approvals execute REQUEST_ID
mcp-policy-gateway-approvals audit   REQUEST_ID
```

The CLI reads the approver's own token from the same `GATEWAY_*` launch variables and requires `GATEWAY_STATE_DB`. Request states are `requested → approved | rejected | expired` and `approved → executing → executed`; any other transition is refused.

## Quickstart

Requires Python 3.11+.

```bash
python -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
.venv/bin/ruff check .
.venv/bin/python -m mcp_policy_gateway.demo
```

The demo generates a temporary RSA keypair, an agent token and a separate approver token. It starts a real MCP stdio subprocess and runs:

1. an allowed read and a cross-tenant denial;
2. an approval-required freeze request, followed by a replay that returns the same request;
3. the agent trying to approve its own request through the operator CLI, which is denied;
4. a human approval and execution in separate operator processes;
5. the agent reading back the executed request and the now-frozen account, plus the correlated audit trail. Run as an MCP stdio server with your trusted launcher:

```bash
.venv/bin/mcp-policy-gateway
```

The launcher must set `GATEWAY_ID_TOKEN`, `GATEWAY_JWT_PUBLIC_KEY_FILE`, `GATEWAY_ISSUER` and `GATEWAY_AUDIENCE`. The key file contains only the issuer's public key. The JWT must be signed with RS256 and contain `iss`, `aud`, `sub`, `tenant_id`, a space-delimited `scope`, `iat` and `exp`. Missing or invalid settings fail startup. Never pass the token as a tool argument or commit it to this repository. These launch variables are for a one-identity stdio process, not multi-tenant remote transport. Set `GATEWAY_STATE_DB` to a SQLite file path to keep approval requests and audit events across restarts and share them with the operator CLI. Without it, the server keeps them in memory.

The installed package uses [`policy-v2.json`](src/mcp_policy_gateway/policy-v2.json) by default. To deploy a reviewed policy file, set `GATEWAY_POLICY_FILE` to its absolute path in the trusted launcher. Each rule specifies `scope` and `risk`, and every exposed tool needs a rule. `request_account_freeze` must keep `mutation` risk and also declare an `approver_scope` and an `approval_ttl_seconds` value between 60 and 86400. The approver scope may not equal any tool scope. Invalid configurations abort startup. Tool results and audit events include `policy_version`; denials include a machine-readable `reason`. A running server keeps its startup snapshot, so restart it to apply a new file. The version is an operator-provided label, not cryptographic proof of policy contents.

## Demonstrated abuse controls

The tests prove the gateway:

1. denies an agent from `tenant_red` trying to read `tenant_blue` data;
2. denies a tool call without its required scope;
3. does not return owner name or email through the summary tool;
4. returns `require_approval` rather than mutating account state; and
5. rejects state-changing requests that omit a reason or idempotency key;
6. refuses self-approval, approval without the approver scope, and cross-tenant approval;
7. returns the same request for an idempotent replay and denies key reuse with a different payload;
8. refuses illegal transitions, approval after expiry and execution before approval;
9. produces exactly one approval decision when six approvers race;
10. resumes from `executing` after a timeout that follows upstream execution, with one effect and a complete correlated audit trail; and
11. aborts any `UPDATE` or `DELETE` on the audit table.

The identity tests also exercise expired/wrong-audience tokens, bad signatures, malformed claims, untrusted tenant/scope arguments and a real MCP client/server exchange.

## Threat model and non-goals

See [THREAT_MODEL.md](THREAT_MODEL.md). This is a pinned-key JWT verification seam, not full OIDC discovery, key rotation, revocation, secrets management or a payment/ledger system. Approval state uses SQLite, not PostgreSQL. The audit triggers block application-level edits but are not tamper-evident against someone who can write to the database file. The upstream is a synthetic table.

## Interview walkthrough

A concise way to explain the project:

> I designed the MCP boundary so the model can reason over safe, scoped data but cannot decide access or execute high-impact actions. Authorization is deterministic, tenant isolation is enforced server-side, and the tool surface minimizes PII. A sensitive mutation becomes a durable request that only a different human identity can approve, outside MCP. Execution is idempotent end to end, so a timeout after the upstream call resumes the request instead of applying it twice.

## Development

```bash
.venv/bin/pytest
.venv/bin/ruff check .
```

CI runs lint, tests and the demo on pushes and pull requests, and uploads the demo output as an artifact. A second job installs the declared dependency floors (`mcp==1.22.0`, `pyjwt==2.10.1`) and runs the suite again. Older `mcp` releases fail to import against current `pydantic`.

## License

MIT. See [LICENSE](LICENSE).
