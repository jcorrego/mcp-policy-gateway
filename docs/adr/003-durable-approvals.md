# ADR 003: durable approval requests with a separate approver

Status: accepted for the synthetic reference implementation.

## Context

Before this change a freeze request returned `require_approval` and nothing else happened. The gateway kept no record of the request, so there was nothing a human could approve. Retries had no defined meaning, and the in-memory audit log disappeared with the process. Release 0.3 on the roadmap asks for durable approvals, idempotency, distinct transitions, a separate approver identity, correlation IDs and recovery after an upstream timeout.

## Decision

- **Persist the request.** `request_account_freeze` writes an approval request in the `requested` state. The record holds the verified requester, tenant, account, reason, the policy version in force, and an expiry taken from the policy rule (`approval_ttl_seconds`).
- **Scope idempotency to the verified caller.** The key is unique per `(tenant, requester, action, idempotency_key)`. A retry with the same payload returns the existing request with `replayed: true` and creates nothing new. Reusing the key with a different payload is denied as `idempotency_key_conflict`. The payload is compared by SHA-256 digest.
- **Store-enforced state machine.** The only legal edges are `requested → approved | rejected | expired`, `approved → executing` and `executing → executed`. Every transition runs inside `BEGIN IMMEDIATE` and does a compare-and-set on the expected prior state, so an illegal edge or a lost race raises instead of overwriting.
- **The approver is a different verified principal.** Approve, reject and execute exist only in the operator CLI (`mcp-policy-gateway-approvals`). They are not MCP tools. The approver authenticates with their own JWT, as the server does. Policy requires a separate `approver_scope` from the same tenant and refuses self-approval. The loader rejects any policy where the approver scope equals one of the tool scopes, so an agent's tool token cannot also serve as an approval credential. Every decision needs a note.
- **Expiry is checked when someone decides.** Deciding after `expires_at` moves the request to `expired` and denies the action.
- **Execution has to survive an unknown outcome.** The executor first claims the request (`approved → executing`) and commits. Then it calls the upstream with the request ID as the idempotency token, and finally commits `executing → executed`. If the upstream call raises, the request stays in `executing` and the result is `upstream_outcome_unknown`. A retry, possibly from a new process, resumes from `executing` and calls the upstream again with the same token. The synthetic upstream applies one effect per token, so a timeout after execution cannot produce a second freeze.
- **The audit log is append-only and correlated.** Audit events go into the same SQLite file. Triggers abort any `UPDATE` or `DELETE`. Each event carries a `correlation_id`: the request ID for approval-flow events and a per-call ID otherwise. A transition and its audit event commit in the same transaction. The approver's note goes into the decision's audit event, because the request row is not the immutable record. Reading an audit trail is itself audited, whether it is allowed or denied.

## Why SQLite and not PostgreSQL yet

The roadmap names PostgreSQL. This increment uses the standard-library `sqlite3` module so the reference stays runnable in ten minutes with no service to install, and so CI needs no database container. The properties under test (serialized writers, compare-and-set transitions, unique idempotency scope, append-only triggers) carry over to PostgreSQL with row locks or `SERIALIZABLE` and a revoked `UPDATE/DELETE` grant. A PostgreSQL adapter is still open roadmap work. This ADR does not claim it exists.

## Consequences and limits

- The upstream is a synthetic table that stands in for an external system honouring an idempotency token. The design relies on that guarantee. An upstream without idempotency would need a reconciliation query before any retry, and this reference does not implement one.
- Two operators who retry the same `executing` request at the same moment can both reach the upstream. The upstream token prevents a duplicate effect, but a lease would avoid the duplicate call.
- The append-only triggers stop accidental or application-level edits. They do not stop someone who has write access to the database file, who can drop the triggers. There is no hash chain or external log shipping.
- Without `GATEWAY_STATE_DB` the MCP server uses an in-memory store, which is fine for tests but not durable. The operator CLI refuses to run without a database file.
- Expiry is evaluated lazily at decision time. No sweeper materializes expired rows.
- An approved request has no separate execution deadline, and execution does not re-check whether the policy changed after approval.
- The operator CLI is a reference surface, not an approval UI. A real approver also needs to see the evidence behind the request, and an approval should be bound to that evidence.
