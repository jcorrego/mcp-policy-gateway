# ADR 004: durable executor leases, with upstream idempotency

Status: proposed implementation increment for roadmap [issue #1](https://github.com/jcorrego/mcp-policy-gateway/issues/1). Synthetic services only, no release tag.

## Problem

ADR 003 lets a fresh process resume an `executing` request after an unknown upstream outcome. It also lets two operators reach the upstream simultaneously. The upstream token prevents duplicate effects, but does not prevent avoidable duplicate calls. Holding the SQLite write lock across upstream I/O would serialize calls at the cost of blocking unrelated approvals and audit writes, and would not solve process death after the upstream effect.

## Decision

Create an additive `execution_leases` table keyed by request ID. Each lease has a random, per-attempt owner and an absolute expiry. Owners and lease records are internal, not model arguments or public response fields. The fixed reference TTL is 30 seconds.

1. Authorize the operator before any claim. Acquire `BEGIN IMMEDIATE`, then sample the clock. An approved request moves to `executing` together with its lease and audit event. An existing `executing` request can be claimed only if its lease is absent or expired. The store's conditional upsert compares expiry under the same lock.
2. A competing claim before expiry returns `ok: false`, `execution_in_progress` and a rounded-up `retry_after_seconds`. It appends a denial audit event but makes no upstream call. This is contention, not a new approval decision.
3. Commit the claim before calling the upstream. Never hold the gateway transaction across upstream I/O. Continue to send the request ID, not the lease owner, as the upstream idempotency token.
4. After success, reacquire the write lock and sample the clock. Only the current, unexpired owner can commit `executed`, release its lease and append the success event. These writes are atomic.
5. An upstream exception under a still-valid owned lease leaves the request `executing`, releases that lease and records `upstream_outcome_unknown` atomically. Immediate retry is possible with the same upstream token. Only the exception class is audited, never its message.
6. A late success or exception after lease expiry or takeover returns `execution_lease_lost` and appends a denial event. It must not finalize the request or delete a successor's lease. That response does not mean the upstream effect did not happen. Query status or retry after contention clears.
7. If a process dies or completion cannot commit, its lease expires naturally. Recovery may wait up to 30 seconds, then resume with the same token. An already-executed request returns `already_executed` without a claim or upstream call.

## Upgrade

`ApprovalStore` creates the new table on opening an existing database. No request rows are rewritten. Legacy `executing` rows without leases can resume immediately. Stop all old executor processes before upgrading: older code ignores the lease table. A mixed-version deployment is not safe for call suppression, although the synthetic upstream still deduplicates effects.

## Proof

`tests/test_execution_leases.py` covers:

- a blocked upstream and a competing executor, proving one call while the lease is live;
- stale success and stale exception while a successor owns the lease;
- expiry without a successor, refusing late finalization;
- a real subprocess killed after persisting its upstream effect, then restart before and at expiry with one total effect;
- opening a pre-lease database with a legacy `executing` row;
- a real SQLite lock wait crossing lease expiry, sampling time after lock acquisition;
- operator authorization before lease acquisition;
- rollback of both claim/state and completion/release when audit persistence fails.

The pre-existing timeout-after-apply test also proves an ordinary exception releases the lease for immediate recovery. CI runs both the resolved SDK and the exact dependency floor, retaining JUnit results and the real MCP/operator demo output.

## Limits and rejected claims

- This is gateway ownership checking, not upstream fencing. A paused worker may still perform upstream I/O after expiry while its successor runs. The upstream must guarantee idempotency for the stable request ID. A non-idempotent upstream still needs reconciliation or an upstream-enforced fencing protocol.
- No heartbeat, lease extension, upstream cancellation or upstream transport timeout exists. Calls exceeding 30 seconds lose their completion rights. The TTL is a reference constant, not a measured production timeout budget.
- Expiry uses a trusted wall clock shared by processes on one host. Backward clock jumps delay recovery, forward jumps allow early takeover. No cross-host clock-skew guarantees are claimed.
- SQLite is the only store. PostgreSQL, distributed workers and production service integration remain outside this increment.
- Audit triggers prevent application-level edits, not a database-file owner dropping tables or triggers.
