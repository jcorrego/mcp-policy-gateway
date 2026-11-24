# Roadmap

Tracked in [issue #1](https://github.com/jcorrego/mcp-policy-gateway/issues/1). All fixtures and upstream effects are synthetic. Merged increments are not release tags.

## 0.2: verified identity and versioned policy

- Implemented and merged in [PR #2](https://github.com/jcorrego/mcp-policy-gateway/pull/2) and [PR #3](https://github.com/jcorrego/mcp-policy-gateway/pull/3): pinned-key RS256 session verification, per-call expiry checks, principal outside model arguments, validated policy snapshots and explicit decision metadata.
- Remaining release work: owner review of the release scope and a versioned release. No full OIDC discovery, key rotation, revocation or remote per-request authentication is claimed.

## 0.3: durable approval and audit

- Implemented and merged in [PR #5](https://github.com/jcorrego/mcp-policy-gateway/pull/5): SQLite approval states, a separate operator identity, scoped idempotency, append-only correlated audit records and retry recovery after an unknown upstream outcome.
- Current increment: durable executor leases, exact-expiry crash recovery, stale-owner completion checks and atomic audit/lease writes. See [ADR 004](docs/adr/004-execution-leases.md) and `tests/test_execution_leases.py`.
- Remaining: PostgreSQL adapter and its concurrency tests; reconciliation for non-idempotent upstreams; explicit execution deadlines and policy-change handling. Leases do not provide upstream fencing or cancellation.

## 0.4: observability and abuse evaluation

- OpenTelemetry policy/tool spans and redacted metrics/logs.
- Versioned adversarial evaluation with machine-readable artifacts.
- A short walkthrough showing allow, deny, approval, execution and safe recovery.

## Outside this workflow

[Issue #4](https://github.com/jcorrego/mcp-policy-gateway/issues/4) proposes an external source-rights evidence provider. The current synthetic account workflow has no fetch, ingest, indexing or training action. No external provider call or integration is part of this increment, and signed source declarations must not be treated as permission by default.
