# Changelog

All notable changes to this reference implementation. Versions follow the roadmap in [issue #1](https://github.com/jcorrego/mcp-policy-gateway/issues/1). No release tag exists until its CI passes.

## Unreleased: durable approval and audit (first part of release 0.3)

### Added

- Freeze requests are stored as approval requests with states `requested`, `approved`, `rejected`, `expired`, `executing` and `executed`. The store enforces the legal edges with compare-and-set updates under a write lock.
- Idempotent replay per verified requester. A key reused with a different payload is denied as `idempotency_key_conflict`.
- `mcp-policy-gateway-approvals` operator CLI (`approve`, `reject`, `execute`, `audit`). It uses a separately verified approver JWT and requires `GATEWAY_STATE_DB`.
- Policy rules for mutations declare `approver_scope` and `approval_ttl_seconds`. The loader rejects an approver scope that equals a tool scope.
- Self-approval, cross-tenant approval and approval without the approver scope are denied. Every decision needs a note.
- Execution recovers after an unknown upstream outcome: the request stays in `executing`, and a retry with the same request-ID token adds no second effect.
- Append-only SQLite audit table with per-request correlation IDs. Triggers abort `UPDATE` and `DELETE`. Decision notes are written into the audit event, and operator reads of an audit trail are audited, whether allowed or denied.
- `get_freeze_request` MCP read tool, and the account summary reports `frozen` after execution.
- CI runs the end-to-end demo and uploads its output. A separate CI job tests the declared dependency floors.
- [ADR 003](docs/adr/003-durable-approvals.md).

### Changed

- Bundled policy is now `policy-v2.json` (version `2026-10-28.v2`).
- The dependency floors were raised to `mcp>=1.22` and `pyjwt[crypto]>=2.10.1`. On a clean install, the previously declared `mcp>=1.9` fails to import against current `pydantic`, and `mcp` 1.22 itself requires `pyjwt>=2.10.1`.

### Still open for 0.3

- PostgreSQL adapter (SQLite only today).
- A lease for concurrent executors, and reconciliation for upstreams that are not idempotent.

## Release 0.2 work (merged, not tagged)

- [#2](https://github.com/jcorrego/mcp-policy-gateway/pull/2): bind MCP tools to a verified RS256 JWT session, revalidated on every call.
- [#3](https://github.com/jcorrego/mcp-policy-gateway/pull/3): validated, versioned policy configuration with explicit deny reasons and `policy_version` on every decision.

## 0.1.0

- Initial policy-first MCP gateway: tenant isolation, scoped tools, minimized output, approval-required freeze, reason and idempotency requirement, structured audit events.
