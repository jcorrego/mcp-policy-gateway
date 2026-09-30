# ADR 002: load a validated policy snapshot at startup

## Decision

Bundle `policy-v1.json` with the installed package. An operator may supply a different file through `GATEWAY_POLICY_FILE` before launching the stdio process. The loader requires a nonempty version, exactly one rule for each exposed tool, an explicit single scope per tool and the tool's fixed risk class. The freeze tool's `mutation` risk cannot be downgraded by configuration. A malformed, missing or incomplete file aborts startup; there is no permissive fallback. Unknown actions deny. Every decision and in-memory audit event carries the loaded policy version and explicit reason.

## Why

Scopes belong in reviewed configuration rather than hard-coded branching. A snapshot avoids a mid-session file edit silently changing authorization while audit events claim a different rule set. Risk class is code-owned because a mistakenly edited policy must not turn a consequential action into an allowed read. The launch operator is trusted to select the file; MCP callers and model arguments cannot select policy or version.

## Limits

The version is a label, not a signed content digest. Operators must review and deploy config under access control; an attacker who controls the process environment or code can still alter policy. There is no hot reload, policy registry, persistent audit storage or policy distribution protocol. Only the current three MCP actions are modeled, and a `require_approval` response does not execute a mutation.
