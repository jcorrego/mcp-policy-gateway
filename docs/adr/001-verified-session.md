# ADR 001: verified identity belongs to the MCP session

Status: accepted for the synthetic stdio reference implementation.

A model can choose MCP tool arguments, including values copied from untrusted documents. It cannot establish its own identity, tenant, or scopes. The adapter therefore reads a bearer JWT and the issuer verification settings from the launch environment, verifies the RS256 signature against a locally pinned public key, and checks issuer, audience, issuance and expiry before starting the server. It checks the token again before every tool call so an expired token cannot continue using a long-running process. The tool signatures expose no identity fields. `GatewayService` still enforces tenant and action scope after authentication.

The test issuer generates its key in memory for each run. It is not an OIDC deployment or a production identity provider. The public key file is operator-owned, never fetched from an untrusted JWT `jku`/`kid` header. One stdio process has one launcher-controlled identity. The launcher and its environment are trusted; an attacker controlling those can replace the token and key. A real multi-user MCP transport needs per-request authentication, key rotation/JWKS policy, revocation, session isolation and an audit backend. The bearer token is intentionally not written to logs or artifacts.

A failed startup has no MCP tools. An invalid/expired token at call time raises a tool error rather than falling back to the original demo principal. Existing service-level audit events still record policy decisions but an authentication failure occurs before a trusted actor is available, so it is not attributed to the in-memory policy log. Future work should add safe authentication-denial telemetry without logging tokens.
