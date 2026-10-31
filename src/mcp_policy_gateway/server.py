"""stdio MCP adapter. Authenticate at launch and again on each tool call."""

import os
from collections.abc import Callable

from mcp.server.fastmcp import FastMCP

from .identity import InvalidSessionError, principal_from_environment
from .models import Principal
from .policy import PolicyConfigError, PolicyEngine, load_policy
from .service import GatewayService
from .store import ApprovalStore, StoreError, SyntheticFreezeUpstream


def build_server(
    principal_provider: Callable[[], Principal], service: GatewayService | None = None
) -> FastMCP:
    """Bind trusted session verification to all tools, never to tool arguments.

    Approval, rejection and execution are deliberately absent: they run through the
    separate operator CLI under a different verified identity.
    """
    gateway = service or GatewayService()
    mcp = FastMCP("Policy Gateway")

    @mcp.tool()
    def get_case(case_id: str) -> dict:
        """Retrieve a support case inside the caller's tenant boundary."""
        return gateway.get_case(principal_provider(), case_id)

    @mcp.tool()
    def get_account_summary(account_id: str) -> dict:
        """Return a minimized account summary; this tool never exposes direct PII."""
        return gateway.get_account_summary(principal_provider(), account_id)

    @mcp.tool()
    def request_account_freeze(account_id: str, reason: str, idempotency_key: str) -> dict:
        """Request a high-impact account freeze. Policy always requires human approval.

        Retrying with the same idempotency key returns the same pending request.
        """
        return gateway.request_account_freeze(
            principal_provider(), account_id, reason, idempotency_key
        )

    @mcp.tool()
    def get_freeze_request(request_id: str) -> dict:
        """Read the state of a freeze approval request inside the caller's tenant."""
        return gateway.get_freeze_request(principal_provider(), request_id)

    return mcp


def service_from_environment(*, require_durable_store: bool) -> GatewayService:
    """Build the service from operator-controlled launch settings; fail closed."""
    try:
        policy = PolicyEngine(load_policy(os.environ.get("GATEWAY_POLICY_FILE")))
    except PolicyConfigError as exc:
        raise SystemExit("invalid_policy_config: configure a valid versioned policy") from exc
    path = os.environ.get("GATEWAY_STATE_DB", "").strip()
    if require_durable_store and (not path or path == ":memory:"):
        raise SystemExit("invalid_state_store: set GATEWAY_STATE_DB to a database file")
    try:
        store = ApprovalStore(path or ":memory:")
        upstream = SyntheticFreezeUpstream(path or ":memory:")
    except StoreError as exc:
        raise SystemExit("invalid_state_store: cannot open GATEWAY_STATE_DB") from exc
    return GatewayService(policy, store, upstream)


def main() -> None:
    try:
        principal_from_environment()
    except InvalidSessionError as exc:
        raise SystemExit("invalid_session: configure a verified startup token") from exc
    service = service_from_environment(require_durable_store=False)
    build_server(principal_from_environment, service).run(transport="stdio")


if __name__ == "__main__":
    main()
