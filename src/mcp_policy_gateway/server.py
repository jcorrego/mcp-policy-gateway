"""stdio MCP adapter. Authenticate at launch and again on each tool call."""

from collections.abc import Callable

from mcp.server.fastmcp import FastMCP

from .identity import InvalidSessionError, principal_from_environment
from .models import Principal
from .service import GatewayService


def build_server(
    principal_provider: Callable[[], Principal], service: GatewayService | None = None
) -> FastMCP:
    """Bind trusted session verification to all tools, never to tool arguments."""
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
        """Request a high-impact account freeze. Policy always requires human approval."""
        return gateway.request_account_freeze(
            principal_provider(), account_id, reason, idempotency_key
        )

    return mcp


def main() -> None:
    try:
        principal_from_environment()
    except InvalidSessionError as exc:
        raise SystemExit("invalid_session: configure a verified startup token") from exc
    build_server(principal_from_environment).run(transport="stdio")


if __name__ == "__main__":
    main()
