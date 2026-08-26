"""stdio MCP adapter for the policy-gated service.

The demo principal is intentionally fixed. In a production deployment, derive it from a
verified identity token/session and never trust tenant or scope values supplied by the model.
"""

from mcp.server.fastmcp import FastMCP

from .models import Principal
from .service import GatewayService

mcp = FastMCP("Policy Gateway")
service = GatewayService()
DEMO_PRINCIPAL = Principal(
    subject="support-agent-demo",
    tenant_id="tenant_red",
    scopes=frozenset(
        {
            "gateway:get_case",
            "gateway:get_account_summary",
            "gateway:request_account_freeze",
        }
    ),
)


@mcp.tool()
def get_case(case_id: str) -> dict:
    """Retrieve a support case inside the caller's tenant boundary."""
    return service.get_case(DEMO_PRINCIPAL, case_id)


@mcp.tool()
def get_account_summary(account_id: str) -> dict:
    """Return a minimized account summary; this tool never exposes direct PII."""
    return service.get_account_summary(DEMO_PRINCIPAL, account_id)


@mcp.tool()
def request_account_freeze(account_id: str, reason: str, idempotency_key: str) -> dict:
    """Request a high-impact account freeze. Policy always requires human approval."""
    return service.request_account_freeze(DEMO_PRINCIPAL, account_id, reason, idempotency_key)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
