"""Operator CLI for freeze approvals. Not an MCP surface; the agent cannot call it.

The approver authenticates with their own verified JWT through the same launch variables
as the server (GATEWAY_ID_TOKEN, GATEWAY_JWT_PUBLIC_KEY_FILE, GATEWAY_ISSUER,
GATEWAY_AUDIENCE). GATEWAY_STATE_DB must point to the shared state database.
"""

from __future__ import annotations

import argparse
import json
import sys

from .identity import InvalidSessionError, principal_from_environment
from .models import Decision
from .server import service_from_environment


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-policy-gateway-approvals")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("approve", "reject"):
        command = commands.add_parser(name)
        command.add_argument("request_id")
        command.add_argument("--note", required=True, help="why this decision was made")
    commands.add_parser("execute").add_argument("request_id")
    commands.add_parser("audit").add_argument("request_id")
    args = parser.parse_args(argv)

    try:
        principal = principal_from_environment()
    except InvalidSessionError as exc:
        raise SystemExit("invalid_session: configure a verified approver token") from exc
    service = service_from_environment(require_durable_store=True)

    if args.command in {"approve", "reject"}:
        result = service.decide_freeze(
            principal, args.request_id, approve=args.command == "approve", note=args.note
        )
    elif args.command == "execute":
        result = service.execute_freeze(principal, args.request_id)
    else:
        result = _audit(service, principal, args.request_id)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


def _audit(service, principal, request_id: str) -> dict:
    """Operators may read the correlated audit trail of requests in their own tenant."""
    request = service.store.get(request_id)
    if request is None:
        return {"ok": False, "reason": "unknown_request"}
    decision = service.policy.authorize_operator(
        principal, action=request.action, resource_tenant=request.tenant_id, requester=None
    )
    if decision.decision is not Decision.ALLOW:
        return {"ok": False, "reason": decision.reason}
    # Denied attempts by other tenants share the correlation id but belong to their audit.
    events = [
        event for event in service.audit_log(correlation_id=request_id)
        if event["tenant_id"] == request.tenant_id
    ]
    return {"ok": True, "request": request.public_view(), "audit": events}


if __name__ == "__main__":
    sys.exit(main())
