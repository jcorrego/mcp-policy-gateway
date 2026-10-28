"""Run a real stdio MCP exchange plus an operator approval against a synthetic issuer.

The agent session and the human approver use different verified tokens from the same
throwaway local issuer. Nothing here talks to a real identity provider or account system.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import TextContent

ISSUER = "https://issuer.example.test"
AUDIENCE = "mcp-policy-gateway"
AGENT_SCOPES = (
    "gateway:get_case gateway:get_account_summary gateway:request_account_freeze "
    "gateway:get_freeze_request"
)


def _token(key, subject: str, scope: str) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "iss": ISSUER, "aud": AUDIENCE, "sub": subject, "tenant_id": "tenant_red",
            "scope": scope, "iat": now, "exp": now + timedelta(minutes=5),
        },
        key,
        algorithm="RS256",
    )


def _operator(env: dict[str, str], *args: str) -> dict:
    result = subprocess.run(
        [sys.executable, "-m", "mcp_policy_gateway.approvals", *args],
        capture_output=True, text=True, env=env, timeout=30, check=False,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(f"operator command failed: {args[0]}: {result.stderr.strip()}")
    return json.loads(result.stdout)


async def run_demo() -> dict[str, Any]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with tempfile.TemporaryDirectory(prefix="gateway-demo-") as directory:
        public_file = Path(directory) / "issuer.pem"
        public_file.write_bytes(public)
        base = {
            **{name: value for name, value in os.environ.items()
               if not name.startswith("GATEWAY_")},
            "GATEWAY_JWT_PUBLIC_KEY_FILE": str(public_file),
            "GATEWAY_ISSUER": ISSUER,
            "GATEWAY_AUDIENCE": AUDIENCE,
            "GATEWAY_STATE_DB": str(Path(directory) / "gateway.sqlite3"),
        }
        agent_env = {**base, "GATEWAY_ID_TOKEN": _token(key, "synthetic-demo-agent", AGENT_SCOPES)}
        approver_env = {
            **base,
            "GATEWAY_ID_TOKEN": _token(
                key, "synthetic-human-approver", "gateway:approve_account_freeze"
            ),
        }
        agent_as_approver = {
            **base,
            "GATEWAY_ID_TOKEN": _token(
                key, "synthetic-demo-agent", "gateway:approve_account_freeze"
            ),
        }
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "mcp_policy_gateway.server"], env=agent_env
        )
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()

            async def call(name: str, args: dict) -> dict:
                response = await session.call_tool(name, args)
                content = response.content[0]
                if response.isError or not isinstance(content, TextContent):
                    raise RuntimeError(f"MCP call failed: {name}")
                return json.loads(content.text)

            freeze = {
                "account_id": "acct_red", "reason": "synthetic exercise",
                "idempotency_key": "demo-001",
            }
            results: dict[str, Any] = {
                "allowed": await call("get_case", {"case_id": "case_red_01"}),
                "cross_tenant": await call("get_case", {"case_id": "case_blue_01"}),
                "approval": await call("request_account_freeze", freeze),
                "replay": await call("request_account_freeze", freeze),
            }
            request_id = results["approval"]["request_id"]
            # Blocking subprocess calls are fine here: the MCP server is idle meanwhile.
            results["self_approval"] = _operator(
                agent_as_approver, "approve", request_id, "--note", "agent tries to self-approve"
            )
            results["human_approval"] = _operator(
                approver_env, "approve", request_id, "--note", "verified out of band"
            )
            results["execution"] = _operator(approver_env, "execute", request_id)
            results["agent_view"] = await call("get_freeze_request", {"request_id": request_id})
            results["summary_after"] = await call(
                "get_account_summary", {"account_id": "acct_red"}
            )
            trail = _operator(approver_env, "audit", request_id)["audit"]
            results["audit_trail"] = [
                {"action": e["action"], "actor": e["actor"], "reason": e["reason"]}
                for e in trail
            ]
            return results


def main() -> None:
    print(json.dumps(asyncio.run(run_demo()), indent=2))


if __name__ == "__main__":
    main()
