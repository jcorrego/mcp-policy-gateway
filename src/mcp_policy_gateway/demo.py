"""Run a real stdio MCP exchange against a throwaway synthetic local issuer."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import TextContent


async def run_demo() -> dict:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "iss": "https://issuer.example.test",
            "aud": "mcp-policy-gateway",
            "sub": "synthetic-demo-agent",
            "tenant_id": "tenant_red",
            "scope": "gateway:get_case gateway:request_account_freeze",
            "iat": now,
            "exp": now + timedelta(minutes=5),
        },
        key,
        algorithm="RS256",
    )
    with tempfile.TemporaryDirectory(prefix="gateway-demo-") as directory:
        public_file = Path(directory) / "issuer.pem"
        public_file.write_bytes(public)
        env = {
            **os.environ,
            "GATEWAY_ID_TOKEN": token,
            "GATEWAY_JWT_PUBLIC_KEY_FILE": str(public_file),
            "GATEWAY_ISSUER": "https://issuer.example.test",
            "GATEWAY_AUDIENCE": "mcp-policy-gateway",
        }
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "mcp_policy_gateway.server"], env=env
        )
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            results = {}
            for label, name, args in (
                ("allowed", "get_case", {"case_id": "case_red_01"}),
                ("cross_tenant", "get_case", {"case_id": "case_blue_01"}),
                ("approval", "request_account_freeze", {
                    "account_id": "acct_red", "reason": "synthetic exercise",
                    "idempotency_key": "demo-001",
                }),
            ):
                response = await session.call_tool(name, args)
                content = response.content[0]
                if response.isError or not isinstance(content, TextContent):
                    raise RuntimeError(f"MCP call failed: {label}")
                results[label] = json.loads(content.text)
            return results


def main() -> None:
    print(json.dumps(asyncio.run(run_demo()), indent=2))


if __name__ == "__main__":
    main()
