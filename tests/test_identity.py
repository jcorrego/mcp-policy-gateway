"""Synthetic issuer tests; no private keys or bearer tokens are committed."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import TextContent

from mcp_policy_gateway.identity import InvalidSessionError, verify_session
from mcp_policy_gateway.models import Principal
from mcp_policy_gateway.server import build_server

ISSUER = "https://issuer.example.test"
AUDIENCE = "mcp-policy-gateway"


@pytest.fixture
def issuer_keys():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return key, public


def claims(**overrides):
    now = datetime.now(UTC)
    data = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "agent-01",
        "tenant_id": "tenant_red",
        "scope": "gateway:get_case gateway:get_account_summary",
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }
    data.update(overrides)
    return data


def signed(key, **overrides):
    return jwt.encode(claims(**overrides), key, algorithm="RS256")


def test_valid_session_binds_principal(issuer_keys):
    key, public = issuer_keys
    principal = verify_session(signed(key), public, ISSUER, AUDIENCE)
    assert principal.subject == "agent-01"
    assert principal.tenant_id == "tenant_red"
    assert principal.scopes == frozenset({"gateway:get_case", "gateway:get_account_summary"})


@pytest.mark.parametrize(
    "override",
    [
        {"exp": datetime.now(UTC) - timedelta(minutes=1)},
        {"aud": "unrelated-tool"},
        {"iss": "https://other.example.test"},
        {"iat": datetime.now(UTC) + timedelta(minutes=5)},
        {"sub": ""},
        {"tenant_id": ""},
        {"scope": ["gateway:get_case"]},
        {"scope": "gateway:get_case\ngateway:request_account_freeze"},
    ],
)
def test_invalid_claims_fail_closed(issuer_keys, override):
    key, public = issuer_keys
    with pytest.raises(InvalidSessionError, match="invalid_session"):
        verify_session(signed(key, **override), public, ISSUER, AUDIENCE)


def test_wrong_signature_and_algorithm_fail_closed(issuer_keys):
    key, public = issuer_keys
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong_algorithm = jwt.encode(
        claims(), "not-a-key-with-at-least-32-bytes", algorithm="HS256"
    )
    for token in (signed(other), wrong_algorithm):
        with pytest.raises(InvalidSessionError, match="invalid_session"):
            verify_session(token, public, ISSUER, AUDIENCE)


def test_missing_claims_fail_closed(issuer_keys):
    key, public = issuer_keys
    for field in ("exp", "iat", "iss", "aud", "sub", "tenant_id", "scope"):
        payload = claims()
        payload.pop(field)
        with pytest.raises(InvalidSessionError, match="invalid_session"):
            verify_session(jwt.encode(payload, key, algorithm="RS256"), public, ISSUER, AUDIENCE)


def test_startup_without_session_refuses_to_serve():
    env = {k: v for k, v in os.environ.items() if not k.startswith("GATEWAY_")}
    result = subprocess.run(
        [sys.executable, "-m", "mcp_policy_gateway.server"],
        input="", capture_output=True, text=True, env=env, timeout=10,
    )
    assert result.returncode != 0
    assert "invalid_session" in result.stderr


def test_tools_recheck_authentication_before_each_call():
    calls = 0

    def session_principal():
        nonlocal calls
        calls += 1
        if calls > 1:
            raise InvalidSessionError("invalid_session")
        return Principal("agent-01", "tenant_red", frozenset({"gateway:get_case"}))

    server = build_server(session_principal)

    async def exercise():
        allowed = await server._tool_manager.call_tool("get_case", {"case_id": "case_red_01"})
        assert allowed["ok"] is True
        with pytest.raises(ToolError, match="invalid_session"):
            await server._tool_manager.call_tool("get_case", {"case_id": "case_red_01"})

    asyncio.run(exercise())
    assert calls == 2


def test_mcp_session_ignores_model_identity_and_denies_cross_tenant(issuer_keys, tmp_path):
    key, public = issuer_keys
    public_file = tmp_path / "issuer.pem"
    public_file.write_bytes(public)
    env = {**os.environ, "GATEWAY_ID_TOKEN": signed(key),
           "GATEWAY_JWT_PUBLIC_KEY_FILE": str(public_file),
           "GATEWAY_ISSUER": ISSUER, "GATEWAY_AUDIENCE": AUDIENCE}

    async def exercise():
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "mcp_policy_gateway.server"], env=env
        )
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                assert {tool.name for tool in tools.tools} == {
                    "get_case", "get_account_summary", "request_account_freeze"
                }
                schema = next(t.inputSchema for t in tools.tools if t.name == "get_case")
                assert "tenant_id" not in schema["properties"]
                assert "scopes" not in schema["properties"]
                allowed = await session.call_tool("get_case", {"case_id": "case_red_01"})
                assert isinstance(allowed.content[0], TextContent)
                assert json.loads(allowed.content[0].text)["ok"] is True
                denied = await session.call_tool("get_case", {"case_id": "case_blue_01"})
                assert isinstance(denied.content[0], TextContent)
                assert json.loads(denied.content[0].text)["reason"] == "cross_tenant_access"
                escalated = await session.call_tool("request_account_freeze", {
                    "account_id": "acct_red", "reason": "synthetic test",
                    "idempotency_key": "try-01",
                })
                assert isinstance(escalated.content[0], TextContent)
                assert json.loads(escalated.content[0].text)["reason"] == "missing_scope"
                spoof = await session.call_tool("get_case", {
                    "case_id": "case_blue_01", "tenant_id": "tenant_blue",
                    "scopes": ["gateway:get_case"]
                })
                assert spoof.isError or (
                    isinstance(spoof.content[0], TextContent)
                    and json.loads(spoof.content[0].text)["reason"] == "cross_tenant_access"
                )

    asyncio.run(exercise())
