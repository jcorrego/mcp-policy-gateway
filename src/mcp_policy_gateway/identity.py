"""Verify a startup JWT before binding a principal to the stdio MCP session."""

from __future__ import annotations

import os
from pathlib import Path

import jwt

from .models import Principal


class InvalidSessionError(ValueError):
    """A session must not reach any MCP tool until verification succeeds."""


def verify_session(token: str, public_key: bytes, issuer: str, audience: str) -> Principal:
    """Accept only RS256 signatures from the trusted, locally pinned issuer key.

    The caller controls neither the accepted algorithm nor the key path through JWT headers.
    A verified token's scope is the maximum permission for this process/session.
    """
    if not all((token, public_key, issuer, audience)):
        raise InvalidSessionError("invalid_session")
    try:
        claims = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=issuer,
            audience=audience,
            options={"require": ["exp", "iat", "iss", "aud", "sub", "tenant_id", "scope"]},
            leeway=0,
        )
    except (jwt.PyJWTError, ValueError, TypeError) as exc:
        raise InvalidSessionError("invalid_session") from exc

    subject, tenant, scope = (claims.get(field) for field in ("sub", "tenant_id", "scope"))
    if (
        not isinstance(subject, str) or not subject.strip()
        or not isinstance(tenant, str) or not tenant.strip()
        or not isinstance(scope, str) or any(char.isspace() and char != " " for char in scope)
    ):
        raise InvalidSessionError("invalid_session")
    return Principal(subject=subject, tenant_id=tenant, scopes=frozenset(scope.split()))


def principal_from_environment() -> Principal:
    """Operator-provided launch configuration, never MCP/tool/model input."""
    try:
        token = os.environ["GATEWAY_ID_TOKEN"]
        issuer = os.environ["GATEWAY_ISSUER"]
        audience = os.environ["GATEWAY_AUDIENCE"]
        public_key = Path(os.environ["GATEWAY_JWT_PUBLIC_KEY_FILE"]).read_bytes()
    except (KeyError, OSError) as exc:
        raise InvalidSessionError("invalid_session") from exc
    return verify_session(token, public_key, issuer, audience)
