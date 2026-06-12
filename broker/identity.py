"""Scoped agent identity — issue and verify HS256 JWTs.

Pure functions over the signing secret. No network, no I/O. The broker maps the two
exception types below onto the frozen event `reason` enum (SPEC §4.2):
    ExpiredTokenError  -> "expired_token"
    InvalidTokenError  -> "invalid_token"  (bad signature, malformed, missing claims)

Fails loud at import time if the secret is unset or too short — we never want a weak or
absent secret to surface as a per-request surprise.
"""

import os
import time

import jwt

_SECRET = os.environ.get("AGENTGATE_JWT_SECRET", "")
_ALGO = "HS256"
_MIN_SECRET_LEN = 32

if len(_SECRET) < _MIN_SECRET_LEN:
    raise RuntimeError(
        "AGENTGATE_JWT_SECRET must be set and >= "
        f"{_MIN_SECRET_LEN} chars (got {len(_SECRET)}). Refusing to start."
    )


class InvalidTokenError(Exception):
    """Token is malformed, badly signed, or missing required claims."""


class ExpiredTokenError(Exception):
    """Token signature is valid but the token has expired."""


def issue_token(agent_id: str, scope: list[str], ttl_seconds: int = 3600) -> str:
    """Issue a scoped identity token. Claims match SPEC §4.1 exactly."""
    now = int(time.time())
    claims = {
        "sub": agent_id,
        "agent_id": agent_id,
        "scope": list(scope),
        "iat": now,
        "exp": now + ttl_seconds,
    }
    return jwt.encode(claims, _SECRET, algorithm=_ALGO)


def verify_token(token: str) -> dict:
    """Verify and decode a token. Returns claims, or raises the mapped exception."""
    try:
        claims = jwt.decode(token, _SECRET, algorithms=[_ALGO])
    except jwt.ExpiredSignatureError as exc:
        raise ExpiredTokenError(str(exc)) from exc
    except jwt.PyJWTError as exc:
        raise InvalidTokenError(str(exc)) from exc

    if "agent_id" not in claims or "scope" not in claims:
        raise InvalidTokenError("token missing required claims: agent_id / scope")
    if not isinstance(claims["scope"], list):
        raise InvalidTokenError("token scope claim must be a list")
    return claims


def peek_agent_id(token: str) -> str:
    """Best-effort agent_id from an UNVERIFIED token, for event labelling on failure.

    Never used for an allow decision — only so a denial event can name the agent even
    when verification failed.
    """
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
        return claims.get("agent_id") or claims.get("sub") or "unknown"
    except jwt.PyJWTError:
        return "unknown"
