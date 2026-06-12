"""Policy decision — the heart of the enforcement plane.

`decide()` is a pure function: given verified token claims and a target service, it
returns ("ALLOW", "ok") or ("DENY", reason). No I/O, unit-testable without FastAPI.

Exact string match only. No wildcards, no prefix matching — wildcard scope is how
zero-trust dies.
"""

# Known internal services and where the broker proxies an ALLOW to.
SERVICE_MAP = {
    "prod-db": "http://127.0.0.1:7001",
    "secrets-store": "http://127.0.0.1:7002",
    "internal-api": "http://127.0.0.1:7003",
}


def decide(claims: dict, target_service: str) -> tuple[str, str]:
    """Return (decision, reason).

    The frozen reason enum (SPEC §4.2) has no `unknown_service`; an unknown target is
    treated as a scope violation — the agent's scope cannot grant a service that does
    not exist — and is reported as such.
    """
    if target_service not in SERVICE_MAP:
        return ("DENY", "scope_violation")

    scope = claims.get("scope", [])
    if target_service not in scope:
        return ("DENY", "scope_violation")

    return ("ALLOW", "ok")
