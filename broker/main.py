"""AgentGate policy broker — the enforcement plane (FastAPI).

Every request to an internal service passes through here. The broker validates the
agent's scoped JWT, checks the target against the token's allowlist, then proxies
(ALLOW) or refuses at the network layer (DENY → 403). Every decision emits exactly one
structured event to Splunk HEC. On DENY, Sentinel is fired as a background task AFTER
the 403 is already committed — intelligence never gates enforcement.

Default-deny: any error path (missing header, malformed JWT, unknown service, internal
exception) resolves to DENY. There is no code path where a failure yields an ALLOW.
"""

import logging
from datetime import datetime, timezone

from dotenv import load_dotenv

# Load .env BEFORE importing broker submodules — identity/emit read os.environ at import
# time (e.g. the JWT-secret guard), so the environment must be populated first.
load_dotenv()

import httpx  # noqa: E402
from fastapi import BackgroundTasks, Request  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402

from broker import emit, identity, policy  # noqa: E402

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("agentgate.broker")

app = FastAPI(title="AgentGate", description="Zero-Trust Enforcement Plane for AI Agents")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_event(
    agent_id: str,
    target_service: str,
    action: str,
    decision: str,
    reason: str,
    token_scope: list,
    src_ip: str,
) -> dict:
    """Construct the frozen JSON-RPC decision event (SPEC §4.2)."""
    return {
        "jsonrpc": "2.0",
        "method": "agentgate.decision",
        "params": {
            "agent_id": agent_id,
            "target_service": target_service,
            "action": action,
            "decision": decision,
            "reason": reason,
            "token_scope": token_scope,
            "src_ip": src_ip,
            "timestamp": _utc_now(),
        },
    }


def sentinel_hook(event: dict) -> None:
    """Fire the Sentinel investigation loop. Runs as a BackgroundTask AFTER the 403 is
    committed — intelligence never gates enforcement.

    Lazy import + blanket guard: a broken sentinel install must neither stop the broker
    from booting nor surface into any request path.
    """
    try:
        from sentinel import agent as sentinel_agent

        sentinel_agent.investigate(event)
    except Exception as exc:  # noqa: BLE001 — enforcement is never blocked by Sentinel
        log.warning("sentinel hook failed (enforcement unaffected): %s", exc)


def _deny(
    agent_id: str,
    service: str,
    action: str,
    reason: str,
    token_scope: list,
    src_ip: str,
    background: BackgroundTasks,
) -> JSONResponse:
    """Emit the DENY event, schedule Sentinel, return 403. Used for every denial path."""
    event = _build_event(agent_id, service, action, "DENY", reason, token_scope, src_ip)
    emit.emit_decision(event)
    background.add_task(sentinel_hook, event)
    return JSONResponse(
        status_code=403,
        content={
            "error": f"AgentGate: access to '{service}' denied",
            "decision": "DENY",
            "reason": reason,
        },
    )


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": "agentgate-broker"}


@app.api_route("/{service}/{path:path}", methods=["GET"])
async def enforce(service: str, path: str, request: Request, background: BackgroundTasks):
    src_ip = request.client.host if request.client else "unknown"
    action = f"GET /{path}"

    # 1. Authorization header.
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return _deny("unknown", service, action, "invalid_token", [], src_ip, background)
    token = auth[7:].strip()

    # 2. Verify the token. agent_id for the event comes from the unverified sub on failure.
    try:
        claims = identity.verify_token(token)
    except identity.ExpiredTokenError:
        agent_id = identity.peek_agent_id(token)
        return _deny(agent_id, service, action, "expired_token", [], src_ip, background)
    except identity.InvalidTokenError:
        agent_id = identity.peek_agent_id(token)
        return _deny(agent_id, service, action, "invalid_token", [], src_ip, background)

    agent_id = claims["agent_id"]
    token_scope = claims.get("scope", [])

    # 3. Policy decision.
    decision, reason = policy.decide(claims, service)

    if decision == "DENY":
        return _deny(agent_id, service, action, reason, token_scope, src_ip, background)

    # 4. ALLOW — emit first (the decision was allow regardless of upstream health),
    #    then proxy.
    event = _build_event(agent_id, service, action, "ALLOW", reason, token_scope, src_ip)
    emit.emit_decision(event)

    upstream = policy.SERVICE_MAP[service]
    target_url = f"{upstream}/{path}"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            proxied = await client.get(target_url)
        return JSONResponse(status_code=proxied.status_code, content=proxied.json())
    except Exception as exc:  # noqa: BLE001 — upstream failure, not a policy failure
        log.warning("upstream proxy failed: %s", exc)
        return JSONResponse(
            status_code=502,
            content={"error": f"AgentGate: upstream '{service}' unreachable", "decision": "ALLOW"},
        )
