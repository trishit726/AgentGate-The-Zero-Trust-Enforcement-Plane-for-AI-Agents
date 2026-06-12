"""Splunk MCP Server client — streamable HTTP, encrypted-token auth.

This is the MCP-bonus surface: Sentinel pulls its investigation context through the
Splunk MCP Server (`saia_generate_spl` -> `splunk_run_query`), not the raw SDK.

Failure contract: each public call has a 30 s timeout and one retry, then raises
MCPUnavailable. The caller (sentinel/agent.py) decides on fallback — this module never
falls back silently.

Health check (also the on-camera proof the encrypted token authenticates):
    python -m sentinel.mcp_client
"""

import asyncio
import json
import logging
import os

import httpx
from dotenv import load_dotenv

load_dotenv()

from mcp import ClientSession  # noqa: E402
from mcp.client.streamable_http import streamablehttp_client  # noqa: E402

log = logging.getLogger("agentgate.sentinel.mcp")

_MCP_URL = os.environ.get("SPLUNK_MCP_URL", "https://localhost:8089/services/mcp")
# The token is opaque ciphertext pasted from the Splunk MCP app. Join-split guards
# against whitespace/newline paste artifacts, which silently break auth.
_MCP_TOKEN = "".join(os.environ.get("SPLUNK_MCP_TOKEN", "").split())
_VERIFY_TLS = os.environ.get("SPLUNK_VERIFY_TLS", "false").lower() == "true"
_TIMEOUT_S = 30.0


class MCPUnavailable(Exception):
    """MCP endpoint unreachable, auth failed, or tool call errored after retry."""


def _require_token() -> None:
    if not _MCP_TOKEN:
        raise MCPUnavailable("SPLUNK_MCP_TOKEN is unset — Sentinel cannot reach MCP")


def _httpx_factory(headers=None, timeout=None, auth=None) -> httpx.AsyncClient:
    # Splunk on 8089 serves a self-signed cert; verification is intentionally off for
    # localhost (documented in README). Everything else matches the SDK default factory.
    return httpx.AsyncClient(
        verify=_VERIFY_TLS,
        headers=headers,
        timeout=timeout,
        auth=auth,
        follow_redirects=True,
    )


async def _session_call(coro_name: str, *args) -> object:
    """Open a streamable-HTTP MCP session and run one operation inside it."""
    headers = {"Authorization": f"Bearer {_MCP_TOKEN}"}
    async with streamablehttp_client(
        _MCP_URL,
        headers=headers,
        timeout=_TIMEOUT_S,
        httpx_client_factory=_httpx_factory,
    ) as (read_stream, write_stream, _get_session_id):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            if coro_name == "list_tools":
                return await session.list_tools()
            if coro_name == "call_tool":
                tool_name, tool_args = args
                return await session.call_tool(tool_name, tool_args)
            raise ValueError(f"unknown operation {coro_name}")


def _run_with_retry(coro_name: str, *args) -> object:
    """Sync wrapper: one retry, then MCPUnavailable. Safe to call from a worker thread."""
    _require_token()
    last_exc: Exception | None = None
    for attempt in (1, 2):
        try:
            return asyncio.run(asyncio.wait_for(_session_call(coro_name, *args), _TIMEOUT_S + 10))
        except Exception as exc:  # noqa: BLE001 — converted to the failure contract below
            last_exc = exc
            log.warning("MCP %s attempt %d failed: %s", coro_name, attempt, exc)
    raise MCPUnavailable(f"MCP {coro_name} failed after retry: {last_exc}")


def _result_text(result) -> str:
    """Flatten an MCP CallToolResult into text."""
    if getattr(result, "isError", False):
        parts = [getattr(c, "text", "") for c in (result.content or [])]
        raise MCPUnavailable(f"MCP tool returned error: {' '.join(parts)[:500]}")
    if getattr(result, "structuredContent", None):
        return json.dumps(result.structuredContent)
    return "\n".join(getattr(c, "text", "") for c in (result.content or []) if getattr(c, "text", ""))


# ---------------------------------------------------------------- public surface

def list_tools() -> list[dict]:
    """Startup health check. Returns [{name, description, input_schema}, ...]."""
    result = _run_with_retry("list_tools")
    return [
        {
            "name": t.name,
            "description": (t.description or "").strip().split("\n")[0][:120],
            "input_schema": t.inputSchema,
        }
        for t in result.tools
    ]


def generate_spl(natural_language: str) -> str:
    """saia_generate_spl: natural language -> SPL string."""
    result = _run_with_retry("call_tool", "saia_generate_spl", {"prompt": natural_language})
    text = _result_text(result).strip()
    # The tool may wrap the SPL in JSON ({"spl": ...} or similar) — unwrap if so.
    try:
        payload = json.loads(text)
        if isinstance(payload, dict):
            for key in ("spl", "query", "search", "generated_spl"):
                if isinstance(payload.get(key), str):
                    return payload[key]
    except (json.JSONDecodeError, TypeError):
        pass
    return text


def run_query(spl: str) -> list[dict]:
    """splunk_run_query: SPL -> result rows."""
    result = _run_with_retry("call_tool", "splunk_run_query", {"query": spl})
    text = _result_text(result).strip()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return [{"raw": text}] if text else []
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("results", "rows", "events", "data"):
            if isinstance(payload.get(key), list):
                return payload[key]
        return [payload]
    return []


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(f"MCP health check -> {_MCP_URL}")
    print(f"token: {'set, ' + str(len(_MCP_TOKEN)) + ' chars (whitespace-stripped)' if _MCP_TOKEN else 'MISSING'}")
    tools = list_tools()
    print(f"\nAUTH OK — server listed {len(tools)} tools:\n")
    for t in tools:
        print(f"  {t['name']}: {t['description']}")
        print(f"    input schema: {json.dumps(t['input_schema'])[:300]}")
