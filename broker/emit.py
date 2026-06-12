"""HEC emitter — push structured events to Splunk.

Reused for both decision events (index=agentgate) and, in Phase 2, Sentinel reports
(index=agentgate_investigations). The HEC envelope carries the MCP-TA sourcetype so the
TA's CIM field extractions apply (SPEC §4.2).

ALL exceptions are swallowed and logged. A Splunk outage must never 500 the broker or
block an enforcement decision — emission is best-effort observability, not the product.
"""

import logging
import os

import requests
import urllib3

log = logging.getLogger("agentgate.emit")

_HEC_URL = os.environ.get("SPLUNK_HEC_URL", "https://localhost:8088/services/collector/event")
_HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN", "")
_SOURCETYPE = os.environ.get("SPLUNK_HEC_SOURCETYPE", "mcp:jsonrpc")
_VERIFY_TLS = os.environ.get("SPLUNK_VERIFY_TLS", "false").lower() == "true"
_TIMEOUT = 3.0

# Local Splunk uses a self-signed cert; with verification intentionally off, silence the
# per-request urllib3 warning so it doesn't drown the broker's own logs.
if not _VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def emit_decision(event: dict, index: str = "agentgate") -> None:
    """POST one event to Splunk HEC. Best-effort: never raises."""
    if not _HEC_TOKEN:
        log.warning("SPLUNK_HEC_TOKEN unset — skipping emit (event=%s)", event.get("method"))
        return

    envelope = {
        "index": index,
        "sourcetype": _SOURCETYPE,
        "event": event,
    }
    headers = {"Authorization": f"Splunk {_HEC_TOKEN}"}

    try:
        resp = requests.post(
            _HEC_URL,
            json=envelope,
            headers=headers,
            timeout=_TIMEOUT,
            verify=_VERIFY_TLS,
        )
        if resp.status_code != 200:
            log.warning("HEC non-200: %s %s", resp.status_code, resp.text[:200])
    except Exception as exc:  # noqa: BLE001 — best-effort, never propagate
        log.warning("HEC emit failed (swallowed): %s", exc)
