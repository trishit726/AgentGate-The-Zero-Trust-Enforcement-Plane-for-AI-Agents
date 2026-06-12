"""Sentinel — the investigation agent. Fired by the broker on every DENY.

Loop: context pull via Splunk MCP Server -> reason with Foundation-Sec -> write the
triage report to index=agentgate_investigations. Every stage degrades gracefully and
the degradation is FLAGGED in the report (context_source / model fields) — honesty in
the artifact. investigate() never raises: enforcement and the decision event are never
blocked or broken by the intelligence layer.
"""

import logging
import re
import time
from datetime import datetime, timezone

from broker import emit
from sentinel import llm, mcp_client

log = logging.getLogger("agentgate.sentinel")

_SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _fallback_spl(agent_id: str) -> str:
    """Locally templated context query, used when saia_generate_spl is unavailable.

    agent_id is interpolated into SPL, so it is strictly validated first — a hostile
    token `sub` claim must not become an SPL injection.
    """
    if not _SAFE_ID.match(agent_id):
        agent_id = "unknown"
    return (
        f'search index=agentgate "params.agent_id"="{agent_id}" earliest=-15m '
        "| table _time params.agent_id params.target_service params.decision "
        "params.reason params.token_scope{}"
    )


def _pull_context(agent_id: str) -> tuple[list[dict], str, str]:
    """Returns (rows, context_source, spl_used).

    Primary path is the MCP-bonus moment: saia_generate_spl -> splunk_run_query.
    If SAIA (cloud assistant) is unavailable, the SPL is templated locally but the
    query still runs through the MCP Server (context_source=mcp_templated_spl).
    Only if MCP itself is down do we report context unavailable.
    """
    prompt = (
        f"search index agentgate where params.agent_id is {agent_id} in the last 15 "
        "minutes, table _time agent_id target_service decision reason"
    )
    try:
        try:
            spl = mcp_client.generate_spl(prompt)
            source = "mcp"
        except mcp_client.MCPUnavailable as exc:
            log.warning("saia_generate_spl unavailable, templating SPL locally: %s", exc)
            spl = _fallback_spl(agent_id)
            source = "mcp_templated_spl"
        rows = mcp_client.run_query(spl)
        return rows, source, spl
    except mcp_client.MCPUnavailable as exc:
        log.warning("MCP context pull failed entirely: %s", exc)
        return [], "unavailable", ""


def _stub_narrative(params: dict) -> dict:
    """Deterministic report when the local model is down. Mechanical facts only."""
    scope = params.get("token_scope", [])
    return {
        "probable_cause": "(narrative unavailable — model offline)",
        "blast_radius": "none — access was refused at the network layer; zero data exfiltrated",
        "evidence": (
            f"token scope={scope}; attempted target={params.get('target_service')}; "
            f"reason={params.get('reason')}"
        ),
        "recommended_action": "review agent session; re-run triage when model is available",
    }


def investigate(event: dict) -> None:
    """Full Sentinel loop. NEVER raises — top-level guard writes whatever we have."""
    try:
        params = event.get("params", {})
        agent_id = params.get("agent_id", "unknown")
        incident_id = f"ag-{int(time.time())}"
        log.info("sentinel: investigating %s (agent=%s)", incident_id, agent_id)

        rows, context_source, spl_used = _pull_context(agent_id)
        log.info("sentinel: context via %s — %d rows", context_source, len(rows))

        model_used = llm._MODEL
        try:
            narrative = llm.triage(event, rows)
        except llm.LLMUnavailable as exc:
            log.warning("sentinel: LLM unavailable, writing stub narrative: %s", exc)
            narrative = _stub_narrative(params)
            model_used = "stub (model offline)"

        report = {
            "incident_id": incident_id,
            "agent_id": agent_id,
            "target_service": params.get("target_service", "unknown"),
            "probable_cause": narrative["probable_cause"],
            "blast_radius": narrative["blast_radius"],
            "evidence": narrative["evidence"],
            "recommended_action": narrative["recommended_action"],
            "model": model_used,
            "context_source": context_source,
            "context_rows": len(rows),
            "spl_used": spl_used[:500],
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        emit.emit_decision(report, index="agentgate_investigations")
        log.info(
            "sentinel: report %s written (cause=%s, context=%s)",
            incident_id,
            report["probable_cause"],
            context_source,
        )
    except Exception as exc:  # noqa: BLE001 — Sentinel must never break the broker
        log.error("sentinel: investigation failed (enforcement unaffected): %s", exc)
