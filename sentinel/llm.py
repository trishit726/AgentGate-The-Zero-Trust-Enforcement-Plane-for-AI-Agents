"""Local Foundation-Sec triage wrapper (Ollama).

`triage()` turns a deny event + MCP-pulled context rows into the SPEC §4.3 report
fields. Local inference only — never a hosted-model API. temperature=0 for live-demo
determinism. Raises LLMUnavailable on any failure; the caller substitutes the stub.
"""

import json
import logging
import os

import requests
from dotenv import load_dotenv

load_dotenv()

log = logging.getLogger("agentgate.sentinel.llm")

_OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
_MODEL = os.environ.get("OLLAMA_MODEL", "fdtn-ai/Foundation-Sec-8B-Instruct")
_TIMEOUT_S = 60.0

_REQUIRED_KEYS = ("probable_cause", "blast_radius", "evidence", "recommended_action")


def _extract_json(content: str) -> dict:
    """Parse model output that may wrap the JSON object in markdown code fences.

    This GGUF build emits ```json ... ``` even with format=json, so fall back to
    slicing from the first '{' to the last '}'.
    """
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        start, end = content.find("{"), content.rfind("}")
        if start == -1 or end <= start:
            raise
        return json.loads(content[start : end + 1])

_SYSTEM_PROMPT = """You are a SOC triage analyst embedded in AgentGate, a zero-trust
enforcement plane for AI agents. A network-layer policy broker has just DENIED an AI
agent's request to an internal service. You receive the deny event and recent decision
history for that agent pulled from Splunk.

Respond with ONLY a JSON object with exactly these keys:
- "probable_cause": one of "prompt_injection", "misconfiguration", "credential_misuse",
  or "unknown" — pick prompt_injection when a normally well-scoped agent suddenly
  requests an out-of-scope sensitive service; misconfiguration when the pattern suggests
  the scope or deployment is wrong.
- "blast_radius": one short sentence on impact. Remember: the broker refused at the
  network layer, so if all attempts were DENY, zero data was exfiltrated.
- "evidence": one or two short sentences citing the concrete facts (scope, target,
  history counts) that support the cause.
- "recommended_action": one short sentence for the analyst.

Be precise and factual. No markdown, no prose outside the JSON object."""


class LLMUnavailable(Exception):
    """Ollama unreachable, model missing, timeout, or unparseable output."""


def triage(deny_event: dict, context_rows: list[dict]) -> dict:
    """Run Foundation-Sec over the incident. Returns the §4.3 narrative fields."""
    params = deny_event.get("params", {})
    user_msg = json.dumps(
        {
            "deny_event": params,
            "recent_decisions_from_splunk": context_rows[:20],
        },
        default=str,
    )

    try:
        resp = requests.post(
            f"{_OLLAMA_URL}/api/chat",
            json={
                "model": _MODEL,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0},
                "messages": [
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": user_msg},
                ],
            },
            timeout=_TIMEOUT_S,
        )
        resp.raise_for_status()
        content = resp.json()["message"]["content"]
        report = _extract_json(content)
    except Exception as exc:  # noqa: BLE001 — single failure contract for the caller
        raise LLMUnavailable(f"Foundation-Sec triage failed: {exc}") from exc

    missing = [k for k in _REQUIRED_KEYS if k not in report]
    if missing:
        raise LLMUnavailable(f"triage output missing keys: {missing}")
    return {k: report[k] for k in _REQUIRED_KEYS}
