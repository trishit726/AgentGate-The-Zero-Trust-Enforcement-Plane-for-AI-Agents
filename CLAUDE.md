# CLAUDE.md — AgentGate

> Claude Code reads this file at the start of every session. Keep it accurate.
> Full spec lives in `SPEC.md`. Build plan lives in `TASKS.md`. Required diagram in `architecture_diagram.md`.

## What this is

**AgentGate — The Zero-Trust Enforcement Plane for AI Agents.**

A network-layer policy broker that sits *below* an AI agent's reasoning. Each agent
holds a scoped identity token; a broker enforces an identity→allowlist policy on every
request to internal services. If the token doesn't grant a service, the connection is
refused at the network layer — the agent cannot prompt-inject or reason its way past it.
Every allow/deny decision streams into Splunk; on a denial, an investigation agent
("Sentinel") auto-triages the incident and writes a report back to Splunk. The SOC
analyst sees the full picture in seconds.

**One-liner for the demo:** "The agent was prompt-injected. The network refused. Splunk
saw everything. The analyst had the full picture in 8 seconds."

## Hackathon context (why decisions are the way they are)

- **Event:** Splunk Agentic Ops Hackathon. Deadline **Mon Jun 15, 09:00 PDT (9:30 PM IST)**.
- **Track:** Security. **Bonus targeted:** Best Use of Splunk MCP Server ($1,000).
- **Builder:** solo, strong at backend/systems, weaker at frontend. Scope accordingly.
- **Judging criteria:** Technological Implementation, Design, Potential Impact, Quality of Idea.
- **Winner pattern:** ONE pain point solved deeply, 80–100% functional, newest native stack,
  AI tied to a concrete workflow, business-value framing. Polish > breadth.

## Verified environment state (already confirmed working — do NOT re-litigate)

- Splunk **Enterprise** running locally, dev license applied (`DEVLICENSE:...@gmail.com`),
  10 GB, valid till Nov 2026. Admin login.
- **Splunk MCP Server** app installed, "Server is active", endpoint
  `https://localhost:8089/services/mcp`. An **encrypted MCP token is created and verified** —
  an external client authenticated and listed tools successfully.
- **MCP tools available:** `splunk_run_query`, `splunk_get_metadata`,
  `splunk_get_kv_store_collections`, `splunk_get_knowledge_objects`,
  `splunk_run_saved_search`, `saia_generate_spl`, `saia_explain_spl`,
  `saia_ask_splunk_question`, `saia_optimize_spl`.
- **MCP TA** (by Rod Soto) installed — ingests/normalizes MCP JSON-RPC events, CIM-compliant.
- **AI Toolkit (AITK)** installed.
- **Phase 2 findings (verified Jun 13):** the `saia_*` MCP tools proxy to Splunk's cloud
  SAIA API which returns 404 on this instance — Sentinel falls back to a locally-templated
  SPL but still pulls context through `splunk_run_query` over MCP (`context_source` field
  records which path ran). Indexes `agentgate` + `agentgate_investigations` exist and the
  HEC token allows both. Ollama installed; model = `hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF`.
  Splunk search-time extraction duplicates JSON fields into multivalues — dashboard SPL
  must `mvdedup`/`values()`.

## HARD CONSTRAINTS — read before writing any code

1. **NO Splunk Hosted Models.** Those are Cloud-only; we are on Enterprise. The investigation
   model (Foundation-Sec-8B-Instruct) runs **locally via Ollama** (open weights,
   `fdtn-ai/Foundation-Sec-8B-Instruct`, GGUF Q4). Never call a "hosted model" API.
2. **Use Dashboard Studio (native), NOT a React/Splunk-UI app.** The dashboard is a
   Dashboard Studio JSON definition. No webpack, no React, no custom frontend build.
3. **The MCP bonus is won by Sentinel genuinely calling MCP tools.** Sentinel must invoke
   `saia_generate_spl` then `splunk_run_query` over the MCP endpoint with the encrypted token —
   not bypass MCP with the raw SDK. (Raw SDK is the *fallback only* if MCP calls fail.)
4. **Live-demo determinism > live inference.** The broker calls Sentinel inline on DENY so the
   triage is reproducible on camera. Never let the 3-min video depend on two live LLM calls.
5. **Forecast/value never depends on LLM availability.** If Ollama or MCP is down, the deny is
   still enforced and still lands in Splunk; only the narrative degrades. Enforcement is the product.

## Stack

- Python 3.11. `fastapi` + `uvicorn` (broker), `flask` (3 mock services), `pyjwt`,
  `httpx`, `requests`, `python-dotenv`.
- Ollama serving `Foundation-Sec-8B-Instruct` (Q4 GGUF).
- Splunk Enterprise: HEC for ingest, MCP Server + MCP TA, Dashboard Studio.
- MCP transport: streamable HTTP to `https://localhost:8089/services/mcp` (token auth).

## Commands

```bash
# install
pip install -r requirements.txt

# run the three mock services (ports 7001/7002/7003)
python -m services.prod_db & python -m services.secrets_store & python -m services.internal_api &

# run the broker (port 8800 — NOT 8000; Splunk Web owns 8000 on this machine)
uvicorn broker.main:app --port 8800 --reload

# issue a scoped agent token
python scripts/issue_token.py --agent checkout-bot --scope internal-api

# run the prompt-injection demo (drives the whole flow on camera)
python scripts/attack_demo.py
```

## Repo layout

```
broker/      policy broker (FastAPI): identity.py, policy.py, emit.py, main.py
services/    three mock internal services (Flask): prod_db, secrets_store, internal_api
sentinel/    investigation agent: agent.py, mcp_client.py, llm.py
splunk/      indexes.conf, savedsearches.conf (3 rules), dashboard.json
scripts/     issue_token.py, seed_agents.py, attack_demo.py
```

## Conventions

- Every broker decision (ALLOW and DENY) emits ONE structured event. Event schema is fixed —
  see SPEC.md §"Event contract". Do not change field names; the MCP TA / CIM extractions and
  the SPL rules depend on them.
- Keep mock services trivial: each just returns `{"service": "...", "data": "..."}` on GET.
  Their only job is to be a target the broker allows or denies.
- Secrets/tokens via `.env` (see `.env.example`). Never hardcode the MCP token or HEC token.
- Index names: `agentgate` (decisions), `agentgate_investigations` (Sentinel reports).

## Do NOT

- Do not build a React frontend. Do not scaffold a Splunk app with the UI toolkit.
- Do not call Splunk Hosted Models or any external LLM API by default.
- Do not add PrescientOps/TokenWatch features (CDTSM, OTel, DeepEval). Out of scope.
- Do not let MCP/Ollama setup bleed past Saturday morning — fall back and keep moving.
