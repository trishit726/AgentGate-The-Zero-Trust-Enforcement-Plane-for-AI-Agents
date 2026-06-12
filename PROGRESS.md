# AgentGate — Build Progress Report

**As of:** Fri Jun 13, 2026 · **Deadline:** Mon Jun 15, 09:00 PDT (9:30 PM IST)
**Status: feature-complete.** All build phases (0–3) passed their gates with live
verification; Phase 4 ship artifacts are written and pushed. Remaining work is human-only:
record the video, submit on Devpost.

Repo: https://github.com/trishit726/AgentGate-The-Zero-Trust-Enforcement-Plane-for-AI-Agents

---

## What AgentGate is

A zero-trust enforcement plane for AI agents. Every agent holds a scoped JWT identity; a
FastAPI policy broker sits between agents and internal services and refuses out-of-scope
requests **at the network layer (403, no route)** — below the agent's reasoning, where
prompt injection cannot reach. Every decision (ALLOW and DENY) streams to Splunk via HEC.
On every DENY, an investigation agent ("Sentinel") pulls context **through the Splunk MCP
Server**, reasons with **Foundation-Sec-8B-Instruct running locally via Ollama**, and
writes a triage report back to Splunk. A native Dashboard Studio dashboard gives the SOC
analyst the full picture.

---

## Features implemented (all verified working)

### 1. Enforcement core (Phase 1) ✅
- **Scoped identities** — HS256 JWTs with an explicit service allowlist
  (`broker/identity.py`); token issuing scripts (`scripts/issue_token.py`,
  `scripts/seed_agents.py`) with a 3-agent demo roster (checkout-bot, analytics-bot,
  ops-bot).
- **Policy broker** (`broker/main.py`, `broker/policy.py`) — validates the JWT, exact-match
  scope check (no wildcards), proxies ALLOWs to the target, returns 403 on DENY.
  **Default-deny:** every error path (missing/expired/malformed token, unknown service,
  internal exception) resolves to DENY.
- **Three mock internal services** (Flask): prod-db :7001, secrets-store :7002,
  internal-api :7003.
- **Event pipeline** (`broker/emit.py`) — one structured JSON-RPC event per decision to
  Splunk HEC (`index=agentgate`, MCP-TA sourcetype, CIM-friendly fields). Best-effort:
  a Splunk outage can never block enforcement.

### 2. Sentinel investigation agent (Phase 2) ✅ — the MCP-bonus surface
- **MCP client** (`sentinel/mcp_client.py`) — streamable-HTTP client to the Splunk MCP
  Server (`https://localhost:8089/services/mcp`) with encrypted-token auth. Health check
  verified: AUTH OK, 14 tools listed.
- **Investigation loop** (`sentinel/agent.py`) — on every DENY: context pull over MCP
  (`saia_generate_spl` → `splunk_run_query`) → local LLM triage → report to
  `index=agentgate_investigations` with probable cause, blast radius, evidence,
  recommended action.
- **Local LLM** (`sentinel/llm.py`) — Foundation-Sec-1.1-8B-Instruct (Q4 GGUF) via Ollama,
  temperature 0 for determinism. No hosted model, no data egress.
- **Graceful degradation, honestly flagged** — SAIA cloud assistant 404s on this Enterprise
  instance, so SPL is templated locally but still executed *through the MCP Server*
  (`context_source=mcp_templated_spl` recorded in every report); if Ollama is down, a stub
  report still lands (`model="stub (model offline)"`). Enforcement never depends on either.
- **Verified:** live DENY → incident report in Splunk; with a normal-behavior baseline in
  context, Foundation-Sec classifies the attack as **`prompt_injection`** with correct
  evidence and zero-exfiltration blast radius.

### 3. Detection + dashboard (Phase 3) ✅
- **Three SPL correlation rules** (`splunk/savedsearches.conf`), all live and scheduled:
  - R1 scope-violation rollup per agent/target (every 5 min)
  - R2 sensitive-service denial = the demo alert (every minute, severity critical) —
    **verified firing** in Triggered Alerts
  - R3 denial-burst anomaly (>5 denials/min per agent)
- **Dashboard Studio "AgentGate Control"** (`splunk/dashboard.json`), dark theme, verified
  rendering in browser: KPI row (allowed/denied/identities), live decision feed with
  icon+text status (accessibility: never color alone), agent identity map with scopes,
  denial timeline, latest Sentinel investigation as a field/value triage table.
- **One-command deploy** (`scripts/deploy_splunk.py`) — pushes rules + dashboard over REST,
  idempotent, no Splunk restart.
- **Deterministic demo** (`scripts/attack_demo.py`) — three acts: legitimate baseline
  (including ops-bot *allowed* into secrets-store — policy, not blacklist), the
  prompt-injection attempt refused with 403, then Sentinel's triage retrieved live over
  MCP. Verified end to end.

### 4. Tokenomics — AI observing AI with its own cost meter ✅ (stretch goal)
- Sentinel meters every inference: prompt/completion/total tokens + wall time from Ollama,
  written into each report.
- New full-width dashboard panel joins per-identity requests/denials with investigation
  count, summed LLM tokens, and average triage seconds.
  Verified live: checkout-bot — 467 tokens, 18.3 s avg triage.

### 5. Ship artifacts (Phase 4) ✅
- `README.md` (value-first, stranger-runnable quick start), MIT `LICENSE`,
  `architecture_diagram.md` (Mermaid + the three required explanations),
  `DEMO_SCRIPT.md` (timed ≤3-min shot list built around measured latencies),
  `SPEC.md`, `TASKS.md` (all gates annotated with evidence).
- Repo public on GitHub, pushed, secrets excluded (`.env`, `tokens/` gitignored).

---

## Verified evidence trail

| Gate | Evidence |
|---|---|
| Gate 1 | ALLOW proxies; DENY 403s; both events visible in `index=agentgate` |
| Gate 2 | Incident `ag-1781303147` in `agentgate_investigations`; context pulled via `splunk_run_query` over MCP |
| Gate 3 | `attack_demo.py` end to end: 5 ALLOWs → 1 DENY → R2 alert fired → incident `ag-1781303759` = `prompt_injection` → dashboard verified in browser |
| Stretch | Tokenomics fields in report `ag-1781306429` (467 tokens / 18.3 s); panel SPL verified over MCP |

## Engineering notes / friction discovered (feedback-form material)

- `saia_*` MCP tools proxy to Splunk's cloud SAIA API → 404 on local Enterprise; designed
  an honest MCP-preserving fallback.
- Splunk search-time extraction duplicates JSON fields into multivalues → all SPL uses
  `mvdedup()`.
- REST API spells alert args differently from savedsearches.conf
  (`alert_type`/`alert_comparator`/`alert_threshold` vs `counttype`/`relation`/`quantity`).
- Dashboard Studio markdown does **not** substitute `$ds:result.*$` tokens on this build →
  investigation panel is a transposed table instead.
- `round()` cannot wrap an aggregation inside `stats` → moved to post-join `eval`.

## What remains (human-only)

1. **Restart the broker** once so it picks up the tokenomics code, then one
   `attack_demo.py --fast` warm-up run.
2. **Record the ≤3-min video** — follow `DEMO_SCRIPT.md`.
3. **Devpost submission** (track = Security) before Mon 9:30 PM IST.
4. **Most Valuable Feedback form** by Jun 19 — use the friction list above.
