# AgentGate — Architecture Blueprint (Supervisor Directives)

**Role of this document:** executable blueprint for the coding agent. The supervisor (this
document) defines structure, contracts, and boundaries. The coding agent writes the code.
Read CLAUDE.md hard constraints first; they override anything ambiguous here.

---

## 0. Non-negotiable safety boundaries (enforced by supervisor review)

1. **Default-deny everywhere.** Any error path in the broker (missing header, malformed JWT,
   unknown service, policy module exception) resolves to DENY + 403. There is no code path
   where a failure produces an ALLOW.
2. **Secrets discipline.** The MCP token, HEC token, and JWT secret live only in `.env`
   (gitignored). `.env.example` ships placeholders only. The literal MCP token appears in
   **zero** repo files, commits, or dashboard panels.
   - ⚠️ The MCP token captured from the screenshots contains whitespace artifacts inside the
     base64 blocks. **Do not use the pasted string.** Re-copy from the Splunk MCP Server app
     token page into `.env` as one unbroken line. Rotate the token before the repo/video goes
     public (it has appeared in screenshots).
3. **Enforcement never depends on intelligence.** Sentinel (MCP + Ollama) is fired
   fire-and-forget after the 403 is already committed. No Sentinel failure may delay, block,
   or alter a broker decision or its HEC event.
4. **Event schema is frozen** (SPEC §4.2). Field names are load-bearing for the MCP TA
   extractions and the three SPL rules. Never rename, never nest differently.
5. **No React, no Splunk UI toolkit, no webpack.** The dashboard is one Dashboard Studio
   JSON definition (`splunk/dashboard.json`). No hosted models; Foundation-Sec-8B via Ollama.

---

## 1. Phase 1 — Enforcement Core (detailed build plan)

Build order matters: services → identity → policy → emit → main → scripts. Each step is
independently testable before the next.

### 1.1 `services/` — three mock targets (build first, 20 min)

Three near-identical Flask apps. Each exposes exactly one route:

| Module | Service name | Port | Route | Response |
|---|---|---|---|---|
| `services/prod_db.py` | `prod-db` | 7001 | `GET /` and `GET /<path>` | `{"service": "prod-db", "data": "customer_records_v2"}` |
| `services/secrets_store.py` | `secrets-store` | 7002 | same | `{"service": "secrets-store", "data": "aws_keys, db_credentials"}` |
| `services/internal_api.py` | `internal-api` | 7003 | same | `{"service": "internal-api", "data": "order_status: ok"}` |

Keep them trivial — they exist only to be allowed or refused. No auth on the services
themselves (the broker is the only path in the demo narrative).

### 1.2 `broker/identity.py` — scoped JWT issue/verify

- `issue_token(agent_id: str, scope: list[str], ttl_seconds: int = 3600) -> str`
  - Claims exactly per SPEC §4.1: `sub`, `agent_id`, `scope`, `iat`, `exp`. HS256,
    secret from `AGENTGATE_JWT_SECRET`.
- `verify_token(token: str) -> dict`
  - Returns claims on success. Raises two distinct exceptions the broker maps to event
    reasons: `ExpiredTokenError` → `expired_token`, `InvalidTokenError` (everything else:
    bad signature, malformed, missing claims) → `invalid_token`.
- No network, no I/O. Pure functions over the secret. Refuse to start if the secret is unset
  or shorter than 32 chars (fail loud at boot, not at request time).

### 1.3 `broker/policy.py` — the decision function

- `SERVICE_MAP = {"prod-db": "http://localhost:7001", "secrets-store": "http://localhost:7002", "internal-api": "http://localhost:7003"}`
- `decide(claims: dict, target_service: str) -> tuple[str, str]` returning
  `("ALLOW", "ok")` or `("DENY", reason)`.
  - Target not in `SERVICE_MAP` → `("DENY", "scope_violation")` (the frozen reason enum has
    no `unknown_service`; map it here and note it in a comment).
  - Target not in `claims["scope"]` → `("DENY", "scope_violation")`.
  - Exact string match only. No wildcards, no prefix matching — wildcard scope is how
    zero-trust dies.
- Pure function. Unit-testable without FastAPI.

### 1.4 `broker/emit.py` — HEC emitter

- `emit_decision(event: dict) -> None` — POST to `SPLUNK_HEC_URL`
  (`https://localhost:8088/services/collector/event`), header `Authorization: Splunk <SPLUNK_HEC_TOKEN>`.
- HEC envelope: `{"index": "agentgate", "sourcetype": SPLUNK_HEC_SOURCETYPE, "event": <decision JSON-RPC payload per SPEC §4.2>}`.
  Sourcetype comes from `.env` so it can be matched to whatever the MCP TA expects
  (inspect the TA's `props.conf` once; do not hardcode a guess).
- 3-second timeout, `verify` controlled by `SPLUNK_VERIFY_TLS` (false for local self-signed).
- **Swallow and log all exceptions.** A Splunk outage must never 500 the broker. Same
  function reused later for `agentgate_investigations` with an `index` parameter.

### 1.5 `broker/main.py` — FastAPI enforcement plane

Single catch-all route: `@app.api_route("/{service}/{path:path}", methods=["GET"])`
(GET only — the mocks are GET-only; keep it tight).

Request flow, in order:
1. Extract `Authorization: Bearer <jwt>`. Missing/malformed header → DENY `invalid_token`.
2. `verify_token` → on exception, DENY with the mapped reason. `agent_id` for the event comes
   from the unverified `sub` claim if decodable, else `"unknown"`.
3. `policy.decide(claims, service)`.
4. **DENY:** build the SPEC §4.2 event (`timestamp` = UTC ISO-8601 `Z`, `src_ip` from
   `request.client.host`, `action` = `"GET /" + path`), `emit_decision(event)`, schedule
   `sentinel_hook(event)` as a FastAPI `BackgroundTask`, return
   `403 {"error": "AgentGate: access to '<service>' denied", "decision": "DENY", "reason": reason}`.
   The 403 returns immediately; Sentinel runs after the response.
5. **ALLOW:** proxy via `httpx` to `SERVICE_MAP[service]` + path (5 s timeout; upstream
   failure → 502, but the decision event still says ALLOW — the *decision* was allow),
   emit the ALLOW event, return the upstream body.
6. `sentinel_hook(event)`: in Phase 1, a no-op stub that logs "sentinel: would investigate".
   Phase 2 replaces the body, not the call site.

### 1.6 `scripts/` — token tooling

- `issue_token.py` — argparse: `--agent`, repeatable `--scope`, `--ttl` (default 3600).
  Prints the JWT to stdout.
- `seed_agents.py` — issues the demo roster and writes to `tokens/<agent>.jwt` (gitignored):
  - `checkout-bot` → `["internal-api"]` (the demo victim)
  - `analytics-bot` → `["prod-db", "internal-api"]`
  - `ops-bot` → `["prod-db", "secrets-store", "internal-api"]` (shows ALLOW to secrets-store
    is possible when scoped — proves it's policy, not a hardcode)

### 1.7 Gate 1 acceptance (must all pass before Phase 2)

```bash
# ALLOW: proxies and returns service body
curl -s http://localhost:8000/internal-api/ -H "Authorization: Bearer $(cat tokens/checkout-bot.jwt)"
# DENY: 403, scope_violation
curl -s http://localhost:8000/secrets-store/credentials -H "Authorization: Bearer $(cat tokens/checkout-bot.jwt)"
# DENY: invalid_token (no header) and expired_token (issue with --ttl 1, sleep 2)
```
Then in Splunk: `index=agentgate | stats count by decision, reason` shows both ALLOW and
DENY rows with all SPEC §4.2 fields extracted.

---

## 2. Phase 2 — Sentinel Investigation Agent (architecture)

### 2.1 Module responsibilities

```
broker DENY ──BackgroundTask──▶ sentinel/agent.py  investigate(event)
                                   │ 1. context  ── sentinel/mcp_client.py ──▶ Splunk MCP Server
                                   │              (saia_generate_spl → splunk_run_query)
                                   │              fallback: raw REST search, flagged "sdk_fallback"
                                   │ 2. reason   ── sentinel/llm.py ──▶ Ollama Foundation-Sec-8B
                                   │              fallback: deterministic stub report
                                   └ 3. write    ── broker/emit.py(index="agentgate_investigations")
```

### 2.2 `sentinel/mcp_client.py` — Splunk MCP Server client

- **Transport:** streamable HTTP via the official `mcp` Python SDK
  (`mcp.client.streamable_http.streamablehttp_client`).
- **Endpoint:** `SPLUNK_MCP_URL` = `https://localhost:8089/services/mcp` (from `.env`, never
  hardcoded).
- **Auth:** header `Authorization: Bearer <SPLUNK_MCP_TOKEN>` — the encrypted token already
  created and verified in the environment. The token is opaque ciphertext: treat it as a
  single line, strip whitespace/newlines defensively on load
  (`token = "".join(raw.split())` guards against paste artifacts), and refuse to start
  Sentinel with a clear log line if it's unset.
- **TLS:** port 8089 uses Splunk's self-signed cert → construct the SDK's underlying httpx
  client with `verify=False` when `SPLUNK_VERIFY_TLS=false` (localhost-only; note it in README).
- **Surface (keep it to exactly what the bonus needs):**
  - `generate_spl(natural_language: str) -> str` → calls tool `saia_generate_spl`, returns the
    SPL string.
  - `run_query(spl: str) -> list[dict]` → calls tool `splunk_run_query`, returns result rows.
  - One `list_tools()` used at startup as a health check (also the on-camera proof moment —
    log the tool names it returns).
- **Failure contract:** 30 s timeout, one retry, then raise `MCPUnavailable`. The caller
  decides on fallback; this module never falls back silently.

### 2.3 `sentinel/llm.py` — local Foundation-Sec wrapper

- `triage(deny_event: dict, context_rows: list[dict]) -> dict` → POST
  `{OLLAMA_URL}/api/chat`, model `OLLAMA_MODEL`, `temperature: 0` (demo determinism),
  `format: "json"`, system prompt = SOC triage analyst that must return exactly the SPEC §4.3
  report fields.
- Validate the returned JSON against the §4.3 keys; on parse failure or timeout (60 s) raise
  `LLMUnavailable`.

### 2.4 `sentinel/agent.py` — the loop

`investigate(event)` — **never raises**, top-level try/except writes whatever it has:
1. `incident_id = "ag-" + unix_ts`.
2. Context: `spl = mcp.generate_spl(f"denied requests for agent {agent_id} in the last 15 minutes")`
   → `rows = mcp.run_query(spl)`. On `MCPUnavailable`: fall back to one direct REST search
   against `https://localhost:8089/services/search/v2/jobs/export` and set
   `"context_source": "sdk_fallback"` in the report (honesty in the artifact; MCP path sets
   `"context_source": "mcp"`).
3. Reason: `llm.triage(...)`. On `LLMUnavailable`: stub report with
   `"probable_cause": "(narrative unavailable — model offline)"` and the mechanical facts
   (agent, target, scope) filled from the event.
4. Write the §4.3 report via `emit_decision(report, index="agentgate_investigations")`.

### 2.5 `.env` contract (and `.env.example` with placeholders)

```
AGENTGATE_JWT_SECRET=change-me-32-chars-minimum-random
SPLUNK_HEC_URL=https://localhost:8088/services/collector/event
SPLUNK_HEC_TOKEN=<hec-token>
SPLUNK_HEC_SOURCETYPE=<match the MCP TA sourcetype, e.g. mcp:jsonrpc — verify in TA props.conf>
SPLUNK_MCP_URL=https://localhost:8089/services/mcp
SPLUNK_MCP_TOKEN=<paste the encrypted MCP token as ONE unbroken line — no spaces/newlines>
SPLUNK_VERIFY_TLS=false
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=fdtn-ai/Foundation-Sec-8B-Instruct
```

### 2.6 Gate 2 acceptance

A forced DENY produces a row in `index=agentgate_investigations` with
`context_source="mcp"`, and Sentinel's log shows the `saia_generate_spl` call, the SPL it got
back, and the `splunk_run_query` rows. Screen-record this log once — it is the MCP-bonus
evidence even if something flakes later.

---

## 3. Dashboard blueprint — "AgentGate Control"
### Vercel-style dark minimalism inside native Dashboard Studio

**Constraint honesty first:** Dashboard Studio cannot load custom fonts (no Geist/Inter) and
allows no CSS injection. The Vercel look is therefore achieved through the four levers Studio
*does* expose: true-black absolute-layout canvas, per-viz `backgroundColor`/`fontColor`
options, `splunk.rectangle` shapes as hairline borders, and markdown panels for
typography-driven hierarchy. That combination gets ~90% of the aesthetic natively.

### 3.1 Design tokens (use these literal values everywhere)

| Token | Value | Use |
|---|---|---|
| `bg.canvas` | `#000000` | layout background (true black) |
| `bg.card` | `#0A0A0A` | panel backgrounds (one step off black) |
| `border.hairline` | `#1F1F1F` | rectangle strokes, 1px |
| `text.primary` | `#EDEDED` | values, table cells, headings |
| `text.secondary` | `#888888` | labels, captions, axis text |
| `accent.allow` | `#4ADE80` | ALLOW status (icon+word, never color alone) |
| `accent.deny` | `#F87171` | DENY status (icon+word) |
| `accent.line` | `#FFFFFF` | single monochrome chart series |

All pass WCAG AA on `#0A0A0A` (the two accents and both text tones exceed 4.5:1).

### 3.2 Root JSON skeleton

```json
{
  "title": "AgentGate Control",
  "layout": {
    "type": "absolute",
    "options": {
      "width": 1440, "height": 860,
      "display": "auto-scale",
      "backgroundColor": "#000000"
    },
    "structure": [ /* blocks per §3.3, rectangles first so they render beneath */ ]
  },
  "defaults": {
    "dataSources": { "ds.search": { "options": {
      "queryParameters": { "earliest": "-60m", "latest": "now" },
      "refresh": "10s", "refreshType": "delay"
    }}}
  },
  "dataSources": { /* §3.4 */ },
  "visualizations": { /* §3.3 */ }
}
```

Also set the dashboard theme to **dark** in Studio's UI settings so native chrome
(tooltips, scrollbars) matches; the explicit `backgroundColor` overrides the theme's
dark-gray with true black.

### 3.3 Bento grid — absolute positions (24px margins, 16px gutters)

Every card = a `splunk.rectangle` (fill `#0A0A0A`, stroke `#1F1F1F`, strokeWidth 1, small
corner radius if the option is available) positioned *under* a content viz inset by 16px.
This is what produces the hairline-border Bento look.

| # | Panel | Viz type | x | y | w | h |
|---|---|---|---|---|---|---|
| 0 | Header wordmark | `splunk.markdown` | 24 | 24 | 1392 | 64 |
| 1 | KPI: Requests (60m) | `splunk.singlevalue` | 24 | 104 | 336 | 112 |
| 2 | KPI: Denials | `splunk.singlevalue` | 376 | 104 | 336 | 112 |
| 3 | KPI: Active agents | `splunk.singlevalue` | 728 | 104 | 336 | 112 |
| 4 | KPI: Investigations | `splunk.singlevalue` | 1080 | 104 | 336 | 112 |
| 5 | Live decision feed | `splunk.table` | 24 | 232 | 912 | 340 |
| 6 | Latest investigation | `splunk.markdown` (token-fed) | 952 | 232 | 464 | 604 |
| 7 | Denial timeline | `splunk.line` | 24 | 588 | 448 | 248 |
| 8 | Agent identity map | `splunk.table` | 488 | 588 | 448 | 248 |

Panel directives:
- **Header (0):** markdown only — `# AgentGate` + thin `text.secondary` subtitle
  "Zero-Trust Enforcement Plane — live". Typography IS the header; no logo image.
- **KPIs (1–4):** `options: { "backgroundColor": "transparent", "majorColor": "#EDEDED" }`,
  sparkline off except Denials (sparkline in `accent.deny`). Label via a small markdown
  caption or the viz title in `text.secondary` — Vercel cards are number-forward.
- **Live feed (5):** columns `time, status, agent_id, target_service, reason`. `status` is
  built in SPL: `eval status=if(decision="DENY","✕ DENY","✓ ALLOW")` (icon **+ word** —
  the accessibility commitment). Color the status column via `columnFormat` color mapping
  (`#F87171`/`#4ADE80`); rows on `#0A0A0A` with no zebra striping; header text
  `text.secondary`.
- **Investigation (6):** the signature panel. Data source: latest row from
  `agentgate_investigations`; feed fields into dashboard **tokens** via the data source's
  token binding, and render a markdown template:
  `## Incident $tok_incident$` / `**Probable cause:** $tok_cause$` / headings per SPEC §4.3
  field. Structured headings double as the screen-reader text alternative.
- **Timeline (7):** `timechart span=1m count(eval(decision="DENY"))`. Single white series,
  `backgroundColor: "transparent"`, hide legend and axis titles, `text.secondary` axis
  labels. A spike on black is the whole story.
- **Identity map (8):** `stats values(token_scope) as scope, count(eval(decision="ALLOW")) as allows, count(eval(decision="DENY")) as denials by agent_id`.

### 3.4 Data sources (one per panel, IDs `ds_kpi_*`, `ds_feed`, `ds_invest`, `ds_timeline`, `ds_identity`)

All `index=agentgate` except `ds_invest` (`index=agentgate_investigations | head 1`).
10 s refresh on feed/KPIs/timeline; 15 s on investigation.

### 3.5 Build sequence for the coding agent

1. Author the skeleton JSON by hand per this spec (rectangles → content vizzes → data sources).
2. Import into Dashboard Studio once, fix any option-name drift in the UI (Studio is the
   source of truth for exact option keys), then **export the JSON back into
   `splunk/dashboard.json`** so the repo artifact is the verified one.
3. Verify the two failure-mode renders: empty `agentgate_investigations` (panel 6 must show a
   graceful "No investigations yet" via SPL `fillnull`/`appendpipe` default row) and zero
   denials (timeline flat, not broken).

---

## 4. Execution order & gates (hand to the coding agent verbatim)

1. Phase 0 leftovers: `requirements.txt`, `.env.example`, indexes, HEC token, Ollama pull. **Gate 0** per TASKS.md.
2. Phase 1 §1.1→1.7 in order. Stop at **Gate 1** and verify in Splunk before touching Sentinel.
3. Phase 2 §2.2→2.4. `mcp_client.list_tools()` health check first — if MCP auth fails for
   >45 min, take the documented SDK fallback and keep moving (TASKS.md hard rule).
4. Phase 3: savedsearches.conf (3 rules per SPEC §6), then dashboard per §3, then
   `attack_demo.py` (deterministic: issue token → 1 ALLOW → injected DENY → poll
   `agentgate_investigations` until the report lands → print it).
5. Phase 4/5 per TASKS.md. Before the repo goes public: rotate the MCP token, confirm
   `.env` and `tokens/` are gitignored, grep the tree for the token prefix as a final check.
