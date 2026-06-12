# AgentGate — 72-Hour Build Plan

Deadline: **Mon Jun 15, 09:00 PDT / 9:30 PM IST.** Submit with margin — Monday AM, not Monday night.
Each phase has a gate. If a gate fails, fall back (noted) and keep moving. Polish > breadth.

---

## Phase 0 — Scaffold (Fri night, ~1 hr) ✅ infra already verified

- [x] Splunk Enterprise up, dev license applied
- [x] MCP Server installed + active, encrypted token created and verified
- [x] MCP TA installed
- [x] `pip install -r requirements.txt`; create `.env` from `.env.example`
- [x] Create Splunk indexes `agentgate` and `agentgate_investigations`
- [x] Enable a Splunk **HEC** token; put it in `.env`
- [x] Pull `Foundation-Sec-8B-Instruct` Q4 GGUF into Ollama; confirm one prompt returns
      (model in use: `hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF`)
- [ ] `architecture_diagram.md` finalized at repo root (done — review only)

**Gate 0 (by ~midnight):** HEC token works (one curl event lands in `index=agentgate`) AND
Ollama answers one triage-style prompt. If Ollama won't run on this hardware → fall back to an
external LLM API with an egress note in README; decide NOW, not Saturday.

---

## Phase 1 — Enforcement core (Sat AM–PM)

- [x] `services/` — three trivial Flask GET endpoints (prod-db, secrets-store, internal-api)
- [x] `broker/identity.py` — issue + verify scoped JWT (HS256)
- [x] `broker/policy.py` — `is_allowed(agent_scope, target_service)`
- [x] `broker/emit.py` — POST decision event to HEC with MCP-TA sourcetype
- [x] `broker/main.py` — FastAPI: validate → enforce → proxy/refuse → emit
- [x] `scripts/issue_token.py`, `scripts/seed_agents.py`

**Gate 1 (Sat midday):** an ALLOW proxies and a DENY returns 403, and **both events are
visible in `index=agentgate`** in Splunk. This is the spine — everything else hangs off it.

---

## Phase 2 — Investigation agent (Sat PM–Eve)

- [x] `sentinel/mcp_client.py` — streamable-HTTP client to `localhost:8089/services/mcp`,
      token auth; wrap `saia_generate_spl` and `splunk_run_query`
- [x] `sentinel/llm.py` — Ollama Foundation-Sec wrapper, SOC-triage system prompt
- [x] `sentinel/agent.py` — on DENY: MCP context pull → reason → write report to
      `agentgate_investigations`; graceful degrade (MCP→SDK fallback; LLM-down→stub report)
- [x] Wire broker DENY → async `sentinel.investigate(event)`

**Gate 2 (Sat night):** a DENY produces a triage report in `agentgate_investigations`, and
Sentinel demonstrably used the **MCP tools** to get there. This secures the bonus claim.
✅ **PASSED (verified Jun 13):** live DENY → incident `ag-1781303147` in
`agentgate_investigations` with a real Foundation-Sec narrative; context pulled via
`splunk_run_query` over MCP (`context_source=mcp_templated_spl` — SAIA cloud returns 404
on this instance, so SPL is locally templated but the query still runs through MCP).

---

## Phase 3 — Detection + dashboard (Sun AM–PM)

- [x] `splunk/savedsearches.conf` — 3 SPL correlation rules (scope violation, sensitive-path,
      denial-rate anomaly); rule 2 fires the demo alert
- [x] `splunk/dashboard.json` — Dashboard Studio "AgentGate Control": live feed, identity map,
      denial timeline, latest investigation (markdown). Accessibility: icon+text, AA contrast.
- [x] `scripts/attack_demo.py` — drives the full prompt-injection flow deterministically
- [x] `scripts/deploy_splunk.py` — REST deploy of rules + dashboard (idempotent, no restart)

**Gate 3 (Sun midday):** running `attack_demo.py` produces, end to end, a denial → event →
alert → investigation → dashboard update, reproducibly. Pre-run once so the live take can rely
on the summary, then do ONE live query for the wow moment.
✅ **PASSED (verified Jun 13):** `attack_demo.py --fast` ran end to end — 5 baseline ALLOWs,
one DENY (403, scope_violation), rule R2 in Triggered Alerts (fired 2×), incident
`ag-1781303759` triaged as **prompt_injection** (the ALLOW baseline is what flips the
classification from misconfiguration — keep Act 1). Sentinel latency ≈ 75–85 s on this
hardware: pre-run before recording. All dashboard panel SPL verified over MCP.
Dashboard verified in browser (Jun 13). Note: this Splunk build's markdown viz does NOT
substitute `$ds:result.*$` tokens — the investigation panel is a transposed field/value
table instead (renders reliably; still structured + screen-reader friendly).

---

## Phase 4 — Ship (Sun Eve)

- [x] `README.md` — problem, value-first; setup/run; mirror Splunk vocabulary; note local
      Foundation-Sec (not hosted) + MCP usage; cross-reference AgentReady if built
- [x] `LICENSE` (MIT), visible in repo About
- [ ] Record demo video ≤3 min (shot list in `DEMO_SCRIPT.md`); no copyrighted music
- [x] Final pass on `architecture_diagram.md` at repo root (SAIA-fallback honesty note added)
- [ ] Push public repo; verify a stranger could run it from the README
      (git repo initialized, initial commit `3bba7b1` — create the GitHub repo and push;
      also fixed for strangers: `mcp` added to requirements.txt, deploy creds + real
      Ollama model tag added to `.env.example`, `SPEC (2).md` renamed to `SPEC.md`)

**Gate 4 (Sun night):** repo public, video uploaded, all required artifacts present.

---

## Phase 5 — Submit (Mon AM)

- [ ] Devpost submission, track = Security, links verified live
- [ ] Submit **before 9:00 PDT / 9:30 PM IST** with margin
- [ ] File **Most Valuable Feedback** form (by Jun 19) — log the MCP/TA/HEC/install friction
      you hit along the way

---

## If ahead of schedule (optional, do NOT bloat scope)

- [x] **Tokenomics panel:** add per-identity request counts + Sentinel token usage as one
      dashboard panel → lets you say "tokenomics" / "AI observing AI with its own cost meter".
      ≤2 hrs, Sunday polish window only.
      ✅ Done (Jun 13): Sentinel now meters its own inference (tokens_prompt/completion/total,
      inference_ms from Ollama) into every report; full-width 💰 Tokenomics panel joins
      per-identity requests/denials with investigations + LLM token cost. Verified live
      (checkout-bot: 467 tokens, 18.3 s avg triage). NOTE: restart the broker so it picks up
      the new sentinel code — older reports lack token fields (sum just skips them).
- [ ] **AgentReady** (separate submission, Platform track + Developer Tools bonus): only start
      if Gate 3 passed by Sun midday. Scope it brutally — AppInspect CLI wrapper + 5–6
      agent-readiness checks + LLM auto-fix on the SAME Ollama + a generated static HTML report
      (NOT a React app).

## Hard rules

- One project at 95% beats two at 60%. AgentGate first, always.
- Submission overhead is ~4–5 hrs (video, README, diagram, form). Protect Sunday evening.
- If MCP or Ollama setup stalls >45 min at any gate, take the documented fallback and move on.
- Do not add CDTSM / OTel / DeepEval / hosted-model anything. Out of scope by design.
