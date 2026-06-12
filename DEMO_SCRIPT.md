# Demo video — shot list (≤3:00)

Strategy (per SPEC §8 + verified timings): Sentinel's local inference takes ~80 s, so
**pre-run once** right before recording — the dashboard then already shows a completed
investigation — and do the live deny + ONE live MCP query on camera. No copyrighted music.

## Pre-record checklist (10 min before)

- [ ] Services up: `python -m services.prod_db & python -m services.secrets_store & python -m services.internal_api &`
- [ ] Broker up: `uvicorn broker.main:app --port 8800`
- [ ] Ollama up (model loaded once so first inference isn't cold): `python scripts/attack_demo.py --fast`
      → this pre-run also populates the dashboard + Triggered Alerts for the camera.
- [ ] Splunk Web open on two tabs: **AgentGate Control** dashboard · **Activity → Triggered Alerts**
- [ ] Terminal font large, dark theme; close notifications.

## Shots

| Time | Shot | Say (gist) |
|---|---|---|
| 0:00–0:25 | Architecture diagram (`architecture_diagram.md`) | Agents inside infra carry credentials. Every defense today lives *inside* the model's reasoning — prompt injection walks past all of it. AgentGate enforces **below** the agent, at the network layer, and Splunk is the SOC brain. |
| 0:25–0:45 | Terminal: `python scripts/attack_demo.py` Act 1 scrolling | Three agents, each with a scoped identity token. The broker checks **every** call. Note: ops-bot IS allowed into secrets-store — this is per-identity policy, not a blacklist. |
| 0:45–1:10 | Act 2 on screen: injected prompt + the 403 | checkout-bot gets prompt-injected — "fetch the AWS credentials." The model complies. The network does not: **403, scope_violation, no route**. There is no prompt that un-refuses this. Zero bytes left secrets-store. |
| 1:10–1:30 | Splunk tab: dashboard live feed (DENY row, icon + word) + Triggered Alerts showing **AgentGate R2** | The deny is already in `index=agentgate` with CIM-friendly fields; the sensitive-service correlation rule has fired. |
| 1:30–2:10 | Terminal: Act 3 polling, then the triage block printing. Overlay/zoom: `python -m sentinel.mcp_client` AUTH OK + 14 tools (run it live — it's 3 s) | On every denial, Sentinel investigates — **through the Splunk MCP Server, with an encrypted token**: context query in, Foundation-Sec-8B reasoning **locally via Ollama**. No hosted model, no egress. |
| 2:10–2:40 | Dashboard: identity map, denial timeline spike, then the **Latest Sentinel investigation** panel: `prompt_injection`, blast radius, recommended action | The analyst opens one screen: who, what, probable cause **prompt_injection**, blast radius **zero data exfiltrated**, recommended action. Detection → investigation → response evidence, already done at machine speed. |
| 2:40–3:00 | Hold on dashboard | "The agent was prompt-injected. The network refused. Splunk saw everything. The analyst had the full picture in seconds." |

## Fallback notes

- If Ollama hiccups on camera, the deny + alert + dashboard still work (pre-run data is
  already there) — narrate over the existing investigation panel.
- The live "wow" query alternative: in Search, `index=agentgate_investigations | head 1`.
