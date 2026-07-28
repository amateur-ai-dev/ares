# ARES — Resume / Live Status

> Living status snapshot. Update on any significant change. Complements `docs/MASTER_PLAN.md` (intent) — this is live state.

**Last updated:** 2026-07-28

## Where we are

Pre-build / planning. ARES (formerly "Prahari") in its **own repo** (`amateur-ai-dev/ares`). Wayfinder map charted — destination = a **GO/NO-GO decision** on building ARES as a real internal SOC tool (goal: must genuinely get used; no target org yet).

## Wayfinder map (GitHub issues, this repo)

- Map: #1 "ARES go/no-go: build it as a real SOC tool?" (`wayfinder:map`)
- **Research DONE + resolved:** #2 model triage quality, #3 competitive landscape, #4 on-prem driver. Notes in `docs/research/`.
- **Frontier (takeable now):** #5 prototype proof (unblocked, reshaped), #6 effort vs payoff (grilling), #7 path-to-first-user (grilling), #9 differentiation wedge (grilling, graduated from #3)
- **Blocked:** #8 GO/NO-GO decision (needs #5,#6,#7,#9)

### Research verdicts (all point to conditional GO)

- **#2 model:** MARGINAL — local SLM viable ONLY inside retrieval+orchestration pipeline as HITL decision-support (raw ≈0% TP → wrapped ~93%). Best: Foundation-Sec-8B default, CyberSecQwen-4B low-VRAM. Architecture > model.
- **#3 competition:** "private" not unfilled (Elastic + AI_SOC already there). Wedge must be: turnkey single-org + stack-agnostic + code-scan-first.
- **#4 privacy pull:** moderate-strong but segment-gated. Lead with mandated/IP-sensitive SOCs (defense, HIPAA/PCI, EU DORA/NIS2), not mainstream.

### Implications carried forward

- Prototype #5 must test the PIPELINE (RAG + planner/adjudicator), not raw model.
- MASTER_PLAN framing shifts: HITL decision-support (not autonomous); pitch off "private" onto turnkey+stack-agnostic+code-scan; target mandated segments.

## Done

- `docs/MASTER_PLAN.md` — full architecture + phased plan. Status: **DRAFT, awaiting owner approval** (§12). No impl code until approved.
- `docs/PITCH.md` — one-page pitch, MSSP-framed.
- apollo-soc reuse analysis complete — ~600 lines worth lifting (enums, finding sub-models, scanner base/registry/semgrep, correlation, keyword_search). Postgres DB layer + compliance scanners + OCSF/VEX = skip.
- Repo created, README + .gitignore in place.

## Not done / open

- MASTER_PLAN still unapproved. 4 open questions unresolved (§11): Q1 name (now ARES — backronym TBD), Q2 sample data, Q3 model pick, Q4 frontend.
- Wayfinder map for ARES: **charting in progress** — destination not yet named (grilling was interrupted to fix the repo location).
- No `MASTER_PLAN` rename to "ARES" folded in yet (still says Prahari in places).
- V2.0 roadmap drafted in chat, not yet written into the plan doc.

## Next

1. Finish wayfinder charting — name the destination, map the frontier, create tickets.
2. Resolve §11 open questions.
3. Fold ARES rename + DB-location section + V2 roadmap + apollo-soc reuse into MASTER_PLAN, get approval.
