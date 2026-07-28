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

- Repo `amateur-ai-dev/ares` created (private), cut clean from Second-brain-. README + .gitignore. 2 commits pushed to `main`.
- `docs/MASTER_PLAN.md` — full architecture + phased plan. Status: **DRAFT, awaiting owner approval** (§12). No impl code until approved.
- `docs/PITCH.md` — one-page pitch, MSSP-framed.
- apollo-soc reuse analysis — ~600 lines worth lifting (enums, finding sub-models, scanner base/registry/semgrep, correlation, keyword_search). Postgres DB + compliance scanners + OCSF/VEX = skip.
- **Wayfinder map fully charted** (#1) — destination named (GO/NO-GO), 8 tickets created + wired, 3 research tickets resolved (#2/#3/#4), 1 fog ticket graduated (#9), prototype (#5) reshaped + unblocked.
- `docs/research/01-03` cited notes committed + pushed.

## Not done / open

- **#8 GO/NO-GO** decision — the destination, still open (blocked by #5,#6,#7,#9).
- Frontier tickets unworked: #5 prototype (HITL, buildable now), #6 effort, #7 first-user, #9 wedge (all HITL grilling — need Nithin).
- MASTER_PLAN not yet updated for research findings: rename Prahari→ARES, DB-location section, V2 roadmap, apollo-soc reuse, **framing shift (HITL decision-support / off-"private" wedge / mandated segments)**. Doc still unapproved.
- §11 open questions (name backronym, sample data, model, frontend) — deferred to post-GO (out of scope on the map).

## Next

1. Work a frontier ticket — recommend **#5 prototype** (pull Foundation-Sec-8B, run 5-10 alerts through minimal RAG+pipeline path); strongest input to the GO/NO-GO. Or grill #9 wedge / #6 effort / #7 first-user live.
2. When #5,#6,#7,#9 close → resolve **#8 GO/NO-GO**.
3. If GO: fold research framing + rename + V2 into MASTER_PLAN, get approval, then a separate build-spec map.
