# ARES — Code2Impact deck copy

Writing material only, mapped slide-by-slide to `Code2Impact_TechSphere26_Submission_Template_v1.7.26.pptx`.
Nothing here has been written into the PPTX — paste what you want.

**Convention used below**
- Plain text = ready to paste.
- `[[…]]` = you must supply (team name, BU, track) or verify before use.
- Every number in "our" columns is a measured figure from `docs/PAPER.md` §6. Numbers marked `[[verify]]` are industry-context claims I have NOT verified and you should either source or delete.

---

## Slide 1 — Title

**Project/Idea Name:** ARES SecOps

**Tagline** (pick one)
1. The model proposes. The tools dispose. Every claim badged verified, refuted, or unproven.
2. An AI security analyst that is structurally incapable of asserting something it has not proven.
3. Local-only incident analysis where the AI can be wrong about what matters, but cannot make the tool state a falsehood.

*Recommendation: #1. It is the thesis in eight words and it is the thing no competing submission can say.*

**Team:** `[[Team name]]` · `[[members]]` · `[[Business Unit]]`

**Technology Track:** `[[AI / Cybersecurity — pick per the track list]]`

---

## Slide 2 — Divider

**Project/Idea Name — ARES SecOps**

Optional strapline under it: *Deterministic verification for AI-assisted security operations.*

---

## Slide 3 — Executive Summary

**Current Challenge**
Security teams are being handed AI assistants that summarise incidents fluently and confidently — and cannot tell the analyst which parts of that summary were checked and which were guessed. In security, an unverifiable claim is worse than no claim: it is acted on. The industry response has been to make models bigger, which improves the prose and does nothing about the epistemics.

**Proposed Solution**
ARES inverts the division of labour. Deterministic code enumerates and *proves* every relationship in the event log; the AI model only decides which proven relationships form the attack. Every statement the tool emits carries a badge — VERIFIED, REFUTED, or APORIA (honestly unproven) — and a VERIFIED badge cannot exist without an immutable execution record proving it, enforced by both a single code path and database triggers. It runs entirely on the analyst's own machine.

**Expected Business Value**
Risk and quality first, efficiency second: analysts stop re-deriving what the assistant asserted, unverified AI output stops entering incident records, and the whole capability runs air-gapped — no customer telemetry leaves the estate.

**One-sentence impact**
"ARES helps security analysts by separating what the machine has *proven* from what a model merely *believes*, resulting in AI assistance that can be trusted in an evidence-bearing workflow."

---

## Slide 4 — Problem Statement

**Background**
An incident investigation is a chain of factual joins: this process spawned that one; that process opened this connection. Today an analyst reconstructs the chain by hand across tens of thousands of events, or asks an LLM and receives a fluent narrative with no way to tell which links were verified against the log and which were plausible-sounding fabrication. Both routes are expensive. The second is worse, because it is fast enough to be trusted.

Measured on our evaluation corpus: a single day of one workstation's Sysmon telemetry contains **196,081 events**, from which **794 process relationships are derivable**. Day two: **587,286 events, 1,704 relationships**. That is one machine, two days.

**Who is affected**
Tier-1 and Tier-2 SOC analysts, incident responders, and anyone downstream who consumes an incident record — customer, auditor, regulator.

**Why it matters**

| Lens | Impact |
|---|---|
| **Customer** | Incident findings shared with a customer must be defensible. An AI-authored claim with no provenance cannot be defended in a post-incident review. |
| **Engineer** | The analyst re-verifies the assistant's output by hand, so the assistant adds a step instead of removing one. Assistance that must be checked is not assistance. |
| **Operations** | Investigation time is dominated by manual correlation across event volumes no human reads. Throughput is capped by the slowest, most tedious task. |
| **Business** | Unverifiable AI output in a security record is a governance liability — and sending security telemetry to a hosted model is often simply not permitted. |

**Quantify the pain**
Use the measured ones. They are yours and they are defensible:

- **196,081 → 794** — events an analyst would have to read, versus relationships that actually exist in them, for one machine-day.
- **1 of 794** — how much of the derivable evidence a naive "ask the LLM to find the links" approach recovered: **3 of 794** (§6.1). That is the honest baseline, and it is devastating.
- **8** — false-verification defects an independent adversarial test suite found in code that had already passed a phase gate, a correctness review *and* an adversarial review (§6.7).
- `[[verify]]` industry alert-fatigue / MTTR figures if you want a fourth tile — do not invent one.

---

## Slide 5 — Opportunity & Innovation

**What opportunity did you identify?**

- **The gap:** every AI security assistant on the market outputs claims of uniform, unmarked confidence. The analyst cannot separate the checked from the guessed, so they must either trust everything or check everything.
- **Why current approaches are insufficient:** the field is treating hallucination as a model-quality problem to be solved with scale. It is an architecture problem. A bigger model asked to do exact string comparison across 196,081 events still guesses — it just guesses more persuasively. Our first build proved this: asking the model to *discover* the links recovered 3 of 794.
- **What makes ours different and timely:** we do not ask the model to be reliable. We make it structurally impossible for the model's opinion to become a stated fact. And local models are now just good enough at *selection* — the judgement task — for that split to be practical on a laptop.

**Innovation highlights**

**1 — The inversion: tools enumerate and prove, the model only selects.**
Exact identifier matching is what code is perfect at and models are worst at. Moving discovery to code and leaving only judgement to the model took selection recall from **0% to 66.7% on identical data**, and collapsed 25 model calls into one. Same model, same log — a different division of labour.

**2 — The badge firewall: a VERIFIED badge cannot be forged, including by us.**
A badge is issuable only through one function, and only with a matching immutable verifier-execution row; SQLite triggers enforce it independently, and stamped claims become immutable at the database level. When an adversarial pass found a claim's text could be rewritten *after* stamping, that hole was closed with a trigger — not a code convention. **Verification precision was 100% across all twelve runs, both arms, four window sizes.**

**3 — APORIA: the tool is allowed to say "I could not prove this".**
Most systems degrade an unproven claim into a hedged assertion. ARES emits it as a first-class, never-hidden badge. An honest unknown is operationally more valuable than a confident guess, and it is the class of output no confidence score gives you.

---

## Slide 6 — Solution Overview

**Overview**
ARES is a locally-hosted incident analysis tool. It ingests Windows Sysmon event logs, deterministically enumerates every candidate relationship between events and proves or refuses each one, ranks the proven set by suspicion, and asks a local AI model to select which of those proven relationships constitute the attack. It then presents the result to the analyst — through a read-only local dashboard and downloadable reports — with every claim badged. Nothing leaves the machine.

**Key capabilities**

| | |
|---|---|
| **Deterministic verification** | Every relationship is proven by exact identifier join, not inferred. Same input, same answer, every time. |
| **Unforgeable badges** | VERIFIED requires an immutable proof record. Enforced in code *and* by database trigger. Stamped claims are immutable. |
| **Honest uncertainty** | APORIA is a first-class outcome and is never hidden from the analyst. |
| **Runs air-gapped** | Local model, local database, loopback-only dashboard. No telemetry leaves the host. |

**User journey**

- **Input** — Windows Sysmon event log (untrusted third-party data)
- **Processing** — Code enumerates every candidate link, proves or refuses each, ranks by suspicion; the model selects the attack-relevant subset from the *proven* set only
- **Output** — Badged incident view on a local read-only dashboard, plus Markdown/HTML reports
- **Outcome** — An investigation an analyst can defend line by line, because every line states whether it was proven

---

## Slide 7 — Solution Architecture

**Diagram:** use `docs/diagrams/ares-hld.svg` (architecture) and `docs/diagrams/ares-dataflow.svg` (data flow) — both already sized for a full slide. Put the HLD on this slide; the data-flow diagram belongs in the appendix or as a second architecture slide if you have room.

**Recommended-layers mapping** (fill the template's six boxes)

| Template layer | ARES |
|---|---|
| Front-End / UI | Read-only dashboard, Python stdlib `http.server`, bound to 127.0.0.1 only; hardened Jinja templates |
| APIs & Services | Local CLI pipeline (`run_incident`); no network service surface beyond loopback |
| AI Models / Agents | Local LLM via Ollama (selection only, advisory, never authoritative) |
| Data & Storage | SQLite — proven facts, badges, and immutable verifier-execution records |
| Cloud / GreenLake | **Deliberately none at runtime.** Cloud model is a test-harness arm, off by default, never in a demo. `[[If the track expects a GreenLake story, frame it as: the same binary runs unchanged on a GreenLake private-cloud host — the point is that it *needs* nothing external.]]` |
| Integrations | Hayabusa (Sysmon/EVTX timeline), MITRE ATT&CK technique mapping |

**Data flow**
User → Log ingest → Deterministic enumeration & verification (badge locked here) → Suspicion ranking → Model selection → Badged dashboard & reports → Analyst action

**One line to say aloud at this slide:**
"The model sits *downstream* of verification, not upstream of it. It never touches a raw event, and it can never write a badge."

---

## Slide 8 — Technology Stack

| Layer | Choice |
|---|---|
| UI | Python stdlib `http.server` + hardened Jinja2 templates |
| Backend | Python 3, `uv` toolchain |
| Database | SQLite (with enforcement triggers) |
| AI / ML | Ollama — `qwen2.5:7b-instruct` local selector; `nomic-embed-text` embeddings; frontier model as a *test* arm only |
| Cloud | None required at runtime — full function offline / air-gapped |
| Automation | Hayabusa 3.10.0 timeline engine; scripted dataset fetch with pinned digests |
| Security | CSP `default-src 'none'`; autoescaping forced on including strings, with `\|safe`, `Markup` and `escape_silent` **removed from the environment** so a template that reaches for them fails to render; URL-scheme allowlist; `StrictUndefined`; loopback bind with Host-header validation; non-GET rejected; SQLite immutability triggers; digest-pinned toolchain downloads; gitleaks-clean history |

**Why these technologies**

- **Fit** — SQLite gives us *enforcement*, not just storage: the badge firewall is a trigger, so it holds even against our own future code.
- **Security & compliance** — no runtime cloud dependency means security telemetry never leaves the estate. Everything ARES renders is untrusted (model output, attacker-influenced log fields), so escaping is enforced by removing the escape hatches rather than by convention.
- **Scalability & performance** — the expensive path is deterministic and linear in events; the model sees a ranked shortlist, not the log. Cost scales with the shortlist, which we control.
- **Speed of delivery** — stdlib-first, no framework, no service mesh. The whole surface is small enough to be reviewed, which is the point of a security tool.
- **Reuse** — Hayabusa and MITRE ATT&CK are established open standards, not bespoke parsing.

---

## Slide 9 — Prototype / Demo

**Screenshots to capture**
1. Dashboard index — badge counts and the incident list (`scripts/serve_dashboard.py`, http://127.0.0.1:8420/)
2. Claim detail view — one claim showing its badge and the verifier execution that proves it, with an APORIA claim visible in the same view

**Demonstration scenario**

1. **User action** — Analyst points ARES at a day of Sysmon telemetry from a compromised workstation and runs one command.
2. **System response** — Tools enumerate 794 candidate relationships and prove or refuse every one; the local model selects the attack-relevant subset from the proven set; the dashboard comes up on loopback with every claim badged.
3. **Final outcome** — The analyst reads an attack chain where each link states whether it was proven, refuted, or honestly unknown — and can open the proof behind any VERIFIED badge.

**The moment to engineer into the live demo:** show an APORIA claim on screen and say *"a normal assistant would have written this as a fact."*

---

## Slide 10 — Outcomes & Business Impact

**Quantitative benefits** — the template's Current/Expected framing, using measured figures

| Metric | Current | Expected |
|---|---|---|
| Evidence recovery from a machine-day of logs | 3 of 794 relationships (naive LLM approach) | **794 of 794 enumerated and adjudicated; 66.7% of the true attack chain selected** |
| Analyst reading load | 196,081 raw events | A ranked shortlist of proven relationships |
| Unverified claims entering the incident record | Unbounded — no provenance marking exists | **Structurally zero** — a claim cannot be badged VERIFIED without an immutable proof record |
| Verification precision | Not measurable | **100% across 12 runs** (adjudicated set) |
| Telemetry leaving the estate | Whatever the hosted assistant is sent | **Zero** — no runtime network dependency |

**Honesty line, and keep it in — it is a strength, not a weakness:**
Precision is 100% on the **33 relationships the answer key adjudicates**; the key has nothing to say about the other 761 badges (4.2% adjudication coverage). We report the coverage next to the precision because a metric quoted without its denominator is exactly the failure mode this project exists to eliminate.

**Strategic alignment** (tick these on the template)
- AI-Driven Future — AI applied where judgement is needed, verification where proof is needed
- Operational Excellence — deterministic, reproducible, auditable investigations
- Customer Outcomes — findings that survive a customer's post-incident review
- Innovation at Scale — the badge firewall is a general pattern, reusable by any AI system that must not assert falsehoods

**Headline outcome — the single number for the judges:**
> **3 → 794.** Same log, same model. The architecture, not the model, is what recovered the evidence.

*(Alternative if you prefer a trust number over a capability number: **"Zero forged badges in twelve runs — enforced by the database, not by good intentions."**)*

---

## Slide 11 — Roadmap & Call to Action

**Phase 1 — Proof of Concept — complete (hackathon window)**
Two relationship types shipped and adversarially tested; two real APT29 attack days scored end-to-end on both a local and a frontier selector; dashboard, reports, HLD/LLD, security review and single-command install all delivered.

**Phase 2 — Pilot — `[[timeframe]]`**
Widen the relationship catalogue beyond the two shipped predicates, and rebuild the prioritiser — **our most actionable finding is that ranking, not the model, is the bottleneck** (a ranking change alone moved a score from 16.7% to 55.6% with no model or code change). Run against live SOC telemetry with analysts in the loop.

**Phase 3 — Production Rollout — `[[timeframe]]`**
Additional log sources beyond Sysmon, analyst feedback captured as evaluation data, and the badge firewall extracted as a reusable component for other AI-assisted workflows with an evidentiary burden.

**Support needed**
- **SMEs** — SOC analysts to define which relationship types actually earn their keep
- **Test Environment** — access to representative (or safely synthetic) enterprise telemetry
- **Infrastructure** — a host with a local GPU for the on-prem model
- Cloud resources: *not required* — say this out loud, it is differentiating

**Closing statement**
> "ARES transforms AI-assisted security operations by making verification structural rather than aspirational — the model can be wrong about what matters, but it cannot make the tool assert something false."

---

## Slide 12 — Appendix / judging criteria

No copy needed. But map your emphasis to the weighting when you rehearse:

| Criterion | Weight | Your strongest material |
|---|---|---|
| Problem Relevance | 20% | Slide 4 — 196,081 events, and the 3-of-794 baseline |
| Innovation | 20% | Slide 5 — the inversion, the badge firewall, APORIA |
| Technical Design | 20% | Slide 7 + the security row on slide 8 |
| Business Impact | 20% | Slide 10 — including the honest 4.2% coverage caveat |
| Feasibility | 15% | It is **built and measured on real APT29 data**, not proposed |
| Demo Quality | 5% | Slide 9 — the APORIA moment |

**Extra appendix slides worth adding if allowed:**
- The batch-size table (§6.4): 25 → 51.5%, 75 → 33.3%, 100 → 27.3%, 300 → 0%. *"More context did not help"* is a genuinely counter-intuitive result and judges remember it.
- The eight adversarial defects (§6.7), including `True == 1` in Python passing a check for event type 1. Concrete, memorable, and proves the rigour is real.

---

## Cross-deck consistency notes

1. **Do not say "the model's picks are never stored."** Selections *are* persisted (`model_selections` table). The correct framing everywhere: **selections are stored apart from proven facts and can never carry a badge.** Both diagrams have been corrected; `HLD_LLD.md`, `design-spec.html` and `PAPER.md` never carried the wrong wording.
2. **Never quote precision without coverage.** Always the pair: 100% on adjudicated / 4.2% adjudication coverage.
3. **Always quote the 78% structural ceiling** alongside the 66.7% and 55.6% recall figures — two of four relationship types were cut, so 100% was never reachable, and saying so first is stronger than being asked.
4. **The cloud model is a test instrument, not a component.** If a slide implies ARES calls out to a hosted model at runtime, that slide is wrong.
