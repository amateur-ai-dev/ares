# Resources

Trust ranking: primary source (the code that produced the number) > published
method > my explanation.

## Primary — inside this repo

| Resource | What it grounds | Trust |
|---|---|---|
| `src/ares/scoring.py` → `score_claims` | Every metric definition. Comments record why unlisted badges are not counted false. | Highest — it *is* the number |
| `src/ares/store.py` → badge firewall + triggers | Why a VERIFIED badge cannot be forged | Highest |
| `scripts/run_incident.py` (print block) | The exact wording of the scoreboard | Highest |
| `eval/ground_truth/apt29-day1.edges.yaml` | The 36/33 denominator, negative confounder pairs | Highest — owner-audited 20/20 |
| `docs/MASTER_PLAN.md` §metrics | Why the 50–60% band and 78% ceiling were set | High |

## External — for the paper's framing

| Resource | Use | Status |
|---|---|---|
| MITRE ATT&CK Evaluations, APT29 emulation | Provenance of day 1 / day 2 | Cited in `ATTACK_SCRIPT.md` |
| OTRF Security Datasets | The corpus itself, pinned at commit `d9d40ef` | In `datasets.lock` |
| Sysmon event schema docs (EID 1/3/7/11) | Field semantics behind each predicate | Needed for §3 of paper |

**Gap to fill:** no external citation yet for *precision/recall on graph edge
extraction* as a task. The paper will be stronger with one — worth a search
before submission so the metric choice reads as standard practice rather than
invented for this project.

## Communities — for wisdom, not knowledge

Untested, listed as candidates only:

- **r/blueteamsec**, **r/AskNetsec** — will tell you fast whether "the model
  proposes, tools dispose" reads as obvious or novel to practitioners.
- **DFIR Discord / Sysmon community** — the people who will know immediately
  whether a 78% ceiling on Sysmon-only causality matches their experience.

That ceiling claim is the one most worth testing on real practitioners before a
judge tests it for you.
