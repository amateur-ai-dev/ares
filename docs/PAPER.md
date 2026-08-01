# ARES: Making a Language Model Prove What It Claims

**A feasibility study in verified incident analysis**

Nithin Gowda · August 2026 · *Draft — day-2 results pending*

---

## Abstract

Language models are fluent about security incidents and frequently wrong about
them. The confident-and-wrong failure is worse than an obvious one, because a
plausible answer gets acted on. ARES tests one response to that: let the model
propose whatever it likes, then let deterministic code check every claim against
the raw logs. A claim survives only if a mechanical check proves it. Everything
else is labelled unproven rather than quietly dropped.

This paper reports what happened when that idea was built and run against real
attack data on a laptop. The headline finding is not the accuracy score. It is
that **the verification layer held under the worst conditions we could give it**:
faced with a proposer producing near-garbage, it rejected 167 of 172 claims and
stamped nothing false. The models we could run locally, meanwhile, largely failed
to find the real causal links at all — a separate and equally useful result.

---

## 1. The problem, in one example

Early in the project we asked a security-tuned 8-billion-parameter model a simple
question. A Word process starts `rundll32.exe`, which then opens a handle to
`lsass.exe` — the Windows process that holds credentials in memory.

The model answered: **"DLL Side-loading."**

Confident. Well-written. Wrong. The actual techniques are credential dumping
(T1003.001) with a `rundll32` proxy execution (T1218.011). It also produced no
ATT&CK identifier at all.

Nothing about the answer signalled its own unreliability. An analyst under time
pressure would have had no way to tell that response from a correct one. That is
the failure mode this project exists to address — not that models are wrong
sometimes, but that **being wrong looks exactly like being right**.

## 2. The idea

> **The model proposes. Deterministic tools dispose.**

ARES never treats a model's output as a conclusion. Each claim gets routed to a
small program that checks it against the actual log records. Three outcomes:

- **Verified** — a mechanical check confirmed it against the logs.
- **Refuted** — the logs contradict it.
- **Aporia** — the evidence needed to decide simply is not present.

The third one carries most of the honesty. Real logs are incomplete. A system
that hides what it could not prove is more dangerous than one that says so
plainly, because silence reads as absence of a problem.

Crucially, "verified" is not a matter of confidence, phrasing, or model
agreement. It means a specific comparison between specific fields in specific log
records returned true.

## 3. What gets checked

Four relationship types were specified; two were built (§7 explains the cut).

| Relation | What it proves | What it does **not** prove |
|---|---|---|
| `SPAWNED` | Process A started process B | That A intended B's behaviour |
| `PROCESS_OPENED_CONNECTION` | This process opened this network connection | That the connection was malicious |
| `WROTE_PATH_BEFORE_EXECUTION` | A wrote the file B later ran | *(specified, not built)* |
| `SAME_SESSION` | Two events share a logon session | *(specified, not built)* |

The right-hand column is deliberate. Each check states its own limits, so a
verified badge cannot be quietly read as more than it is.

**Multi-step stories are never verified.** "Phishing email → macro → credential
dump" chains several relations into one narrative. Proving each link does not
prove the chain. With no rule defined for composing links, every such story is
recorded as an Aporia by construction — no matter how many individual steps
checked out.

## 4. The firewall

A stamp reading "VERIFIED" is worth exactly as much as the guarantee behind it.
So the central engineering problem was making that stamp unforgeable.

Two independent barriers:

1. A single function is the only sanctioned way to apply a badge.
2. **The database itself refuses** to store a verified badge unless a matching
   proof record exists — same incident, same relation type, the same two events
   in the same order, and a successful result.

The second barrier exists because the first is not enough. Function-only
enforcement is bypassed by any code that writes SQL directly — including
well-meaning code written later by someone who never read the rule.

**We attacked it.** Eight bypass attempts, all blocked by the database:

| Attempt | Result |
|---|---|
| Write a badge with no proof at all | blocked |
| Cite real proof belonging to a *different* claim | blocked |
| Cite real proof under a *different* relation type | blocked |
| Same events, different incident | blocked |
| Same proof, the two events **reversed** | blocked |
| Stamp an unbadged claim by direct SQL | blocked |
| Alter the proof to fit a forged claim | blocked |
| Delete the proof a badge depends on | blocked |

**One genuine leak was found this way.** A claim that was *already* badged could
afterwards have its text and its hostnames rewritten while keeping the stamp.
Since every check is scoped to a single machine, swapping the hostnames made the
badge describe something nobody had verified. Fixed by freezing a claim once it
carries a badge.

That leak had survived a phase gate and two prior reviews. It was found by
attacking the system rather than reading it.

## 5. Grading it honestly

To measure whether ARES finds the real story, you need to already know the real
story. So before any analysis code was written, we hand-built an **answer key**
for two real attacks: every genuine causal link, plus deliberate traps, plus
links that genuinely happened but left no usable trace.

Three decisions make the grading defensible:

**Written before the code.** Both answer keys were finished before a single line
of the analysis pipeline existed. Otherwise the key drifts toward whatever the
code happens to do.

**One attack is practice, one is the exam.** The first is for iteration. The
second is scored **once**, with no tuning afterward, whatever the number.

**The key was audited.** It was drafted by an independent model working from
MITRE's published attack script, then spot-checked by the project owner: twenty
randomly selected links, rendered so each check was a simple value comparison
requiring no security expertise. **Twenty of twenty confirmed.**

That audit found a real defect — in the audit tool, not the key. It was showing
the wrong field for one relation type, asking the reader to compare a DLL path
against the process that loaded it. Two values that should never match. The check
that caught it was one non-expert comparing two strings.

## 6. What actually happened

### 6.1 A reasoning model that could not answer

The intended local model was a security-tuned 8B **reasoning** variant. It proved
unusable for this task, for an unexpected reason: it narrates. Given thirty
events, it works through them one at a time in prose and never reaches its
answer. Measured: the entire token budget consumed by internal reasoning, and an
**empty answer field**. Instructing it not to reason made no difference.

The arithmetic ruled it out — roughly eight minutes per batch, against forty-plus
batches per incident. Five hours for a single run.

The fix was to constrain output to a rigid structure, forcing the first token to
be part of the answer rather than a preamble. That plus a smaller general-purpose
model brought a batch from over ten minutes to sixty-six seconds.

**This is a finding, not a footnote.** Reasoning-tuned models are a poor fit for
high-volume structured extraction on constrained hardware — and you only discover
it by running one.

### 6.2 The main result

A 3-billion-parameter general-purpose model, run over the practice attack:

| | |
|---|---|
| Links proposed | 172 |
| Refuted by the logs | 34 |
| Unprovable → Aporia | 133 |
| **Stamped verified** | **5** |
| **Falsely stamped** | **0** |
| Real attack links found | **0 of 33** |

Read those two columns separately, because they say different things.

**The model failed.** It found none of the 33 real attack links. Not one — we
checked for reversed direction and mislabelled relations too. It was not close.

**The tool worked.** Of 172 proposals from a model producing essentially noise,
**167 were caught**. The five that survived were genuine process relationships —
real, just ordinary background activity rather than part of the attack. **Nothing
false was stamped verified.**

A bare language model would have returned 172 confident-sounding claims. ARES
returned five proven ones and an explicit list of what it could not establish.

That is the thesis, tested under the most hostile condition available: a proposer
generating near-garbage. The verification layer did not degrade gracefully — it
simply refused.

### 6.3 Adversarial tests found what reviews missed

The relationship checks were tested twice: once by the model that wrote them, and
once by an independent model **forbidden from seeing the existing tests**.

The blind suite found **eight ways to produce a false verification** in code that
had already passed a phase gate, a correctness review, and an adversarial review:

- A record claiming to be its own parent
- Two records each claiming the other as parent
- Longer loops — A→B→C→A
- Two records sharing an identity, so the true parent is ambiguous
- Whitespace accepted as a valid identifier
- Type confusion between text and numbers
- **A boolean accepted as the event type** — in Python, `True == 1`, so `True`
  passed a check for event type 1

None of these appear in clean data. All of them produce a false "verified" from
malformed input, which is the one outcome the design cannot tolerate.

The lesson generalises: **tests written by the author of the code inherit the
author's blind spots.** The independent suite cost minutes and found eight real
defects.

## 7. What was cut, and why

Under a fixed deadline, two of four relation types were dropped. The reason was
arithmetic, not preference.

The exam attack contains 23 verifiable links. `SPAWNED` alone covers 11 — **48%**,
below the project's own 50–60% pass mark *before the system makes a single
mistake*. That is a rigged test: no implementation, however perfect, could pass.
Adding the second relation raises the reachable maximum to **78%**, making the
target meaningful again.

The two cut relations are the most expensive to build and cover only 5 of 23
links. **Those 5 are permanently out of reach for this build**, and that ceiling
is quoted alongside every score rather than folded silently into it.

## 8. Limitations

Stated plainly, because a feasibility study that hides its caveats is marketing.

1. **Not a blind evaluation.** Whoever wrote the exam's answer key had to read its
   logs. A production evaluation needs a sealed key the builder cannot see.
2. **The key is AI-drafted, human-audited** — 20 of 20 spot-checked, but that is a
   sample, not a proof.
3. **78% ceiling**, so no score here is comparable to one from a complete system.
4. **Not the intended model.** The named security-tuned model could not run this
   workload; results come from general-purpose substitutes.
5. **Verified-precision is near-trivial for these two relations.** They are
   mechanical joins, so on well-formed logs they are correct by construction. The
   figure is a *floor* — any dip means a defect — not an achievement. The real
   test of precision is the adversarial fixture suite in §6.3.
6. **The logs themselves cap performance.** Only 37% of network events can be tied
   back to a process start; 27% of processes have no recorded parent. Unprovable
   links become Aporias by design — that is the system working, not failing.

## 9. What this establishes

**The verification layer is sound and worth building.** It survived direct attack
on its integrity boundary, caught a real leak, and refused 97% of a bad model's
output without stamping anything false.

**Small local models were the binding constraint, not the architecture.** The 3B
model found nothing. Whether a stronger local model closes that gap is the
question the remaining runs answer — and because verification is deterministic,
swapping the model changes what gets *proposed* but cannot change what gets
*proven*. That property is what makes the comparison meaningful.

**The honest negative result has value.** A tool that says "I could not prove
this" 133 times is more useful to an analyst than one that produces 172 confident
assertions, because the first can be trusted where it does speak.

---

*Draft. Exam-attack results and the frontier-model comparison are pending and
will be reported as measured, including if they are unflattering.*
