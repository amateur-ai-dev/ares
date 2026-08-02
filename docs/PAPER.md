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
second was to be scored **once**, with no tuning afterward, whatever the number.

**That promise was not kept, and the paper says so rather than quietly dropping
it.** The exam attack's first score (16.7%) was investigated, found to be capped
by a configuration limit rather than by the system's ability (§6.5), and re-scored
at a wider setting. Investigating it required inspecting where the exam's true
links ranked. **The exam is therefore no longer a blind test, and its 55.6% should
be read as a tuned result, not a held-out one.** The honest position is that this
study now has *no* untouched evaluation set, and a further attack would be needed
to recover one.

**The key was audited.** It was drafted by an independent model working from
MITRE's published attack script, then spot-checked by the project owner: twenty
randomly selected links, rendered so each check was a simple value comparison
requiring no security expertise. **Twenty of twenty confirmed.**

That audit found a real defect — in the audit tool, not the key. It was showing
the wrong field for one relation type, asking the reader to compare a DLL path
against the process that loaded it. Two values that should never match. The check
that caught it was one non-expert comparing two strings.

## 6. What actually happened

### 6.1 The pipeline had the work backwards

The first build asked the model to *discover* links by spotting matching
identifiers across thousands of raw events. That is exact string comparison — the
task a language model is worst at and ordinary code is perfect at. Measured on the
practice attack: **794 links were derivable deterministically; the model found 3.**

The fix inverted the division of labour. **Tools enumerate every candidate link
and prove or refuse each one. The model only decides which proven links are the
attack.** Selection is judgement, and judgement is what a model is for.

That single change took selection recall from 0% to 66.7% on the same data, and
collapsed 25 model calls into one. It is the most important change in the project.

### 6.2 A reasoning model that could not answer

The intended local model was a security-tuned 8B **reasoning** variant. It proved
unusable, for an unexpected reason: it narrates. Given a batch of links it works
through them one at a time in prose and never reaches its answer. Measured on a
20-link batch: a correct, well-argued selection — preceded by **6,204 characters
of internal reasoning** and cut off before the answer was complete. At 300 links
the answer field never begins.

**This is a deployability failure, not a capability failure.** The model knows the
answer. It cannot deliver it inside a token budget. That distinction matters,
because the two problems have completely different fixes.

### 6.3 The main result: the tool works

Using a frontier model as the selector — testing the *harness*, not local
inference — across both attacks:

| | Practice attack | Exam attack |
|---|---|---|
| Links enumerated by tools | 794 | 1,704 |
| Links shown to the model | 300 | 1,500 |
| Real attack links found | **22 of 33** | **10 of 18** |
| **Selection recall** | **66.7%** | **55.6%** |
| **Verification precision** | **100%** | **100%** |
| **Falsely stamped verified** | **0** | **0** |
| Links proposed | 27 | 29 |

**Both attacks clear the 50–60% target, against a 78% structural ceiling.** The
architecture is not the constraint.

### 6.4 A small local model works — but only in small pieces

A general-purpose 7B model, run over the practice attack, with the links split
into batches:

| Links per call | Selection recall | Links proposed |
|---|---|---|
| **25** | **51.5%** (17 of 33) | 50 |
| 75 | 33.3% (11 of 33) | 51 |
| 100 | 27.3% (9 of 33) | 28 |
| 300 | **0%** | 0 |

At 300 links in one call the model returns a **well-formed, empty answer**. Not a
crash, not truncation — it reads the task and declines. Split into batches of 25,
the same model on the same data clears the target band.

**More context did not help.** Recall falls monotonically as the batch grows. The
constraint is not the size of the context window — the 300-link prompt fitted
comfortably inside it — but how much a small model will engage with at once.

The cost is noise. The local model proposed 50 links to find 17 (a 34% hit rate);
the frontier model proposed 27 to find 22 (81%). Nearly twice the reading for
two-thirds the coverage. Recall alone hides that, and an analyst would feel it
immediately.

### 6.5 The real bottleneck was ranking, not the model

The exam attack was first scored at 16.7% and looked like a collapse. It was not.

All 18 findable links **were** enumerated by the tools. Only **6 of them ranked
inside the top 300** that the model was shown. Their ranks: 7, 8, 52, 54, 82, 165
— then 351, 398, 400, 401, 404, 408, 441, 578, 680, 681, 1391, 1409.

**The reachable maximum was 33.3%, not 100%.** Both arms were being graded against
an impossible denominator. Widening the window to 1,500 links moved the frontier
arm from 16.7% to **55.6%** with no change to the model, the prompt, or a line of
analysis code.

**The component that decides what the model *sees* mattered more than the model.**
That is the most actionable finding in this study, and it was invisible until a
result that looked like model failure was investigated instead of reported.

Widening the window is not free: the frontier model's hit rate fell from 81% to
34% as the shortlist grew from 300 to 1,500 candidates. Recall is bought with the
analyst's attention.

### 6.6 What verification precision does and does not show

**100%, in all twelve runs performed** — two model arms, four batch sizes, two
window sizes, including runs that failed at everything else.

This is a *floor, not an achievement*. The two relations are deterministic joins
on identifiers, so on well-formed logs they are correct by construction. Any dip
would mean a defect. It is reported because a dip would be the alarm, not because
100% is impressive.

The meaningful claim is what it is paired with: **selection quality varied
enormously across runs — 0% to 66.7% — and not one bad selection ever became a
verified claim.** Model judgement and verified fact stayed decoupled under every
condition tested, including a model producing pure noise. That is the thesis.

### 6.7 Adversarial tests found what reviews missed

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

None of these appear in clean data. All produce a false "verified" from malformed
input — the one outcome the design cannot tolerate.

A separate attack on the integrity boundary found a real leak: a claim's text
could be rewritten *after* it had been stamped verified. Closed with a database
trigger making stamped claims immutable.

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
4. **Not the intended model.** The named security-tuned model could not deliver a
   parseable answer within its token budget (§6.2); local results come from a
   general-purpose 7B substitute.
7. **The local arm is proven on one attack only.** The exam attack was never
   scored locally — the run was abandoned after 4 hours 45 minutes at 72%
   complete. Every local number in this paper comes from the practice attack.
8. **The local batch size was chosen and scored on the same attack.** Batches of
   25 were selected because they performed best on the practice attack, and the
   51.5% is that attack's score. That is circular, and the exam run that would
   have broken the circularity is the one that was not completed.
9. **No untouched evaluation set remains** (§5).
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

**The architecture was never the constraint.** With a capable selector the harness
clears its target on both attacks — 66.7% and 55.6% against a 78% ceiling.

**A small local model is viable, in small pieces.** A 7B running entirely on a
laptop reached 51.5% when the work was handed to it 25 links at a time, and 0%
when handed 300 at once. The gap between local and frontier (51.5% vs 66.7%) is
real and should not be talked away — but it is a gap in *judgement quality*, and
because verification is deterministic, swapping the model changes what gets
*proposed* and cannot change what gets *proven*. That property is what makes the
comparison meaningful, and it is why a weaker model degrades the output's
usefulness without ever degrading its trustworthiness.

**What decides what the model sees matters more than which model it is.** A
ranking change moved one arm 16.7% → 55.6%; no model swap in this study moved any
number that far.

**The honest negative result has value.** A tool that says "I could not prove
this" 133 times is more useful to an analyst than one that produces 172 confident
assertions, because the first can be trusted where it does speak.

---

*Draft, 2026-08-02. Both attacks are now scored on the frontier arm and the
practice attack on the local arm; the exam attack was never completed locally and
is reported as missing rather than estimated.*
