# ARES — Frequently Asked Questions

Last updated 2026-08-02. Every number here is measured. Where something is not
measured, it says so.

---

## What is ARES?

A locally-hosted assistant for investigating security incidents. You give it
Windows event logs from a compromised machine; it reconstructs what happened —
which process started which, which one opened a network connection — and shows
you the chain.

Everything runs on your own laptop. No cloud, no account, no data leaving the
machine.

## What makes it different from just asking ChatGPT about my logs?

A language model asked to analyse logs will produce confident, fluent claims.
Some will be true. Some will be invented. You cannot tell which from the output,
and checking them by hand costs more than doing the analysis yourself.

ARES splits the work in two:

- **Deterministic code** finds and proves every causal link. This is ordinary
  string and identifier matching — no model involved, same answer every time.
- **The model** only decides which proven links are *interesting*.

The model can be wrong about what matters. It cannot make the tool assert
something false, because it is never the thing doing the asserting.

## What do the badges mean?

Every claim carries one of three:

- **VERIFIED** — deterministic code checked this and it holds.
- **REFUTED** — checked, and the evidence contradicts it.
- **APORIA** — cannot be determined from the available evidence.

Aporia is the important one. It is the tool saying *"I don't know"* instead of
guessing. Most of the value is here: an analyst can trust a tool that admits its
limits, and cannot trust one that never does.

## How accurate is it?

Measured on two real published attacks (MITRE's APT29 evaluation logs):

| | Attack 1 | Attack 2 |
|---|---|---|
| Real attack links found | 22 of 33 | 10 of 18 |
| **Found** | **66.7%** | **55.6%** |
| Wrong among the links the key could rule on | 0 of 33 | 0 of 18 |

Both clear the 50–60% target set before any code was written, against a
structural ceiling of 78% (see below).

**A necessary correction to how we first reported this.** The "100%" is precision
over the badges the answer key *adjudicates* — 33 of them on attack 1. The system
issued **794** badges in that run; the remaining **761 were never adjudicated**,
because the key describes the attack, not every ordinary process relationship in
the log.

Stated correctly:

- **Precision on adjudicated edges: 33/33 (100%)**
- **Adjudication coverage: 4.2% of badges issued**

We previously wrote "not one false verified badge" without that qualifier. That
claim went further than the evidence and has been withdrawn. What holds is that
no badge the key could rule on was wrong, and that the adversarial fixture suite
— not this number — is what tests the verification logic properly.

## Why can't it find 100% of the attack?

Two reasons, both honest limits rather than bugs:

1. **The logs don't record enough.** Only 37% of network events can be tied back
   to the process that started them; 27% of processes have no recorded parent.
   Those links are physically unprovable from the evidence — they become Aporias
   by design. This puts a hard ceiling of **78%** on what any system could find.
2. **Two of four planned relation types were cut** for time. Those cover 5 links
   we can never reach in this build.

## Does it use a local model or a cloud model?

Both were tested, deliberately, to answer two different questions.

- **Local model** (a 7B running entirely on the laptop) answers *"can this run
  privately on modest hardware?"* — measured at **51.5%** on attack 1.
- **Frontier model** (via a cloud API) answers *"is the tool design itself
  sound?"* — measured at 66.7% and 55.6%.

The product is the local one. The cloud arm is a diagnostic and is never used in
the demo.

## Has the local model been tested on both attacks?

**No — only on attack 1.** The second local run was abandoned after 4 hours 45
minutes at 72% complete. This is stated everywhere the local number appears,
because one scored incident is one scored incident.

## Is a bigger local model going to do better?

Probably — but that is an **extrapolation, not a measurement**, and it is
labelled as such wherever it appears.

What is actually measured:

- A 7B clears the target band when work is fed to it in small batches.
- The same model returns a **well-formed empty answer** when given 300 links at
  once. It declines rather than fails.
- A security-tuned 8B *reasoning* model knows the answers but cannot deliver
  them — it spends its whole token budget narrating and gets cut off mid-answer.

Those are failure modes of *packaging*, not of understanding. That is the honest
basis for expecting better hardware and a larger security-tuned model to do
better. It is not proof.

## What's this "demo data" versus "evaluation data"?

Two completely separate things, deliberately kept apart:

- **Demo data** — a small synthetic incident, authored by us, designed to run in
  a couple of minutes and be legible on a screen. **It is curated. Any number it
  produces is a demonstration of the interface, not evidence about accuracy.**
- **Evaluation data** — MITRE's published APT29 logs. Every accuracy figure in
  this FAQ, the paper and the dashboard comes from these.

They live in separate directories and separate databases, the running mode is
recorded against every run, and scoring one against the other's answer key is a
hard error rather than a warning. We built the separation into the code because
"we were careful" is not a control.

## Is any of this production-ready?

No, and it is not presented as one. It is a feasibility study.

Not built: authentication, access control, multi-user support, log ingestion at
scale, alerting, anything resembling an audit trail for regulated use.

## Does any of my data leave my machine?

Not in normal use. The local model runs on your hardware.

The one exception is the **frontier diagnostic arm**, which sends log excerpts to
a cloud API. It is opt-in, never part of the demo, and exists only to answer a
research question about the tool's design.

## Is the tool itself secure?

The threat model is written down in `SECURITY.md` — every surface enumerated,
each mitigation marked implemented, planned, or deferred with a reason.

Highlights of what it covers: parsing untrusted third-party log files, binding a
local web server, and executing security scanners over user-supplied code.

On that last point, stated carefully: **ARES itself does not execute code you
give it — it reads and pattern-matches.** But the scanners it invokes are real
programs parsing hostile input, and a dependency scanner may resolve package
manifests. "Never executed" is a claim about our code, not a sandbox guarantee
about the whole toolchain, and `SECURITY.md` draws that line explicitly rather
than letting the simpler sentence stand.

What it is *not*: a professional security audit or penetration test. That is not
achievable solo on this timeline, and the document says so rather than implying
otherwise.

## Why should I trust your accuracy numbers?

You partly shouldn't, and the limitations section of the paper says exactly why.
The honest position:

- The answer keys were written **before** the analysis code existed, so they
  couldn't drift toward whatever the code happened to do.
- They were drafted by an independent model from MITRE's published attack script,
  then spot-audited by hand: **20 of 20 confirmed**.
- **But**: there is no longer a held-out test set. The second attack was meant to
  be scored once and never tuned against. That promise was broken when a poor
  result was investigated and re-run at a wider setting. The 55.6% is therefore a
  *tuned* number, and the paper marks it as such.

Publishing that last point costs us something. Not publishing it would cost more.

## What was the most surprising finding?

That the component deciding **what the model sees** mattered more than which
model was used.

One attack initially scored 16.7% and looked like model failure. Investigation
showed that of its 18 findable links, only 6 were being shown to the model at
all — the rest ranked too low to make the shortlist. The reachable maximum was
33.3%, not 100%.

Widening that shortlist moved the score to **55.6%** with no change to the model,
the prompt, or a line of analysis code. No model swap in the entire study moved
any number that far.

## Who built this and why?

A solo build, under a hackathon deadline, to test one specific idea: that you can
get the usefulness of a language model in security work without inheriting its
tendency to invent things — by never letting it be the thing that asserts.

The result: model judgement varied from 0% to 66.7% across runs. Not one bad
judgement ever became a verified claim.
