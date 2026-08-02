# 0001 — The five metrics have different subjects

**Date:** 2026-08-02
**Lesson:** [0001 Reading the scoreboard](../lessons/0001-reading-the-scoreboard.html)
**Status:** taught, not yet confirmed retained

## The insight

The five figures are not five views of one "accuracy". They split by subject:

- **Verification precision** → the *tools*. Deterministic, so 100% is a floor.
- **Selection recall** → the *model*. The real result.
- **Verified-edge recall** → *end to end*, and an integrity check on the pair.
- **Selections made** → *analyst workload*.
- **Malformed discarded** → *deployability*, not intelligence.

Conflating tool-precision with model-recall is the single most likely way to
misspeak in front of a judge — in either direction.

## Why it is non-obvious

The scoreboard prints them adjacently with identical formatting, which invites
reading them as one scale. The tool's own output is what creates the confusion.

## Consequence for the paper

The claim to lead with is *decoupling*: local selection is markedly worse
(51.5% vs 66.7%) and zero bad selections became a VERIFIED badge. That is the
architecture working, and it is a stronger story than any single number.

## Open question for next session

Does the user want to defend the **hit-rate gap** (34% vs 81%) or downplay it?
It is the most attackable number in the set — worse than the recall gap from an
analyst's point of view, and not currently addressed in the paper.

## Revisit if

Selection recall and verified-edge recall ever diverge in a real run. That would
make record 0001's "equal so far" framing stale and signal a verifier bug.
