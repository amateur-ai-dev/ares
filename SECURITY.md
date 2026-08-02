# Security

This document covers **what ARES actually ships**, not what it plans to. Where a
surface is designed but not built, it says so. Where a mitigation is weaker than
it sounds, it says that too.

**What this is not:** a professional security audit or a penetration test. ARES
is a solo-built feasibility study produced under a deadline. It has had one
adversarial review pass (see [Review history](#review-history)) and no external
testing. Treat it accordingly.

Last updated 2026-08-02.

---

## Threat model in one line

ARES parses **hostile input by design** — third-party Windows event logs from
compromised machines — renders **model-generated text** to a browser, executes a
**downloaded third-party binary**, and (in planned scope) runs static analysis
over **user-supplied source code**. Every one of those is an attacker-influenced
data path.

---

## Status table

| # | Surface | Status | Severity if wrong |
|---|---|---|---|
| A | Install: third-party binary download | **Implemented + tested** | Critical — RCE |
| B | Install: source checkout pinning | **Not implemented** | High |
| C | Untrusted log parsing | **Partially implemented** | Medium |
| D | HTML rendering of untrusted text | **Implemented + tested** | High — stored XSS |
| E | URL/attribute context | **Implemented + tested** | High |
| F | Demo/evaluation result separation | **Implemented + tested** | Integrity, not safety |
| G | Web server binding and Host validation | **In progress** (dashboard being built) | High |
| H | SQL injection | **Implemented by construction** | High |
| I | Secrets in repository | **Implemented + scanned clean** | Medium |
| J | SAST over user-supplied code | **Not built** | Critical if built carelessly |
| K | Archive/upload handling | **Not built** | High |
| L | Excel export formula injection | **Not built** (Excel export cut) | Medium |

---

## A. Install: third-party binary download — implemented

`scripts/setup_toolchain.sh` downloads a Hayabusa release archive, extracts it,
and **executes the resulting binary**. Until 2026-08-02 it did so with no
integrity check at all. A compromised release asset or GitHub account would have
been arbitrary code execution on anyone who followed the documented install.

**Now:** the archive's SHA-256 is pinned in `datasets.lock` and verified **before
extraction**. Verified in both directions — a tampered digest refuses to extract
or run; a correct one installs normally.

**Weakness, stated plainly:** Yamato-Security publishes no checksum file for this
release, so the pin is **trust-on-first-use**. It proves the bytes have not
changed since 2026-08-02. It does **not** prove they were the vendor's intended
bytes at that moment. That is genuinely weaker than the OTRF dataset pins, which
came with published digests.

## B. Install: source checkout pinning — NOT implemented

The documented install is `git clone` of the default branch, which is mutable.
A reader following the instructions tomorrow may get different code than one
following them today.

**Deliberately not fixed by shipping a `curl | bash` one-liner.** A pipe-to-shell
installer without release tagging and published checksums is a *worse* posture,
not a smaller deliverable — and a tool whose entire claim is "nothing is asserted
without proof" should not ask a stranger to execute an unverified script.

**Deferred:** tagged release + checkout instructions. Not done for time.

## C. Untrusted log parsing — partially implemented

Logs are JSON Lines from third-party captures of compromised hosts.

**Implemented:** parsing is `json.loads` into plain dicts — no `eval`, no pickle,
no YAML `load` on log data (`yaml.safe_load` is used for ground-truth keys, which
are repository-controlled, not user input). Type confusion is explicitly guarded:
`type(EventID) is int` rather than `== 1`, because Python evaluates `True == 1`
as true and a boolean `EventID` reached a verification path during adversarial
testing.

**Not implemented:** resource bounds. A hostile log can be arbitrarily large or
deeply nested; there is no size cap, line-length cap or timeout. On a local
single-user tool this is denial of service against yourself, which is why it is
ranked Medium — but it is a real gap, and "add a timeout" does not fix
memory exhaustion during parse.

## D. HTML rendering of untrusted text — implemented

Model rationales are stored in `claim_text` and rendered to the browser. Log
fields (image paths, command lines) are attacker-influenced. Both are stored-XSS
sinks.

**Implemented** in `src/ares/rendering.py`, with a regression suite:

- One template environment, always autoescaping. **Jinja does not autoescape by
  default** — a bare `Environment` escapes nothing — so this is configured
  explicitly, including `default_for_string=True` so in-memory templates are
  covered.
- `|safe`, `Markup` and `escape_silent` **raise** rather than render. A template
  that reaches for one fails instead of silently creating an injection point.
- `StrictUndefined`: a missing value is an error, not a blank.
- Content-Security-Policy of `default-src 'none'` — **script has no permitted
  source at all**, since these pages need none. Emitted as a `<meta>` tag because
  exported reports are opened from disk with no server headers.
- No external assets. No CDN, no web fonts, no remote images.

## E. URL and attribute context — implemented

**Found while writing D's regression tests**, and worth recording because it is a
common misconception: **autoescaping does not protect URL context.**
`javascript:alert(1)` in an `href` survives HTML-escaping completely intact,
because nothing in it needs escaping.

**Implemented:** a scheme allowlist (`http`, `https`, `mailto`, plus relative
URLs). Everything else — `javascript:`, `data:`, `vbscript:`, schemes invented
later — collapses to a dead anchor. Control characters are stripped before scheme
parsing, since `java\tscript:` is how a naive check gets bypassed.

## F. Demo/evaluation separation — implemented

An integrity control rather than a safety one, but it is the one most likely to
discredit the project if it fails.

The demo corpus is authored in this repository, so any score it produced would be
self-graded. **Demo mode therefore refuses to compute accuracy figures at all** —
a caveat printed beside a number gets cropped out of a screenshot; a number that
was never produced cannot be.

Enforced at two independent layers: mode is derived from the corpus path and
declared by the key, recorded against the run in the database, and scoring aborts
on mismatch. Verified: forcing `--mode eval` on the demo corpus raises; scoring a
demo run against the evaluation key raises.

## G. Web server binding and Host validation — in progress

The dashboard is being built now. Required and specified:

- Bind `127.0.0.1` only, never `0.0.0.0`.
- **Validate the Host header.** Loopback binding is *not* an access-control
  boundary: DNS rebinding lets a remote page reach a loopback service, and on a
  shared machine every local user can reach it.
- Read-only routes. No state mutation, no upload in this scope.

**Not claimed until the dashboard lands and is tested.**

## H. SQL injection — implemented by construction

All database access uses parameterised queries. No string-built SQL anywhere in
`src/ares/`. Schema identifiers are literals in source, never interpolated from
input.

Related: the **badge firewall**. A VERIFIED badge requires a matching immutable
`verifier_executions` row, enforced by both a single badge-assignment function
and SQLite triggers, including a trigger making badged claims immutable — added
after adversarial testing found a badged claim's text could be rewritten
post-badge. Independent blind testing found **eight** ways to produce a false
verification (cycles, self-parenting, duplicate GUIDs, whitespace identifiers,
boolean/int type confusion); all are blocked at the database.

## I. Secrets — implemented, scanned clean

No credentials are required to run ARES locally. The frontier diagnostic arm uses
an existing OAuth session, not a stored key.

**Scanned 2026-08-02** with `gitleaks` across the repository's full history:

```
31 commits scanned.
scanned ~1168573 bytes (1.17 MB) in 148ms
no leaks found
```

A tool that scans other people's code for hardcoded secrets should be able to
show a clean scan of itself. Re-run with `gitleaks detect --no-banner --redact`.

## J. SAST over user-supplied code — NOT built

Planned scope (`semgrep`, `gitleaks`, `osv-scanner` over uploaded artifacts).
Nothing is implemented.

**A claim we are narrowing before making it.** The intended wording was "uploaded
code is never executed". That is not fully defensible: ARES's own code would only
read and pattern-match, but the scanners it invokes are real programs parsing
hostile input, and a dependency scanner may resolve package manifests.

The honest form: **ARES does not execute code you give it.** That is a statement
about our code, not a sandbox guarantee about the whole toolchain. If this
feature ships, subprocesses must use argument lists (never `shell=True`), with
no network, a working directory confined to the artifact, resource limits, and a
timeout.

## K. Archive/upload handling — NOT built

If uploads ship, zip-slip (path traversal via archive entry names), symlink
escape, and decompression bombs all need explicit handling. **No design exists
yet.** Named here so it is not discovered during implementation.

## L. Excel export — NOT built

Excel export was cut from scope. Recorded because it carries a non-obvious risk:
a cell beginning `=`, `+`, `-` or `@` is executed as a formula by spreadsheet
software, and ARES renders attacker-influenced strings. If Excel export is ever
added, values must be prefixed or quoted, not passed through.

---

## Review history

**2026-08-02 — one adversarial review pass** (automated, `gpt-5.6` via Codex),
verdict **NO-SHIP until Tier-0 findings closed**. Eight Tier-0 findings.

Closed: unverified binary (A), XSS environment (D), URL context (E), and two
honesty findings — demo/eval crossing in a user-facing document (F), and a
precision claim that overstated what the ground-truth key can support.

Open: B, C's resource bounds, G until the dashboard lands, J, K.

**Process disclosure:** the project's own standing rule requires a three-loop
adversarial gauntlet before plan approval. Under deadline this was reduced to a
single pass by explicit decision. That is recorded in `docs/MASTER_PLAN.md`
§16.7c rather than absorbed silently. **This code has had one third of its
intended security scrutiny.**

## Reporting a vulnerability

Open an issue at `github.com/amateur-ai-dev/ares`. This is a research project
with no security SLA and no production deployment.
