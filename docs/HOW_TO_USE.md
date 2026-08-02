# How to use ARES

Written for someone with no security background and no coding background. If a
step assumes something you don't have, that's a bug in this document — say so.

---

## 1. What this tool is, in one paragraph

When a computer gets attacked, it leaves a trail in its logs — thousands of
lines recording every program that started and every network connection made.
Somewhere in there is the story of the attack. ARES reads that trail and
reconstructs the story: this program started that one, which then phoned out to
an outside address.

The important part: **it separates what it can prove from what it is guessing.**

---

## 2. What you need before you start

- A Mac or Linux machine.
- About 6 GB of free disk space (most of that is the AI model).
- A log file to analyse. One comes with the tool, so you can start without one.

You do **not** need to understand security, or read code.

---

## 3. Installing it

Open the Terminal app and paste these three lines, one at a time, pressing Enter
after each:

```bash
git clone https://github.com/amateur-ai-dev/ares.git
cd ares
./scripts/setup_toolchain.sh
```

The last one takes a few minutes — it downloads the AI model.

> **Why three commands instead of one?**
> You'll often see tools install with a single line that downloads a script and
> immediately runs it. That asks you to execute code you haven't seen, from a
> location that could change after you read this page. ARES is a tool about
> proving claims rather than trusting them, so it doesn't ask you to do that.
> The three commands above let you look at what you're running first.

---

## 4. Running your first analysis

Still in Terminal, from inside the `ares` folder:

```bash
uv run python scripts/run_incident.py --incident demo --arm local
```

That's the built-in demo incident. It takes a couple of minutes.

**What you'll see while it runs:** a stream of progress lines. The tool is doing
three things in order — reading the log, working out every provable connection
between events, then asking the AI which of those connections look like an
attack.

---

## 5. Reading the result

At the end you'll get a block that looks like this:

```
Run counts: edges-enumerated=794, edges-verified=794, verified-edges-shown=300,
            selections=50, ...
Selection recall:        51.5% (17/33)
Verification precision: 100.0% (33/33)
```

In plain terms:

| What it says | What it means |
|---|---|
| `edges-enumerated=794` | The tool found 794 provable connections in the log. |
| `verified-edges-shown=300` | It showed the AI the 300 most suspicious of them. |
| `selections=50` | The AI picked 50 as attack-related. |
| `Selection recall: 51.5%` | Of the real attack steps, it found just over half. |
| `Verification precision: 100%` | **Nothing was wrongly marked as proven.** |

**The one to care about is the last one.** It means everything the tool told you
was *proven* really was proven. It being 100% is expected, not impressive — but
if it ever drops below 100%, something is broken and you should not trust that
run.

---

## 6. The three badges

Every finding carries one of these. This is the heart of the tool.

**VERIFIED** — checked by ordinary code, not by AI. This happened.

**REFUTED** — checked, and the evidence says it did *not* happen.

**APORIA** — "I cannot tell from this evidence."

That third one is deliberate and it is the tool's most useful feature. Logs are
incomplete: sometimes a program connects to the internet but the record of that
program starting was never written. A tool that guesses in that situation will
eventually send you chasing something that never happened. ARES says *I don't
know* and shows you why.

**If you remember one thing from this document:** trust VERIFIED, investigate
APORIA, and be suspicious of any security tool that never says "I don't know".

---

## 7. Demo data versus real data

The tool ships with two kinds of data and keeps them strictly apart.

**Demo data** is a small fake incident we wrote ourselves. It runs fast and is
easy to follow on screen. Because we wrote both the incident *and* the answer
key, it will always look good — so **its scores prove nothing about accuracy.**
It's there to show you how the tool behaves, not how well it performs.

**Evaluation data** is real: published logs from a genuine attack simulation run
by MITRE, a US non-profit that tests security products. Every accuracy figure we
publish comes from this.

The tool records which kind you're using and refuses to score one against the
other's answer key. You'll always be able to tell which you're looking at.

---

## 8. Running it on the real evaluation data

```bash
uv run python scripts/run_incident.py --incident day1 --arm local
```

This one is much bigger — around 200,000 log entries — and takes 15–20 minutes
on a laptop. That is the honest cost of running an AI model locally instead of
in someone else's data centre.

---

## 9. When something goes wrong

**"command not found: uv"** — the setup script didn't finish. Run
`./scripts/setup_toolchain.sh` again and watch for errors near the end.

**It seems frozen** — check whether it's actually working:

```bash
ollama ps
```

If a model is listed, it's thinking, not stuck. Local models are slow; several
minutes without visible output is normal.

**Everything got very slow** — the model needs several GB of memory. Close other
large applications, especially browsers and Docker.

**`Selection recall: 0.0%`** — the AI returned nothing usable. Usually it was
given too much at once. Try adding `--batch-size 25` to your command.

---

## 10. What this tool will not do

Stated plainly so you don't rely on it for something it can't do:

- It is **not** production software. No logins, no user accounts, no access
  control.
- It reads **Windows event logs only**, in one specific format.
- It finds **just over half** of a real attack's steps in testing — useful as an
  assistant, not a replacement for a human analyst.
- It cannot prove links the logs never recorded. Roughly a quarter of program
  starts have no recorded parent; those connections are unknowable, and the tool
  will tell you so rather than guess.

---

## 11. Where to go next

- **`docs/FAQ.md`** — common questions, including the accuracy numbers and their
  caveats.
- **`docs/PAPER.md`** — the full write-up, including everything that went wrong.
- **`SECURITY.md`** — how the tool protects itself, and what it doesn't cover.
