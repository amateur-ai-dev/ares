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

> **There is a one-line installer too — but read this first.**
> You'll often see tools install with a single line that downloads a script and
> immediately runs it. That asks you to execute code you haven't seen, from a
> location that could change after you read this page. ARES has one
> (`INSTALL.md`), and it's built carefully: it pins an exact version, checks that
> version hasn't been tampered with, and refuses to run with administrator
> powers. But the safest way to use it is still to download it, check it, then
> run it — which is two commands, not one. The three above are simpler still,
> because you can read every file before anything runs.

---

## 4. Running your first analysis

There are two ways: a window in your browser, or a typed command. **Start with
the browser** — it's the same tool either way.

### The browser way

```bash
uv run python scripts/serve_dashboard.py
```

Then open **http://127.0.0.1:8420/** — that address means "this computer". The
page is not on the internet and cannot be reached from another machine.

On that page:

1. Under **Analyse a log**, click the file button and pick
   `samples/demo-incident.json` from the ares folder.
2. Leave **Selector arm** on *local* — that means the AI runs on your own
   computer. The **Local model** box below it lists the AI models you actually
   have installed; the recommended one is already selected.
3. Leave the other boxes as they are.
4. Click **RUN ANALYSIS**.

> If the **Local model** box says *unavailable*, the AI service isn't running.
> Open another Terminal window and type `ollama serve`, leave it running, then
> reload the page.

You'll land on a page that refreshes itself while the work happens, then fills in
with the results and a row of numbers describing the run. Nothing is uploaded
anywhere — "upload" here means "hand this file to the program running on your own
computer".

There's a second box, **Review code**, that takes a `.zip` of source code and
lists the security problems in it. Try it with `samples/vulnerable-app.zip`,
which has nine deliberate defects planted in it. ARES reads that code. It never
runs it.

### The typed way

```bash
uv run python scripts/run_incident.py --incident demo --arm local
```

Same built-in demo incident. It takes a couple of minutes.

**What you'll see while it runs:** a stream of progress lines. The tool is doing
three things in order — reading the log, working out every provable connection
between events, then asking the AI which of those connections look like an
attack.

---

## 5. Reading the result

At the end you'll get a summary that looks roughly like this:

```
Incident: demo (demo mode, local arm)
Run counts: edges-enumerated=30, edges-verified=30, selections=9, aporias=2

  Demo mode: no accuracy figures are produced here.
  This dataset was written by us, so any score would be meaningless.
```

In plain terms:

| What it says | What it means |
|---|---|
| `edges-enumerated=30` | The tool found 30 provable connections in the log. |
| `selections=9` | The AI picked 9 of them as attack-related. |
| `aporias=2` | Two connections it honestly could not determine. |

**Why no accuracy percentage here?** Because this is the demo dataset, and we
wrote both the incident *and* the answer key. Scoring our own homework would
produce a flattering number that means nothing. The tool refuses to compute one.

Accuracy figures come only from the real evaluation data (section 8), where the
attack was staged by someone else.

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
uv run python scripts/run_incident.py --incident day1 --arm local --batch-size 25
```

This one is much bigger — around 200,000 log entries — and takes 15–20 minutes
on a laptop. That is the honest cost of running an AI model locally instead of
in someone else's data centre.

Here you *do* get accuracy figures:

```
Selection recall:        51.5% (17/33)
Precision on adjudicated key edges: 33/33
Adjudication coverage:   33 of 794 badges (4.2%)
```

Reading those honestly:

- **51.5%** — it found just over half of the real attack's steps.
- **33/33** — of the connections the answer key is able to rule on, none were
  wrong.
- **4.2%** — but the key only rules on 33 of the 794 connections found. The other
  761 are ordinary background activity the key never describes, so it cannot
  vouch for them either way.

That third line matters. A tool that reported only "100%" would be inviting you
to believe something the evidence does not support.

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

**A number looks too good** — check the first line of output says `eval mode`.
Demo-mode runs never produce accuracy figures at all; if you are looking at a
percentage, it came from the real evaluation data.

---

## 10. What this tool will not do

Stated plainly so you don't rely on it for something it can't do:

- It is **not** production software. No logins, no user accounts, no access
  control.
- It reads **Windows event logs only**, in one specific format.
- It finds **just over half** of a real attack's steps in testing — useful as an
  assistant, not a replacement for a human analyst.
- Its accuracy is measured against an answer key that describes the attack, not
  every relationship in the log. The key can rule on about 4% of what the tool
  reports; the rest is untested by that measurement.
- It cannot prove links the logs never recorded. Roughly a quarter of program
  starts have no recorded parent; those connections are unknowable, and the tool
  will tell you so rather than guess.

---

## 11. Where to go next

- **`docs/FAQ.md`** — common questions, including the accuracy numbers and their
  caveats.
- **`docs/PAPER.md`** — the full write-up, including everything that went wrong.
- **`SECURITY.md`** — how the tool protects itself, and what it doesn't cover.
