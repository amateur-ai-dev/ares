# Installing ARES

Three ways, in order of how much you should trust them.

---

## 1. Verified installer (recommended)

Download it, check it, then run it. The check is the point — do not skip it.

```sh
curl -fsSLO https://github.com/amateur-ai-dev/ares/releases/download/v0.1.0/install.sh
shasum -a 256 install.sh
# expect: (filled in by scripts/release.sh when the tag is cut)
sh install.sh
```

**What the installer does, and refuses to do:**

- Pins a **tag**, and verifies the commit that tag resolves to. `main` is
  mutable; a tag that has been moved makes the install abort rather than proceed.
- **Refuses to run as root.** Nothing in ARES needs privilege.
- Clones over **HTTPS only**. No `git://`, no ssh fallback.
- Installs into one directory (`~/ares`, or `$ARES_HOME`) and refuses to
  overwrite an existing one.
- **Does not run the toolchain step for you.** It prints the command. Someone who
  just downloaded a script should see the next command before it runs, not after.

---

## 2. Clone and run

Identical result, one less moving part, and you can read everything before it
executes. If you are at all unsure, use this.

```sh
git clone https://github.com/amateur-ai-dev/ares.git
cd ares
./scripts/setup_toolchain.sh
```

---

## 3. The `curl | sh` one-liner

```sh
curl -fsSL https://github.com/amateur-ai-dev/ares/releases/download/v0.1.0/install.sh | sh
```

It works. **It is the least defensible of the three** and it is listed last on
purpose: you are executing a script you have not read, and the checksum you were
given no longer protects you because you never compared it against anything.

For a security tool, that trade is a poor one. Method 1 costs one extra command.

---

## Note on repository visibility

`amateur-ai-dev/ares` is currently **private**, so the anonymous download URLs
above return 404. Either:

- authenticate first — `gh auth login`, then use method 2; or
- make the repository public before sharing the install command.

The installer detects the failure and says so rather than producing a confusing
git error.

---

## After installing

```sh
cd ~/ares
uv run python scripts/serve_dashboard.py
open http://127.0.0.1:8420/
```

Sample data to try it against ships in `samples/`:

| File | Use |
|---|---|
| `samples/demo-incident.json` | Upload under **Analyse a log**. Demo corpus — deliberately produces no accuracy score. |
| `samples/vulnerable-app.zip` | Upload under **Review code**. Nine planted defects across eight CWEs. |

Pick the selector on the dashboard: **local** runs on this machine and offers a
**Local model** dropdown listing what Ollama actually has pulled; **frontier** is
the test arm and ignores that choice. If Ollama is not running the dropdown says
so and tells you the command, rather than accepting the job and failing minutes
later.

---

## Requirements

- `git`, `curl`, `python3` (3.12+)
- [`uv`](https://docs.astral.sh/uv/) for dependency management
- [Ollama](https://ollama.com), **installed and running** (`ollama serve`), for the
  local selection arm. `setup_toolchain.sh` checks the daemon answers on
  `localhost:11434` and pulls `qwen2.5:7b-instruct` — the model the published
  local result was measured with — but it does **not** install Ollama itself.
  Chaining one `curl | sh` installer into another means running two scripts you
  never read.
- Optional, for the code-review add-on: `semgrep`, `gitleaks`, `osv-scanner`.
  Missing ones are reported in the results as not-run rather than silently
  skipped.

ARES makes **no network calls at analysis time**. Everything above is setup.
