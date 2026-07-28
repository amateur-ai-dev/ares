# ARES

**A private AI analyst for your SOC.** ARES is a locally-hosted AI security-operations assistant: it triages alerts (severity + MITRE ATT&CK + next steps), answers threat-intel questions from your own runbooks, and scans code for vulnerabilities — all on your own hardware, with no data ever leaving the building.

Formerly working-named *Prahari* (प्रहरी — "sentinel").

## Status

Pre-build. Architecture and delivery plan are defined; no implementation code yet.

- Plan: [`docs/MASTER_PLAN.md`](docs/MASTER_PLAN.md) — full architecture, tech stack, phased delivery. Currently **DRAFT, awaiting approval**.
- Pitch: [`docs/PITCH.md`](docs/PITCH.md) — the one-page case, framed for managed-services.
- Live status: [`resume.md`](resume.md).

## What it does (V1)

1. **Alert & log triage** — explain an alert, assign + justify severity, map to MITRE ATT&CK, suggest next steps.
2. **Threat-intel Q&A** — plain-English answers grounded in *your* runbooks/CVE notes (RAG), with sources cited.
3. **Code vulnerability scanning** — SAST via a local model + semgrep, findings tagged with CWE.

## Stack (planned)

Local-only: **Ollama** (security-tuned SLM) · **FastAPI** · **SQLite + sqlite-vec** (one file, RAG vector store) · **Jinja2 + HTMX + Tailwind**. No cloud, no API keys, no data egress.
