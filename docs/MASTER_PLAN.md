# Prahari — Master Plan

> **Prahari** (प्रहरी, Sanskrit: *sentinel / guard*) — a locally-hosted, domain-specific security-operations assistant. Working name; rename freely.
>
> **Status:** DRAFT — awaiting owner approval. No implementation code will be written until this plan is approved.
> **Owner:** Nithin · **Author:** engineering session · **Last updated:** 2026-07-21

---

## 0. Read this first (why this doc exists)

You are a **capable developer** but **new to security operations as a field**. You want to **learn sec-ops before we build**, because the tool is only as good as the builder's grasp of the domain (what "severity" really means, what good triage looks like, which vulnerability classes matter).

So this document is two things at once:

1. A **plan** — what we build, in what order, with what tools. (Assumes you can code; choices are justified on *engineering merit*, not skill level.)
2. A **sec-ops primer** — the domain knowledge you need loaded before building, in plain language. Sections tagged **📚 LEARN** teach the *field*; sections tagged **🔧 BUILD** are engineering decisions.

The heart of the "knowledge-first" ask is **§2A (sec-ops domain primer)** — read that closely. The tech-concept notes (§2B) are lighter, since the stack is your home turf.

Nothing here is code. Read it, push back, and approve (or amend) before we write a line.

---

## 1. What we are building (plain English)

A **local security-operations assistant** for a **single organization**, up to **3 users** (not simultaneous), running entirely on your **Apple M4, 16GB Mac** — no cloud, no data leaving the machine.

It does three jobs, built one at a time:

1. **Threat-intel Q&A** — an analyst asks a security question ("what is CVE-2024-3094? are we exposed?") and the assistant answers using *your* documents (runbooks, policies, CVE notes), not the open internet.
2. **Alert / log triage** — paste a SIEM alert or log snippet; the assistant explains what happened, rates severity, suggests next steps.
3. **Code vulnerability scanning** — upload or paste code; the assistant flags likely vulnerabilities and explains them.

All three are driven by a **small language model (SLM)** running locally, plus a **web dashboard** to use it, behind a **login with roles**.

### What it is NOT (scope guardrails)
- ❌ Not a multi-tenant SaaS serving many client companies. (Single org only. Multi-tenant is a *later* rewrite, noted in §11.)
- ❌ Not a real-time SIEM / not ingesting live network traffic. It analyzes what you give it.
- ❌ Not a fine-tuned/custom-trained model (you don't have the ML skill yet — we use RAG instead, explained below).
- ❌ Not high-concurrency. 16GB RAM + one model = a few sequential users.

---

## 2A. 📚 LEARN — SEC-OPS DOMAIN PRIMER (read this closely)

This is the knowledge you asked to have *before* we build. Without it, you can't judge whether the tool's outputs are any good. Each concept, plain language.

### The setting
- **Sec-Ops / SOC.** "Security Operations" is the practice of defending an organization's systems day-to-day. The team/room that does it is a **SOC** (Security Operations Center). Their job loop: **detect → triage → investigate → respond → recover → learn.** Prahari is a *copilot* for that loop, not a replacement.
- **Blue team vs red team.** **Blue** = defenders (what we're building for). **Red** = attackers/pentesters who probe defenses. **Purple** = the two collaborating. Prahari is a **blue-team** tool.

### The signals a SOC drowns in
- **Log.** A timestamped record of something that happened (a login, a firewall block, a file change). Machines emit millions.
- **Event vs alert.** An **event** is any logged occurrence. An **alert** is an event (or pattern) a detection rule decided is *worth a human's attention*. SOCs get far more alerts than they can handle → **alert fatigue** → real threats missed. **This is the pain Prahari's triage feature attacks.**
- **SIEM.** *Security Information and Event Management* — the system that collects logs from everywhere, runs detection rules, and raises alerts (e.g. Splunk, Elastic, Microsoft Sentinel, Wazuh). Prahari does **not** replace a SIEM; it helps an analyst *understand and prioritize* the alerts a SIEM produces.
- **EDR / IDS/IPS / NDR.** Sensors that feed the SIEM: **EDR** (Endpoint Detection & Response — watches laptops/servers), **IDS/IPS** (Intrusion Detection/Prevention — watches network traffic), **NDR** (Network Detection & Response). You just need to recognize them as *sources of alerts*.

### Triage — the core skill your tool must imitate
- **Triage.** Rapidly deciding, for each alert: *is this real, how bad, what next?* Three buckets: **true positive** (real threat), **false positive** (rule fired but harmless — most alerts), **benign true positive** (real activity but authorized). A good triage assistant explains *which* and *why*.
- **Severity & priority.** How bad (impact) and how urgent (impact × likelihood × exposure). Usually **Critical / High / Medium / Low / Info**. Prahari's triage must assign and *justify* a severity — that justification is the product.
- **IOC — Indicator of Compromise.** A concrete artifact suggesting a breach: a malicious IP, file hash, domain, or URL. Analysts pivot on IOCs ("has this hash been seen elsewhere?").
- **MITRE ATT&CK.** THE industry map of attacker behavior — a catalog of **tactics** (the attacker's goal, e.g. *Initial Access, Persistence, Exfiltration*) and **techniques** (how, e.g. *T1566 Phishing*). Mapping an alert to ATT&CK turns "weird log line" into "this looks like the *Persistence* stage." Prahari's triage should reference ATT&CK where it can — huge value, and it grounds the model.

### Vulnerabilities & threat intel
- **Vulnerability.** A weakness that could be exploited (unpatched software, misconfiguration, a code bug). Different from a **threat** (who/what might attack) and a **risk** (likelihood × impact of it happening).
- **CVE.** *Common Vulnerabilities and Exposures* — a global ID for a specific known vulnerability, e.g. **CVE-2024-3094** (the xz backdoor). When news says "patch CVE-XXXX," this is the label.
- **CVSS.** *Common Vulnerability Scoring System* — a 0.0–10.0 severity score for a CVE (9.0+ = Critical). Lets you rank what to fix first. Prahari should speak in CVE + CVSS terms.
- **Threat intelligence (CTI).** Curated knowledge about attackers, campaigns, IOCs, and vulnerabilities. This is what the **Phase-1 Q&A** feature serves: your analysts ask questions, the model answers from your CTI documents.
- **Threat intel Q&A vs a search box.** The value isn't keyword search — it's the model *synthesizing* across your runbooks/CVE notes and *explaining* in context.

### Code vulnerabilities (Phase 3's domain)
- **OWASP Top 10.** The industry's list of the 10 most critical *web-application* security risks (e.g. **Injection**, **Broken Access Control**, **SSRF**). The common language for "what's wrong with this app."
- **CWE.** *Common Weakness Enumeration* — a catalog of *types* of code weakness, e.g. **CWE-89 SQL Injection**, **CWE-79 Cross-Site Scripting (XSS)**, **CWE-78 OS Command Injection**. A CVE is a *specific* bug; a CWE is the *category* of bug. Prahari's scanner should tag findings with CWE IDs — precise, searchable, credible.
- **SAST vs DAST.** **SAST** (Static Application Security Testing) analyzes code *without running it* — reading source for dangerous patterns. **DAST** runs the app and attacks it. Prahari's scanner is **SAST** (we never execute uploaded code — safer, and matches the model's strength: reading code).
- **False positives, again.** SAST tools (and LLMs) over-report. That's why §8 Phase 3 pairs the model's *explanation* with a fast deterministic tool (`semgrep`) for *confirmation*. Understanding this trade-off is why you, the builder, must know the domain.

### The frameworks people will expect you to speak
- **NIST CSF** (Identify, Protect, Detect, Respond, Recover) and **incident-response lifecycle** (Prepare → Detect & Analyze → Contain → Eradicate → Recover → Post-incident). You don't implement these, but Prahari's language and triage steps should echo them so real analysts trust it.

> **Why this primer matters for the build:** these terms become the *vocabulary of the prompts, the severity labels, the finding schema, and the sample data*. When we design the triage prompt, we'll tell the model to "map to MITRE ATT&CK, assign CVSS-style severity, cite CWE for code" — decisions that only make sense once you know the words above.

---

## 2B. 📚 tech concepts (lighter — this is your home turf)

Skim these; you likely know most. Included so the doc is self-contained.

- **LLM / SLM.** A Large Language Model is a program that predicts text — it powers chatbots. A **Small** Language Model (SLM) is the same idea but with far fewer "parameters" (internal numbers), so it fits on a laptop instead of a datacenter. Ours is **4 billion parameters (4B)**. For comparison, ChatGPT-class models are hundreds of billions. Small = private, cheap, fast enough — at the cost of some cleverness, which we compensate for with RAG (below).

- **Parameters & "weight."** More parameters = smarter but bigger and slower. "Lightweight model" = few parameters = fits in your 16GB. Your hard ceiling on an M4/16GB is roughly a **4B model held live**, or a **7–8B model swapped in on demand**.

- **Quantization / GGUF / Q4.** A model's parameters are normally stored as big precise numbers. **Quantization** shrinks them to smaller, rougher numbers (like saving a photo as a smaller JPEG). `Q4` = 4-bit quantization = ~4× smaller, tiny quality loss. **GGUF** is just the file format these quantized models ship in. So "CyberSecQwen-4B Q4_K_M GGUF" = the 4-billion-param security model, 4-bit-compressed, ~2.5GB file.

- **Ollama.** A free program that runs these models locally with one command. Think "Docker for language models." You run `ollama pull <model>` once, then any app on your machine can talk to it at `http://localhost:11434`. This is the single biggest reason a low-proficiency dev can do this — Ollama hides all the hard parts.

- **RAG (Retrieval-Augmented Generation).** THE key idea. A small model doesn't *know* your company's runbooks or the latest CVEs. Instead of expensively re-training it (fine-tuning), we **retrieve** relevant chunks of your documents and **paste them into the question** before the model answers. So the model reads your docs at question-time and answers from them. No training, no ML skill needed. This is why we chose RAG over fine-tuning for a low-proficiency team.

- **Embeddings & vector search.** To "find relevant chunks," we convert every document chunk into a list of numbers (an **embedding**) that captures its meaning. Similar meaning → similar numbers. When you ask a question, we embed the question too and find the chunks with the closest numbers (**vector search**). A separate small model (`nomic-embed-text`, via Ollama) makes these embeddings.

- **Vector database.** Where embeddings live and get searched. Most tutorials use a heavy separate server (Chroma, Pinecone). We use **`sqlite-vec`** — a tiny extension that does vector search *inside an ordinary SQLite file*. No extra server to run. One `.db` file holds everything. (This is a deliberate laziness/lightweight win.)

- **RBAC (Role-Based Access Control).** "Who can do what." We define a few **roles** (e.g. Admin, Analyst, Viewer) and attach permissions to roles, not to individual people. Assign a user a role and they inherit its permissions. Standard, simple, auditable.

- **Prompt injection (security risk for US).** Because we paste retrieved documents (and pasted logs, and uploaded code) *into the model's prompt*, a malicious document could contain text like "ignore your instructions and…". Since this is a **security tool handling untrusted input by design**, we must treat all ingested content as hostile. Mitigations are in §9.

---

## 3. 🔧 BUILD — architecture (the whole system on one screen)

```
                         ┌──────────────────────────────────────────┐
   Browser (you)         │              Prahari (localhost)          │
  ┌───────────────┐      │                                           │
  │  Dashboard    │◄────►│  FastAPI backend (Python)                 │
  │  (HTMX +      │ HTTP │   ├─ Auth + RBAC (login, roles)           │
  │   Tailwind)   │      │   ├─ Q&A / triage / scan endpoints        │
  └───────────────┘      │   ├─ RAG engine ──────────┐               │
                         │   │                        ▼               │
                         │   │              ┌──────────────────┐      │
                         │   │              │  SQLite (1 file) │      │
                         │   │              │  • users/roles   │      │
                         │   │              │  • documents     │      │
                         │   │              │  • embeddings    │      │
                         │   │              │   (sqlite-vec)   │      │
                         │   │              │  • alerts/scans  │      │
                         │   │              └──────────────────┘      │
                         │   ▼                                         │
                         │  Ollama (localhost:11434)                  │
                         │   ├─ CyberSecQwen-4B  (sec brain)          │
                         │   ├─ nomic-embed-text (embeddings)         │
                         │   └─ Qwen2.5-Coder-7B (code vuln, on-demand)│
                         └──────────────────────────────────────────┘
                              Everything on ONE machine. No cloud.
```

**How a question flows (Phase 1 example):**
1. You log in, type a question in the dashboard.
2. FastAPI checks your role allows it.
3. RAG engine embeds your question → searches `sqlite-vec` → gets top relevant doc chunks.
4. Backend builds a prompt: *[your docs] + [your question] + [safety rules]* → sends to CyberSecQwen-4B via Ollama.
5. Model's answer streams back to the dashboard, with the source chunks shown so you can verify.

---

## 4. 🔧 BUILD — tech stack and *why* (every choice justified)

Guiding rule: **fewest moving parts, lowest weight, friendliest to a beginner.** Reuse before adding. Native before library. One file before a server.

| Layer | Choice | Why this, not the alternative |
|---|---|---|
| **Model runtime** | **Ollama** | One-command local model hosting; hides GPU/Metal/quantization. Beginner-critical. Alternative (raw llama.cpp / vLLM) = far more setup. |
| **Security model** | **CyberSecQwen-4B** (fallback: Foundation-Sec-8B Q4) | Beats the 8B Cisco model at half the size; ~2.5GB fits 16GB with room to spare. Fallback is a one-command pull if the 4B GGUF import is fiddly. |
| **Embeddings** | **nomic-embed-text** (via Ollama) | Small, runs in Ollama you already have, good quality. No extra install. |
| **Code-vuln model** | **Qwen2.5-Coder-7B** (Phase 3 only, on-demand) | Best small coding model (88% HumanEval); loaded only when scanning, unloaded after, so it doesn't compete with the sec model for RAM. |
| **Vector store** | **sqlite-vec** | Vector search *inside* SQLite. No separate DB server. One file. Backup = copy a file. |
| **Database** | **SQLite** (one file) | Users, roles, docs, embeddings, alerts, scans — all in one `.db`. Zero server. Perfect for ≤3 users. Postgres would be overkill. |
| **Backend** | **Python + FastAPI** | Python is the native language of the AI/model ecosystem (Ollama clients, sqlite-vec, embeddings). FastAPI is the modern standard: async, typed, auto-generated API docs, first-class auth deps. |
| **Auth** | **Session cookie + passlib(bcrypt)**, hand-rolled | 3 users doesn't justify a heavy auth framework — ~40 lines beats a dependency. bcrypt password hashing is non-negotiable (never store plain passwords). |
| **Frontend** | **Server-rendered Jinja2 + HTMX + Tailwind (CDN) + Alpine.js** | Engineering call, not a skill call: no Node build/bundler, no API-layer duplication, no client state to sync — the server owns state, HTML swaps over the wire. Lightest thing that yields a real dashboard. **Swappable to React/Next if you prefer a SPA** (see Q4, §11); it's a bigger surface for marginal gain here. |
| **Charts** | **Chart.js** (single file, self-hosted) | Dashboard needs a few graphs (alerts over time, severity mix). One JS file, no framework. |
| **Packaging/run** | **`uv`** + a `Makefile` / `run.sh` | `uv` = fast, modern Python env manager. One script starts Ollama + the app. |

**What we deliberately are NOT using (and why):** React/Next.js (build-tool overhead you don't need), Docker (extra layer; native `uv` + Ollama is simpler on one Mac — revisit if we ever deploy off your laptop), Chroma/Pinecone (separate server; sqlite-vec replaces it), a message queue / Celery (no background-job scale here), Postgres (SQLite is enough for 3 users).

---

## 5. 🔧 BUILD — models, concretely (with the M4/16GB reality)

**RAM budget on a 16GB Mac:** macOS + browser + your apps eat ~5–6GB. That leaves **~10GB** for us.

| Model | Role | Size (Q4) | Loaded when |
|---|---|---|---|
| CyberSecQwen-4B | Q&A + triage brain | ~2.5–3GB | Held live (default model) |
| nomic-embed-text | Make embeddings | ~0.3GB | Loaded on ingest/query |
| Qwen2.5-Coder-7B | Code-vuln scanning | ~4.5GB | On-demand; Ollama unloads sec model first |

**Key constraint:** we can hold **one big model live at a time.** The sec model stays hot; the coder model swaps in when you run a scan (a few seconds' load), then releases. This is fine for ≤3 non-concurrent users; it would *not* scale to a busy MSSP (see §11).

**Model install path (exact commands at build time):**
- Foundation-Sec-8B fallback: `ollama pull <registry>/Foundation-Sec-8B`.
- CyberSecQwen-4B: pull the GGUF from Hugging Face (`athena129/CyberSecQwen-4B`), 3-line `Modelfile`, `ollama create cybersecqwen`. One-time, ~10 min.

---

## 6. 🔧 BUILD — data model (what lives in the one SQLite file)

Plain-English tables (exact columns finalized in Phase 1):

- **users** — id, email, password_hash (bcrypt), role, created_at.
- **roles / permissions** — Admin (manage users + everything), Analyst (ask, triage, scan, ingest docs), Viewer (read past results only).
- **documents** — id, title, source, raw_text, ingested_at. (Your runbooks/CVEs/policies.)
- **chunks** — id, document_id, chunk_text, embedding (via sqlite-vec). (Documents split into searchable pieces.)
- **conversations / messages** — chat history per user (question, answer, cited chunk ids).
- **alerts** — id, raw_alert, model_summary, severity, status, created_by, created_at. (Phase 2.)
- **scans** — id, filename, language, findings(json), created_by, created_at. (Phase 3.)
- **audit_log** — who did what, when. (A security tool must log its own use.)

One file. Backup = copy the file. Reset = delete the file.

---

## 7. 🔧 BUILD — auth & RBAC design (kept minimal on purpose)

- **3 roles:** Admin, Analyst, Viewer (defined above). No custom permission editor — 3 users don't need it.
- **Login:** email + password, hashed with bcrypt, session cookie (HttpOnly, SameSite=Lax, Secure when not localhost).
- **First-run:** create the first Admin via a one-time setup screen or CLI command.
- **Enforcement:** a FastAPI dependency checks the session's role on every protected endpoint. Deny by default.
- **Not doing (yet):** OAuth/SSO, password reset email flows, 2FA. Noted as future hardening in §11. For 3 internal users on localhost, a solid session login is proportionate.

---

## 8. 🔧 BUILD — phased delivery (vertical slices)

Each phase is a **vertical slice** — a thin but *complete* path from dashboard → backend → model → back. You get something usable at the end of every phase. We build test-first (per your global rules) where it counts (RAG retrieval, auth, scan parsing).

### Phase 0 — Foundations & learning (½–1 day)
- Install Ollama, `uv`. Pull `nomic-embed-text` + the sec model. Confirm they answer.
- Bare FastAPI "hello" + one HTMX page rendering. Confirms the whole toolchain runs on your Mac.
- **Deliverable:** you can chat with the raw local model in a browser box. No RAG yet.

### Phase 1 — Threat-intel Q&A (RAG) + auth + dashboard shell (core phase)
- Login + 3 roles. Dashboard shell (nav, layout).
- Ingest documents → chunk → embed → store in sqlite-vec.
- Ask a question → retrieve → answer with cited sources.
- **Deliverable:** log in, upload your runbooks, ask questions, get grounded answers. This is the backbone; Phases 2–3 reuse this engine.

### Phase 2 — Alert / log triage
- Paste/upload an alert or log. Model summarizes, rates severity, suggests actions.
- Alerts saved, listed, filterable; dashboard charts (alerts over time, severity mix).
- **Deliverable:** a working SOC-triage view.

### Phase 3 — Code vulnerability scanning
- Paste/upload code or a file. Load Qwen2.5-Coder-7B on demand, prompt it for vulnerabilities, parse findings (severity, line, explanation, fix).
- Optionally cross-check with a fast static tool (e.g. `semgrep`, already on your machine) to reduce hallucinated findings — model *explains*, static tool *confirms*.
- **Deliverable:** upload code, get an explained vulnerability report.

### Phase 4 — Polish & hardening
- Audit log view, backups, rate limits, prompt-injection hardening (§9), docs, one-command start.

*(Later / out of first scope: multi-tenant, fine-tuning, more models — §11.)*

---

## 9. 🔒 Security of the tool itself (it's a security product — it must be secure)

Because Prahari ingests **untrusted content** (documents, logs, code) and feeds it to a model, and it's a security tool, we bake in:

- **Prompt-injection defense.** Retrieved/pasted content is wrapped and clearly delimited in the prompt; system instructions assert that document content is *data, not commands*. We never let model output trigger actions automatically.
- **Code-scan sandboxing.** Uploaded code is **never executed** — only read as text and analyzed. No `eval`, no running the sample.
- **Local-only by default.** Binds to `127.0.0.1`. Not exposed to the network unless you deliberately change it (and then: TLS + real auth review).
- **Secrets.** No API keys needed (all local). Session secret + first-admin password handled via env/`.env` (gitignored), never committed.
- **Password hashing** with bcrypt; **deny-by-default** RBAC; **audit log** of all actions.
- **Input limits.** Max upload size, max prompt length — prevents memory blowups on a 16GB box.
- **Dependency hygiene.** Few dependencies (ponytail: less code = less attack surface); pin versions.

---

## 10. 📚 LEARN — the SEC-OPS learning path (the real gap)

The stack you can pick up as we code. The **domain** is what to front-load. Priority order — the tool's quality depends on you grasping these:

1. **SOC workflow & triage** — re-read §2A. Understand detect→triage→respond and true/false-positive. (1 hr) *Search: "SOC analyst tier 1 triage explained."*
2. **MITRE ATT&CK** — browse `attack.mitre.org`; click 2–3 techniques (e.g. T1566 Phishing) to see the structure. This is the backbone of good triage output. (1–2 hr)
3. **CVE + CVSS** — read one CVE end-to-end (try CVE-2024-3094, the xz backdoor) and how its CVSS score is built. (45 min)
4. **OWASP Top 10 + CWE** — skim the OWASP Top 10 list; look up CWE-89 (SQLi) and CWE-79 (XSS). Grounds Phase 3. (1 hr)
5. **Incident response lifecycle (NIST)** — the 6 phases, once, for vocabulary. (30 min)
6. **(Optional, hands-on)** spin up a free tier of an open SIEM (Wazuh) later to *feel* what real alerts look like — informs your sample data.

Tech bits (Ollama API, RAG mechanics, sqlite-vec, HTMX) I teach **in context** as we hit them in Phase 0/1 — no pre-study needed there.

I use the global `teach` skill to explain each domain piece as it touches a build decision (e.g. we'll design the triage prompt *and* learn ATT&CK mapping together).

---

## 11. Open questions & future (decide now or defer)

**Need a decision before/early in build:**
- **Q1. Project name** — keep "Prahari" or rename? (Cosmetic, low stakes.)
- **Q2. Sample data** — do you have real runbooks/CVEs/logs/code to test with, or should I generate realistic sample data for development?
- **Q3. Model pick** — start with CyberSecQwen-4B (one-time GGUF import, best fit) or Foundation-Sec-8B (one-command pull, heavier)? Recommendation: **CyberSecQwen-4B**, fallback ready.
- **Q4. Frontend** — HTMX + Jinja (recommended: lightest, server-owns-state) or React/Next SPA (heavier, but if you want a richer client)? You're a capable dev, so it's a real preference, not a skill constraint.

**Explicitly deferred (not in first build, noted so we design without painting into a corner):**
- Multi-tenant / MSSP mode (per-client data isolation) — would move DB to Postgres, add tenant scoping everywhere. Big. Only if the product direction demands it.
- Fine-tuning your own model — revisit once you're comfortable and have labeled data.
- SSO/2FA/password-reset, network deployment + TLS, on-machine encryption at rest.
- Live SIEM/log-source connectors.

---

## 12. Approval

**This plan needs your explicit approval before any implementation code is written.**

Please respond with one of:
- ✅ **"Approved"** — I start Phase 0.
- ✏️ **Amendments** — tell me what to change (stack, scope, phasing, models, name) and I revise this doc first.
- ❓ **Questions** — anything in §2/§10 unclear, ask; I'll teach it before we proceed.

Once approved, I create `resume.md`, set up the task list, and begin Phase 0.
