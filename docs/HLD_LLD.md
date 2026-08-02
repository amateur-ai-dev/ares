# ARES — High-Level and Low-Level Design

Describes **the system as built**, not as originally planned. Two predicates
ship, not four; the two cut ones are marked as such everywhere they appear.

Last updated 2026-08-02. Diagrams are Mermaid — they render on GitHub and in any
Markdown viewer, and deliberately pull no external JavaScript, because ARES's own
Content-Security-Policy forbids exactly that.

---

# Part 1 — High-Level Design

## 1.1 The one idea

Everything follows from a single split:

```mermaid
flowchart LR
    A[Raw event logs] --> B{Two different jobs}
    B -->|Deterministic code| C["Find and PROVE<br/>every causal link<br/><br/>Cannot be wrong<br/>except via a bug"]
    B -->|Language model| D["Decide which proven links<br/>are the ATTACK<br/><br/>Wrong constantly.<br/>That is the job"]
    C --> E[(Claims + badges<br/>durable)]
    D --> F[Selections<br/>in memory only]
    E --> G[Dashboard / reports]
    F --> G
    style C fill:#e8f4ea,stroke:#1f6b3a
    style D fill:#fdf0e8,stroke:#a8531f
    style E fill:#e8eef7,stroke:#2a4f7c
    style F fill:#f7f0f0,stroke:#8c3a3a,stroke-dasharray: 4 3
```

**The dashed box is the point.** Model selections are held in memory and never
enter the claims table. A model opinion cannot become a stored fact, because the
two never share storage.

## 1.2 Component view

```mermaid
flowchart TB
    subgraph CLI["Entry points"]
        R[run_incident.py]
        S[serve_dashboard.py]
    end

    subgraph Deterministic["Deterministic core — no model involved"]
        L[loader<br/>JSON Lines → events]
        EN[enumerator<br/>every candidate edge]
        P[predicates<br/>SPAWNED · PROCESS_OPENED_CONNECTION]
        V[verifier + BADGE FIREWALL]
    end

    subgraph Interpretive["Interpretive — model involved"]
        PR[prioritiser<br/>rank, order only]
        PO[proposer<br/>selection]
    end

    subgraph Models["Selectors"]
        OL[Ollama local<br/>qwen2.5-7b<br/>THE PRODUCT]
        FR[Codex frontier<br/>diagnostic only<br/>never demoed]
    end

    subgraph Storage["Storage"]
        DB[(SQLite<br/>claims · verifier_executions · runs)]
    end

    subgraph Output["Presentation"]
        RE[rendering<br/>hardened Jinja env]
        RP[report<br/>one model → MD + HTML]
        DA[dashboard<br/>127.0.0.1 read-only]
    end

    R --> L --> EN --> P --> V --> DB
    V --> PR --> PO
    PO <--> OL
    PO <-.diagnostic.-> FR
    DB --> RP --> RE
    S --> DA --> RE
    DA --> DB
    SC[scoring<br/>vs frozen key] --> DB

    style V fill:#e8f4ea,stroke:#1f6b3a,stroke-width:3px
    style RE fill:#e8f4ea,stroke:#1f6b3a,stroke-width:2px
    style FR stroke-dasharray: 5 4
```

## 1.3 Deployment

```mermaid
flowchart TB
    subgraph Laptop["One laptop — Apple M4, 16GB. No cloud, no account."]
        subgraph AresProc["ARES process"]
            PY[Python 3.12 · uv]
            SQ[(SQLite file<br/>data/eval/ · data/demo/)]
        end
        OLL[Ollama daemon<br/>~5GB resident]
        BR[Browser → 127.0.0.1:8420]
        HB[Hayabusa binary<br/>digest-pinned]
    end
    CX[Codex OAuth<br/>DIAGNOSTIC ARM ONLY<br/>opt-in · never in the demo]

    PY <--> SQ
    PY <-->|HTTP localhost:11434| OLL
    BR -->|GET only| PY
    PY --> HB
    PY <-.->|only when explicitly asked| CX

    style CX fill:#f7f0f0,stroke:#8c3a3a,stroke-dasharray: 5 4
    style Laptop fill:#f8f8f5
```

**Only the dashed box leaves the machine, and only on request.** Default
operation is fully local.

## 1.4 Data flow, end to end

```mermaid
sequenceDiagram
    participant U as Analyst
    participant C as CLI
    participant D as Deterministic core
    participant DB as SQLite
    participant M as Local model
    participant W as Dashboard

    U->>C: run_incident --incident day1 --arm local
    C->>D: load + enumerate
    D->>D: apply predicates to every candidate
    D->>DB: persist claim + verifier_execution (atomic)
    Note over DB: Badge firewall: a VERIFIED badge<br/>REQUIRES a matching execution row.<br/>Triggers enforce it, not convention.
    D-->>C: 794 verified edges
    C->>C: prioritise → top N
    loop each batch of 25
        C->>M: "which of these are the attack?"
        M-->>C: selections + rationales (JSON schema)
    end
    Note over C: Selections stay in memory.<br/>They are NEVER written to claims.
    C->>DB: read claims for scoring
    C-->>U: recall + adjudication-scoped precision
    U->>W: serve_dashboard --db ...
    W->>DB: read-only
    W-->>U: badges · selections · APORIAS
```

---

# Part 2 — Low-Level Design

## 2.1 Data model

```mermaid
erDiagram
    runs ||--o{ claims : produces
    claims ||--o| verifier_executions : "REQUIRED for a VERIFIED badge"

    runs {
        text run_id PK
        text incident_id
        text arm "local | frontier"
        text dataset_mode "demo | eval — enforced"
    }
    claims {
        int claim_id PK
        text incident_id
        text predicate_type
        text badge "VERIFIED | REFUTED | APORIA"
        text source_event_id
        text target_event_id
        text source_hostname
        text target_hostname
        text claim_text "MODEL-ORIGINATED — untrusted, XSS sink"
    }
    verifier_executions {
        int execution_id PK
        int claim_id FK
        text predicate
        text ordered_event_pair
        int result "1 = holds"
    }
```

`claim_text` is model output. It is the reason `src/ares/rendering.py` exists.

## 2.2 The badge firewall

The project's central integrity control.

```mermaid
flowchart TB
    A[Predicate evaluated] --> B{Outcome}
    B -->|true| C[Write verifier_execution<br/>result=1]
    B -->|false| D[badge = REFUTED]
    B -->|undeterminable| E[badge = APORIA]
    C --> F[Assign VERIFIED via the<br/>SINGLE badge-assignment function]
    F --> G{{"TRIGGER: matching<br/>verifier_executions row?"}}
    G -->|no| H[ABORT]
    G -->|yes| I[Badge stored]
    I --> J{{"TRIGGER: badged claims<br/>are IMMUTABLE"}}
    J -->|"UPDATE attempted"| K[ABORT]

    style G fill:#e8f4ea,stroke:#1f6b3a,stroke-width:2px
    style J fill:#e8f4ea,stroke:#1f6b3a,stroke-width:2px
    style H fill:#f7e8e8,stroke:#8c3a3a
    style K fill:#f7e8e8,stroke:#8c3a3a
```

**Two independent layers, deliberately.** A single application-level function
would be one refactor away from a bypass. The triggers hold even if the Python is
wrong.

The immutability trigger exists because adversarial testing found a badged
claim's text could be rewritten *after* it was badged — a real leak, closed.

Blind adversarial testing found **eight** false-verification paths in code that
had already passed a phase gate and two reviews: self-parenting, mutual parenting,
longer cycles (A→B→C→A), duplicate GUIDs making the parent ambiguous, whitespace
identifiers, text/number type confusion, and a boolean accepted as an event type
(Python evaluates `True == 1` as true).

## 2.3 The two shipped predicates

```mermaid
flowchart LR
    subgraph SP["SPAWNED — EID 1 → EID 1"]
        A1[parent.ProcessGuid] --> A2{equal?}
        A3[child.ParentProcessGuid] --> A2
        A4[same Hostname] --> A2
        A2 -->|yes + guards pass| A5[VERIFIED]
    end
    subgraph PC["PROCESS_OPENED_CONNECTION — EID 1 → EID 3"]
        B1[process.ProcessGuid] --> B2{equal?}
        B3[connection.ProcessGuid] --> B2
        B4[same Hostname] --> B2
        B2 -->|yes| B5[VERIFIED]
        B6["no matching EID 1<br/>(27% of processes<br/>have no recorded parent)"] --> B7[APORIA]
    end
```

Both are **host-scoped identifier joins**. That is why precision on adjudicated
edges is expected to sit at 100% — it is a floor, not an achievement.

**Cut from scope:** `WROTE_PATH_BEFORE_EXECUTION` and `SAME_SESSION`. They cover
5 of day 2's 23 true edges, permanently out of reach for this build. EID 3 carries
no `LogonId`, which is what makes `SAME_SESSION` expensive.

## 2.4 Selection path

```mermaid
flowchart TB
    A[794 verified edges] --> B[prioritise<br/>LOLBins · encoded PowerShell<br/>non-system paths · external IPs]
    B --> C["top-N window (default 300)"]
    C --> D{batch size?}
    D -->|"None — single shot"| E[1 call]
    D -->|"25 — local models"| F[N calls]
    E --> G[schema-constrained JSON]
    F --> G
    G --> H[parse + salvage truncated arrays]
    H --> I[reject any edge_id not in the batch]
    I --> J[selections — IN MEMORY ONLY]

    style J fill:#f7f0f0,stroke:#8c3a3a,stroke-dasharray: 4 3
    style B fill:#fdf0e8,stroke:#a8531f
```

**The prioritiser is the measured bottleneck.** On day 2, all 18 in-scope true
edges were enumerated but only 6 ranked inside the top 300 — a reachable ceiling
of 33.3%. Widening the window to 1500 moved the frontier arm 16.7% → 55.6% with
no model change. Ranking mattered more than model choice.

Ordering **never** affects a badge. It changes only what the model is shown.

## 2.5 Dataset-mode enforcement

```mermaid
flowchart TB
    A[corpus path] -->|"'demo' in parts"| C[mode from log]
    B[key file] -->|dataset_mode field| D[mode from key]
    C --> E{agree?}
    D --> E
    E -->|no| F[ABORT]
    E -->|yes| G[record on run]
    G --> H{demo?}
    H -->|yes| I["REFUSE to score.<br/>No accuracy figure produced."]
    H -->|no| J[score against frozen key]

    style F fill:#f7e8e8,stroke:#8c3a3a
    style I fill:#e8eef7,stroke:#2a4f7c,stroke-width:2px
```

Derived independently from two sources that must agree, so a wrong `--mode` flag
cannot override the filesystem and a wrong key cannot override the run.

Demo mode produces **no number at all**. A caveat printed beside a figure gets
cropped out of a screenshot; a figure that was never produced cannot be.

## 2.6 Rendering, hardened

```mermaid
flowchart LR
    A["Untrusted text:<br/>model rationales,<br/>log fields, filenames"] --> B[build_environment]
    B --> C[autoescape ALWAYS<br/>incl. string templates]
    B --> D["|safe · Markup · escape_silent<br/>RAISE"]
    B --> E[StrictUndefined]
    B --> F["|url — scheme allowlist"]
    C --> G[HTML out]
    D --> G
    E --> G
    F --> G
    G --> H["CSP: default-src 'none'<br/>script has NO source"]
    style B fill:#e8f4ea,stroke:#1f6b3a,stroke-width:2px
```

Jinja **does not autoescape by default**; a bare `Environment` escapes nothing.
Escape hatches raise rather than render, so a template using one fails instead of
quietly creating an injection point.

`|url` exists because **autoescaping does not protect URL context** —
`javascript:alert(1)` in an `href` survives HTML-escaping completely intact. Found
while writing the regression suite for the escaping itself.

## 2.7 Measured results

| Arm | Incident | Window | Selection recall | Adjudicated precision |
|---|---|---|---|---|
| Frontier | day 1 | 300 of 794 | **66.7%** (22/33) | 33/33 |
| Frontier | day 2 | 1500 of 1704 | **55.6%** (10/18) | 18/18 |
| Local (qwen 7b, batch 25) | day 1 | 300 of 794 | **51.5%** (17/33) | 33/33 |
| Local, batch 75 / 100 / 300 | day 1 | 300 | 33.3% / 27.3% / **0%** | — |

Batch 300 returns a **well-formed empty answer** — the model declines rather than
fails. More context did not help; recall falls monotonically as the batch grows.

**Adjudication coverage: 33 of 794 badges (4.2%).** The key describes the attack
narrative, not every relation in the log, so it cannot rule on the other 761.
Precision figures here are scoped to what it can adjudicate and claim nothing
beyond it.

**Not measured:** day 2 on the local arm. That run was abandoned at 72% after
4h45m. Local is proven on one incident only.
