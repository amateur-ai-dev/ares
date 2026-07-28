# 01 — Can a Local Small Language Model Produce Trustworthy SOC Triage & CTI Answers?

**Research question:** Can a locally-runnable small language model (~4B–8B) produce SOC-grade
alert-triage and threat-intelligence answers that a security analyst would actually trust?

**Method:** Review of security-specific LLM benchmarks + published eval numbers for the candidate
local models + practitioner/field reports. Primary sources only (arXiv, NeurIPS, Hugging Face model
cards, vendor eng. blogs, Help Net Security). Web search via WebSearch/WebFetch (Firecrawl MCP was
not available in this environment).

_Date: 2026-07-28. Read-only research note; no repo code touched._

---

## Key findings

### On the benchmark landscape (what small vs frontier models score)

- **CTIBench** (NeurIPS'24 spotlight) is the most relevant benchmark: CTI-MCQA (multiple-choice CTI
  knowledge), CTI-RCM (CVE→CWE root-cause mapping), CTI-VSP (severity), ATT&CK technique
  extraction, threat-actor attribution. GPT-4 leads across most tasks; open Llama3-70B is broadly
  *comparable* to Gemini-1.5, but the 8B baseline lags well behind — i.e. raw general-purpose 8B is
  not frontier-grade out of the box. https://arxiv.org/abs/2406.07599
- **CyberMetric** (RAG-built MCQ, up to 10k questions): GPT-4o/GPT-4-turbo reach ~96% on the
  80-question set and ~88% on 10k. **Small models (Llama-3-8B, Phi-2, Gemma-7b) lag noticeably**,
  and expert humans average ~72% (≈ Llama-2-70B). Takeaway: scale + domain data matter; a generic
  small model sits below human-expert level on broad cyber knowledge.
  https://arxiv.org/abs/2402.07688
- **CyberSOCEval** (Meta + CrowdStrike, 2025) is the closest thing to a "real SOC" benchmark —
  malware analysis + threat-intel reasoning. Headline: **even frontier models are far from
  saturating it**; larger models do better (scaling holds) but reasoning/test-time-scaling models
  do *not* get the coding/math-style boost, indicating models simply aren't trained to reason about
  security. Current LLMs have "skills gaps that hinder their utility." This is a ceiling problem for
  *everyone*, not just small models. https://arxiv.org/abs/2509.20166 ·
  https://www.crowdstrike.com/en-us/press-releases/crowdstrike-and-meta-deliver-new-benchmarks-for-evaluation-of-ai-performance-in-cybersecurity/
- **SEvenLLM** (CTI incident analysis, 28 tasks, bilingual), **SecEval** (2,000 MCQs across 9 security
  domains), and **CyberBench** (multi-task) round out the suite but publish fewer head-to-head
  small-vs-frontier numbers. https://arxiv.org/abs/2405.03446

### On the specific candidate local models

- **Foundation-Sec-8B** (Cisco Foundation AI; Llama-3.1-8B continued-pretrained on 5.1B security
  tokens). Published CTIBench (5-shot, temp 0.3): **CTI-MCQA 67.39 vs Llama-3.1-8B 64.14 and
  Llama-3.1-70B 68.23; CTI-RCM 75.26 vs 66.43 (8B) and 72.66 (70B)** — i.e. it *matches or beats a
  70B model* on CTI tasks at 8B, with only ~2% MMLU drop. Vendor is explicit on limits: knowledge
  cutoff (misses new CVEs/exploits), can't self-verify facts (hallucination), no autonomous security
  decisions, requires professional review. https://huggingface.co/fdtn-ai/Foundation-Sec-8B ·
  https://blogs.cisco.com/security/foundation-sec-cisco-foundation-ai-first-open-source-security-model
- **CyberSecQwen-4B** (athena129; fine-tune of Qwen3-4B-Instruct). On its own card, under the
  Foundation-Sec eval protocol: **CTI-RCM 0.6664 (≈97.3% of Foundation-Sec-8B's 0.6850) and CTI-MCQ
  0.5868 vs Foundation-Sec-8B's 0.4996 (+8.7 pts)** — at half the parameters. BUT heavy caveats:
  trained on only ~14,776 records, **CTI-RCM data anchored to 2021** (under-represents newer
  vulnerability classes), **no RL safety alignment**, and "poor output outside cybersecurity." Narrow
  specialist, not a general SOC assistant. https://huggingface.co/athena129/CyberSecQwen-4B
  - _Numbers caveat:_ CyberSecQwen's card reports Foundation-Sec-8B CTI-RCM at 0.685 while Cisco's own
    card reports 0.7526 — different eval harness/protocol, so treat the +/− deltas as indicative, not
    absolute. The two models are in the same rough tier.
- **Peers** (Lily-Cybersecurity-7B, WhiteRabbitNeo) exist as community security-tuned models but lack
  comparable published CTIBench/CyberMetric numbers and skew toward offensive/red-team framing;
  weaker fit for defensive triage than the two above.

### On real-world trust (field & practitioner reports)

- **Raw small-model triage fails; structured workflow rescues it.** A 2025 study gave four models
  (GPT-5-mini, Claude 3 Haiku, Qwen3-30B, Gemma-3-27B) only an alert description + brief log summary:
  **0% true-positive detection — all classified everything benign.** Wrapping the *same* models in a
  constrained multi-agent pipeline (planner→SQL, summarizer, adjudicator) lifted accuracy to **~93%
  (three models >90%)**. Conclusion: **orchestration and evidence-grounding matter more than model
  size.** https://letsdatascience.com/news/researchers-show-structured-llm-workflows-improve-alert-tria-5b13951e
- **Lightweight local models are viable as decision-support, not autonomy.** A fine-tuned 14B model
  for incident response ran on commodity hardware, was ~22% faster than the best frontier model
  tested, and used candidate-simulation to *bound* hallucination — but researchers stress it is **not
  validated for autonomous SOC use**; operators must treat outputs "as guidance to be validated,"
  and fully autonomous IR is called "unrealistic" near-term. https://www.helpnetsecurity.com/2025/08/21/lightweight-llm-incident-response/
- **Vendors converge on the same pattern:** ground every verdict in empirical evidence and keep the
  analyst in the loop to contain hallucination and preserve defensible investigations (Corelight
  agentic triage). Surveys of AI-augmented SOCs flag hallucination + prompt-injection as the core
  risks of moving from augmentation toward autonomy. https://corelight.com/blog/agentic-triage-soc-transformation ·
  https://www.mdpi.com/2624-800X/5/4/95

---

## Best candidate model + why

**Primary: Foundation-Sec-8B (Cisco Foundation AI).**
- Best-documented, most mature security SLM; matches/beats Llama-3.1-70B on CTIBench CTI tasks at 8B.
- Broad security coverage (MITRE ATT&CK, NIST, GDPR, CVE→CWE), permissive local deployment, active
  vendor with a reasoning variant and its own FAITH benchmark harness.
- Runs comfortably locally (8B; ~5–6GB quantized).

**Strong secondary / RAM-constrained option: CyberSecQwen-4B.**
- Roughly Foundation-Sec-8B tier on CTI-MCQ/CTI-RCM at *half* the size — excellent for edge/low-VRAM
  ARES deployments where scope is narrow (CTI Q&A + CVE→CWE mapping).
- Accept its limits explicitly: 2021 data anchor, no safety alignment, degrades outside cyber. Use as
  a specialist tool behind a router, not as the general assistant.

Recommendation for ARES: **default to Foundation-Sec-8B**, offer CyberSecQwen-4B as the lightweight
profile. Neither should answer from parametric memory alone — both must sit behind RAG (fresh
CVE/threat feeds to beat knowledge cutoff) and a structured, human-in-the-loop triage workflow.

---

## Bottom line

**Verdict: MARGINAL — "good enough" only inside the right architecture, not as a raw chatbot.**
Confidence: **Moderate-to-high.**

- **As a bare Q&A model, a local 4B–8B is NOT trustworthy for autonomous triage.** Benchmarks show
  small models trail frontier and human experts on broad cyber knowledge, and the strongest field
  evidence shows raw small-model alert triage detecting **0%** of true positives. Even frontier
  models don't saturate SOC-grade benchmarks (CyberSOCEval) — so the ceiling is low for everyone,
  and hallucination + knowledge-cutoff are real, model-card-acknowledged failure modes.
- **As a component in a structured, evidence-grounded, human-in-the-loop pipeline, YES it clears the
  "gets used" bar.** The same small models hit **~93%** triage accuracy once wrapped in
  planner/summarizer/adjudicator orchestration with deterministic evidence retrieval — and
  specialized SLMs (Foundation-Sec-8B, CyberSecQwen-4B) already rival 70B models on CTI tasks.
- **Go/no-go implication for ARES: GO, conditionally.** Build ARES as decision-support (analyst stays
  in the loop), not autonomous adjudication. The model choice is the *easy* part; the trust comes
  from architecture — RAG over live CVE/intel feeds (to defeat the training cutoff), constrained
  tool-calling, evidence-cited verdicts, and mandatory human sign-off. Ship a specialized security
  SLM, not a generic one, and never let it answer triage from parametric memory alone.

---

### Sources

- CTIBench — https://arxiv.org/abs/2406.07599
- CyberMetric — https://arxiv.org/abs/2402.07688
- CyberSOCEval (Meta + CrowdStrike) — https://arxiv.org/abs/2509.20166 · https://www.crowdstrike.com/en-us/press-releases/crowdstrike-and-meta-deliver-new-benchmarks-for-evaluation-of-ai-performance-in-cybersecurity/
- SEvenLLM — https://arxiv.org/abs/2405.03446
- Foundation-Sec-8B model card — https://huggingface.co/fdtn-ai/Foundation-Sec-8B
- Cisco Foundation AI blog — https://blogs.cisco.com/security/foundation-sec-cisco-foundation-ai-first-open-source-security-model
- CyberSecQwen-4B model card — https://huggingface.co/athena129/CyberSecQwen-4B
- Structured LLM workflow triage study — https://letsdatascience.com/news/researchers-show-structured-llm-workflows-improve-alert-tria-5b13951e
- Lightweight LLM incident response (Help Net Security) — https://www.helpnetsecurity.com/2025/08/21/lightweight-llm-incident-response/
- Corelight agentic triage — https://corelight.com/blog/agentic-triage-soc-transformation
- AI-Augmented SOC survey (MDPI) — https://www.mdpi.com/2624-800X/5/4/95
