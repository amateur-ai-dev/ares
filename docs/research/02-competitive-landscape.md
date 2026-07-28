# 02 — Competitive Landscape: AI-Assisted SOC Triage & Threat-Intel Q&A

**Research date:** 2026-07-28
**Question:** Who already does AI-assisted SOC triage / threat-intel Q&A, and is *"runs fully local, no data egress"* a genuine unfilled gap for ARES (a local-first, Ollama-based triage + RAG + code-scan assistant for a small single-org SOC)?

**Method:** Web search + primary-source review (vendor docs, pricing pages, press releases, one peer-reviewed paper). Firecrawl was unavailable in this environment, so WebSearch/WebFetch were used per the fallback rule.

---

## 1. Landscape Table

### Commercial AI-SOC tools

| Tool | Cloud / Local | Cost model | Audience | Source |
|------|---------------|------------|----------|--------|
| **Microsoft Security Copilot** | **Cloud-only.** No on-prem/air-gapped path; explicitly *not* for US-gov clouds (GCC, GCC High, DoD, Azure Gov). Copilot LLM cannot run offline/on-prem. | SCU-based: $4/hr provisioned, $6/hr overage. As of Ignite 2025 bundled into M365 E5 (400 SCU / 1,000 users, cap 10,000 SCU/mo). | Enterprise (M365 E5 shops). | [Pricing](https://www.microsoft.com/en-us/security/pricing/microsoft-security-copilot) · [Data/compliance FAQ](https://learn.microsoft.com/en-us/copilot/security/faq-data-compliance) · [No-cloud limitation](https://licendi.com/en/blog/using-microsoft-copilot-without-the-cloud/) |
| **CrowdStrike Charlotte AI** (incl. Detection Triage) | **Cloud** (runs inside Falcon platform / Falcon Fusion). No on-prem/local option. | No public pricing; enterprise quote. Bundled with Falcon platform tiers + Agentic SOAR. | Enterprise; Falcon customers. | [Detection Triage PR](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-delivers-next-breakthrough-in-ai-powered-agentic-cybersecurity-with-charlotte-ai-detection-triage/) · [Agentic SOAR pricing](https://www.crowdstrike.com/en-us/platform/charlotte-ai/agentic-soar/pricing/) |
| **Elastic AI Assistant / Attack Discovery** | **Cloud OR fully local / air-gapped.** Supports BYO local LLM via Ollama, LM Studio, and **vLLM in air-gapped (no outbound network) setups**. Attack Discovery reuses the same connectors. | Part of Elastic Security (Platinum/Enterprise tiers); LLM cost is BYO. Self-hostable stack. | Enterprise + mid-market Elastic Security users; the one commercial tool with a genuine local story. | [Local LLM (LM Studio)](https://www.elastic.co/docs/explore-analyze/ai-features/llm-guides/connect-to-lmstudio-security) · [vLLM air-gapped](https://www.elastic.co/docs/solutions/security/ai/connect-to-vLLM) · [BYO-LLM](https://www.elastic.co/guide/en/security/8.19/connect-to-byo-llm.html) |
| **Google SecOps — Gemini / Duet AI** (ex-Chronicle) | **Cloud-only** (Google Cloud SecOps). | Per-employee tiered (Enterprise / Enterprise Plus); Gemini included in Enterprise+ packages; agentic features use "security tokens". | Enterprise. | [Duet AI GA](https://cloud.google.com/blog/products/ai-machine-learning/duet-ai-for-developers-and-in-security-operations-now-ga) · [Gemini in SecOps](https://cloud.google.com/chronicle/docs/secops/gemini-chronicle) · [Agentic SOC tokens](https://docs.cloud.google.com/chronicle/docs/agentic-soc/security-tokens) |
| **SentinelOne Purple AI** | **Cloud** ("nothing to deploy… no data leaves *the platform*" — but the platform is SentinelOne cloud). | Bundled from Singularity Complete (~$179.99/endpoint list); Agentic SOC Analyst in higher tier. As of Jun 2026 opened to all customers. | Mid-market + enterprise. | [Purple AI](https://www.sentinelone.com/platform/purple/) · [Packages](https://www.sentinelone.com/platform-packages/) · [Agentic to all customers (Jun 2026)](https://www.sentinelone.com/press/sentinelone-opens-purple-ai-agentic-investigation-to-all-customers-bringing-frontier-ai-directly-into-the-soc/) |
| **Splunk AI Assistant (for SPL / in Enterprise Security)** | **"Cloud-connected"** — even on-prem Splunk Enterprise installs send NL→SPL processing to Splunk's multi-tenant **cloud** AI service. Data stays local; the *inference* does not. Not fully local. | Bundled with Splunk Cloud / ES; Cloud Connect required for on-prem. | Enterprise Splunk shops. | [Cloud-connected on-prem AI](https://www.splunk.com/en_us/blog/artificial-intelligence/introducing-splunk-ai-assistant-for-spl-through-a-cloud-connected-solution-on-prem-ai-without-the-gpu-hassle.html) · [AI Assistant overview](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.6/ai-assistant-in-security-and-agentic-capabilities/ai-assistant-overview) |

### Open-source / self-hostable local options

| Project | Local? | What it does | Source |
|---------|--------|--------------|--------|
| **AI_SOC** (zhadyz) | Fully local-first (Ollama, Foundation-Sec-8B) | LLM alert triage w/ structured JSON + confidence, **RAG over MITRE ATT&CK / CVE / runbooks**, Wazuh + TheHive, multi-agent orchestration. Closest analog to ARES. | [GitHub](https://github.com/zhadyz/AI_SOC) |
| **Wazuh-Ollama SOC Integration** (eddiepeter75) | Fully local | Wazuh active-response → Python → Ollama LLM analysis of high-severity alerts. | [GitHub](https://github.com/eddiepeter75/Wazuh-Ollama-SOC-Integration) |
| **Wazuh Copilot / SERC** (peer-reviewed) | Local-capable | LLM-powered assistant over Wazuh SIEM/XDR with RAG-based event extraction + IR guidance. | [MDPI Sensors 25(3):870](https://www.mdpi.com/1424-8220/25/3/870) |
| **SOCFortress CoPilot** | Local LLM option (Ollama) | NL chat agent over Wazuh Manager, Wazuh Indexer/OpenSearch, Velociraptor. | [Local LLM guide](https://socfortress.medium.com/how-to-add-a-local-llm-to-your-ai-soc-analyst-without-buying-a-gpu-9459e251bfd8) |
| **DIY RAG-over-runbooks** (Ollama + ChromaDB + nomic-embed) | Fully local | Generic but directly applicable pattern: local embeddings + vector store + local LLM answering over runbooks/FAQs. Low barrier to replicate. | [Local RAG guide](https://www.fundesk.io/local-llm-ollama-rag-private-ai-guide) |

---

## 2. Where "local / private" is a real gap — vs. where it is not

**Where it IS a genuine gap (vs. the Big-5 cloud tools):**
- Microsoft, CrowdStrike, Google, SentinelOne are **cloud-only**; Splunk's assistant is "cloud-connected" (inference leaves the building). For a shop with a hard no-egress / air-gap / data-sovereignty requirement, **none of the four market leaders qualify**, and Microsoft explicitly excludes even US-gov clouds.
- All are **enterprise-priced and platform-locked** (you must be an M365 E5 / Falcon / SecOps / SentinelOne / Splunk customer). A **small single-org SOC** on a budget, or one not standardized on any of these SIEM/EDR stacks, is genuinely underserved by the commercial market.
- The **code-scan** dimension (RAG + static analysis of the org's own code) is not a first-class feature of any of these SOC assistants — it's the least-covered part of the ARES concept.

**Where it is NOT a gap (the local angle is already occupied):**
- **Elastic already ships a fully-local, air-gapped commercial option** (BYO-LLM via Ollama/vLLM, explicitly for no-outbound-network deployments). This is the single most important finding: "local + private" is *not* an unfilled commercial niche — a major vendor does it today.
- The **OSS/DIY local-first space is active and growing**: AI_SOC in particular already combines *local Ollama triage + RAG over MITRE/CVE/runbooks + Wazuh + TheHive* — i.e., the core ARES value proposition largely exists as open source. SOCFortress, Wazuh-Ollama, and the SERC paper reinforce that this is a well-trodden pattern, not virgin territory.
- The generic **Ollama + ChromaDB RAG-over-runbooks** recipe is now a commodity tutorial. The "private RAG" building block has near-zero moat.

---

## 3. Bottom line

**Is there a defensible niche for ARES? → MARGINAL (lean toward "yes, but narrow"). Confidence: Medium-High.**

- The **privacy / no-egress angle alone is weak** as a differentiator. It is already served commercially by **Elastic** (air-gapped BYO-LLM) and by a **crowded, capable OSS field** — most notably **AI_SOC**, which is a near-direct analog (local triage + RAG over ATT&CK/CVE/runbooks). Do not position ARES as "the first/only local SOC assistant" — that claim is false and easily debunked.
- A **defensible niche does exist**, but it is narrow and comes from *combination + polish + audience*, not from "local" as such:
  1. **Turnkey, single-small-org, opinionated** product where the OSS alternatives are PoC-grade, stack-specific, and assembly-required.
  2. **Not tied to a specific SIEM/EDR** (Elastic's local story requires the Elastic stack; AI_SOC assumes Wazuh+TheHive) — ARES being stack-agnostic and lightweight is real differentiation.
  3. **Code-scan as a first-class pillar** — the genuinely under-covered dimension across the entire landscape.
- **Go / No-Go recommendation:** conditional **GO**, provided ARES's pitch shifts from "local & private" (table stakes) to "**turnkey, stack-agnostic, single-org triage + RAG + code-scan that a 1–3 person security team can run in an afternoon**." If ARES ends up as "yet another Ollama + Wazuh + RAG script," it is undifferentiated from AI_SOC/SOCFortress and the effort is hard to justify.

**Biggest risk to the thesis:** Elastic's air-gapped AI Assistant + Attack Discovery, and the AI_SOC project, together demonstrate that both the commercial and OSS worlds already cover "local SOC AI." ARES must win on integration/UX/scope, not privacy.

---

### Sources (consolidated)
- Microsoft Security Copilot: [pricing](https://www.microsoft.com/en-us/security/pricing/microsoft-security-copilot), [data/compliance FAQ](https://learn.microsoft.com/en-us/copilot/security/faq-data-compliance), [no-cloud limitation](https://licendi.com/en/blog/using-microsoft-copilot-without-the-cloud/)
- CrowdStrike Charlotte AI: [Detection Triage PR](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-delivers-next-breakthrough-in-ai-powered-agentic-cybersecurity-with-charlotte-ai-detection-triage/), [Agentic SOAR pricing](https://www.crowdstrike.com/en-us/platform/charlotte-ai/agentic-soar/pricing/)
- Elastic: [LM Studio local LLM](https://www.elastic.co/docs/explore-analyze/ai-features/llm-guides/connect-to-lmstudio-security), [vLLM air-gapped](https://www.elastic.co/docs/solutions/security/ai/connect-to-vLLM), [BYO-LLM](https://www.elastic.co/guide/en/security/8.19/connect-to-byo-llm.html), [8.16 blog](https://www.elastic.co/blog/whats-new-elastic-security-8-16-0)
- Google SecOps: [Duet AI GA](https://cloud.google.com/blog/products/ai-machine-learning/duet-ai-for-developers-and-in-security-operations-now-ga), [Gemini in SecOps](https://cloud.google.com/chronicle/docs/secops/gemini-chronicle), [agentic tokens](https://docs.cloud.google.com/chronicle/docs/agentic-soc/security-tokens)
- SentinelOne Purple AI: [product](https://www.sentinelone.com/platform/purple/), [packages](https://www.sentinelone.com/platform-packages/), [Jun 2026 GA-to-all](https://www.sentinelone.com/press/sentinelone-opens-purple-ai-agentic-investigation-to-all-customers-bringing-frontier-ai-directly-into-the-soc/)
- Splunk: [cloud-connected on-prem AI](https://www.splunk.com/en_us/blog/artificial-intelligence/introducing-splunk-ai-assistant-for-spl-through-a-cloud-connected-solution-on-prem-ai-without-the-gpu-hassle.html), [AI Assistant overview](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.6/ai-assistant-in-security-and-agentic-capabilities/ai-assistant-overview)
- OSS: [AI_SOC](https://github.com/zhadyz/AI_SOC), [Wazuh-Ollama](https://github.com/eddiepeter75/Wazuh-Ollama-SOC-Integration), [SERC / Wazuh Copilot (MDPI)](https://www.mdpi.com/1424-8220/25/3/870), [SOCFortress local LLM](https://socfortress.medium.com/how-to-add-a-local-llm-to-your-ai-soc-analyst-without-buying-a-gpu-9459e251bfd8), [DIY local RAG](https://www.fundesk.io/local-llm-ollama-rag-private-ai-guide)
