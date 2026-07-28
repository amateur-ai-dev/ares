# 03 — Is "No Data Leaves the Building" a Real Adoption Driver for SOCs?

**Research question:** For a go/no-go on building ARES (a LOCAL, private AI SOC assistant), is "no data leaves the building" a genuine adoption driver that SOCs will switch tools for, or a nice-to-have they won't act on?

**Method note:** Firecrawl MCP was not available in this environment; research was done via WebSearch + WebFetch against surveys, regulator-adjacent guidance, security press, and vendor/practitioner writeups. Dates reflect a July 2026 vantage point. Confidence caveats are noted throughout — several stats come from vendor-published surveys (directional, not peer-reviewed).

---

## Bottom line (read first)

**The no-egress angle carries MODERATE-to-STRONG adoption pull — but it is a segment-gated driver, not a universal one.** (Confidence: Moderate-High.)

- For **hard-mandate segments** (defense/classified, government, regulated healthcare/PCI, and increasingly EU financial/critical-infrastructure under DORA/NIS2/GDPR), local-only processing is a **switch-deciding, table-stakes requirement** — cloud AI-SOC tools are often simply disqualified. Here the pull is **strong**.
- For the **broad commercial mid-market**, privacy is a real and rising concern (bans, DLP gaps, source-code-leak incidents) but it currently shapes *guardrails and vendor questions* more than *tool switching*. Cloud SaaS still wins most deals on speed, features, and OpEx economics. Here the pull is **moderate, and mostly a differentiator rather than a deal-maker**.
- The category itself is early: AI-SOC agents sit at ~1–5% market penetration (Gartner "Technology Trigger"), so ARES is competing for an emerging, not saturated, market — good timing, but the mainstream buyer has not yet been forced to choose local.

**Implication for ARES:** "No data leaves the building" is a legitimate wedge, but lead with the segments where it is *mandatory* (defense/gov, healthcare, EU-regulated finance, IP-sensitive orgs handling source code). Do not assume the average commercial SOC will rip out CrowdStrike/Microsoft to get it.

---

## Evidence FOR privacy / no-egress as a genuine driver

### 1. Hard regulatory mandates that block sending SOC logs/code/incident data to cloud LLMs

- SOC telemetry (usernames, IPs, device data) is **personal data under GDPR Chapter V**, so every out-of-region inference call is a documented cross-border transfer / compliance event. Some frameworks **eliminate the choice entirely and force local-only processing**: HIPAA (with BAAs), PCI DSS, French HDS healthcare hosting, German public-sector rules, Taiwan localization. "When a mandate hits, 'fastest' stops being a real option." — https://underdefense.com/blog/ai-soc-data-residency/
- **Defense industrial base:** CUI/ITAR technical data must reside on US-jurisdiction infrastructure; DFARS 252.204-7012 requires cloud handling CDI to meet FedRAMP Moderate or equivalent; sovereignty exposure exists even with in-region servers if the provider's parent faces foreign legal compulsion. — https://www.kiteworks.com/cmmc-compliance/data-sovereignty-defense-contractors-compliance/
- **Classified / air-gapped:** DoD Impact Levels IL5 and IL6 require air-gapped, physically-separated, US-person-only environments with no outbound connectivity — "no API calls to model vendors, licensing callbacks, or telemetry." Real deployments exist (Army "Ask Sage" in IL5 cArmy Cloud; Intel/Iternal "AirgapAI" for US military running fully offline). — https://stealthcloud.ai/ai-privacy/defense-ai-classified/ , https://legalclarity.org/dod-impact-levels-explained-il2-il4-il5-and-il6-2/ , https://www.truefoundry.com/blog/air-gapped-ai-deploying-enterprise-llms-in-highly-regulated-industries
- **EU stack (GDPR + NIS2 + DORA + AI Act):** converging toward "know where data lives, control who can touch it, prove it." GDPR transfer restrictions create *de facto* residency requirements; DORA designates AI vendors as regulated ICT dependencies for financial entities; NIS2 pushes tamper-evident logging and supplier governance. One vendor survey cites 41% of enterprises requesting EU-only key custody and 34% requiring data-flow maps that exclude trans-Atlantic hops for production telemetry. — https://www.kiteworks.com/regulatory-compliance/nis2-dora-eu-ai-compliance/ , https://www.kiteworks.com/gdpr-compliance/eu-data-sovereignty-gdpr-compliance/

### 2. Documented reluctance to send sensitive telemetry/code to cloud AI

- **Cisco 2024 Data Privacy Benchmark (2,600 privacy/security pros):** 27% of organizations have *completely banned* GenAI apps; 63% restrict what data can be entered; 61% restrict which tools are allowed — driven by data privacy/security concerns. Named blockers include JPMorgan Chase, Northrop Grumman, Apple, Verizon, Spotify. — https://www.cfodive.com/news/one-in-four-companies-ban-genai/705966/
- **Samsung source-code leak (2023):** engineers pasted semiconductor source code and internal meeting transcripts into ChatGPT three times in 20 days; Samsung banned GenAI company-wide. The canonical cautionary tale for code/telemetry egress — directly analogous to a SOC pasting logs/IOCs/scripts into a cloud model. Wall Street banks (Citi, Goldman, JPMorgan) restricted ChatGPT early for the same reason. — https://www.forbes.com/sites/siladityaray/2023/05/02/samsung-bans-chatgpt-and-other-chatbots-for-employees-after-sensitive-code-leak/ , https://www.bloomberg.com/news/articles/2023-05-02/samsung-bans-chatgpt-and-other-generative-ai-use-by-staff-after-leak
- **2025 leadership surveys:** 43% of security leaders cite protecting proprietary datasets/IP/customer data as a top challenge; leaders explicitly worry employees will pass sensitive data to GenAI causing leaks. 83% of orgs lack automated controls to keep sensitive data out of public AI tools and 86% have no visibility into AI data flows — i.e., the risk that motivates on-prem is real and largely unmitigated today. — https://www.cybersecurity-insiders.com/cloud-security-report-2025-ciso-priorities-for-securing-the-modern-cloud/ , https://www.kiteworks.com/cybersecurity-risk-management/ai-security-gap-2025-organizations-flying-blind/
- **"Why self-host" writeups converge on one line:** self-hosted/air-gapped LLMs mean "zero data leaving your network," satisfying GDPR/HIPAA/CMMC/SOC 2/EU AI Act "by design," and are "the only practical option for fully air-gapped deployments." — https://petronellatech.com/blog/private-ai-deployment-guide-enterprise/ , https://www.digitalapplied.com/blog/local-llm-deployment-privacy-guide-2025 , https://www.darkanalytics.com/post/top-9-considerations-for-on-premises-open-source-llm-deployment-with-sensitive-data

---

## Evidence AGAINST (privacy as nice-to-have; cloud gets adopted anyway)

- **Cloud SaaS dominates deployment economics.** Cloud commands ~70% of the AI-SaaS market on scalability + OpEx (no capex); public cloud ~68% of general SaaS. The default enterprise buying reflex is cloud, and on-prem carries real cost/ops burden that buyers routinely accept cloud to avoid. — https://www.fortunebusinessinsights.com/ai-saas-market-111182 , https://market.us/report/software-as-a-service-saas-market/
- **The incumbents shipping AI-SOC are cloud-first and being adopted.** Microsoft Security Copilot (Nov 2025: extended to all M365 E5 customers) and CrowdStrike Charlotte AI are the default recommendation for most mid-size SOCs — "add AI tooling to your existing platform." Distribution + bundling beats standalone privacy pitches for the mainstream buyer. — https://guptadeepak.com/tools/top-5-ai-security-tools-2026/ , https://www.microsoft.com/en-us/security/blog/2025/03/24/microsoft-unveils-microsoft-security-copilot-agents-and-new-protections-for-ai/ , https://www.crowdstrike.com/en-us/blog/crowdstrike-expands-ai-security-services-to-strengthen-soc-readiness/
- **Region-locked cloud is "good enough" for much of the mid-market.** The residency framework itself says region-locked cloud satisfies most EU mid-market needs; full on-prem is reserved for "hard-mandate sectors." So for a large slice of buyers, a data-residency checkbox (not local inference) closes the gap. — https://underdefense.com/blog/ai-soc-data-residency/
- **Adoption research is driven by workflow value, not privacy.** Practitioner-centered SOC adoption studies frame LLM uptake around trust, accuracy, and fit into analyst workflows — privacy is a constraint to clear, not the primary purchase motivator. — https://arxiv.org/abs/2604.21679 , https://arxiv.org/html/2508.18947v1
- **Behavior gap:** despite stated concern, 83–86% of orgs still lack controls/visibility over AI data flows — evidence that many talk privacy but keep using cloud AI without switching. Concern ≠ action for the average org.

---

## Which segments genuinely REQUIRE local (ranked by strength of mandate)

1. **Defense / classified / national security (strongest).** Air-gapped IL5/IL6, ITAR/CUI, US-person-only. Cloud LLM APIs are structurally disqualified. Local is not a preference — it's the only legal option.
2. **Government / public sector.** German public-sector rules, sovereign-cloud mandates, national data-localization laws. Strong.
3. **Regulated healthcare & payments.** HIPAA-with-BAA, PCI DSS, French HDS force local/controlled processing of the relevant data classes. Strong for the regulated data; SOC telemetry often carries it.
4. **EU financial services & critical infrastructure.** DORA (ICT third-party rules) + NIS2 (tamper-evident logging, supplier governance) + GDPR transfer limits. Strong and tightening; "region-locked" sometimes accepted, but sovereignty pressure pushes toward local.
5. **IP-sensitive enterprises handling source code / trade secrets** (semiconductors, pharma, defense primes). Not always a legal mandate but a hard *policy* line post-Samsung — high willingness to buy local.
6. **General commercial mid-market (weakest).** Privacy is a stated concern and a vendor-selection question, but region-locked cloud or DLP guardrails usually suffice; cloud incumbents win on features/economics.

---

## Confidence & caveats

- **Confidence: Moderate-High** on the segmentation conclusion (multiple independent sources — regulators' frameworks, surveys, and vendor writeups — agree on the mandate-driven segments).
- Several quantitative stats (41%/34% EU key-custody, 83%/86% control gaps, market-share splits) are **vendor-published surveys** — treat as directional. The Cisco 27%-ban figure and the Samsung incidents are well-corroborated.
- The strongest, most defensible claim: **in mandated segments the no-egress property is a switch-deciding requirement; in the commercial mainstream it is a differentiator whose pull is real but currently secondary to features/price/distribution.**

## Sources

- https://underdefense.com/blog/ai-soc-data-residency/
- https://www.kiteworks.com/cmmc-compliance/data-sovereignty-defense-contractors-compliance/
- https://www.kiteworks.com/regulatory-compliance/nis2-dora-eu-ai-compliance/
- https://www.kiteworks.com/gdpr-compliance/eu-data-sovereignty-gdpr-compliance/
- https://stealthcloud.ai/ai-privacy/defense-ai-classified/
- https://legalclarity.org/dod-impact-levels-explained-il2-il4-il5-and-il6-2/
- https://www.truefoundry.com/blog/air-gapped-ai-deploying-enterprise-llms-in-highly-regulated-industries
- https://www.cfodive.com/news/one-in-four-companies-ban-genai/705966/
- https://www.forbes.com/sites/siladityaray/2023/05/02/samsung-bans-chatgpt-and-other-chatbots-for-employees-after-sensitive-code-leak/
- https://www.bloomberg.com/news/articles/2023-05-02/samsung-bans-chatgpt-and-other-generative-ai-use-by-staff-after-leak
- https://www.cybersecurity-insiders.com/cloud-security-report-2025-ciso-priorities-for-securing-the-modern-cloud/
- https://www.kiteworks.com/cybersecurity-risk-management/ai-security-gap-2025-organizations-flying-blind/
- https://petronellatech.com/blog/private-ai-deployment-guide-enterprise/
- https://www.digitalapplied.com/blog/local-llm-deployment-privacy-guide-2025
- https://www.darkanalytics.com/post/top-9-considerations-for-on-premises-open-source-llm-deployment-with-sensitive-data
- https://www.fortunebusinessinsights.com/ai-saas-market-111182
- https://market.us/report/software-as-a-service-saas-market/
- https://guptadeepak.com/tools/top-5-ai-security-tools-2026/
- https://www.microsoft.com/en-us/security/blog/2025/03/24/microsoft-unveils-microsoft-security-copilot-agents-and-new-protections-for-ai/
- https://www.crowdstrike.com/en-us/blog/crowdstrike-expands-ai-security-services-to-strengthen-soc-readiness/
- https://arxiv.org/abs/2604.21679
- https://arxiv.org/html/2508.18947v1
