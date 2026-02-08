# FIPS 199 Security Categorization Checklist

FIPS 199 categorization determines your FedRAMP impact level (Low, Moderate, or High) by assessing the potential impact of a security breach across three dimensions: confidentiality, integrity, and availability. Your overall impact level is the **high-water mark** — the highest rating across all three dimensions.

This is the first technical decision in your FedRAMP journey, and it directly determines your control count (156, 323, or 410), cost, and timeline. Getting it wrong means either over-investing (categorizing too high) or failing assessment (categorizing too low).

## Step 1: Understand the Impact Levels

| Level | Definition | Example Consequence |
|-------|-----------|-------------------|
| **Low** | Limited adverse effect on operations, assets, or individuals | Minor inconvenience, easily recoverable |
| **Moderate** | Serious adverse effect on operations, assets, or individuals | Significant financial loss, degraded mission capability |
| **High** | Severe or catastrophic effect on operations, assets, or individuals | Loss of life, major financial loss, inability to perform mission |

## Step 2: Identify the Information Types

Before you can categorize, you need to know exactly what federal data your system processes.

- [ ] **List all federal data types** your system will store, process, or transmit. Be specific. Don't just say "agency data" — identify the categories.
- [ ] **Check NIST SP 800-60 Vol. 2** for provisional impact levels. This document maps common federal information types to recommended confidentiality, integrity, and availability levels. It's your primary reference.
- [ ] **Identify if any of these special data types are present:**
  - Personally Identifiable Information (PII) — typically Moderate minimum
  - Protected Health Information (PHI) — typically Moderate minimum
  - Law enforcement sensitive data — typically High
  - National security information — typically High
  - Financial transaction data — typically Moderate minimum
  - Critical infrastructure data — typically High

## Step 3: Categorize Each Dimension

### Confidentiality (unauthorized disclosure)

What's the worst-case impact if federal data in your system were exposed to unauthorized parties?

- [ ] **Low:** Disclosure would cause limited harm. No PII, no sensitive operational data. Publicly available information processed in aggregate.
- [ ] **Moderate:** Disclosure would cause serious harm. Contains PII, financial data, or pre-decisional policy information. Most SaaS applications processing agency user data fall here.
- [ ] **High:** Disclosure would cause severe or catastrophic harm. Contains classified-adjacent data, law enforcement records, intelligence data, or information whose exposure could endanger lives.

**Your confidentiality rating:** ____________

### Integrity (unauthorized modification)

What's the worst-case impact if federal data in your system were improperly modified or destroyed?

- [ ] **Low:** Modification would cause limited harm. Data is easily recoverable from other sources. No decisions of consequence are made based solely on this data.
- [ ] **Moderate:** Modification would cause serious harm. Data drives operational decisions, financial transactions, or personnel actions. Corruption would degrade agency mission capability.
- [ ] **High:** Modification would cause severe or catastrophic harm. Data integrity is life-safety critical (e.g., medical systems, air traffic control support) or modification could cause major, irreversible financial or operational damage.

**Your integrity rating:** ____________

### Availability (disruption of access)

What's the worst-case impact if your system were unavailable for an extended period?

- [ ] **Low:** Disruption would cause limited harm. Agency has alternative means to accomplish the mission. System is not time-sensitive.
- [ ] **Moderate:** Disruption would cause serious harm. Agency operations would be significantly degraded. Workarounds exist but are costly or slow.
- [ ] **High:** Disruption would cause severe or catastrophic harm. System supports real-time mission-critical operations. No viable alternatives exist. Downtime could endanger lives or national security.

**Your availability rating:** ____________

## Step 4: Determine Overall Impact Level

Your overall FIPS 199 categorization is the **highest rating** across all three dimensions.

**SC {system name} = {(confidentiality, ___), (integrity, ___), (availability, ___)}**

**Overall impact level: ____________**

## Decision Trees by Service Type

### SaaS (most common FedRAMP path)

```
Does the system process PII?
├── No → Does it support critical operations?
│   ├── No → Likely LOW
│   └── Yes → Likely MODERATE
└── Yes → Is the PII sensitive (SSN, financial, health)?
    ├── No → Likely MODERATE
    └── Yes → Is it bulk PII (>1M records) or law enforcement?
        ├── No → MODERATE
        └── Yes → Likely HIGH
```

### PaaS

```
What data will tenants store on the platform?
├── Unknown/unrestricted → Categorize at MODERATE minimum
│   (you can't control what tenants put on a PaaS)
├── Controlled/limited data types → Match to data types above
└── Tenant isolation failures could expose cross-tenant data?
    └── Yes → Consider bumping availability and confidentiality up one level
```

### IaaS

```
IaaS providers typically need HIGH categorization because:
├── Tenants may run any workload type
├── Infrastructure compromise affects all tenants
└── Compute/storage resources could contain any data classification
```

## Step 5: Validate Your Categorization

- [ ] **Cross-check with agency expectations.** Your sponsoring agency may have specific categorization requirements. Some agencies mandate Moderate minimum for all cloud services.
- [ ] **Compare with similar FedRAMP-authorized products.** Look up comparable CSOs on the FedRAMP Marketplace (marketplace.fedramp.gov) and check their impact levels.
- [ ] **Document your rationale.** Write a 1–2 page justification covering: the information types processed, the impact analysis for each dimension, and the resulting categorization. This goes into your SSP as Appendix K.
- [ ] **Review with your 3PAO.** Your assessor should validate the categorization early. If they disagree, it's much cheaper to fix now than after you've built documentation for the wrong baseline.

## Common Mistakes

**Categorizing too low to save money.** The 3PAO will catch this, and you'll have to redo everything at the higher baseline. It's more expensive in the long run.

**Categorizing too high "just to be safe."** Going from Moderate (323 controls) to High (410 controls) adds $500K–$1.5M+ in costs and months of additional work. Only categorize at High if the data genuinely warrants it.

**Forgetting about metadata.** Your system might not store "the data" but it might store metadata about the data (user names, access patterns, search queries) that has its own sensitivity. Account for this.

**Ignoring availability for SaaS.** Many SaaS providers correctly categorize at Moderate for confidentiality and integrity but underrate availability. If agencies can't access your service, what's the operational impact?

## LI-SaaS Consideration

FedRAMP offers a Low Impact SaaS (LI-SaaS) category for SaaS systems that are genuinely low-impact across all three dimensions. LI-SaaS has the same 156 controls as Low, but only 66 are tested by the 3PAO (the rest are attested). This path is faster and cheaper, but it's only appropriate for systems where a security breach would have truly limited consequences (e.g., collaboration tools with no sensitive data, public-facing informational services).
