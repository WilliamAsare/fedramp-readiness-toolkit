# FedRAMP 20x Transition Readiness Checklist

FedRAMP 20x is the most significant overhaul of the program since its inception. It replaces document-heavy processes with automation-first authorization, using machine-readable evidence and real-time telemetry instead of 500-page Word documents. The transition is phased, and CSPs need to prepare now.

## Current 20x Timeline

| Phase | Status | What It Covers |
|-------|--------|---------------|
| Phase 1: 20x Low Pilot | Completed | 12 authorizations from 26 submissions, avg ~5 weeks |
| Phase 2: 20x Moderate Pilot | Active (Nov 2025) | Moderate baseline with automated assessment |
| Phase 3: Formalized Low/Moderate | FY26 Q3-Q4 | Official requirements, 3PAO accreditation for 20x |
| Phase 4: 20x High Pilot | FY27 Q1-Q2 | High baseline; Rev 5 providers must go machine-readable |
| Phase 5: End of Rev 5 Agency Auth | FY27 Q3-Q4 | No new authorizations under traditional Rev 5 path |

**Critical deadline:** September 2026 — all CSPs must transition authorization packages to OSCAL format.

## What 20x Changes

20x replaces traditional control narratives with three key concepts:

1. **Key Security Indicators (KSIs):** Measurable security outcomes that replace paragraph-long control implementation descriptions. Think of them as pass/fail signals that can be automatically verified.

2. **Machine-readable evidence:** Instead of screenshots in Word documents, evidence is submitted via APIs and OSCAL documents that can be automatically validated.

3. **Continuous telemetry:** Real-time (or near-real-time) security data flowing from your systems to demonstrate ongoing compliance, rather than monthly snapshots.

## Preparation Checklist

### OSCAL Readiness (Required by September 2026)

- [ ] **All authorization documents in OSCAL format.** SSP, SAP, SAR, and POA&M must be machine-readable OSCAL JSON. The toolkit generates OSCAL by default.
  - Run: `python scripts/ssp_generator.py --format oscal`
- [ ] **Control implementation statements are structured.** Not just prose paragraphs — each implementation statement maps to specific components and responsibility assignments.
- [ ] **OSCAL validation passes.** All generated documents validate against FedRAMP's Schematron rules without errors.
  - Run: `python scripts/oscal_validator.py --input your-ssp.json --baseline moderate`
- [ ] **Profile resolution works correctly.** Your OSCAL SSP correctly references the FedRAMP profile and resolves all required controls.

### API-Driven Evidence Generation

- [ ] **Evidence can be collected programmatically.** Manual evidence collection (screenshots, exported CSVs) should be replaced with API-driven collection.
  - Run: `python scripts/evidence_collector.py --provider aws --families AC,SC,AU`
- [ ] **Evidence is timestamped and integrity-hashed.** Every evidence artifact should include collection timestamp and SHA-256 hash.
- [ ] **Evidence maps directly to controls.** Each artifact includes metadata linking it to specific control IDs and components.
- [ ] **Evidence generation is repeatable.** Running the same collection twice produces consistent, comparable results.

### Continuous Monitoring Infrastructure

- [ ] **Real-time vulnerability data available via API.** Cloud security services (Security Hub, Defender, SCC) provide continuous posture data that can be queried programmatically.
- [ ] **Configuration compliance is continuously monitored.** AWS Config, Azure Policy, or GCP Assured Workloads continuously evaluate your infrastructure against security rules.
- [ ] **Compliance dashboard operational.** A dashboard (Grafana, Streamlit, or custom) shows real-time compliance posture by control family.
  - Run: `python scripts/compliance_scorer.py --dashboard`
- [ ] **Automated alerting for compliance drift.** When a control implementation degrades (e.g., encryption disabled, security group opened), alerts fire immediately.
- [ ] **Month-over-month trend data retained.** Compliance scoring stored in a database for trend analysis.

### Key Security Indicator Preparation

KSI definitions are still being finalized by FedRAMP's Automating Assessments working group. Based on the 20x Low pilot and published working group materials:

- [ ] **Identify which of your controls map to likely KSIs.** Focus on controls that have measurable, automatable outcomes:
  - Encryption status (on/off) per storage resource
  - MFA enforcement (enabled/disabled) per user account
  - Vulnerability age per finding
  - Logging enabled (yes/no) per service
  - Network segmentation rules per boundary component
- [ ] **Build automated checks for these indicators.** Each KSI should have a corresponding automated test.
- [ ] **Ensure indicators can report status via API.** KSIs need to be queryable, not just documented.

### Engagement with 20x Working Groups

FedRAMP operates four working groups on GitHub that are shaping 20x requirements:

- [ ] **Follow the Automating Assessments working group.** This group is defining KSIs and machine-readable evidence standards. This is the most relevant to your toolkit preparation.
- [ ] **Follow the Vulnerability Management working group.** They're defining how vuln data should be reported under 20x.
- [ ] **Monitor working group outputs for your baseline.** Pay attention to the Moderate pilot outcomes if you're targeting Moderate.
- [ ] **Subscribe to FedRAMP blog and changelog.** Set up RSS monitoring for fedramp.gov updates.

## Dual-Track Strategy

For CSPs starting today, the recommended approach is:

1. **Build for the current Rev 5 Agency Authorization path.** This is the only fully operational path for most CSPs right now.
2. **Use OSCAL from day one.** Even if your agency accepts Word documents, generate OSCAL as your primary format. You'll need to convert eventually.
3. **Automate evidence collection now.** Don't build a manual evidence process that you'll have to replace.
4. **Track 20x milestones quarterly.** As 20x phases go live, validate your toolkit outputs against the new requirements.

## What NOT to Do

- Don't wait for 20x to start your FedRAMP process. The traditional path is still available and agencies still need authorized CSPs now.
- Don't build a "20x-only" compliance approach unless you're specifically accepted into the Moderate or High pilot programs.
- Don't assume 20x means less work. It means different work — automation instead of documentation, but the security requirements are the same.
- Don't ignore your 3PAO's guidance on 20x readiness. They're adapting their methodologies too and can advise on what's coming.
