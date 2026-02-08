# 3PAO Selection Guide

A Third-Party Assessment Organization (3PAO) is required for FedRAMP authorization. They conduct the Readiness Assessment (RAR), the initial Security Assessment, and annual assessments thereafter. Choosing the wrong 3PAO is expensive to fix — switching mid-assessment means starting over.

## Prerequisites

3PAOs must be accredited by the American Association for Laboratory Accreditation (A2LA) under ISO/IEC 17020:2012. Only A2LA-accredited organizations can perform FedRAMP assessments.

Find the current list at: https://a2la.qualtraxcloud.com/ShowDocument.aspx?ID=5621

## Selection Criteria

### Must-Have

- [ ] **A2LA accreditation is current and in good standing.** Verify directly with A2LA, not just the 3PAO's website.
- [ ] **Experience at your impact level.** A 3PAO experienced with Low assessments may struggle with High. Ask for their track record specifically at your baseline.
- [ ] **No conflicts of interest.** The 3PAO cannot have provided consulting or remediation services to you for the same system. FedRAMP requires independence.
- [ ] **Availability aligned with your timeline.** Good 3PAOs are booked months out. Confirm they can start when you need them.

### Strongly Recommended

- [ ] **Experience with your cloud provider.** A 3PAO familiar with AWS GovCloud will be more efficient assessing an AWS-based system than one that primarily assesses Azure environments.
- [ ] **Experience with your service type.** SaaS, PaaS, and IaaS assessments have different focuses. Find a 3PAO that's assessed similar products.
- [ ] **Clear communication about findings.** During your evaluation calls, assess how clearly they explain issues. A 3PAO that can't explain findings clearly will slow you down during remediation.
- [ ] **Track record of successful authorizations.** Ask how many CSPs they've assessed that achieved authorization (vs. failed or abandoned).

### Evaluation Process

- [ ] **Get 3+ quotes.** Pricing varies significantly — $75K–$400K depending on baseline and complexity.
- [ ] **Request sample deliverables.** Ask to see redacted examples of their SAP, SAR, and test case procedures. Quality varies widely.
- [ ] **Ask about their assessment methodology.** How do they handle controls inherited from the cloud provider? How do they test application-layer controls? What tools do they use for vulnerability scanning?
- [ ] **Discuss FedRAMP 20x readiness.** Ask if they're participating in the 20x working groups and how they're adapting their methodology.
- [ ] **Check references.** Talk to 2-3 CSPs the 3PAO has assessed. Ask about responsiveness, thoroughness, and fairness.
- [ ] **Clarify the engagement scope.** Make sure the quote covers: RAR (if needed), SAP development, security testing, SAR writing, and support during PMO review. Some 3PAOs charge separately for each phase.

## Cost Expectations

| Baseline | RAR | Initial Assessment | Annual Assessment |
|----------|-----|-------------------|-------------------|
| Low/LI-SaaS | $25K–$50K | $75K–$150K | $50K–$100K |
| Moderate | $40K–$75K | $150K–$300K | $100K–$200K |
| High | $50K–$100K | $250K–$400K | $150K–$300K |

These are rough ranges. Actual costs depend on system complexity, number of components, and geographic distribution.

## Red Flags

- 3PAO offers to both consult on remediation AND perform the assessment (conflict of interest)
- Pricing that's dramatically below market (they may cut corners)
- Can't provide references from successful FedRAMP authorizations
- Unfamiliar with OSCAL or resistant to machine-readable assessment outputs
- Long delays in responding during the selection process (expect worse during the actual assessment)
