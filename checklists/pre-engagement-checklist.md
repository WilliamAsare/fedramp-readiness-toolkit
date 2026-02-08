# Pre-Engagement Checklist

Before starting the FedRAMP process, work through this checklist to make sure your organization is actually ready to commit. FedRAMP is a 12–18 month effort that requires dedicated staff, significant budget, and sustained executive support. Skipping this assessment phase is one of the most common (and expensive) mistakes CSPs make.

## Organizational Readiness

- [ ] **Executive sponsor identified.** You need a C-level or VP who will champion the effort, allocate budget, and break down internal roadblocks. This person must understand that FedRAMP is an ongoing commitment, not a one-time project.
- [ ] **Dedicated team assembled.** Plan for 8–10 FTEs across security, engineering, compliance, and project management. Smaller teams are possible with heavy automation, but 3 is the absolute minimum (and that's a stretch).
- [ ] **Budget allocated.** Confirm realistic budget for your target baseline:
  - Low/LI-SaaS: $250K–$500K initial, $100K–$200K/year ongoing
  - Moderate: $500K–$1.5M initial, $200K–$500K/year ongoing
  - High: $1M–$3M+ initial, $500K–$1M/year ongoing
- [ ] **Timeline expectations set.** Traditional authorization takes 12–18 months. FedRAMP 20x may reduce this to weeks for Low, but Moderate and High will take longer. Don't promise agency customers a date you can't hit.
- [ ] **Legal review of FedRAMP obligations.** Your legal team should review the continuous monitoring requirements, incident reporting obligations (US-CERT notification within 1 hour for certain incidents), and data handling restrictions.

## Technical Readiness

- [ ] **Cloud infrastructure on FedRAMP-authorized IaaS/PaaS.** If you're not already on AWS GovCloud, Azure Government, or GCP Assured Workloads, plan for migration. Building on authorized infrastructure lets you inherit a large chunk of controls.
- [ ] **Authorization boundary defined (at least in draft).** You should be able to draw a line around "this is the system" and identify every component, data flow, and external connection. This doesn't need to be final, but you need a starting point.
- [ ] **FIPS 140-2/140-3 validated cryptography in use.** Check now. This is a strict pass/fail requirement. If you're using non-validated crypto libraries, remediation can take months. Run the FIPS crypto audit in the federal mandates checklist.
- [ ] **Vulnerability management program active.** You need regular scanning (OS, web app, database, container), a patching process, and the ability to remediate High vulns within 30 days.
- [ ] **Centralized logging and monitoring.** Audit logs must be collected, retained, and reviewable. If you don't have centralized logging today, stand it up before starting FedRAMP.
- [ ] **Multi-factor authentication deployed.** MFA must be enforced for all privileged access and supported for all users. Agency CAC/PIV credential support is a separate requirement.

## Business Readiness

- [ ] **Federal agency sponsor identified (for Agency Authorization path).** You need at least one federal agency willing to sponsor your authorization. Ideally, you already have a federal customer or prospect.
- [ ] **Market demand validated.** FedRAMP is expensive. Make sure there's enough federal revenue potential to justify the investment. Talk to your sales team about pipeline.
- [ ] **Commercial vs. government parity decision made.** Will you maintain a single codebase/infrastructure for both commercial and government, or build a separate government environment? Single infrastructure is strongly recommended to avoid drift, but some CSPs need isolation for High baseline.
- [ ] **FedRAMP PMO contacted.** Schedule an intake call with the FedRAMP PMO (info@fedramp.gov). They provide free guidance on authorization paths, timeline expectations, and common pitfalls. Do this in your first week.

## Existing Compliance Leverage

- [ ] **Inventory existing certifications.** List all current compliance certifications and audits (SOC 2 Type II, ISO 27001, HIPAA, PCI DSS, StateRAMP, etc.). These provide reusable evidence and controls.
- [ ] **Run cross-framework mapping.** Use `config/fedramp-controls-mapping.yaml` to identify which FedRAMP controls overlap with your existing certifications.
- [ ] **Gather recent audit reports.** Collect your most recent SOC 2 report, penetration test results, and vulnerability scan reports. These will feed into the gap analysis.

## Next Steps

Once everything above is checked:

1. Complete the **FIPS 199 categorization** (`checklists/fips199-categorization.md`) to confirm your impact level
2. Run through the **federal mandates checklist** (`checklists/federal-mandates-checklist.md`) for the six pass/fail requirements
3. Run the **gap analysis tool** (`scripts/gap_analysis.py`) to quantify your readiness
4. Select a 3PAO using the **3PAO selection guide** (`checklists/3pao-selection-guide.md`)
