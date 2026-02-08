# FedRAMP Overview

A primer on FedRAMP for people new to federal cloud compliance. If you already know the difference between a P-ATO and an ATO, skip this and head to the [gap analysis guide](guides/gap-analysis.md).

## What FedRAMP actually is

FedRAMP (Federal Risk and Authorization Management Program) is the US government's standardized approach to evaluating cloud services for security. If you sell a cloud product and want federal agencies as customers, your service needs FedRAMP authorization.

The core idea is "do once, use many." Instead of each agency running its own security assessment of your product, FedRAMP creates a reusable security package that any agency can rely on. The program currently covers about 585 cloud service offerings in the FedRAMP Marketplace.

## Impact levels

FedRAMP uses FIPS 199 to categorize systems by how much damage a security breach would cause.

**Low** is for data where a breach would have limited adverse effect. Public-facing websites, collaboration tools that don't handle sensitive data. 156 controls, roughly $250K-$500K total cost.

**Moderate** is where most CSPs land. It covers data where a breach would have a "serious adverse effect." CRM systems, project management tools, email platforms. 323 controls, $500K-$1.5M. About 73% of all FedRAMP authorizations are Moderate.

**High** is for systems where a breach could cause "severe or catastrophic" damage. Law enforcement, financial systems, healthcare data. 410 controls, $1M-$3M+.

There's also **LI-SaaS** (Low Impact SaaS), a lighter path for simple SaaS products. Same 156 controls, but only 66 are tested by the 3PAO while 90 are attested by the CSP.

## How authorization works

There's really only one fully operational path right now: **Agency Authorization**. A federal agency sponsors your cloud service, you prepare a massive documentation package, a third-party assessment organization (3PAO) tests your security controls, and the agency issues an Authority to Operate (ATO).

The old JAB P-ATO path has been effectively replaced. The FedRAMP Authorization Act (December 2022) restructured governance around a FedRAMP Board, a PMO within GSA, and a Technical Advisory Group.

### The typical timeline

For a Moderate authorization, expect:

1. **Preparation (3-6 months):** Impact level decision, 3PAO selection, PMO engagement, documentation kickoff
2. **Documentation (3-6 months):** SSP writing (300-500+ pages), supporting policies, inventory workbooks
3. **Assessment (2-4 months):** 3PAO tests controls, writes the Security Assessment Report
4. **Remediation (1-3 months):** Fix findings, document in POA&M
5. **Authorization (1-3 months):** Agency review and ATO issuance

Total: 12-18 months and $500K-$1.5M for Moderate.

## FedRAMP 20x

Announced March 2025, FedRAMP 20x replaces document-heavy processes with automation-first authorization. The 20x Low pilot completed with 12 authorizations averaging about 5 weeks instead of 12-18 months. The Moderate pilot launched November 2025.

Key changes: control narratives become Key Security Indicators (KSIs) with real-time telemetry, OSCAL machine-readable formats become mandatory (September 2026 deadline), and API-driven compliance reporting replaces manual documentation review.

This toolkit supports both the current Rev 5 Agency path and the 20x transition.

## NIST 800-53 Rev 5

FedRAMP baselines build on NIST SP 800-53 Rev 5, which defines security controls organized into 20 families. FedRAMP uses 18 of those families (PM is agency responsibility, PT is agency discretion).

The eight most scrutinized families: Access Control (AC), System and Communications Protection (SC), System and Information Integrity (SI), Audit and Accountability (AU), Identification and Authentication (IA), Configuration Management (CM), Incident Response (IR), and Assessment/Authorization/Monitoring (CA).

Rev 5 added the **Supply Chain Risk Management (SR)** family, now mandatory across all baselines.

## The six non-negotiable requirements

Every Readiness Assessment must validate these. Zero flexibility:

1. **FIPS 140-2/140-3 validated cryptographic modules** everywhere cryptography is used
2. **CAC/PIV credential** authentication support for agency users
3. System operating at **Digital Identity Level 2 or 3**
4. Ability to remediate **High vulns in 30 days, Moderate in 90, Low in 180**
5. Compliance with **federal records management** requirements (NARA, FOIA)
6. External DNS supporting **DNSSEC**

Failing any one means your Readiness Assessment Report gets rejected.

## Common failure points

**Boundary definition errors** are the #1 cause of RAR rejection. Your authorization boundary must account for every location where federal data exists, every component in the SSP, and all external connections. Inconsistencies between diagrams and narrative get flagged immediately.

**Non-FIPS cryptography** is the most common technical failure. Every data entry/exit point and all internal paths must use validated modules.

**Unauthorized external services** will fail assessment. Every third-party service touching federal data must itself be FedRAMP authorized at the appropriate level.

## Where to go from here

- [Getting Started](getting-started.md) to install the toolkit and run your first gap analysis
- [Gap Analysis Guide](guides/gap-analysis.md) to assess your current readiness
- [SSP Development Guide](guides/ssp-development.md) to start building your documentation package
- The `checklists/` directory for baseline-specific compliance checklists
