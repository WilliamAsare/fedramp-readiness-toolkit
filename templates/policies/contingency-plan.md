# Information System Contingency Plan

**Document Version:** 1.0
**Last Reviewed:** [DATE]
**Next Review Due:** [DATE + 1 year]
**Last Test Date:** [DATE]
**Document Owner:** [CISO/Security Director Name]

## 1. Purpose

Establishes contingency and disaster recovery procedures for [SYSTEM NAME] per NIST SP 800-53 Rev 5 CP controls and FedRAMP requirements. This plan ensures mission-essential functions can resume within defined recovery objectives.

## 2. System Overview

**System Name:** [SYSTEM NAME]
**FIPS 199 Impact Level:** [Low / Moderate / High]
**Primary Hosting:** [AWS GovCloud / Azure Government / GCP Assured Workloads]
**Primary Region:** [REGION]
**DR Region:** [REGION]

## 3. Recovery Objectives

| Metric | Target | Justification |
|--------|--------|--------------|
| **Recovery Time Objective (RTO)** | [X hours] | Maximum acceptable downtime |
| **Recovery Point Objective (RPO)** | [X hours] | Maximum acceptable data loss |
| **Maximum Tolerable Downtime (MTD)** | [X hours] | Business impact threshold |

## 4. Roles and Responsibilities

| Role | Name | Contact | Responsibility |
|------|------|---------|---------------|
| Contingency Plan Coordinator | [NAME] | [CONTACT] | Overall CP execution |
| IT Recovery Lead | [NAME] | [CONTACT] | Technical recovery |
| Data Recovery Lead | [NAME] | [CONTACT] | Data restoration |
| Communications Lead | [NAME] | [CONTACT] | Stakeholder communication |
| Executive Authority | [NAME] | [CONTACT] | CP activation decision |

## 5. Contingency Plan Activation

### 5.1 Activation Criteria

The CP is activated when any of the following occur:
- System downtime exceeds [THRESHOLD, e.g., 1 hour] without resolution
- Primary region/data center becomes unavailable
- Data corruption or loss affecting federal data
- Security incident requiring full system rebuild
- Natural disaster or infrastructure failure affecting primary hosting

### 5.2 Activation Process

1. Incident detected and escalated to Contingency Plan Coordinator
2. Coordinator assesses situation and recommends activation to Executive Authority
3. Executive Authority authorizes CP activation
4. Coordinator notifies all CP team members and sponsoring agency
5. Recovery teams begin execution per Phase assignments below

## 6. Recovery Strategy

### 6.1 Data Backup (CP-9)

| Data Type | Backup Method | Frequency | Retention | Storage Location |
|-----------|--------------|-----------|-----------|-----------------|
| Application databases | [Automated snapshots] | [Every X hours] | [X days] | [DR Region] |
| Object storage | [Cross-region replication] | [Real-time] | [Per retention policy] | [DR Region] |
| Configuration data | [IaC in version control] | [On every change] | [Indefinite] | [Git repo] |
| Audit logs | [Replicated to DR] | [Real-time] | [Per AU-11 requirements] | [DR Region] |
| Secrets/keys | [Replicated KMS] | [Real-time] | [Per key rotation schedule] | [DR Region] |

### 6.2 Alternate Processing Site (CP-7, High baseline)

**DR Site:** [LOCATION/REGION]
**Activation Time:** [HOURS to operational]
**Capacity:** [Full / Reduced]

### 6.3 Recovery Procedures

**Phase 1: Assessment (0-1 hours)**
1. Assess scope and severity of disruption
2. Determine if primary site is recoverable or if failover is required
3. Notify sponsoring agency and FedRAMP PMO

**Phase 2: Infrastructure Recovery (1-X hours)**
1. If failover: activate DR infrastructure using [IaC TOOL — Terraform/CloudFormation]
2. Verify network connectivity and security controls in DR environment
3. Restore DNS to point to DR environment
4. Verify FIPS-validated cryptography operational in DR environment

**Phase 3: Data Recovery (X-Y hours)**
1. Restore databases from most recent backup
2. Verify data integrity (checksums, row counts, application validation)
3. Quantify data loss against RPO
4. Document any data gaps

**Phase 4: Application Recovery (Y-Z hours)**
1. Deploy application components to DR infrastructure
2. Run application health checks
3. Verify all security controls operational (MFA, logging, encryption, boundary protection)
4. Conduct limited functional testing

**Phase 5: Validation and Resumption**
1. Verify service is operational with full functionality
2. Run security scans against DR environment
3. Notify sponsoring agency of recovery completion
4. Begin monitoring for anomalies

## 7. Plan Testing (CP-4)

The contingency plan is tested annually using one of these methods:

- **Tabletop exercise:** Walk through the CP with all team members, discussing each step
- **Simulation:** Simulate a disruption and execute recovery procedures in a test environment
- **Parallel test:** Recover to DR site while primary remains operational, verify functionality
- **Full interruption test:** (Highest confidence) Actually fail over to DR and verify recovery

Test results must be documented including: what was tested, outcomes, issues discovered, and remediation actions.

## 8. Plan Maintenance

- Reviewed and updated at least annually
- Updated after significant system changes
- Updated after each CP test based on lessons learned
- Updated after any actual contingency activation
- Contact information verified quarterly

---

*Replace all [PLACEHOLDERS] with your organization's specific values. Attach the most recent CP test report as an appendix.*
