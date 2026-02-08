# FedRAMP Moderate Baseline Checklist

The Moderate baseline covers 323 controls across 17 control families and represents 73% of all FedRAMP authorizations. If you're building a SaaS product for federal agencies and it handles PII or supports significant agency operations, this is almost certainly your baseline.

This checklist is organized by the eight most scrutinized control families (AC, AU, CA, CM, IA, IR, SC, SI) plus critical items from the remaining families. It focuses on the areas where CSPs most commonly fail.

## Access Control (AC) — ~25 controls at Moderate

The AC family is one of the largest and most complex. Assessors spend significant time here.

- [ ] **AC-1: Access control policy and procedures.** Documented policy covering all AC family requirements. Must be reviewed and updated at least every 3 years (policy) and annually (procedures).
- [ ] **AC-2: Account management.** Automated account management using a centralized identity provider. Must support:
  - Defined account types (individual, shared, group, system, guest, temporary)
  - Role-based access control with defined roles documented
  - Account creation, modification, disabling, and removal procedures
  - Annual review of all accounts
  - Automatic disabling of inactive accounts after 90 days (FedRAMP parameter)
  - Automatic logout after 15 minutes of inactivity for non-privileged, 10 minutes for privileged (AC-12 / SC-10)
- [ ] **AC-3: Access enforcement.** RBAC or ABAC consistently enforced. Demonstrate with configuration evidence, not just policy.
- [ ] **AC-4: Information flow enforcement.** Network segmentation between boundary zones. Security groups, NACLs, or firewall rules restricting traffic to only required flows.
- [ ] **AC-5: Separation of duties.** Defined incompatible duties. Common: developers cannot deploy to production, security reviewers cannot modify security configurations they audit.
- [ ] **AC-6: Least privilege.** Privileged access restricted to minimum necessary. Service accounts use minimal permissions. Periodic privilege reviews documented.
- [ ] **AC-7: Unsuccessful logon attempts.** Account lockout after 3 consecutive failed attempts (FedRAMP parameter). Lockout for minimum 30 minutes or until administrator unlock.
- [ ] **AC-8: System use notification.** Login banner displayed before authentication. Must include: authorized use only, monitoring consent, consequences of misuse.
- [ ] **AC-17: Remote access.** All remote access encrypted via VPN or equivalent. Session timeouts enforced. Remote access authorization documented per user.

## Audit and Accountability (AU) — ~15 controls at Moderate

- [ ] **AU-2: Audit events.** Define auditable events covering: successful/failed logins, privilege escalation, object access, policy changes, administrative actions. Must capture: user identity, event type, timestamp, source/destination, success/failure.
- [ ] **AU-3: Content of audit records.** Each record includes: what happened, when, where, source, outcome, and who.
- [ ] **AU-6: Audit review, analysis, and reporting.** Regular log review process (automated preferred). Correlate audit records across components. Report findings to designated personnel.
- [ ] **AU-7: Audit reduction and report generation.** Ability to search, sort, filter, and report on audit data. SIEM or log analysis tooling required.
- [ ] **AU-9: Protection of audit information.** Audit logs protected from unauthorized modification or deletion. Immutable logging (write-once storage) strongly recommended.
- [ ] **AU-11: Audit record retention.** Retain audit records for minimum 1 year (FedRAMP Moderate parameter), with at least 90 days immediately available for analysis.
- [ ] **AU-12: Audit generation.** All components within the boundary generate audit records for the events defined in AU-2.

## Assessment, Authorization, and Monitoring (CA) — ~10 controls at Moderate

- [ ] **CA-2: Control assessments.** Annual assessment by an accredited 3PAO. Assessment plan (SAP) submitted at least 60 days before authorization anniversary.
- [ ] **CA-3: Information exchange.** All interconnections with external systems documented via Interconnection Security Agreements (ISAs) or MOUs.
- [ ] **CA-5: Plan of action and milestones.** Active POA&M tracking all open vulnerabilities and weaknesses. Updated monthly.
- [ ] **CA-7: Continuous monitoring.** Continuous monitoring strategy documented and implemented. Monthly deliverables submitted on schedule.
- [ ] **CA-9: Internal system connections.** All internal connections between authorization boundary components documented.

## Configuration Management (CM) — ~15 controls at Moderate

- [ ] **CM-1: Configuration management policy.** Documented CM policy and procedures reviewed on schedule.
- [ ] **CM-2: Baseline configuration.** Documented baseline configurations for all system components. Use CIS Benchmarks or DISA STIGs as starting points. Deviations documented and justified.
- [ ] **CM-3: Configuration change control.** Formal change management process with: request, review, approval, implementation, and verification. Security impact analysis for all changes.
- [ ] **CM-4: Impact analysis.** Security impact analysis before implementing changes. Document how the change affects the authorization boundary.
- [ ] **CM-6: Configuration settings.** Restrictive configuration settings implemented per CIS/STIG guidelines. Document any deviations with justification.
- [ ] **CM-7: Least functionality.** Disable unnecessary ports, protocols, services, and functions. Document what's enabled and why.
- [ ] **CM-8: System component inventory.** Accurate, current inventory of all hardware, software, and firmware within the boundary. Updated with every change.

## Identification and Authentication (IA) — ~12 controls at Moderate

- [ ] **IA-2: Identification and authentication (organizational users).** Unique user IDs for all users. MFA required for all privileged and non-privileged network access.
  - IA-2(1): MFA for privileged accounts
  - IA-2(2): MFA for non-privileged accounts
  - IA-2(12): PIV/CAC acceptance (see federal mandates checklist)
- [ ] **IA-4: Identifier management.** Unique identifiers assigned to all users, devices, and services. Identifiers disabled after 90 days of inactivity.
- [ ] **IA-5: Authenticator management.** Password complexity requirements:
  - Minimum 12 characters (FedRAMP Moderate parameter)
  - Mix of upper, lower, numeric, and special characters
  - Changed at least every 60 days (though NIST 800-63B recommends against forced rotation — follow FedRAMP's specific parameter)
  - No reuse of last 24 passwords
- [ ] **IA-8: Identification and authentication (non-organizational users).** External users identified and authenticated. PIV/CAC for federal users.

## Incident Response (IR) — ~10 controls at Moderate

- [ ] **IR-1: Incident response policy and procedures.** Documented IR policy and plan reviewed annually.
- [ ] **IR-2: Incident response training.** IR team trained within 90 days of role assignment, then annually.
- [ ] **IR-3: Incident response testing.** IR plan tested annually via tabletop exercise, simulation, or actual incident review.
- [ ] **IR-4: Incident handling.** Defined process for detection, analysis, containment, eradication, and recovery. Includes evidence preservation.
- [ ] **IR-5: Incident monitoring.** Continuous tracking of security incidents.
- [ ] **IR-6: Incident reporting.** US-CERT notification requirements:
  - Category 1 (unauthorized access): report within 1 hour
  - Category 2 (denial of service): report within 2 hours
  - All incidents: report to sponsoring agency and FedRAMP PMO per timeline
- [ ] **IR-8: Incident response plan.** Comprehensive IR plan addressing: mission, team structure, roles, communication, phases, and integration with other plans.

## System and Communications Protection (SC) — ~25 controls at Moderate

- [ ] **SC-1: Policy and procedures.** Documented SC policy reviewed on schedule.
- [ ] **SC-5: Denial-of-service protection.** DDoS mitigation in place (AWS Shield, Azure DDoS Protection, Cloud Armor, or equivalent).
- [ ] **SC-7: Boundary protection.** Boundary devices (firewalls, proxies) at all external connections. Default-deny rule. Only authorized traffic allowed.
  - SC-7(3): Access points limited and monitored
  - SC-7(4): External telecommunications services routed through managed interfaces
  - SC-7(5): Deny by default, allow by exception
- [ ] **SC-8: Transmission confidentiality and integrity.** All data in transit encrypted using FIPS-validated cryptography. TLS 1.2 minimum.
- [ ] **SC-12: Cryptographic key establishment and management.** Key management procedures documented. Key rotation on schedule.
- [ ] **SC-13: Cryptographic protection.** FIPS 140-2/3 validated modules for all cryptographic operations. (See federal mandates checklist for detailed verification.)
- [ ] **SC-20/21/22: DNS (DNSSEC).** DNSSEC configured and validated. (See federal mandates checklist.)
- [ ] **SC-28: Protection of information at rest.** All federal data encrypted at rest using FIPS-validated cryptography.

## System and Information Integrity (SI) — ~15 controls at Moderate

- [ ] **SI-1: Policy and procedures.** Documented SI policy reviewed on schedule.
- [ ] **SI-2: Flaw remediation.** Patching within FedRAMP SLAs (30/90/180 days). Monthly patch cycle minimum.
- [ ] **SI-3: Malicious code protection.** Anti-malware deployed on all applicable components. Real-time scanning enabled. Signatures updated automatically.
- [ ] **SI-4: System monitoring.** Inbound and outbound traffic monitored. Alerts for suspicious activity. SIEM integration.
- [ ] **SI-5: Security alerts and advisories.** Process for monitoring security advisories (CVEs, vendor alerts) and responding.
- [ ] **SI-10: Information input validation.** Input validation on all user-supplied data. Protection against injection attacks.
- [ ] **SI-16: Memory protection.** ASLR, DEP, stack canaries, or equivalent memory protections enabled.

## Remaining Critical Control Families

### Contingency Planning (CP)
- [ ] **CP-2: Contingency plan.** Documented contingency/DR plan reviewed annually.
- [ ] **CP-4: Contingency plan testing.** Tested annually. Results documented.
- [ ] **CP-9: System backup.** Regular backups of system data and configurations. Tested restoration.
- [ ] **CP-10: System recovery.** Defined RTO and RPO. Recovery procedures documented and tested.

### Personnel Security (PS)
- [ ] **PS-3: Personnel screening.** Background checks for all personnel with access to federal data. Rescreening per risk level.
- [ ] **PS-4: Personnel termination.** Access revoked same day as termination. Equipment recovered. Exit procedures documented.

### Risk Assessment (RA)
- [ ] **RA-3: Risk assessment.** Documented risk assessment updated annually or after significant changes.
- [ ] **RA-5: Vulnerability monitoring and scanning.** Monthly vulnerability scans of all components. Remediation within SLA.

### Supply Chain Risk Management (SR) — New in Rev 5
- [ ] **SR-1: Policy and procedures.** Supply chain risk management policy documented.
- [ ] **SR-2: Supply chain risk management plan.** Covers all third-party components and services.
- [ ] **SR-3: Supply chain controls and processes.** Due diligence on third-party providers. SBOM maintained for key components.

## Using the Gap Analysis Tool

Run the gap analysis against the Moderate baseline to see exactly where you stand:

```bash
python scripts/gap_analysis.py \
  --baseline moderate \
  --input your-implementation-status.yaml \
  --output-dir reports/gap-analysis/
```

The gap report shows compliance percentage by control family, highlights critical gaps, and estimates remediation effort.
