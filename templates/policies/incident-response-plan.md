# Incident Response Plan

**Document Version:** 1.0
**Last Reviewed:** [DATE]
**Next Review Due:** [DATE + 1 year]
**Document Owner:** [CISO/Security Director Name]
**Approved By:** [Authorizing Official Name]

## 1. Purpose

This plan establishes the incident response capabilities for [SYSTEM NAME] in accordance with NIST SP 800-53 Rev 5 IR family controls and FedRAMP requirements.

## 2. Scope

Covers all security incidents affecting [SYSTEM NAME] and the federal data it processes. Applies to all personnel, contractors, and third-party service providers.

## 3. Incident Response Team

| Role | Name | Contact | Backup |
|------|------|---------|--------|
| IR Lead | [NAME] | [PHONE/EMAIL] | [BACKUP NAME] |
| Security Analyst | [NAME] | [PHONE/EMAIL] | [BACKUP NAME] |
| System Administrator | [NAME] | [PHONE/EMAIL] | [BACKUP NAME] |
| Communications Lead | [NAME] | [PHONE/EMAIL] | [BACKUP NAME] |
| Legal Counsel | [NAME] | [PHONE/EMAIL] | [BACKUP NAME] |
| Executive Sponsor | [NAME] | [PHONE/EMAIL] | [BACKUP NAME] |

### External Contacts

| Organization | Contact | Purpose |
|-------------|---------|---------|
| FedRAMP PMO | info@fedramp.gov | FedRAMP incident notification |
| US-CERT | soc@us-cert.gov / 1-888-282-0870 | Federal incident reporting |
| Sponsoring Agency ISSO | [CONTACT] | Agency notification |
| 3PAO | [CONTACT] | Assessment-related incidents |
| Cloud Provider Security | [CONTACT] | Infrastructure incidents |
| Law Enforcement | [LOCAL FBI FIELD OFFICE] | Criminal activity |

## 4. Incident Categories and Reporting Timelines

FedRAMP aligns with US-CERT incident categories. Reporting timelines are strict.

| Category | Description | Reporting Timeline |
|----------|------------|-------------------|
| CAT 1 | Unauthorized Access | Within 1 hour of detection |
| CAT 2 | Denial of Service | Within 2 hours of detection |
| CAT 3 | Malicious Code | Within 1 hour if spreading |
| CAT 4 | Improper Usage | Within 1 week |
| CAT 5 | Scans/Probes/Recon | Monthly via ConMon |
| CAT 6 | Investigation | As needed |

## 5. Incident Response Phases

### 5.1 Preparation

- IR team trained within 90 days of assignment (IR-2)
- IR plan tested annually via tabletop exercise (IR-3)
- Monitoring tools operational (SIEM, IDS/IPS, endpoint protection)
- Forensic tools and media available
- Communication channels (out-of-band) tested
- Evidence collection procedures documented

### 5.2 Detection and Analysis

**Detection sources:**
- SIEM alerts and correlation rules
- IDS/IPS signatures
- Antivirus/endpoint detection alerts
- User reports
- Vulnerability scan findings
- Cloud provider security alerts (GuardDuty, Defender, SCC)
- External notification (US-CERT, vendor advisories)

**Analysis steps:**
1. Validate the alert (true positive vs. false positive)
2. Determine scope (affected systems, data, and users)
3. Assess severity using the category table above
4. Assign incident number and begin documentation
5. Notify IR Lead and begin escalation per timeline

### 5.3 Containment

**Short-term containment:**
- Isolate affected systems from the network
- Block malicious IP addresses, domains, or accounts
- Disable compromised user accounts
- Preserve volatile evidence (memory dumps, active connections)

**Long-term containment:**
- Apply temporary mitigations (firewall rules, configuration changes)
- Stand up clean replacement systems if needed
- Continue monitoring for related activity

**Evidence preservation:**
- Create forensic images of affected systems before remediation
- Preserve all logs (do not rotate or delete)
- Document chain of custody for all evidence
- Hash all evidence artifacts (SHA-256)

### 5.4 Eradication

- Identify and remove root cause
- Remove malware, unauthorized accounts, or backdoors
- Patch exploited vulnerabilities
- Reset compromised credentials
- Verify removal through scanning and monitoring

### 5.5 Recovery

- Restore systems from known-good backups or rebuilt images
- Verify system integrity before returning to production
- Monitor restored systems closely for recurrence
- Gradually restore service (not all at once)
- Confirm normal operations with system owner

### 5.6 Post-Incident Activity

- Conduct lessons-learned meeting within 2 weeks
- Document incident timeline, actions taken, and outcomes
- Update IR plan based on findings
- Update detection rules to catch similar incidents
- Provide final incident report to sponsoring agency and FedRAMP PMO
- If PII was breached, follow breach notification requirements per [OMB M-17-12]

## 6. Communication Procedures

**Internal escalation:** IR analyst → IR Lead → CISO → Executive Sponsor

**Agency notification:** IR Lead contacts sponsoring agency ISSO within the required timeframe. Use encrypted email or phone.

**US-CERT notification:** IR Lead submits report via US-CERT portal (https://us-cert.cisa.gov/report) within the required timeframe.

**FedRAMP PMO notification:** Email info@fedramp.gov with incident summary, affected systems, and remediation status.

**User notification (if required):** Communications Lead drafts notification. Legal Counsel reviews. Executive Sponsor approves.

## 7. Training and Testing

- All IR team members complete initial training within 90 days of assignment
- Annual refresher training for all IR team members
- Annual IR plan test (tabletop exercise minimum)
- Exercise results documented and gaps remediated
- Post-exercise review within 2 weeks

## 8. Integration with Other Plans

This IR plan integrates with:
- Contingency Plan (CP) — for incidents requiring DR activation
- Configuration Management Plan — for tracking incident-related changes
- Continuous Monitoring Strategy — for ongoing detection and response

---

*This is a template. Replace all bracketed [PLACEHOLDERS] with your organization's specific values, names, and contacts before submission.*
