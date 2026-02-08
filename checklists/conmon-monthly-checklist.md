# Continuous Monitoring Monthly Checklist

FedRAMP authorization is the starting line, not the finish. Failure to maintain continuous monitoring (ConMon) can result in ATO suspension or revocation. This checklist covers the monthly deliverables and actions required to stay in good standing.

## Monthly Deliverables

Due to the sponsoring agency and FedRAMP PMO by the agreed-upon date each month (typically within 30 days of the end of the reporting month):

- [ ] **Updated POA&M.** Current Plan of Action & Milestones reflecting all open vulnerabilities, deviations, and operational requirements.
  - New findings added from this month's scans
  - Remediated items marked as closed with evidence
  - SLA status updated (days open vs. deadline)
  - Risk adjustments documented with justification
  - Run: `python scripts/poam_manager.py --update --scan-dir scans/YYYY-MM/`

- [ ] **Vulnerability scan files (raw).** Upload the actual scan output files, not just summaries:
  - [ ] Operating system / infrastructure vulnerability scans
  - [ ] Web application vulnerability scans
  - [ ] Database vulnerability scans
  - [ ] Container image vulnerability scans (if applicable)
  - Scans must be authenticated (unauthenticated >10% triggers escalation)
  - Run: `python scripts/scan_aggregator.py --month YYYY-MM --output-dir deliverables/`

- [ ] **Updated inventory.** Current Integrated Inventory Workbook reflecting any changes to hardware, software, or network components within the boundary.

- [ ] **Continuous Monitoring Monthly Executive Summary.** A brief report covering:
  - New vulnerabilities discovered
  - Vulnerabilities remediated
  - POA&M status (open items, overdue items, trends)
  - Significant changes to the system
  - Incidents (if any)
  - Overall risk posture

- [ ] **Deviation Requests (if applicable).** Any requests to deviate from FedRAMP requirements must be formally submitted with justification, interim mitigations, and a remediation plan.

- [ ] **Significant Change Requests (if applicable).** Changes to the authorization boundary, data flows, or security architecture require advance notification. Major changes may require re-assessment.

## Monthly Security Actions

### Vulnerability Management

- [ ] **Run all required scans.**
  - OS/infrastructure: at least monthly (weekly recommended)
  - Web application: at least monthly with quarterly authenticated scan
  - Database: at least monthly
  - Container: on every image build plus monthly full scan
- [ ] **Triage new findings.** Categorize each finding by severity and determine remediation approach (fix, mitigate, accept with justification, or mark as false positive).
- [ ] **Check SLA compliance.** Review all open vulnerabilities against FedRAMP deadlines:
  - High: 30 days from discovery
  - Moderate: 90 days from discovery
  - Low: 180 days from discovery
- [ ] **Escalation threshold check.** Verify you are NOT approaching these triggers:
  - 5+ High vulns aged >30 days → Detailed Finding Review
  - 10+ Moderate vulns aged >90 days → DFR
  - Unauthenticated scans >10% of total → DFR
  - Run: `python scripts/poam_manager.py --check-escalation`

### System Monitoring

- [ ] **Review audit logs.** Check for anomalies, unauthorized access attempts, and policy violations.
- [ ] **Verify security tool health.** Confirm all security monitoring tools (SIEM, IDS/IPS, endpoint protection) are operational and current.
- [ ] **Check configuration compliance.** Run configuration scans against baselines (CIS Benchmarks, DISA STIGs) and document any drift.
- [ ] **Review access control.** Check for dormant accounts, privilege creep, and role assignment accuracy.

### Incident Management

- [ ] **Log and report any incidents.** Even minor security events should be logged. Incidents meeting US-CERT reporting thresholds must be reported within the required timeframes.
- [ ] **Update incident response contacts.** Verify the IR team contact list is current.

## Quarterly Actions (Every 3 Months)

- [ ] **Authenticated web application scan.** Beyond the monthly scans, conduct a thorough authenticated scan quarterly.
- [ ] **Review and update policies.** Check all security policies for currency and accuracy.
- [ ] **Tabletop exercise or IR drill.** Conduct an incident response exercise at least quarterly.
- [ ] **POA&M trend analysis.** Generate trend report showing month-over-month vulnerability posture.
  - Run: `python scripts/compliance_scorer.py --trend --months 3`

## Annual Actions

- [ ] **Full security assessment by 3PAO.** Schedule the annual assessment SAP at least 60 days before your authorization anniversary date. Late SAP submission triggers a Corrective Action Plan.
- [ ] **Annual penetration test.** Conduct a full penetration test (included in the annual assessment or separate).
- [ ] **Contingency Plan test.** Test your disaster recovery and contingency plan annually and document the results.
- [ ] **Security awareness training.** Complete annual security awareness training for all personnel with system access.
- [ ] **Policy review.** Full review and update of all security policies and procedures.

## Packaging Deliverables

Use the scan aggregator to package everything:

```bash
python scripts/scan_aggregator.py \
  --month 2026-02 \
  --scan-dir scans/2026-02/ \
  --poam-file deliverables/poam-current.xlsx \
  --inventory-file deliverables/inventory-current.xlsx \
  --output-dir deliverables/2026-02/
```

This produces a timestamped ZIP containing all monthly deliverables in the format expected by the FedRAMP PMO.
