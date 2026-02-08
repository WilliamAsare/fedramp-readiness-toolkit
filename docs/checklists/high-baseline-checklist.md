# FedRAMP High Baseline Checklist

The High baseline covers 410 controls and applies to systems where a security breach could cause severe or catastrophic adverse effect. Think systems handling law enforcement data, critical infrastructure information, health records at scale, or defense-adjacent workloads.

High adds 87 controls beyond Moderate, with significantly more stringent parameters and additional control enhancements. The High baseline was specifically analyzed using the MITRE ATT&CK Framework v8.2 for threat-based methodology.

## Key Differences from Moderate

- **87 additional controls** (410 vs. 323), mostly additional enhancements to existing control families
- **Stricter parameters:** Shorter timeframes, more frequent reviews, stronger requirements
- **More control enhancements:** Controls like AC-2 have additional enhancements at High (e.g., AC-2(11) usage conditions, AC-2(12) account monitoring for atypical usage, AC-2(13) account disabling for high-risk individuals)
- **Higher cost:** $1M-$3M+ initial, $500K-$1M annual
- **Longer timeline:** 18+ months typical
- **Mandatory GovCloud/Government cloud regions** for most implementations
- **Dedicated infrastructure requirements** in many cases

## Additional Controls at High (Key Additions Beyond Moderate)

### Access Control — Additional Enhancements
- [ ] **AC-2(11):** Usage conditions — enforce conditions for system account usage
- [ ] **AC-2(12):** Account monitoring for atypical usage — automated monitoring and alerts for unusual behavior patterns
- [ ] **AC-2(13):** Disable accounts for high-risk individuals within 1 hour
- [ ] **AC-3(4):** Discretionary access control — limit information sharing privileges
- [ ] **AC-4(4):** Flow control of encrypted information — inspect encrypted traffic at boundary
- [ ] **AC-6(7):** Review of user privileges — review all privileges annually
- [ ] **AC-6(8):** Privilege levels for code execution — restrict software execution privilege

### Audit — Additional Enhancements
- [ ] **AU-9(2):** Store audit records on separate system/media from the audited system
- [ ] **AU-9(3):** Cryptographic protection of audit information
- [ ] **AU-10:** Non-repudiation — system provides evidence of actions that cannot be denied
- [ ] **AU-12(1):** System-wide and time-correlated audit trail
- [ ] **AU-12(3):** Changes by authorized individuals — ability to change audit behaviors in near real-time

### System and Communications Protection — Additional
- [ ] **SC-3:** Security function isolation — kernel and security functions isolated from non-security
- [ ] **SC-4:** Information in shared resources — prevent unauthorized information transfer
- [ ] **SC-7(8):** Route traffic through authenticated proxy for specific communication paths
- [ ] **SC-7(21):** Isolation of system components — logically or physically separate components
- [ ] **SC-8(1):** Cryptographic protection for ALL transmitted information (not just federal data)
- [ ] **SC-28(1):** Cryptographic protection at rest with separate key management system
- [ ] **SC-46:** Cross-domain security — for systems spanning multiple security domains

### System and Information Integrity — Additional
- [ ] **SI-4(2):** Automated tools and mechanisms for real-time analysis of events
- [ ] **SI-4(4):** Inbound and outbound traffic monitoring at system boundary
- [ ] **SI-4(5):** System-generated alerts when indicators of compromise detected
- [ ] **SI-6:** Security function verification — verify correct operation of security functions at startup and on command
- [ ] **SI-7:** Software, firmware, and information integrity — detect unauthorized changes
- [ ] **SI-7(1):** Integrity checks at startup and on defined events

### Contingency Planning — Stricter Requirements
- [ ] **CP-2(1):** Coordinate with related plans (e.g., business continuity, disaster recovery)
- [ ] **CP-2(3):** Resume mission-essential functions within defined time period
- [ ] **CP-6:** Alternate storage site — geographically separate from primary
- [ ] **CP-7:** Alternate processing site — operational within defined timeframe
- [ ] **CP-8:** Telecommunications services — alternate telecom services available

### Personnel Security — Additional
- [ ] **PS-3(3):** Information requiring special access — additional screening for personnel with access to especially sensitive information

## Dedicated Infrastructure Considerations

Most High systems require:
- [ ] **Dedicated cloud regions** (AWS GovCloud, Azure Government, GCP Assured Workloads)
- [ ] **US-person staffing requirements** for personnel with logical or physical access
- [ ] **Dedicated or isolated network infrastructure** per SC-7(21)
- [ ] **Separate key management** per SC-28(1)
- [ ] **Alternate processing and storage sites** per CP-6 and CP-7

## Running the Gap Analysis

```bash
python scripts/gap_analysis.py \
  --baseline high \
  --input your-implementation-status.yaml \
  --output-dir reports/gap-analysis/
```

## Important Note

If you're starting from scratch, strongly consider achieving Moderate authorization first and then upgrading to High. The incremental effort from Moderate to High is significantly less than going straight to High, and you'll have a working compliance program in place before tackling the additional requirements.
