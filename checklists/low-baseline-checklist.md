# FedRAMP Low Baseline Checklist

The Low baseline covers 156 controls and applies to systems where a security breach would have limited adverse effect. This is a subset of the Moderate baseline, so if you've reviewed the Moderate checklist, many items will be familiar but with relaxed parameters.

Low is the most common baseline for FedRAMP 20x pilot authorizations. The 20x Low pilot achieved average authorization times of ~5 weeks.

## Key Differences from Moderate

- **Fewer controls:** 156 vs. 323 (roughly half)
- **Relaxed parameters:** Some controls have less restrictive FedRAMP parameter values
- **Simpler documentation:** Shorter SSP, fewer appendices
- **Faster assessment:** 3PAO assessment takes less time and costs less ($75K-$150K vs. $150K-$300K)
- **Lower ongoing burden:** Monthly ConMon deliverables are the same but with fewer controls to track

## LI-SaaS vs. Low

If you qualify for LI-SaaS (Low Impact SaaS), you get the same 156 controls but only 66 are tested by the 3PAO. The other 90 are attested (self-certified). LI-SaaS is faster and cheaper, but only for SaaS systems with genuinely low-impact data.

## Critical Controls at Low

The same six federal mandates apply (FIPS crypto, PIV/CAC, digital identity, vuln remediation, records management, DNSSEC). Review the federal mandates checklist first.

### Access Control (AC) — Key Low Controls
- [ ] **AC-1:** Access control policy and procedures
- [ ] **AC-2:** Account management (automated management, inactive account disabling)
- [ ] **AC-3:** Access enforcement (RBAC/ABAC)
- [ ] **AC-7:** Unsuccessful logon attempts (lockout after 3 attempts)
- [ ] **AC-8:** System use notification (login banner)
- [ ] **AC-17:** Remote access (encrypted, authorized)
- [ ] **AC-20:** Use of external systems (policy for external access)

### Audit and Accountability (AU)
- [ ] **AU-2:** Auditable events defined and captured
- [ ] **AU-3:** Audit record content (who, what, when, where, outcome)
- [ ] **AU-6:** Audit review and analysis
- [ ] **AU-12:** Audit generation (all boundary components)

### Configuration Management (CM)
- [ ] **CM-2:** Baseline configuration documented
- [ ] **CM-6:** Configuration settings (restrictive defaults)
- [ ] **CM-7:** Least functionality (disable unnecessary services)
- [ ] **CM-8:** System component inventory

### Identification and Authentication (IA)
- [ ] **IA-2:** Unique user identification with MFA for privileged access
- [ ] **IA-5:** Authenticator management (password policy)
- [ ] **IA-8:** Non-organizational user authentication

### System and Communications Protection (SC)
- [ ] **SC-7:** Boundary protection (firewall, default-deny)
- [ ] **SC-8:** Transmission confidentiality (TLS with FIPS crypto)
- [ ] **SC-13:** Cryptographic protection (FIPS 140 validated)
- [ ] **SC-28:** Protection of information at rest

### System and Information Integrity (SI)
- [ ] **SI-2:** Flaw remediation (30/90/180 day SLAs)
- [ ] **SI-3:** Malicious code protection
- [ ] **SI-4:** System monitoring
- [ ] **SI-5:** Security alerts and advisories

### Supply Chain Risk Management (SR)
- [ ] **SR-1:** SCRM policy and procedures
- [ ] **SR-2:** Supply chain risk management plan

## Running the Gap Analysis

```bash
python scripts/gap_analysis.py \
  --baseline low \
  --input your-implementation-status.yaml \
  --output-dir reports/gap-analysis/
```
