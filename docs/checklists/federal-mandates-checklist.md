# Federal Mandates Checklist

These six requirements are strict pass/fail gates for the FedRAMP Readiness Assessment Report (RAR). A failure on any single mandate means your RAR will be rejected. There is no partial credit and no remediation window during the assessment itself. You must satisfy all six before your 3PAO begins the RAR.

Every one of these has tripped up experienced CSPs. Don't assume you're compliant — verify.

## Mandate 1: FIPS 140-2/140-3 Validated Cryptographic Modules

**Controls:** SC-13, SC-8, SC-28

FedRAMP requires FIPS 140-2 or FIPS 140-3 validated cryptographic modules everywhere cryptography is used. This means every data-at-rest encryption point, every data-in-transit encryption point, and every key management operation. "We use AES-256" is not sufficient — the specific implementation must be listed on the CMVP validated modules list.

### Verification Steps

- [ ] **Audit all encryption points.** Map every location where data is encrypted at rest and in transit within your authorization boundary. Include: storage volumes, databases, object storage, message queues, API endpoints, internal service-to-service communication, and backup systems.
- [ ] **Identify the cryptographic module for each point.** For each encryption point, identify the specific library or module performing the cryptography (e.g., OpenSSL, AWS SDK, BoringSSL, Windows CNG).
- [ ] **Verify CMVP validation.** For each module, look up its validation status on the NIST CMVP database at https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules. Record the certificate number.
  - Check that the validated version matches what you're actually running
  - Check that the module is operating in FIPS mode (many modules have FIPS mode disabled by default)
  - Certificates with status "Historical" are acceptable but may draw scrutiny
  - Certificates with status "Revoked" are NOT acceptable
- [ ] **Verify TLS configurations.** All external and internal TLS must use FIPS-approved algorithms:
  - TLS 1.2 minimum (TLS 1.3 preferred)
  - Approved cipher suites only (no RC4, no DES, no export ciphers)
  - Run `nmap --script ssl-enum-ciphers -p 443 your-domain.com` to verify
- [ ] **Audit key management.** Key generation, storage, rotation, and destruction must use FIPS-validated modules. Hardware Security Modules (HSMs) should have their own FIPS 140-2/3 certificates.
- [ ] **Check cloud provider FIPS mode.** If using AWS, ensure FIPS endpoints are configured (e.g., `fips.us-gov-west-1.amazonaws.com`). For Azure, verify FIPS mode on VMs. For GCP, verify BoringCrypto FIPS module is active.
- [ ] **Document in the Cryptographic Modules Table.** Create the required FedRAMP Cryptographic Modules Table listing every module, its certificate number, the algorithm used, and where it's deployed.

### Common Failures

- Using OpenSSL without FIPS mode enabled (the default build is NOT FIPS-validated)
- Container base images using non-validated crypto libraries
- Internal microservice communication using TLS with non-FIPS cipher suites
- Developer tools or monitoring agents within the boundary using non-FIPS crypto
- Assuming the cloud provider handles everything (you're still responsible for your application-layer crypto)

---

## Mandate 2: Agency CAC/PIV Credential Authentication

**Controls:** IA-2, IA-2(12), IA-8

Your system must support authentication using federal Personal Identity Verification (PIV) cards and Common Access Cards (CAC). This is non-negotiable for any system accessed by federal employees.

### Verification Steps

- [ ] **Implement SAML 2.0 or OIDC federation.** Your system must federate with agency Identity Providers (IdPs). Most agencies use SAML 2.0, though OIDC is increasingly accepted.
- [ ] **Support X.509 certificate-based authentication.** PIV/CAC cards contain X.509 certificates. Your federation setup must accept certificate-based authentication from agency IdPs.
- [ ] **Test with at least one agency IdP.** If you have a sponsoring agency, test the actual federation flow. If not, test against a PIV-compatible IdP like Login.gov or MAX.gov.
- [ ] **Handle certificate revocation checking.** Implement OCSP or CRL checking to validate that PIV/CAC certificates haven't been revoked.
- [ ] **Support multi-factor authentication.** PIV/CAC satisfies MFA (something you have + something you know via PIN), but your system must properly recognize and enforce this.
- [ ] **Document the authentication flow.** Create a detailed diagram showing: user presents PIV/CAC → agency IdP authenticates → SAML/OIDC assertion → your application validates → session established.

### Common Failures

- Building username/password authentication only and planning to "add PIV later"
- Not testing the actual federation flow with a real agency IdP
- Failing to handle certificate revocation
- Not supporting the specific SAML attributes agencies expect (e.g., `urn:oid:0.9.2342.19200300.100.1.1` for UID)

---

## Mandate 3: Digital Identity Level (NIST SP 800-63)

**Controls:** IA-1, IA-2, IA-8

Your system must operate at the appropriate digital identity assurance level as defined by NIST SP 800-63:

- **Moderate baseline:** Identity Assurance Level (IAL) 2, Authenticator Assurance Level (AAL) 2, Federation Assurance Level (FAL) 2
- **High baseline:** IAL 2 or 3, AAL 2 or 3, FAL 2 (specific requirements depend on the data)

### Verification Steps

- [ ] **Identity proofing (IAL).** Verify that your user registration process meets IAL 2 requirements: remote or in-person identity proofing, verification of identity evidence, and binding to a digital identity.
- [ ] **Authentication strength (AAL).** Verify AAL 2: multi-factor authentication using at least two different authentication factors (something you know, something you have, something you are).
- [ ] **Federation (FAL).** If federating authentication (which you should be for agency users), verify FAL 2: signed assertions, audience restriction, and bearer token protection.
- [ ] **Map to NIST SP 800-63-3 requirements.** Document how your implementation satisfies each component of the target assurance level.

### Common Failures

- Confusing AAL with IAL (they're different dimensions)
- Not meeting IAL 2 for user enrollment while having strong authentication
- Claiming AAL 2 but allowing password-only fallback paths

---

## Mandate 4: Vulnerability Remediation SLAs

**Controls:** RA-5, SI-2

Your system must demonstrate the ability to consistently remediate vulnerabilities within FedRAMP's mandatory timelines. This isn't just about policy — you must show actual remediation performance data.

### Remediation Timelines

| Severity | Remediation Deadline | FedRAMP Escalation Trigger |
|----------|---------------------|--------------------------|
| **Critical/High** | 30 days from discovery | 5+ High vulns aged >30 days triggers Detailed Finding Review |
| **Moderate** | 90 days from discovery | 10+ Moderate vulns aged >90 days triggers DFR |
| **Low** | 180 days from discovery | Accumulation may trigger review |

### Verification Steps

- [ ] **Scanning infrastructure in place.** Verify you have active scanning for:
  - Operating system vulnerabilities (e.g., Nessus, Qualys, AWS Inspector)
  - Web application vulnerabilities (e.g., OWASP ZAP, Burp Suite, Qualys WAS)
  - Database vulnerabilities
  - Container image vulnerabilities (e.g., Trivy, Snyk, Prisma Cloud)
- [ ] **Scanning cadence established.** Monthly OS/infrastructure scans and annual (minimum) web application penetration testing are required. Many CSPs scan weekly or continuously.
- [ ] **Authenticated scanning configured.** Unauthenticated scans exceeding 10% of total is an escalation trigger. Scans must use privileged credentials for accurate results.
- [ ] **Remediation process documented and tested.** You need a defined process for triaging, assigning, tracking, and verifying vulnerability remediation.
- [ ] **Historical remediation data available.** Collect at least 3 months of vulnerability scan data showing remediation performance. The 3PAO will review your track record, not just your policy.
- [ ] **POA&M process established.** Vulnerabilities that can't be remediated within SLA must have a Plan of Action & Milestones entry with justification, interim mitigations, and a target completion date.
- [ ] **False positive management.** Document your process for validating and marking false positives. False positives must be justified and re-validated periodically.

### Common Failures

- Having scanning tools but no remediation tracking process
- Scanning only external-facing systems (everything inside the boundary must be scanned)
- Unable to produce historical remediation performance data
- Large backlog of unaddressed findings from day one

---

## Mandate 5: Federal Records Management

**Controls:** AU-11, SI-12

Your system must comply with federal records management requirements from the National Archives and Records Administration (NARA) and support Freedom of Information Act (FOIA) response capabilities.

### Verification Steps

- [ ] **Records retention capabilities.** Verify your system can retain records according to agency-specific retention schedules (which vary by record type and agency). At minimum, audit logs must be retained for the period specified by the agency.
- [ ] **Records disposition.** Verify your system can securely dispose of records when retention periods expire. Disposition must be documented and auditable.
- [ ] **FOIA response support.** Verify your system can:
  - Search and retrieve records responsive to FOIA requests
  - Export records in common formats
  - Support redaction of exempt information
  - Provide records within FOIA response timelines
- [ ] **Data portability.** Federal agencies must be able to extract their data from your system in a usable format. Document your data export capabilities and formats.
- [ ] **NARA compliance documentation.** Document how your system supports NARA Bulletin 2010-05 (or current guidance) for managing records in cloud environments.

### Common Failures

- Assuming records management is entirely the agency's responsibility (it's shared)
- No data export capability beyond the application UI
- Audit log retention shorter than what agencies require

---

## Mandate 6: DNSSEC for External DNS

**Controls:** SC-20, SC-21, SC-22

All external DNS zones serving your system must support DNS Security Extensions (DNSSEC) to protect against DNS spoofing and cache poisoning.

### Verification Steps

- [ ] **DNSSEC signing enabled.** Verify your authoritative DNS zones are signed with DNSSEC:
  ```bash
  # Check DNSSEC status for your domain
  dig +dnssec yourdomain.com
  
  # Verify RRSIG records exist
  dig +dnssec +multi yourdomain.com RRSIG
  
  # Check the full chain of trust
  dig +trace +dnssec yourdomain.com
  ```
- [ ] **DS records published.** Verify Delegation Signer (DS) records are published at the parent zone (your domain registrar).
- [ ] **DNSSEC validation working.** Test using online validators:
  - https://dnsviz.net/
  - https://dnssec-analyzer.verisignlabs.com/
- [ ] **Key management documented.** Document your DNSSEC key management process including Key Signing Key (KSK) and Zone Signing Key (ZSK) rotation schedules.
- [ ] **All external zones covered.** DNSSEC must be configured on ALL external DNS zones, not just your primary domain. Include subdomains, API endpoints, and any other externally-resolvable names.

### Common Failures

- Enabling DNSSEC on the primary domain but forgetting subdomains
- Relying on a DNS provider that doesn't support DNSSEC
- Not monitoring DNSSEC key expiration (expired keys break DNS resolution entirely)
- Confusing DNSSEC with DNS-over-HTTPS (they solve different problems)

---

## Summary Checklist

| # | Mandate | Status |
|---|---------|--------|
| 1 | FIPS 140-2/140-3 validated cryptography everywhere | ☐ |
| 2 | Agency CAC/PIV credential authentication support | ☐ |
| 3 | Digital Identity Level 2+ (NIST 800-63) | ☐ |
| 4 | Vulnerability remediation within SLA (30/90/180 days) | ☐ |
| 5 | Federal records management (NARA, FOIA) | ☐ |
| 6 | DNSSEC for all external DNS | ☐ |

**All six must pass before proceeding to the Readiness Assessment Report.**
