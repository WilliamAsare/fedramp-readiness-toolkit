# Access Control Policy

**Document Version:** 1.0
**Last Reviewed:** [DATE]
**Next Review Due:** [DATE + 1 year]
**Document Owner:** [CISO/Security Director Name]
**Approved By:** [Authorizing Official Name]

## 1. Purpose

This policy establishes the access control requirements for [SYSTEM NAME] to protect federal information and information systems in accordance with NIST SP 800-53 Rev 5 and FedRAMP requirements.

## 2. Scope

This policy applies to all personnel, contractors, and third parties who access [SYSTEM NAME] and the federal data it processes, stores, or transmits. This includes all components within the FedRAMP authorization boundary.

## 3. Roles and Responsibilities

<!-- Define your organization's specific roles. Common examples: -->

**System Owner:** Overall accountability for access control implementation and compliance.

**Information System Security Officer (ISSO):** Day-to-day access control management, access reviews, and incident escalation.

**System Administrators:** Implementation and maintenance of access control mechanisms. Management of user accounts, roles, and permissions.

**Users:** Compliance with access control policies, protection of credentials, and reporting of access anomalies.

## 4. Account Management (AC-2)

### 4.1 Account Types

[SYSTEM NAME] supports the following account types:
- **Individual accounts:** Assigned to a single identified user
- **Privileged accounts:** Accounts with elevated permissions for system administration
- **Service accounts:** Non-interactive accounts for system processes and integrations
- **Temporary accounts:** Time-limited accounts with automatic expiration
- **Guest/external accounts:** Accounts for non-organizational users (agency personnel)

<!-- FedRAMP requires you to define all account types your system uses -->

### 4.2 Account Lifecycle

**Creation:** All account creation requests must be submitted through [TICKETING SYSTEM], approved by [APPROVER ROLE], and provisioned by [ADMIN ROLE]. Accounts are created with minimum necessary privileges.

**Modification:** Privilege changes follow the same approval process as account creation. Changes are logged and auditable.

**Review:** All accounts are reviewed at least annually. Privileged accounts are reviewed at least every [90 days — FedRAMP recommended].

**Disabling:** Accounts are disabled after [90 days — FedRAMP Moderate parameter] of inactivity. Accounts of terminated personnel are disabled within [same day] of termination notification.

**Removal:** Disabled accounts are removed after [TIMEFRAME] per the organization's retention requirements.

### 4.3 Shared and Group Accounts

Shared and group accounts are [permitted only for specific documented use cases / prohibited]. When permitted, shared accounts require:
- Documented justification and approval
- Individual accountability through supplementary logging
- Credential changes when any member leaves the group

## 5. Access Enforcement (AC-3)

Access to [SYSTEM NAME] is enforced through [role-based access control (RBAC) / attribute-based access control (ABAC)] implemented in [IDENTITY PROVIDER / APPLICATION FRAMEWORK].

Defined roles include:

| Role | Description | Typical Permissions |
|------|------------|-------------------|
| [Admin] | [System administration] | [Full system access] |
| [Operator] | [Day-to-day operations] | [Read/write operational data] |
| [User] | [Standard user access] | [Read/write own data] |
| [Read-Only] | [Audit and reporting] | [Read-only access] |

<!-- Define all roles used in your system -->

## 6. Separation of Duties (AC-5)

The following duties are incompatible and must not be assigned to the same individual:
- [Development and production deployment]
- [Security audit and security configuration]
- [Account creation and account approval]
- [Financial transaction initiation and approval]

<!-- Define your organization's specific incompatible duties -->

## 7. Least Privilege (AC-6)

All users and service accounts are granted the minimum permissions necessary to perform their assigned duties. Privileged access is:
- Restricted to personnel with documented need
- Approved by [APPROVER ROLE]
- Reviewed at least [every 90 days]
- Logged and monitored

## 8. Unsuccessful Logon Attempts (AC-7)

After [3 — FedRAMP parameter] consecutive unsuccessful logon attempts, the account is locked for [30 minutes — FedRAMP parameter] or until unlocked by an administrator.

## 9. Session Management

- **Session lock:** Sessions lock after [15 minutes — FedRAMP non-privileged parameter] of inactivity for non-privileged users and [10 minutes] for privileged users
- **Session termination:** Sessions terminate after [TIMEFRAME] regardless of activity
- **Concurrent sessions:** Limited to [NUMBER] per user

## 10. Remote Access (AC-17)

All remote access to [SYSTEM NAME] must:
- Use encrypted communications (TLS 1.2+ with FIPS-validated cryptography)
- Require multi-factor authentication
- Be explicitly authorized for each user
- Be monitored and logged

## 11. Multi-Factor Authentication

MFA is required for:
- All privileged access (AC-2, IA-2(1))
- All non-privileged network access (IA-2(2))
- All remote access (AC-17)

Acceptable MFA methods include: [hardware tokens, authenticator apps, PIV/CAC cards]. SMS-based MFA is [not acceptable for privileged access].

## 12. Agency CAC/PIV Support

[SYSTEM NAME] supports federal CAC/PIV card authentication through [SAML 2.0 / OIDC] federation with agency Identity Providers. See the IA policy for detailed implementation.

## 13. Enforcement

Violations of this policy may result in disciplinary action up to and including termination, revocation of system access, and potential legal consequences.

## 14. Review and Update

This policy is reviewed at least every 3 years and updated as needed. Procedures are reviewed at least annually. The ISSO is responsible for initiating the review process.

---

*This is a template. Replace all bracketed [PLACEHOLDERS] with your organization's specific values before submission.*
