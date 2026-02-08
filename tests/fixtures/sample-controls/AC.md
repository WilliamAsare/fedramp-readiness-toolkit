## AC-1

CloudWidget Enterprise has developed, documented, and disseminated an
access control policy that addresses purpose, scope, roles, responsibilities,
and compliance. The policy is reviewed and updated annually or when
significant changes occur. The policy is available to all authorized personnel
via the internal documentation portal.

## AC-2

Account management is handled through AWS IAM for infrastructure accounts and
Amazon Cognito for application user accounts. All accounts require approval
from the system owner before creation. Accounts are reviewed quarterly by
the ISSO. Inactive accounts are disabled after 90 days and removed after
180 days. Emergency accounts expire within 24 hours.

## AC-3

Access enforcement is implemented through AWS IAM policies following
least-privilege principles. Role-based access control (RBAC) is enforced
at the application level. All API endpoints require authenticated sessions
with appropriate role assignments. S3 bucket policies restrict access to
authorized principals only.

## AC-6

Least privilege is enforced through IAM roles with minimal necessary
permissions. Developers do not have production access by default.
Privileged access requires MFA and is logged via CloudTrail.
Privilege escalation requests require manager approval.

## AC-7

After 5 consecutive failed login attempts, the user account is locked for
30 minutes. The lockout threshold and duration are configurable by the ISSO.
Failed login attempts are logged and monitored via CloudWatch alarms.

## AC-17

Remote access to the system is exclusively through HTTPS (TLS 1.2+).
VPN access to the management plane requires MFA. All remote sessions
are logged and monitored. SSH access to instances is disabled; all
management is performed through AWS Systems Manager Session Manager.
