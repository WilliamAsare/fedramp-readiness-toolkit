# Evidence Collection Guide

How to automate the collection of configuration evidence from cloud provider APIs for FedRAMP control validation.

## Why automate evidence collection

Every FedRAMP control needs evidence that it's actually implemented. For a Moderate system, that's 323 controls worth of screenshots, configuration exports, log samples, and policy documents. Collecting this manually before each assessment (and monthly for ConMon) is a full-time job. The `evidence_collector.py` script automates the cloud-provider side of this.

## What evidence looks like

Evidence maps to specific control families:

- **AC (Access Control):** IAM user listings, MFA enrollment status, password policies, role assignments
- **AU (Audit and Accountability):** CloudTrail/Azure Monitor/Cloud Logging configuration, log retention settings, audit log samples
- **CM (Configuration Management):** AWS Config rules, infrastructure-as-code templates, change management records
- **IA (Identification and Authentication):** Credential reports, MFA device inventory, password policy configuration
- **SC (System and Communications Protection):** Security group rules, VPC/VNET configuration, encryption settings, TLS configurations
- **SI (System and Information Integrity):** GuardDuty/Defender/SCC findings, antimalware configuration, patch status

The full mapping is defined in `config/evidence-requirements.yaml`.

## Setup

### Prerequisites

You need API access to your cloud environment. The script uses standard SDK authentication:

- **AWS:** Configure credentials via `aws configure`, environment variables, or IAM role
- **Azure:** Run `az login` or set service principal credentials
- **GCP:** Run `gcloud auth application-default login` or set a service account key

### Configuration

Copy the example config and fill in your details:

```bash
cp config/cloud-api-config.yaml.example config/cloud-api-config.yaml
# Edit with your regions, account IDs, etc.
```

**Important:** Never commit `cloud-api-config.yaml` with real credentials. The `.gitignore` already excludes it, but double-check.

## Collecting evidence

### Specific control families

```bash
# Collect Access Control and System Protection evidence from AWS
python scripts/evidence_collector.py \
  --provider aws \
  --families AC,SC \
  --output-dir evidence/

# Collect all supported families
python scripts/evidence_collector.py \
  --provider aws \
  --all-families \
  --output-dir evidence/
```

### What gets collected

Each run creates a timestamped directory structure:

```
evidence/
  2025-01-15/
    AC/
      iam-users.json          # IAM user listing with MFA status
      password-policy.json    # Account password policy
      account-summary.json    # IAM account summary
    AU/
      cloudtrail-config.json  # Trail configurations and status
    SC/
      security-groups.json    # All security group rules
    manifest.json             # Index of all collected artifacts
```

Every file includes:

- **SHA-256 hash** for integrity verification (assessors care about this)
- **Collection timestamp** in UTC
- **File size** for inventory tracking

### Generating a manifest only

If you don't have API access set up yet but want to know what evidence you'll need:

```bash
python scripts/evidence_collector.py --manifest-only --output-dir evidence/
```

This generates a checklist of every evidence artifact required per control family, including items that need manual collection (policies, procedures, screenshots of UI configurations).

## Evidence integrity

FedRAMP assessors need to trust that evidence hasn't been tampered with. The collector handles this automatically:

- Every artifact gets a SHA-256 hash computed at collection time
- The manifest records hashes, timestamps, and file sizes
- Store evidence in version control or an immutable storage system for audit trail

## Extending to other providers

The evidence collector has an abstraction layer in `scripts/utils/cloud_providers.py`. To add support for a new cloud provider or additional API calls:

1. Add the control-to-API mapping in `config/evidence-requirements.yaml`
2. Implement the collection function in `evidence_collector.py`
3. Follow the same pattern: call API, save JSON, compute hash, return metadata

## Manual evidence

Not everything can be automated. You'll still need to collect manually:

- Policy documents (access control policy, incident response plan, etc.)
- Training records and completion certificates
- Physical security documentation (inherited from cloud provider for most SaaS)
- Configuration screenshots for systems without API access
- Meeting minutes from security review boards

The manifest-only mode lists these alongside automated items so nothing falls through the cracks.

## Scheduling regular collection

For continuous monitoring, you'll want to collect evidence monthly. Add a cron job or CI/CD schedule:

```yaml
# GitHub Actions example
name: Monthly Evidence Collection
on:
  schedule:
    - cron: '0 6 1 * *'  # First of each month at 6am UTC
jobs:
  collect:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install -e .
      - run: python scripts/evidence_collector.py --provider aws --all-families --output-dir evidence/
      - run: git add evidence/ && git commit -m "Monthly evidence collection $(date +%Y-%m)" && git push
```

See the [Continuous Monitoring Guide](continuous-monitoring.md) for the full monthly workflow.
