# Gap Analysis Guide

This guide walks you through running a FedRAMP gap analysis using the toolkit. The gap analysis tool is the single most useful script here: it compares your current security posture against a FedRAMP baseline and tells you exactly where you stand.

## What you'll get

The gap analysis produces three outputs:

1. **HTML dashboard** with visual compliance scoring, per-family breakdown with progress bars, and a prioritized list of critical gaps
2. **Excel workbook** with Summary, By Family, All Controls, and Gaps sheets for stakeholder reporting
3. **JSON report** with the full analysis data for programmatic consumption

## Before you start

Make sure you've downloaded the FedRAMP baselines:

```bash
make baselines
```

## Step 1: Describe your current implementation

Create a YAML file mapping each control you've addressed to its implementation status. You don't need to list every control — anything not listed defaults to "not_implemented."

```yaml
# my-implementation-status.yaml
controls:
  AC-1:
    status: implemented
    notes: "Access control policy v3.2 approved by CISO"
  AC-2:
    status: partial
    notes: "MFA deployed, but inactive account disabling not automated yet"
  SC-13:
    status: implemented
    notes: "FIPS 140-2 validated modules used everywhere"
  IR-1:
    status: not_implemented
    notes: "Policy not started"
  PE-1:
    status: inherited
    notes: "AWS GovCloud data center physical security"
```

Valid status values: `implemented`, `partial`, `planned`, `not_implemented`, `inherited`, `na`

You can also use CSV format (columns: `control_id`, `status`, `notes`) or feed in an existing OSCAL SSP JSON file.

See `examples/sample-implementation-status.yaml` for a realistic 100+ control example of a fictional SaaS company at various stages of readiness.

## Step 2: Map inherited controls (optional but recommended)

If you're building on AWS GovCloud, Azure Government, or GCP Assured Workloads, run the inheritance mapper first:

```bash
# See what AWS GovCloud covers for Moderate
python scripts/inheritance_mapper.py --baseline moderate --provider aws

# Save the mapping for the gap analysis
python scripts/inheritance_mapper.py \
  --baseline moderate \
  --provider aws \
  --gap-analysis-output inheritance-aws.yaml
```

## Step 3: Run the gap analysis

```bash
# Basic analysis
python scripts/gap_analysis.py \
  --baseline moderate \
  --input my-implementation-status.yaml \
  --output-dir reports/

# With inheritance mapping (recommended)
python scripts/gap_analysis.py \
  --baseline moderate \
  --input my-implementation-status.yaml \
  --inheritance-map inheritance-aws.yaml \
  --output-dir reports/

# Quick summary only (no file output)
python scripts/gap_analysis.py \
  --baseline moderate \
  --input my-implementation-status.yaml \
  --summary-only
```

## Step 4: Interpret the results

**Compliance Score** counts only fully implemented, inherited, and N/A controls. This is the number that matters for your 3PAO assessment.

**Coverage Score** adds partial implementations on top, giving you a sense of how close you are.

**Critical Gaps** are controls tied to the six federal mandates (FIPS crypto, PIV/CAC, DNSSEC, etc.) or in the most scrutinized families (SC, IA) that aren't implemented. Fix these first.

**Estimated Remediation** is a rough planning number based on average effort per control family. Useful for budgeting but not precise.

## Step 5: Prioritize remediation

The priority logic:

- **Critical**: Federal mandate controls (SC-13, SC-8, IA-2, etc.) not implemented, or SC/IA family controls with no implementation
- **High**: Controls in the eight most-scrutinized families (AC, SC, SI, AU, IA, CM, IR, CA) not implemented
- **Medium**: Partially implemented controls in scrutinized families, or not-implemented in other families
- **Low**: Planned controls in non-scrutinized families

Start with the critical gaps. Every single one is a potential RAR rejection.

## Full workflow: inheritance + gap analysis

```bash
python scripts/inheritance_mapper.py \
  --baseline moderate --provider aws \
  --gap-analysis-output inheritance.yaml

python scripts/gap_analysis.py \
  --baseline moderate \
  --input my-status.yaml \
  --inheritance-map inheritance.yaml \
  --output-dir reports/
```

This combination answers the two questions every CSP asks: "How far are we from ready?" and "What do we actually have to build versus inherit?"
