# SSP Development Guide

How to build your System Security Plan using the toolkit's agile authoring workflow.

## Overview

The SSP is the central artifact in your FedRAMP authorization package. For a Moderate system it typically runs 300-500+ pages. Writing one from scratch in a Word document is painful and error-prone. This toolkit takes a different approach: you write system metadata in YAML and control narratives in Markdown, and `ssp_generator.py` produces a valid OSCAL SSP.

## The workflow

```
system-metadata.yaml  ─┐
                        ├──▶ ssp_generator.py ──▶ ssp.json (OSCAL)
controls/AC.md         ─┤                         └──▶ ssp.html (optional)
controls/SC.md         ─┤
controls/AU.md         ─┤
inheritance.yaml       ─┘  (optional, from inheritance_mapper.py)
```

## Step 1: Define system metadata

Create a YAML file describing your system. Use `examples/sample-system-metadata.yaml` as a starting point.

```yaml
system:
  name: "Your System Name"
  abbreviation: "YSN"
  version: "1.0"
  fips199_level: moderate    # low, moderate, high
  description: >
    One to two paragraph description of what your system does,
    who uses it, and what kind of data it processes.
  status: operational        # operational, under-development, disposition

boundary:
  description: >
    Describe the authorization boundary. This is the most important
    piece of your SSP. Every component that stores, processes, or
    transmits federal data must be inside this boundary.
  components:
    - name: "Web Application"
      type: software
      description: "React frontend served via CloudFront CDN"
    - name: "API Service"
      type: software
      description: "Python API running on ECS Fargate"
    - name: "Database"
      type: software
      description: "PostgreSQL on RDS with encryption at rest"

  external_services:
    - name: "AWS GovCloud"
      fedramp_status: "FedRAMP High P-ATO"
      usage: "Infrastructure hosting"

responsible_parties:
  system_owner:
    name: "Jane Smith"
    title: "VP Engineering"
    email: "jane@example.com"
  authorizing_official:
    name: "Agency AO"
  isso:
    name: "John Doe"
    title: "ISSO"
```

Key things to get right in the metadata:

- The **boundary description** is the #1 cause of RAR rejection. Be thorough and make sure it matches your boundary diagram.
- List every **component** that handles federal data, including monitoring tools, log aggregators, and CI/CD systems.
- Every **external service** that touches federal data must have its own FedRAMP authorization listed here.

## Step 2: Write control narratives

Create a directory (e.g., `controls/`) with one Markdown file per control family:

```
controls/
  AC.md      # Access Control
  AU.md      # Audit and Accountability
  CM.md      # Configuration Management
  SC.md      # System and Communications Protection
  ...
```

Each file uses `## CONTROL-ID` headings:

```markdown
## AC-1

Your organization has developed, documented, and disseminated an
access control policy that addresses purpose, scope, roles,
responsibilities, and compliance. The policy is reviewed annually
and updated when significant changes occur.

## AC-2

Account management is handled through AWS IAM for infrastructure
accounts and Amazon Cognito for application user accounts. All
accounts require approval from the system owner before creation.
Accounts are reviewed quarterly by the ISSO. Inactive accounts
are disabled after 90 days.
```

Tips for writing good narratives:

- **Be specific.** Don't say "the system uses encryption." Say "data at rest is encrypted using AES-256 via AWS KMS with FIPS 140-2 Level 3 validated HSMs."
- **Name the tools.** Assessors want to know exactly what implements each control. "CloudTrail logs all API calls" is better than "audit logging is enabled."
- **Match the boundary.** Every component mentioned in a narrative should be in your boundary definition, and vice versa. Inconsistencies get flagged.
- **Include FedRAMP parameter values.** When a control has FedRAMP-defined parameters (like "lock account after [FedRAMP: three] failed attempts"), use those exact values.

You don't need narratives for every single control. Controls you inherit from your cloud provider (identified by `inheritance_mapper.py`) get auto-generated narratives referencing the provider's authorization.

## Step 3: Generate the SSP

```bash
# Basic generation
python scripts/ssp_generator.py \
  --metadata system-metadata.yaml \
  --controls-dir controls/ \
  --baseline moderate \
  --output ssp.json

# With inheritance mapping (recommended)
python scripts/ssp_generator.py \
  --metadata system-metadata.yaml \
  --controls-dir controls/ \
  --baseline moderate \
  --inheritance-map inheritance.yaml \
  --output ssp.json \
  --html ssp.html    # human-readable version for review
```

## Step 4: Validate

```bash
python scripts/oscal_validator.py --input ssp.json --type ssp --baseline moderate
```

The validator checks structural requirements and FedRAMP business rules. Fix any errors before proceeding. The most common issues are missing authorization boundary descriptions and controls without `by-component` entries.

## Step 5: Iterate

The SSP is a living document. As your system evolves:

1. Update the YAML metadata and Markdown narratives
2. Regenerate the OSCAL SSP
3. Validate
4. Commit to version control

This workflow keeps your SSP in sync with your actual implementation. No more 500-page Word documents that drift out of date.

## Working with inherited controls

If you ran `inheritance_mapper.py` first (recommended), pass the output to the SSP generator:

```bash
python scripts/inheritance_mapper.py \
  --baseline moderate \
  --provider aws \
  --gap-analysis-output inheritance.yaml

python scripts/ssp_generator.py \
  --metadata system-metadata.yaml \
  --controls-dir controls/ \
  --baseline moderate \
  --inheritance-map inheritance.yaml \
  --output ssp.json
```

Inherited controls get a `leveraged-authorization-type` property in the SSP, and the generator creates narratives like "This control is inherited from the underlying FedRAMP-authorized infrastructure (AWS GovCloud)." You can override these by writing your own narrative for that control ID.

## Integrating with the gap analysis

The gap analysis report tells you which controls still need narratives. A practical workflow:

```bash
# 1. Run gap analysis to see where you stand
python scripts/gap_analysis.py --baseline moderate --input status.yaml --output-dir reports/

# 2. Review the gap report -- focus on not_implemented and partial controls
# 3. Write narratives for implemented controls first
# 4. Generate SSP with what you have
# 5. Use the validator to find missing pieces
# 6. Iterate until the validator is clean
```
