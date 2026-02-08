# OSCAL Guide

How OSCAL is used within this toolkit, and why it matters for your FedRAMP journey.

## What OSCAL is

OSCAL (Open Security Controls Assessment Language) is NIST's machine-readable format for security compliance data. Instead of 500-page Word documents that humans have to read and cross-reference manually, OSCAL puts the same information into structured JSON (or XML/YAML) that tools can parse, validate, and compare automatically.

FedRAMP has set a **September 2026 deadline** for all CSPs to transition authorization packages to OSCAL format. This isn't optional.

## The seven OSCAL models

OSCAL defines seven document models. This toolkit works with five of them directly:

**Catalog** contains the full set of security controls. We use the NIST SP 800-53 Rev 5 catalog as our foundation, stored at `baselines/catalogs/NIST_SP-800-53_rev5_catalog.json`. This single file has 70,000+ lines and defines every control, enhancement, and parameter.

**Profile** selects and tailors controls from a catalog for a specific use case. The FedRAMP baselines (Low, Moderate, High) are profiles that pull specific controls from the NIST catalog and set FedRAMP-specific parameter values. Stored in `baselines/json/`.

**System Security Plan (SSP)** describes a system's security implementation. This is what `ssp_generator.py` produces. It captures system characteristics, authorization boundary, components, and how each control is implemented.

**Plan of Action & Milestones (POA&M)** tracks security findings and their remediation. The `poam_manager.py` script can export to OSCAL POA&M format.

**Assessment Plan (SAP)** and **Assessment Results (SAR)** are used by 3PAOs. Templates are in `templates/oscal/`.

## How the toolkit uses OSCAL

### Profile resolution

When you run `catalog_parser.py --baseline moderate`, it resolves the FedRAMP Moderate profile against the NIST catalog. This means it follows the profile's control selections and parameter substitutions to produce the flat list of 323 controls that apply to a Moderate system. The `compliance-trestle` library's `ProfileResolver` handles this.

### Gap analysis

`gap_analysis.py` compares your implementation status against the resolved baseline. If you provide your status as an OSCAL SSP, it extracts `implemented-requirement` entries and checks for `by-component` details. The output includes OSCAL-compatible JSON.

### SSP generation

`ssp_generator.py` produces a valid OSCAL SSP JSON document from structured YAML metadata and Markdown control narratives. The output follows the FedRAMP SSP template structure and can be validated against FedRAMP's Schematron rules.

### Validation

`oscal_validator.py` checks OSCAL documents against structural requirements and FedRAMP business rules. It's designed for CI/CD integration with clear exit codes (0 = pass, 1 = errors, 2 = config error).

## The compliance-trestle library

This toolkit uses [compliance-trestle](https://github.com/oscal-compass/compliance-trestle) (a CNCF project) as its OSCAL SDK. Install it with `pip install compliance-trestle`. The companion `compliance-trestle-fedramp` plugin adds FedRAMP-specific validation.

Key trestle features we rely on:

- **Pydantic models** for all seven OSCAL document types, giving you type-safe access to every field
- **Profile resolution** that handles parameter substitution and control tailoring
- **Agile authoring** workflow: split an OSCAL document into Markdown fragments for human editing, then reassemble into valid OSCAL
- **CLI tools** for document manipulation (split, merge, validate)

## Authoritative OSCAL sources

These are the official sources the toolkit pulls from. Never recreate this data manually.

- **GSA/fedramp-automation** (GitHub): FedRAMP OSCAL baselines, templates, and Schematron validation rules
- **usnistgov/oscal-content** (GitHub): NIST SP 800-53 Rev 5 catalog in OSCAL format
- **automate.fedramp.gov**: FedRAMP's OSCAL implementation guides and validation web interface

## Working with OSCAL documents

### Exploring a baseline

```bash
# See what controls are in a profile
python -c "
import json
with open('baselines/json/FedRAMP_rev5_MODERATE-baseline.json') as f:
    profile = json.load(f)
imports = profile['profile']['imports']
for imp in imports:
    controls = imp.get('include-controls', [])
    for group in controls:
        ids = group.get('with-ids', [])
        print(f'{len(ids)} controls selected')
"
```

### Validating your SSP

```bash
# Quick validation
python scripts/oscal_validator.py --input my-ssp.json --type ssp --baseline moderate

# Strict mode (warnings become errors)
python scripts/oscal_validator.py --input my-ssp.json --type ssp --baseline moderate --strict
```

### CI/CD integration

Add OSCAL validation to your pipeline:

```yaml
- name: Validate OSCAL SSP
  run: python scripts/oscal_validator.py --input ssp.json --type ssp --baseline moderate
  # Exit code 0 = pass, 1 = validation errors, 2 = input error
```

## Preparing for the OSCAL transition

If your organization is currently using Word/Excel-based compliance documentation:

1. Start with the `ssp_generator.py` workflow: write control narratives in Markdown, system metadata in YAML, and let the tool produce valid OSCAL
2. Use `oscal_validator.py` in CI to catch structural issues early
3. Keep your OSCAL documents version-controlled alongside your infrastructure code
4. Plan for the September 2026 deadline now, not six months before it
