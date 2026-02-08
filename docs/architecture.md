# Architecture

Design decisions and structure of the FedRAMP Readiness Assessment Toolkit.

## Design principles

**Separate content from code.** OSCAL baselines, templates, and checklists live in their own directories. Python automation lives in `scripts/`. This mirrors the pattern from GSA/fedramp-automation and makes it easy for compliance people to update content without touching code.

**OSCAL as the data layer.** Every script that produces or consumes compliance data uses OSCAL models as the interchange format. The NIST 800-53 Rev 5 catalog and FedRAMP profiles are the single source of truth for control data. We never manually recreate control definitions.

**Multi-format output.** Not every organization is ready for OSCAL-only workflows. Scripts produce OSCAL JSON as the primary output, but also generate Excel, CSV, HTML, and Markdown where useful. This is a practical concession to the current state of the industry.

**CI/CD-first validation.** OSCAL documents are validated on every pull request using FedRAMP's Schematron rules. The `oscal_validator.py` script returns clean exit codes for pipeline integration.

**Progressive disclosure.** A CSP brand new to FedRAMP can start with checklists and the gap analysis tool. As they mature, they pick up evidence collection, SSP generation, and continuous monitoring automation. Nothing forces you to use the whole toolkit at once.

## Repository structure

```
fedramp-readiness-toolkit/
├── baselines/              # Authoritative OSCAL data (downloaded, never edited)
│   ├── json/               # FedRAMP Rev 5 profiles (Low, Moderate, High, LI-SaaS)
│   ├── xml/                # XML format (optional)
│   └── catalogs/           # NIST SP 800-53 Rev 5 catalog
│
├── checklists/             # Human-readable compliance checklists
│   ├── pre-engagement-checklist.md
│   ├── fips199-categorization.md
│   ├── federal-mandates-checklist.md
│   ├── boundary-definition.md
│   ├── low/moderate/high-baseline-checklist.md
│   ├── 3pao-selection-guide.md
│   ├── conmon-monthly-checklist.md
│   └── fedramp-20x-readiness.md
│
├── config/                 # Configuration and mapping files
│   ├── fedramp-controls-mapping.yaml   # Control-to-cloud-service mapping
│   ├── evidence-requirements.yaml      # What evidence each control needs
│   ├── cloud-api-config.yaml.example   # Cloud provider API config template
│   └── sla-thresholds.yaml             # Vulnerability remediation SLAs
│
├── scripts/                # Python automation
│   ├── catalog_parser.py          # OSCAL catalog parser and explorer
│   ├── gap_analysis.py            # Baseline vs. implementation comparison
│   ├── inheritance_mapper.py      # Cloud provider control inheritance
│   ├── evidence_collector.py      # Multi-cloud evidence collection
│   ├── poam_manager.py            # POA&M generation, SLA tracking, escalation
│   ├── ssp_generator.py           # OSCAL SSP from YAML/Markdown inputs
│   ├── oscal_validator.py         # FedRAMP Schematron validation
│   ├── compliance_scorer.py       # Composite scoring with trend tracking
│   ├── scan_aggregator.py         # Vuln scan normalization (Nessus/Trivy/etc)
│   ├── inventory_drift.py         # Documented vs. live inventory drift
│   └── utils/
│       ├── oscal_helpers.py       # OSCAL parsing utilities
│       ├── cloud_providers.py     # AWS/Azure/GCP API abstractions
│       └── report_generators.py   # HTML/PDF/Excel report output
│
├── templates/              # Document templates
│   ├── oscal/              # OSCAL JSON templates (SSP, SAP, SAR, POA&M)
│   ├── docx/               # FedRAMP Word templates
│   ├── xlsx/               # Excel templates (POA&M, CIS/CRM, inventory)
│   └── policies/           # Starter policy documents
│
├── tests/
│   ├── unit/               # 131 unit tests
│   ├── integration/        # 31 integration tests (pipeline workflows)
│   └── fixtures/           # Sample OSCAL docs, scan files, control narratives
│
├── examples/               # Complete worked examples
│   ├── sample-ssp/
│   ├── sample-gap-report/
│   └── sample-evidence/
│
└── docs/                   # Documentation
    ├── getting-started.md
    ├── fedramp-overview.md
    ├── architecture.md (this file)
    ├── oscal-guide.md
    └── guides/
        ├── gap-analysis.md
        ├── ssp-development.md
        ├── evidence-collection.md
        └── continuous-monitoring.md
```

## Script architecture

### Data flow

The scripts form a pipeline where outputs from one step feed into the next:

```
NIST Catalog + FedRAMP Profile
        │
        ▼
  catalog_parser.py ────────────▶ Control lists (JSON/CSV/table)
        │
        ▼
  inheritance_mapper.py ────────▶ Inheritance map (YAML/JSON)
        │                              │
        ▼                              ▼
  gap_analysis.py ──────────────▶ Gap report (JSON/HTML/Excel)
        │                              │
        ▼                              ▼
  ssp_generator.py ─────────────▶ OSCAL SSP (JSON)
        │                              │
        ▼                              ▼
  oscal_validator.py ───────────▶ Validation results (pass/fail)

  scan_aggregator.py ───────────▶ Normalized findings (JSON/CSV)
        │
        ▼
  poam_manager.py ──────────────▶ POA&M (JSON/Excel/CSV)
        │
        ▼
  compliance_scorer.py ─────────▶ Compliance score (JSON/HTML)
                                   + SQLite trend data

  evidence_collector.py ────────▶ Evidence artifacts + manifest

  inventory_drift.py ───────────▶ Drift report (JSON/CSV/HTML)
```

### Key dependency: compliance-trestle

The [compliance-trestle](https://github.com/oscal-compass/compliance-trestle) library (CNCF OSCAL Compass project) provides the OSCAL data model layer. It gives us:

- Pydantic models for all seven OSCAL document types
- Profile resolution (flattening FedRAMP profiles against the NIST catalog)
- Agile authoring (split OSCAL into Markdown fragments, reassemble back)
- FedRAMP-specific validation via the `compliance-trestle-fedramp` plugin

We chose trestle over raw JSON manipulation because OSCAL documents are complex (the catalog alone is 70,000+ lines) and getting the model relationships right matters for validation.

### Report generation

The `utils/report_generators.py` module provides a consistent output layer across all scripts. It supports HTML (via Jinja2 templates), Excel (via openpyxl), CSV (via Python stdlib), and JSON. Every script that produces output can write to any of these formats.

## Configuration

### Control mappings

`config/fedramp-controls-mapping.yaml` maps control families to cloud provider services and API calls. This powers both evidence collection and inheritance mapping. The structure:

```yaml
AC:
  aws:
    services: [iam, cognito, sso]
    api_calls:
      - service: iam
        call: list_users
        control_ids: [AC-2]
  azure:
    services: [entra-id, rbac]
```

### SLA thresholds

`config/sla-thresholds.yaml` defines FedRAMP's vulnerability remediation timelines:

```yaml
high:
  remediation_days: 30
  escalation_dfr_days: 30
  escalation_cap_days: 60
moderate:
  remediation_days: 90
low:
  remediation_days: 180
```

## Versioning

Releases are tagged to FedRAMP baseline versions using semantic versioning:

- **Major:** Baseline revision changes (Rev 5 to Rev 6)
- **Minor:** Template updates, new scripts, new checklist content
- **Patch:** Bug fixes, documentation corrections

Tags include the OSCAL version targeted (e.g., `v1.0.0-rev5-oscal1.0.4`).

## Testing strategy

**Unit tests** (131 tests) cover individual functions: catalog parsing, gap analysis logic, inheritance rules, POA&M calculations, OSCAL validation, scoring algorithms, scan normalization, drift detection, and SSP generation.

**Integration tests** (31 tests) validate pipeline workflows: inheritance output feeding gap analysis, scan results flowing through to POA&M, SSP generation through validation, end-to-end assessment pipelines, and edge cases like empty inputs and perfect/zero compliance scores.

Tests run on every PR via GitHub Actions. The 5 skipped tests require downloaded FedRAMP baselines (not included in the repo) and verify exact control counts against the authoritative OSCAL sources.
