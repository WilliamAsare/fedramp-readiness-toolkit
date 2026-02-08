# Changelog

All notable changes to this project will be documented in this file.

This project uses [Semantic Versioning](https://semver.org/). Releases are tagged to FedRAMP baseline versions (e.g., `v1.0.0-rev5-oscal1.0.4`).

## [1.0.0] - 2025-02-07

Initial release targeting NIST SP 800-53 Rev 5 / FedRAMP Rev 5 baselines.

### Scripts (13 automation tools)

- **catalog_parser.py** — Parse NIST 800-53 Rev 5 OSCAL catalog, resolve FedRAMP profiles, filter by family/baseline/keyword, export to CSV/JSON/Markdown/table
- **gap_analysis.py** — Compare implementation status (YAML, CSV, or OSCAL SSP) against FedRAMP baselines. Produces prioritized gap reports with compliance scoring, family summaries, and effort estimation. Accepts both dict and string status formats.
- **inheritance_mapper.py** — Map control inheritance from AWS GovCloud, Azure Government, and GCP Assured Workloads. Supports custom overrides. Produces YAML/JSON/Markdown responsibility matrices.
- **ssp_generator.py** — Generate OSCAL SSP from YAML system metadata and Markdown control narratives. Populates by-component entries, handles inheritance properties, validates output structure.
- **evidence_collector.py** — Multi-cloud evidence collection from AWS, Azure, and GCP APIs. Maps control families to API calls, timestamps artifacts, computes SHA-256 hashes, generates evidence manifests.
- **scan_aggregator.py** — Normalize vulnerability scan results from Nessus CSV, Trivy JSON, Qualys XML, and AWS Inspector JSON. CVE-based deduplication across scanners. Produces unified findings with severity normalization.
- **poam_manager.py** — POA&M lifecycle management. Import findings from scans, calculate SLA deadlines (30/90/180 days), detect overdue items, check FedRAMP escalation triggers (DFR/CAP thresholds), merge month-over-month, export to FedRAMP Excel template.
- **oscal_validator.py** — Validate OSCAL documents (SSP, SAP, SAR, POA&M) against structural requirements and FedRAMP business rules. CI/CD-friendly exit codes.
- **compliance_scorer.py** — Composite compliance scoring from gap analysis and POA&M data. SQLite trend storage. Risk rating calculation. Threshold gates for pipeline enforcement.
- **inventory_drift.py** — Compare documented inventory against live cloud resources. Detect stale, undocumented, and mismatched items. Output JSON, CSV, and HTML drift reports.
- **oscal_helpers.py** — OSCAL parsing utilities used across scripts
- **cloud_providers.py** — AWS/Azure/GCP API abstraction layer
- **report_generators.py** — HTML (Jinja2), Excel (openpyxl), CSV, and JSON report output

### Checklists (10)

- Pre-engagement checklist
- FIPS 199 categorization guide with decision trees
- Federal mandates checklist (6 RAR pass/fail requirements)
- Authorization boundary definition checklist
- Low, Moderate, and High baseline checklists
- 3PAO selection guide
- ConMon monthly checklist
- FedRAMP 20x readiness checklist

### Templates

- OSCAL templates for SSP, SAP, SAR, and POA&M
- FedRAMP DOCX templates (SSP, SAP, SAR)
- Excel templates (POA&M, CIS/CRM Workbook, Integrated Inventory Workbook)
- Policy starter templates: Access Control, Incident Response, Configuration Management, Contingency Plan

### Documentation

- Getting Started guide (15-minute quickstart)
- FedRAMP Overview primer
- Architecture document with data flow diagrams
- OSCAL usage guide
- Gap Analysis workflow guide
- SSP Development guide (agile authoring from YAML + Markdown)
- Evidence Collection guide
- Continuous Monitoring guide with escalation threshold tracking

### Infrastructure

- GitHub Actions CI/CD: OSCAL validation, Python testing, linting, release automation
- Makefile with 13 commands (install, test, lint, format, baselines, validate-oscal, etc.)
- Issue templates for bugs, features, and control updates
- 162 tests (131 unit + 31 integration) covering all scripts and pipeline workflows

### Test coverage highlights

- Full pipeline integration: inheritance → gap analysis → scan aggregation → POA&M → SSP generation → OSCAL validation → compliance scoring
- Cross-script data flow validation
- Edge cases: empty inputs, 100%/0% compliance, garbage OSCAL, identical/completely different inventories
- Month-over-month POA&M merge simulation
- Multi-scanner deduplication
- Escalation threshold detection
