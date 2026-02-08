# FedRAMP Readiness Assessment Toolkit

A comprehensive, open-source toolkit for Cloud Service Providers preparing for FedRAMP authorization. Covers all three impact levels (Low, Moderate, High), built on NIST SP 800-53 Rev 5 baselines and OSCAL machine-readable standards.

**162 tests passing** | **13 automation scripts** | **10 compliance checklists** | **4 policy templates**

## What this toolkit does

FedRAMP authorization is expensive ($250K-$3M+), slow (12-18 months traditionally), and documentation-heavy. This toolkit reduces that burden:

- **Gap analysis** — Compare your current security posture against FedRAMP baselines. Get a prioritized remediation roadmap with compliance scores per control family and estimated effort.
- **Control inheritance mapping** — See exactly which controls you inherit from AWS GovCloud, Azure Government, or GCP Assured Workloads. This is the fastest way to reduce your compliance scope.
- **SSP generation** — Build your System Security Plan from structured YAML metadata and Markdown control narratives. Produces valid OSCAL JSON that passes FedRAMP validation.
- **Vulnerability scan aggregation** — Normalize results from Nessus, Qualys, Trivy, and AWS Inspector into a unified format with CVE-based deduplication.
- **POA&M management** — Track findings, calculate SLA deadlines (30/90/180 days), detect escalation triggers, and export to FedRAMP template format.
- **Evidence collection** — Pull configuration evidence from cloud provider APIs with SHA-256 integrity hashing and structured manifests.
- **OSCAL validation** — Validate all compliance documents against FedRAMP Schematron rules. Designed for CI/CD pipeline integration.
- **Compliance scoring** — Composite posture scoring with SQLite trend tracking and threshold gates for automated quality checks.
- **Inventory drift detection** — Compare documented inventory against live cloud resources to catch undocumented changes.
- **Continuous monitoring automation** — Monthly ConMon deliverable packaging with escalation threshold monitoring.

## Who this is for

CSPs pursuing FedRAMP authorization via the Agency Authorization path or preparing for FedRAMP 20x. Assumes you have a working cloud environment and a security team familiar with NIST 800-53 concepts.

## Quick start

```bash
# Clone and install
git clone https://github.com/your-org/fedramp-readiness-toolkit.git
cd fedramp-readiness-toolkit
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Download official FedRAMP baselines
make baselines

# Explore Moderate baseline controls
python scripts/catalog_parser.py --baseline moderate --output-format table

# Map inherited controls from your cloud provider
python scripts/inheritance_mapper.py --baseline moderate --provider aws --output inheritance.yaml

# Run a gap analysis
python scripts/gap_analysis.py \
  --baseline moderate \
  --input your-implementation-status.yaml \
  --inheritance inheritance.yaml \
  --output-dir reports/
```

See [docs/getting-started.md](docs/getting-started.md) for the full 15-minute walkthrough.

## Repository structure

```
fedramp-readiness-toolkit/
├── baselines/          # FedRAMP Rev 5 OSCAL baselines + NIST catalog
├── checklists/         # Step-by-step compliance checklists (10 checklists)
├── config/             # Control mappings, evidence requirements, SLA thresholds
├── docs/               # Guides, architecture docs, ADRs
├── examples/           # Sample SSPs, gap reports, evidence structures
├── scripts/            # Python automation (13 scripts, ~5,700 lines)
├── templates/          # OSCAL, DOCX, XLSX templates + policy starters
└── tests/              # 162 tests (131 unit + 31 integration)
```

## FedRAMP baselines supported

| Baseline | Controls | Status |
|----------|----------|--------|
| LI-SaaS  | 156 (66 tested, 90 attested) | Supported |
| Low      | 156      | Supported |
| Moderate | 323      | Supported (primary target) |
| High     | 410      | Supported |

## Scripts

| Script | Purpose | Docs |
|--------|---------|------|
| `catalog_parser.py` | Parse NIST 800-53 Rev 5 catalog, resolve FedRAMP profiles | [Getting Started](docs/getting-started.md) |
| `gap_analysis.py` | Compare implementation status against baselines | [Gap Analysis Guide](docs/guides/gap-analysis.md) |
| `inheritance_mapper.py` | Map inherited controls from AWS/Azure/GCP | [Gap Analysis Guide](docs/guides/gap-analysis.md) |
| `ssp_generator.py` | Generate OSCAL SSP from YAML/Markdown inputs | [SSP Development](docs/guides/ssp-development.md) |
| `evidence_collector.py` | Collect config evidence from cloud APIs | [Evidence Collection](docs/guides/evidence-collection.md) |
| `scan_aggregator.py` | Normalize vuln scans (Nessus, Trivy, Qualys, Inspector) | [ConMon Guide](docs/guides/continuous-monitoring.md) |
| `poam_manager.py` | POA&M generation, SLA tracking, escalation alerts | [ConMon Guide](docs/guides/continuous-monitoring.md) |
| `oscal_validator.py` | Validate OSCAL docs against FedRAMP rules | [OSCAL Guide](docs/oscal-guide.md) |
| `compliance_scorer.py` | Composite scoring with trend tracking | [ConMon Guide](docs/guides/continuous-monitoring.md) |
| `inventory_drift.py` | Detect drift between documented and live inventory | [ConMon Guide](docs/guides/continuous-monitoring.md) |

## Documentation

| Document | What it covers |
|----------|---------------|
| [Getting Started](docs/getting-started.md) | Installation, first gap analysis, all script reference |
| [FedRAMP Overview](docs/fedramp-overview.md) | Primer on FedRAMP for newcomers |
| [Architecture](docs/architecture.md) | Design decisions, data flow, testing strategy |
| [OSCAL Guide](docs/oscal-guide.md) | How OSCAL works within the toolkit |
| [Gap Analysis Guide](docs/guides/gap-analysis.md) | Full gap analysis workflow |
| [SSP Development](docs/guides/ssp-development.md) | Agile SSP authoring from YAML + Markdown |
| [Evidence Collection](docs/guides/evidence-collection.md) | Automated evidence gathering setup |
| [Continuous Monitoring](docs/guides/continuous-monitoring.md) | Monthly ConMon workflow and escalation tracking |

## OSCAL and FedRAMP 20x

This toolkit is OSCAL-first. FedRAMP has mandated that all CSPs transition authorization packages to OSCAL format by September 2026. We use the [compliance-trestle](https://github.com/oscal-compass/compliance-trestle) library (CNCF OSCAL Compass project) for all OSCAL operations.

FedRAMP 20x is replacing document-heavy processes with automation-driven authorization. The 20x Low pilot completed with 12 authorizations averaging about 5 weeks. The Moderate pilot launched November 2025. This toolkit supports both the current Rev 5 Agency Authorization path and the 20x transition.

## Authoritative sources

Baseline data comes directly from official sources:

- [GSA/fedramp-automation](https://github.com/GSA/fedramp-automation) — FedRAMP OSCAL baselines and validation rules
- [usnistgov/oscal-content](https://github.com/usnistgov/OSCAL) — NIST SP 800-53 Rev 5 catalog
- [automate.fedramp.gov](https://automate.fedramp.gov) — FedRAMP OSCAL implementation guides
- [fedramp.gov](https://www.fedramp.gov) — Official templates, playbooks, and guidance

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). We welcome control interpretation updates, cloud provider integrations, template improvements, and documentation fixes.

## License

Apache-2.0. See [LICENSE](LICENSE).

## Disclaimer

This toolkit is a community resource and is not officially endorsed by FedRAMP, GSA, or NIST. It helps CSPs prepare for authorization but does not guarantee authorization outcomes. Always consult official FedRAMP documentation and your 3PAO for authoritative guidance.
