# Getting Started

This guide gets you from zero to running your first FedRAMP gap analysis in about 15 minutes.

## Prerequisites

You need Python 3.10 or later and Git. Cloud provider evidence collection (optional) needs the respective CLI tools installed.

```bash
python3 --version  # needs 3.10+
```

## Installation

```bash
git clone https://github.com/your-org/fedramp-readiness-toolkit.git
cd fedramp-readiness-toolkit

python -m venv .venv
source .venv/bin/activate    # macOS/Linux
# .venv\Scripts\activate     # Windows

pip install -e ".[dev]"
```

## Download FedRAMP baselines

The toolkit needs the official NIST 800-53 Rev 5 catalog and FedRAMP baseline profiles:

```bash
make baselines
```

This downloads four FedRAMP baseline profiles (LI-SaaS, Low, Moderate, High) and the NIST SP 800-53 Rev 5 catalog in OSCAL JSON format.

Verify it worked:

```bash
ls baselines/json/
# FedRAMP_rev5_HIGH-baseline.json  FedRAMP_rev5_LOW-baseline.json
# FedRAMP_rev5_MODERATE-baseline.json  FedRAMP_rev5_LI-SaaS-baseline.json

ls baselines/catalogs/
# NIST_SP-800-53_rev5_catalog.json
```

## Explore the control catalog

```bash
# Moderate baseline controls in a formatted table
python scripts/catalog_parser.py --baseline moderate --output-format table

# Per-family breakdown
python scripts/catalog_parser.py --baseline moderate --summary --output-format table

# Filter to one family
python scripts/catalog_parser.py --baseline moderate --family SC --output-format table

# Search for controls by keyword
python scripts/catalog_parser.py --baseline moderate --search "encryption" --output-format table

# Full details on a specific control
python scripts/catalog_parser.py --control SC-13 --output-format detail

# Export to CSV
python scripts/catalog_parser.py --baseline moderate --output-format csv --output moderate-controls.csv
```

## Run a gap analysis

Create a YAML file describing your current implementation status:

```yaml
# my-status.yaml
AC-1:
  status: implemented
  notes: "Access control policy reviewed annually"
AC-2:
  status: partial
  notes: "IAM accounts managed, quarterly review not yet automated"
SC-7:
  status: implemented
  notes: "VPC with WAF and security groups"
SC-13:
  status: not_implemented
  notes: "Need to verify FIPS 140-2 validated modules"
```

You can also use the shorthand format: `AC-1: implemented` (without the nested status/notes).

Run the analysis:

```bash
python scripts/gap_analysis.py \
  --baseline moderate \
  --input my-status.yaml \
  --output-dir reports/
```

This produces a prioritized gap report showing compliance percentage per control family, critical gaps that need immediate attention, and estimated remediation effort. Output includes JSON, HTML dashboard, and Excel workbook.

## Map inherited controls

If you're running on AWS GovCloud, Azure Government, or GCP Assured Workloads, a big chunk of controls are inherited from your cloud provider:

```bash
python scripts/inheritance_mapper.py \
  --baseline moderate \
  --provider aws \
  --output inheritance.yaml
```

This tells you which of the 323 Moderate controls are fully inherited (provider handles it), shared (both you and the provider), or your responsibility. Feed this into the gap analysis:

```bash
python scripts/gap_analysis.py \
  --baseline moderate \
  --input my-status.yaml \
  --inheritance inheritance.yaml \
  --output-dir reports/
```

Your compliance score will improve because inherited controls are no longer gaps.

## Verify your setup

```bash
make test          # All 162 tests
make test-unit     # 131 unit tests only
```

## What to do next

Once you're comfortable with the catalog parser and gap analysis, the recommended path is:

1. **Review the checklists** in `checklists/` for your target baseline, starting with `federal-mandates-checklist.md` (the six pass/fail requirements)
2. **Map your inheritance** to see how much scope reduction your cloud provider gives you
3. **Run the full gap analysis** and prioritize the critical and high-priority gaps
4. **Start writing control narratives** following the [SSP Development Guide](guides/ssp-development.md)
5. **Set up evidence collection** per the [Evidence Collection Guide](guides/evidence-collection.md)
6. **Configure continuous monitoring** per the [Continuous Monitoring Guide](guides/continuous-monitoring.md)

## All available scripts

| Script | What it does | Guide |
|--------|-------------|-------|
| `catalog_parser.py` | Parse and explore NIST 800-53 / FedRAMP controls | This page |
| `gap_analysis.py` | Compare your status against a FedRAMP baseline | [Gap Analysis](guides/gap-analysis.md) |
| `inheritance_mapper.py` | Map inherited controls from cloud providers | [Gap Analysis](guides/gap-analysis.md) |
| `ssp_generator.py` | Build OSCAL SSP from YAML metadata + Markdown narratives | [SSP Development](guides/ssp-development.md) |
| `evidence_collector.py` | Pull configuration evidence from cloud APIs | [Evidence Collection](guides/evidence-collection.md) |
| `scan_aggregator.py` | Normalize vuln scans from Nessus, Trivy, Qualys, Inspector | [Continuous Monitoring](guides/continuous-monitoring.md) |
| `poam_manager.py` | Manage POA&M, track SLAs, check escalation triggers | [Continuous Monitoring](guides/continuous-monitoring.md) |
| `oscal_validator.py` | Validate OSCAL documents against FedRAMP rules | [OSCAL Guide](../oscal-guide.md) |
| `compliance_scorer.py` | Composite compliance scoring with trend tracking | [Continuous Monitoring](guides/continuous-monitoring.md) |
| `inventory_drift.py` | Detect drift between documented and live inventory | [Continuous Monitoring](guides/continuous-monitoring.md) |

## Useful Makefile commands

```bash
make help             # Show all available commands
make baselines        # Download FedRAMP baselines and NIST catalog
make test             # Run all tests (unit + integration)
make test-unit        # Unit tests only
make test-integration # Integration tests only
make test-cov         # Tests with coverage report
make lint             # Check code quality
make format           # Auto-format code
make validate-oscal   # Validate OSCAL documents
make clean            # Remove build artifacts
```

## Troubleshooting

**"File not found" errors when running scripts:** Run `make baselines` to download the required OSCAL files.

**Import errors:** Make sure you installed with `pip install -e .` (the `-e` flag matters).

**Wrong control counts in integration tests:** Your baseline files may be outdated. Re-run `make baselines`.

**Cloud evidence collection fails:** Check that your cloud CLI is authenticated (`aws sts get-caller-identity`, `az account show`, `gcloud auth list`). See `config/cloud-api-config.yaml.example` for configuration.
