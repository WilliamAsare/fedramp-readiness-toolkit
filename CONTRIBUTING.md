# Contributing to the FedRAMP Readiness Assessment Toolkit

Thanks for your interest in contributing. This toolkit is a community resource, and contributions from people with real FedRAMP experience make it better for everyone.

## What we need help with

**Control interpretation updates** are the highest-value contributions. FedRAMP requirements evolve, and interpretations vary between 3PAOs. If you've been through an assessment and found our guidance outdated or incorrect, open a Control Update issue.

**Cloud provider integrations** for evidence collection. We currently support AWS, Azure, and GCP, but coverage across control families is incomplete. Adding new API calls to `evidence_collector.py` and updating `config/evidence-requirements.yaml` directly helps everyone collecting evidence.

**Scanner integrations** for `scan_aggregator.py`. We handle Nessus CSV, Trivy JSON, Qualys XML, and AWS Inspector JSON. Adding Rapid7, Tenable.io, or other scanner formats is straightforward.

**Template improvements** based on actual assessment experience. If a checklist missed something that tripped you up, or a policy template needs better FedRAMP-specific language, that's valuable.

**Documentation fixes** including typos, unclear instructions, outdated references, and better examples.

## How to contribute

### Development setup

```bash
git clone https://github.com/your-org/fedramp-readiness-toolkit.git
cd fedramp-readiness-toolkit
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
make baselines    # Download OSCAL baselines for testing
```

### Making changes

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Run `make format` to auto-format code
4. Run `make lint` to check for issues
5. Run `make test` to verify all 162 tests pass
6. If you changed OSCAL templates, run `make validate-oscal`
7. Open a pull request using the PR template

### Branch naming

Use descriptive branch names: `fix/ac-2-parameter-update`, `feat/rapid7-scanner-support`, `docs/evidence-collection-aws-example`.

### Commit messages

Keep them clear and specific. "Fix AC-2 parameter value to match Rev 5 baseline" is good. "Updates" is not.

## Important rules

**Never manually create or modify control data.** The NIST 800-53 Rev 5 catalog and FedRAMP baselines in `baselines/` come directly from official OSCAL sources. If you think a control count or parameter is wrong, check the authoritative source first.

**Cite your sources.** When updating control interpretations or checklist items, include a reference to the official FedRAMP document, NIST publication, or assessment experience that supports the change. "Per FedRAMP SSP Appendix A, Rev 5" or "verified during Moderate assessment with [3PAO], January 2025" both work.

**Test against known baselines.** The catalog parser must always produce exactly 156 Low, 323 Moderate, and 410 High controls. If your change breaks these counts, something is wrong.

**Don't break the pipeline.** The integration tests validate that scripts work together (inheritance output feeds gap analysis, scan results flow into POA&M, generated SSPs pass validation). All 162 tests must pass before merge.

## Types of contributions

### Control updates

Use the Control Update issue template. Include:

- Which control ID is affected
- What's wrong or outdated
- The correct interpretation with source citation
- Whether this affects checklists, scripts, or both

### New scripts or features

Open a feature request issue first to discuss the approach. For new scripts, follow the existing patterns:

- Accept input via CLI arguments (use argparse)
- Support multiple output formats (JSON, CSV, HTML, Excel where relevant)
- Include unit tests in `tests/unit/` and integration tests if the script connects to other scripts
- Update the relevant guide in `docs/guides/`

### Checklist and policy updates

These are the most accessible contributions. Edit the Markdown files directly and submit a PR. Include a note about what assessment experience or official guidance motivates the change.

## Review process

Pull requests are reviewed on a rolling basis. Changes that affect control interpretations or OSCAL output get extra scrutiny to ensure compliance accuracy.

We follow a quarterly review cadence aligned with FedRAMP's continuous monitoring cycles for larger updates to baselines or templates.

## Code style

We use `black` for formatting and `ruff` for linting. Run `make format` before committing. The CI pipeline enforces this.

## Issue templates

Use the appropriate template when opening issues:

- **Bug Report** for something that's broken
- **Feature Request** for new capabilities
- **Control Update** for FedRAMP control interpretation changes

## Questions?

Open a Discussion thread for questions about FedRAMP interpretation or toolkit architecture. Use Issues for bugs and feature requests.
