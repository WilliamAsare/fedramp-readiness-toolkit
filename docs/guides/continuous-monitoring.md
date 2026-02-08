# Continuous Monitoring Guide

FedRAMP authorization is the starting gate, not the finish line. Once you have your ATO, continuous monitoring (ConMon) keeps it alive. Failure to maintain ConMon can result in ATO suspension or revocation.

This guide covers how to use the toolkit's automation scripts to stay on top of monthly deliverables and avoid the escalation triggers that get FedRAMP's attention.

## What you owe every month

FedRAMP requires these deliverables monthly after authorization:

- Updated POA&M with all open findings and their remediation status
- Raw vulnerability scan files (OS, web application, database, container)
- Service configuration scan results
- Updated system inventory
- Continuous Monitoring Monthly Executive Summary
- Any deviation requests or significant change requests

Missing or late deliverables trigger escalation. The toolkit automates most of this.

## The monthly workflow

Here's the practical sequence using the toolkit scripts:

### 1. Run vulnerability scans and aggregate results

```bash
# Aggregate results from multiple scanners
python scripts/scan_aggregator.py \
  --nessus scans/nessus-january.csv \
  --trivy scans/trivy-january.json \
  --output-dir conmon/2025-01/scans/

# This normalizes findings across scanners, deduplicates by CVE ID,
# and produces a unified findings JSON plus summary statistics
```

The scan aggregator handles Nessus CSV, Qualys XML, AWS Inspector JSON, and Trivy JSON. It normalizes severity levels across scanners and deduplicates findings that appear in multiple scan tools.

### 2. Update the POA&M

```bash
# Import new scan findings into POA&M, calculate SLA deadlines
python scripts/poam_manager.py \
  --import-scans conmon/2025-01/scans/aggregated.json \
  --existing-poam conmon/2024-12/poam.json \
  --output conmon/2025-01/poam.json \
  --csv conmon/2025-01/poam.csv \
  --excel conmon/2025-01/poam.xlsx
```

The POA&M manager:

- Merges new findings with existing open items
- Marks remediated items as closed (when a previous finding no longer appears in scans)
- Calculates SLA deadlines: High = 30 days, Moderate = 90 days, Low = 180 days from first discovery
- Flags overdue items with days past due
- Checks escalation thresholds (more on this below)

### 3. Check for inventory drift

```bash
# Compare documented inventory against live cloud resources
python scripts/inventory_drift.py \
  --documented templates/xlsx/Integrated-Inventory-Workbook.xlsx \
  --live-aws \
  --output conmon/2025-01/drift-report.json \
  --html conmon/2025-01/drift-report.html
```

This catches the common problem of new resources being deployed without updating the inventory workbook. Anything that shows up live but isn't documented needs to either be added to the inventory or removed from the environment.

### 4. Run compliance scoring

```bash
# Generate current compliance posture
python scripts/compliance_scorer.py \
  --gap-analysis reports/gap-analysis.json \
  --poam conmon/2025-01/poam.json \
  --output conmon/2025-01/score.json \
  --html conmon/2025-01/dashboard.html
```

The scorer produces a composite score incorporating control implementation status, open vulnerability counts by severity, overdue POA&M items, and inventory drift percentage. It also stores historical scores in SQLite for trend tracking.

### 5. Collect fresh evidence

```bash
# Pull current configurations from cloud APIs
python scripts/evidence_collector.py \
  --provider aws \
  --all-families \
  --output-dir conmon/2025-01/evidence/
```

See the [Evidence Collection Guide](evidence-collection.md) for full setup instructions.

### 6. Package the deliverables

Organize your monthly ConMon submission:

```
conmon/2025-01/
  scans/
    nessus-january.csv          # Raw scan files
    trivy-january.json
    aggregated.json             # Normalized summary
  poam.xlsx                     # Updated POA&M (FedRAMP template format)
  drift-report.html             # Inventory drift report
  score.json                    # Compliance posture snapshot
  dashboard.html                # Visual compliance dashboard
  evidence/                     # Fresh configuration evidence
  executive-summary.md          # You write this part
```

The executive summary is the one piece you still write manually. It should cover what changed this month, remediation progress, any new risks, and your plan for the coming month.

## Escalation thresholds

FedRAMP's performance management framework defines specific triggers. The `poam_manager.py` script monitors all of these automatically and warns you when you're approaching them:

**Detailed Finding Review (DFR) triggers:**
- 5+ High vulnerabilities aged past 30 days
- 10+ Moderate vulnerabilities aged past 90 days
- Unauthenticated scans exceeding 10% of total (first offense)

**Corrective Action Plan (CAP) triggers:**
- High vulnerabilities aged past 60 days (after DFR)
- Moderate vulnerabilities aged past 120 days (after DFR)
- Unauthenticated scans exceeding 10% (second offense)
- Late annual assessment SAP (less than 60 days before anniversary)
- Late annual assessment package (after anniversary date)

When you run `poam_manager.py`, it calculates these thresholds and includes alerts in the output:

```bash
python scripts/poam_manager.py --check-escalation --poam conmon/2025-01/poam.json
```

If you see escalation warnings, prioritize those remediations immediately. A DFR means FedRAMP is looking at your program closely. A CAP means you're in trouble.

## Automating the monthly cycle

Set up a GitHub Actions workflow (or equivalent) to run the non-interactive parts automatically:

```yaml
name: Monthly ConMon
on:
  schedule:
    - cron: '0 6 1 * *'  # First of each month
jobs:
  conmon:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install -e .

      - name: Collect evidence
        run: python scripts/evidence_collector.py --provider aws --all-families --output-dir conmon/$(date +%Y-%m)/evidence/

      - name: Check inventory drift
        run: python scripts/inventory_drift.py --documented templates/xlsx/Integrated-Inventory-Workbook.xlsx --live-aws --output conmon/$(date +%Y-%m)/drift.json

      - name: Score compliance posture
        run: python scripts/compliance_scorer.py --gap-analysis reports/gap-analysis.json --output conmon/$(date +%Y-%m)/score.json

      - name: Check escalation triggers
        run: python scripts/poam_manager.py --check-escalation --poam conmon/$(date +%Y-%m)/poam.json

      - name: Commit results
        run: |
          git add conmon/
          git commit -m "ConMon $(date +%Y-%m) automated collection"
          git push
```

Scan aggregation and POA&M updates typically need human review before submission, so those stay manual. But evidence collection, drift detection, and escalation checking can run automatically.

## Annual assessment preparation

Once a year, your 3PAO conducts a full reassessment. Start preparing 90 days before your anniversary date:

1. Run a fresh gap analysis to identify any controls that have drifted
2. Resolve all High and Moderate POA&M items (or have documented remediation plans)
3. Update all policy documents that are due for annual review
4. Ensure your inventory workbook is current and matches the live environment
5. Coordinate with your 3PAO on the SAP submission (must be at least 60 days before anniversary to avoid CAP)

The `checklists/conmon-monthly-checklist.md` has the full pre-assessment preparation list.
