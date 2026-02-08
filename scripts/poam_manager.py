#!/usr/bin/env python3
"""
POA&M Manager

Manages the Plan of Action & Milestones (POA&M) for FedRAMP continuous monitoring.
Parses scan aggregator output, tracks remediation SLAs, flags FedRAMP escalation
triggers, and generates POA&M reports in FedRAMP template format.

FedRAMP SLAs:
    High   = 30 days from discovery
    Moderate = 90 days from discovery
    Low    = 180 days from discovery

Escalation triggers:
    5+ High aged >30d  -> Detailed Finding Review; >60d -> Corrective Action Plan
    10+ Mod aged >90d  -> Detailed Finding Review; >120d -> Corrective Action Plan
    >10% unauthenticated scans -> DFR on first offense

Usage:
    python scripts/poam_manager.py --input scan-findings.json --output-dir reports/
    python scripts/poam_manager.py --input scan-findings.json --existing poam.json --output-dir reports/
    python scripts/poam_manager.py --input scan-findings.csv --output-dir reports/ --format xlsx
"""

import argparse
import csv
import json
import logging
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

logger = logging.getLogger(__name__)

# Load SLA thresholds from config
_SLA_CONFIG_PATH = PROJECT_ROOT / "config" / "sla-thresholds.yaml"


def load_sla_config() -> dict:
    """Load SLA and escalation thresholds from config."""
    if _SLA_CONFIG_PATH.exists():
        return yaml.safe_load(_SLA_CONFIG_PATH.read_text())
    # Fallback defaults
    return {
        "remediation_slas": {"high": {"days": 30}, "moderate": {"days": 90}, "low": {"days": 180}},
        "warning_thresholds": {
            "high_vuln_age_warning_days": 20,
            "moderate_vuln_age_warning_days": 75,
            "low_vuln_age_warning_days": 160,
        },
    }


# --- Data structures ---


def get_sla_days(severity: str, config: dict) -> int:
    """Get the SLA deadline in days for a severity level."""
    slas = config.get("remediation_slas", {})
    severity_key = severity.lower()
    if severity_key == "critical":
        severity_key = "high"  # FedRAMP treats critical same as high for SLA
    return slas.get(severity_key, {}).get("days", 90)


def calculate_sla_deadline(first_seen: str, severity: str, config: dict) -> str:
    """Calculate the SLA deadline date."""
    sla_days = get_sla_days(severity, config)
    try:
        seen_dt = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        seen_dt = datetime.now(timezone.utc)
    deadline = seen_dt + timedelta(days=sla_days)
    return deadline.isoformat()


def calculate_age_days(first_seen: str) -> int:
    """Calculate the age of a finding in days."""
    try:
        seen_dt = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return 0
    now = datetime.now(timezone.utc)
    if seen_dt.tzinfo is None:
        seen_dt = seen_dt.replace(tzinfo=timezone.utc)
    return max(0, (now - seen_dt).days)


def is_overdue(first_seen: str, severity: str, config: dict) -> bool:
    """Check if a finding has exceeded its SLA."""
    age = calculate_age_days(first_seen)
    sla_days = get_sla_days(severity, config)
    return age > sla_days


def days_until_sla(first_seen: str, severity: str, config: dict) -> int:
    """Days remaining until SLA breach. Negative means overdue."""
    age = calculate_age_days(first_seen)
    sla_days = get_sla_days(severity, config)
    return sla_days - age


# --- POA&M item generation ---


def create_poam_item(finding: dict, config: dict, poam_id: int) -> dict:
    """Create a POA&M item from a scan finding."""
    severity = finding.get("severity", "MODERATE")
    first_seen = finding.get("first_seen", "")
    age = calculate_age_days(first_seen)
    sla_days = get_sla_days(severity, config)

    return {
        "poam_id": f"POAM-{poam_id:04d}",
        "finding_id": finding.get("finding_id", ""),
        "cve_id": finding.get("cve_id"),
        "title": finding.get("title", ""),
        "severity": severity,
        "cvss_score": finding.get("cvss_score"),
        "affected_resource": finding.get("affected_resource", ""),
        "resource_type": finding.get("resource_type", ""),
        "scanner": finding.get("scanner", ""),
        "weakness_description": finding.get("description", ""),
        "remediation_plan": finding.get("solution", "Apply vendor-supplied patch"),
        "first_seen": first_seen,
        "sla_deadline": calculate_sla_deadline(first_seen, severity, config),
        "sla_days": sla_days,
        "age_days": age,
        "days_remaining": sla_days - age,
        "is_overdue": age > sla_days,
        "status": "Open",
        "milestone": "Remediation in progress",
        "scheduled_completion": calculate_sla_deadline(first_seen, severity, config),
        "vendor_dependency": False,
        "deviation_request": False,
        "false_positive": False,
        "operational_requirement": False,
        "risk_adjustment": None,
        "comments": "",
    }


# --- Escalation analysis ---


def check_escalation_triggers(poam_items: list[dict], config: dict) -> list[dict]:
    """
    Check for FedRAMP performance management escalation triggers.

    Returns a list of triggered escalation conditions with severity.
    """
    triggers = []

    open_items = [i for i in poam_items if i["status"] == "Open"]

    # High vulns aged beyond SLA
    high_overdue_30 = [i for i in open_items if i["severity"] in ("CRITICAL", "HIGH") and i["age_days"] > 30]
    high_overdue_60 = [i for i in open_items if i["severity"] in ("CRITICAL", "HIGH") and i["age_days"] > 60]

    if len(high_overdue_30) >= 5:
        triggers.append({
            "type": "Detailed Finding Review",
            "condition": f"{len(high_overdue_30)} High/Critical vulnerabilities aged >30 days (threshold: 5)",
            "severity": "WARNING",
            "count": len(high_overdue_30),
            "action": "FedRAMP may initiate a Detailed Finding Review. Prioritize remediation immediately.",
        })

    if len(high_overdue_60) >= 5:
        triggers.append({
            "type": "Corrective Action Plan",
            "condition": f"{len(high_overdue_60)} High/Critical vulnerabilities aged >60 days (threshold: 5)",
            "severity": "CRITICAL",
            "count": len(high_overdue_60),
            "action": "FedRAMP will likely require a Corrective Action Plan. Escalate to leadership.",
        })

    # Moderate vulns aged beyond SLA
    mod_overdue_90 = [i for i in open_items if i["severity"] == "MODERATE" and i["age_days"] > 90]
    mod_overdue_120 = [i for i in open_items if i["severity"] == "MODERATE" and i["age_days"] > 120]

    if len(mod_overdue_90) >= 10:
        triggers.append({
            "type": "Detailed Finding Review",
            "condition": f"{len(mod_overdue_90)} Moderate vulnerabilities aged >90 days (threshold: 10)",
            "severity": "WARNING",
            "count": len(mod_overdue_90),
            "action": "FedRAMP may initiate a Detailed Finding Review for Moderate findings.",
        })

    if len(mod_overdue_120) >= 10:
        triggers.append({
            "type": "Corrective Action Plan",
            "condition": f"{len(mod_overdue_120)} Moderate vulnerabilities aged >120 days (threshold: 10)",
            "severity": "CRITICAL",
            "count": len(mod_overdue_120),
            "action": "FedRAMP will likely require a Corrective Action Plan. Escalate to leadership.",
        })

    # Warning thresholds (internal early warnings)
    warning_cfg = config.get("warning_thresholds", {})
    high_warn_days = warning_cfg.get("high_vuln_age_warning_days", 20)
    mod_warn_days = warning_cfg.get("moderate_vuln_age_warning_days", 75)

    high_approaching = [
        i for i in open_items
        if i["severity"] in ("CRITICAL", "HIGH") and high_warn_days <= i["age_days"] <= 30
    ]
    if high_approaching:
        triggers.append({
            "type": "Internal Warning",
            "condition": f"{len(high_approaching)} High/Critical vulns approaching 30-day SLA",
            "severity": "INFO",
            "count": len(high_approaching),
            "action": "Prioritize remediation to avoid FedRAMP escalation.",
        })

    return triggers


# --- Input loading ---


def load_scan_findings(filepath: Path) -> list[dict]:
    """Load scan findings from JSON or CSV."""
    suffix = filepath.suffix.lower()

    if suffix == ".json":
        data = json.loads(filepath.read_text())
        if isinstance(data, dict):
            return data.get("findings", [])
        return data

    elif suffix == ".csv":
        with open(filepath, "r") as f:
            return list(csv.DictReader(f))

    else:
        raise ValueError(f"Unsupported input format: {suffix}. Use .json or .csv")


def load_existing_poam(filepath: Path) -> list[dict]:
    """Load existing POA&M for merging."""
    if not filepath.exists():
        return []
    data = json.loads(filepath.read_text())
    if isinstance(data, dict):
        return data.get("items", [])
    return data


def merge_poam(existing: list[dict], new_items: list[dict]) -> list[dict]:
    """
    Merge new findings into existing POA&M.

    - Existing items matched by finding_id are updated with latest scan data
    - New findings get new POA&M IDs
    - Items no longer in scans are marked as "Remediated (Pending Verification)"
    """
    existing_by_fid = {i["finding_id"]: i for i in existing}
    new_fids = {i["finding_id"] for i in new_items}

    merged = []
    max_id = max((int(i["poam_id"].split("-")[1]) for i in existing), default=0)

    # Update existing items
    for item in existing:
        fid = item["finding_id"]
        if fid in new_fids:
            # Still present in scans — update age and scan data
            new_match = next(n for n in new_items if n["finding_id"] == fid)
            item["age_days"] = new_match["age_days"]
            item["days_remaining"] = new_match["days_remaining"]
            item["is_overdue"] = new_match["is_overdue"]
            merged.append(item)
        else:
            # No longer in scans — potentially remediated
            if item["status"] == "Open":
                item["status"] = "Remediated (Pending Verification)"
                item["comments"] = f"Not found in latest scan on {datetime.now().strftime('%Y-%m-%d')}"
            merged.append(item)

    # Add genuinely new findings
    for item in new_items:
        if item["finding_id"] not in existing_by_fid:
            max_id += 1
            item["poam_id"] = f"POAM-{max_id:04d}"
            merged.append(item)

    return merged


# --- POA&M summary ---


def compute_poam_summary(items: list[dict]) -> dict[str, Any]:
    """Compute POA&M summary statistics."""
    open_items = [i for i in items if i["status"] == "Open"]
    overdue = [i for i in open_items if i.get("is_overdue")]

    by_severity = {}
    for i in open_items:
        sev = i["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1

    return {
        "total_items": len(items),
        "open": len(open_items),
        "overdue": len(overdue),
        "remediated": len([i for i in items if "Remediated" in i.get("status", "")]),
        "by_severity": by_severity,
        "oldest_age_days": max((i["age_days"] for i in open_items), default=0),
        "avg_age_days": round(sum(i["age_days"] for i in open_items) / max(len(open_items), 1), 1),
        "critical_high_overdue": len([
            i for i in overdue if i["severity"] in ("CRITICAL", "HIGH")
        ]),
    }


# --- Output ---


def output_poam_json(items: list[dict], summary: dict, escalations: list[dict], output_path: Path):
    """Write POA&M as JSON."""
    data = {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "toolkit_version": "0.1.0",
        },
        "summary": summary,
        "escalation_triggers": escalations,
        "items": items,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(data, indent=2, default=str))
    logger.info(f"POA&M JSON written to {output_path}")


def output_poam_csv(items: list[dict], output_path: Path):
    """Write POA&M as CSV."""
    if not items:
        return

    fields = [
        "poam_id", "finding_id", "cve_id", "title", "severity", "cvss_score",
        "affected_resource", "scanner", "status", "first_seen", "age_days",
        "sla_days", "days_remaining", "is_overdue", "sla_deadline",
        "remediation_plan", "milestone", "scheduled_completion", "comments",
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(sorted(items, key=lambda x: (
            0 if x.get("is_overdue") else 1,
            {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3}.get(x.get("severity", ""), 4),
        )))
    logger.info(f"POA&M CSV written to {output_path}")


def output_poam_xlsx(items: list[dict], summary: dict, escalations: list[dict], output_path: Path):
    """Write POA&M as Excel workbook."""
    from scripts.utils.report_generators import generate_excel_report

    summary_rows = [{"Metric": k, "Value": v} for k, v in [
        ("Total Items", summary["total_items"]),
        ("Open", summary["open"]),
        ("Overdue", summary["overdue"]),
        ("Critical/High Overdue", summary["critical_high_overdue"]),
        ("Remediated", summary["remediated"]),
        ("Oldest Age (days)", summary["oldest_age_days"]),
        ("Average Age (days)", summary["avg_age_days"]),
    ]]

    escalation_rows = [
        {"Type": e["type"], "Condition": e["condition"], "Severity": e["severity"], "Action": e["action"]}
        for e in escalations
    ] if escalations else [{"Type": "None", "Condition": "No escalation triggers active", "Severity": "OK", "Action": "Continue monitoring"}]

    item_rows = [{
        "POA&M ID": i["poam_id"], "CVE": i.get("cve_id", "N/A"), "Title": i["title"][:80],
        "Severity": i["severity"], "Resource": i["affected_resource"][:60],
        "Status": i["status"], "Age (days)": i["age_days"],
        "SLA (days)": i["sla_days"], "Remaining": i["days_remaining"],
        "Overdue": "YES" if i.get("is_overdue") else "",
        "Remediation Plan": i["remediation_plan"][:100],
        "Deadline": i.get("sla_deadline", "")[:10],
    } for i in items]

    generate_excel_report(
        title="FedRAMP POA&M",
        sheets_data={"Summary": summary_rows, "Escalations": escalation_rows, "POA&M Items": item_rows},
        output_path=output_path,
    )
    logger.info(f"POA&M Excel written to {output_path}")


def print_summary(summary: dict, escalations: list[dict]):
    """Print POA&M summary to console."""
    print(f"\n  POA&M Summary")
    print(f"  {'='*45}")
    print(f"  Total items:     {summary['total_items']}")
    print(f"  Open:            {summary['open']}")
    print(f"  Overdue:         {summary['overdue']}")
    print(f"  Remediated:      {summary['remediated']}")
    print(f"  Avg age (days):  {summary['avg_age_days']}")

    if summary.get("by_severity"):
        print(f"\n  Open by severity:")
        for sev, count in sorted(summary["by_severity"].items()):
            print(f"    {sev}: {count}")

    if escalations:
        print(f"\n  *** ESCALATION TRIGGERS ***")
        for e in escalations:
            indicator = "!!!" if e["severity"] == "CRITICAL" else "!" if e["severity"] == "WARNING" else "~"
            print(f"  {indicator} [{e['type']}] {e['condition']}")
    else:
        print(f"\n  No escalation triggers active.")
    print()


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def main():
    parser = argparse.ArgumentParser(description="FedRAMP POA&M Manager")
    parser.add_argument("--input", "-i", type=Path, required=True, help="Scan findings (JSON or CSV)")
    parser.add_argument("--existing", "-e", type=Path, help="Existing POA&M JSON for merging")
    parser.add_argument("--output-dir", "-o", type=Path, required=True)
    parser.add_argument("--format", "-f", choices=["json", "csv", "xlsx", "all"], default="all")
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()
    setup_logging(args.verbose)

    config = load_sla_config()
    findings = load_scan_findings(args.input)
    logger.info(f"Loaded {len(findings)} findings from {args.input}")

    # Create POA&M items
    poam_items = []
    for idx, finding in enumerate(findings, start=1):
        if finding.get("severity", "").upper() in ("INFORMATIONAL",):
            continue
        poam_items.append(create_poam_item(finding, config, idx))

    # Merge with existing if provided
    if args.existing:
        existing = load_existing_poam(args.existing)
        poam_items = merge_poam(existing, poam_items)
        logger.info(f"Merged with {len(existing)} existing items -> {len(poam_items)} total")

    # Analysis
    escalations = check_escalation_triggers(poam_items, config)
    summary = compute_poam_summary(poam_items)
    print_summary(summary, escalations)

    # Output
    ts = datetime.now().strftime("%Y%m%d")
    args.output_dir.mkdir(parents=True, exist_ok=True)

    if args.format in ("json", "all"):
        output_poam_json(poam_items, summary, escalations, args.output_dir / f"poam-{ts}.json")
    if args.format in ("csv", "all"):
        output_poam_csv(poam_items, args.output_dir / f"poam-{ts}.csv")
    if args.format in ("xlsx", "all"):
        output_poam_xlsx(poam_items, summary, escalations, args.output_dir / f"poam-{ts}.xlsx")


if __name__ == "__main__":
    main()
