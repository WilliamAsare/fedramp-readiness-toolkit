#!/usr/bin/env python3
"""
FedRAMP Gap Analysis Tool

Compares an organization's current security posture against a FedRAMP baseline
and produces a prioritized remediation roadmap. This is the highest-value script
in the toolkit — it answers the question every CSP asks first: "How far are we
from ready?"

Inputs:
    - FedRAMP OSCAL baseline profile (Low/Moderate/High)
    - Organization's control implementation data as either:
      a) OSCAL SSP JSON (with implemented-requirements)
      b) YAML/CSV mapping of control IDs to implementation status

Outputs:
    - Compliance percentage per control family
    - Overall readiness score
    - Critical gaps requiring immediate attention
    - Estimated remediation effort
    - HTML dashboard, Excel workbook, and JSON report

Usage:
    python scripts/gap_analysis.py --baseline moderate --input my-status.yaml --output-dir reports/
    python scripts/gap_analysis.py --baseline moderate --input my-ssp.json --output-dir reports/
    python scripts/gap_analysis.py --baseline moderate --input my-status.yaml --summary-only
"""

import argparse
import csv
import io
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.utils.oscal_helpers import (
    CONTROL_FAMILIES,
    EXPECTED_CONTROL_COUNTS,
    FEDRAMP_ACTIVE_FAMILIES,
    extract_control_ids_from_profile,
    extract_controls_from_catalog,
    filter_catalog_by_baseline,
    get_family_from_control_id,
    load_baseline,
    load_catalog,
    validate_control_count,
)

logger = logging.getLogger(__name__)

# Implementation status categories
IMPLEMENTATION_STATUSES = {
    "implemented": "Fully implemented and operational",
    "partial": "Partially implemented or in progress",
    "planned": "Planned but not yet implemented",
    "not_implemented": "Not implemented and not planned",
    "inherited": "Inherited from FedRAMP-authorized provider",
    "na": "Not applicable (with documented justification)",
}

# Effort estimation (person-days per control) by family — rough averages
EFFORT_ESTIMATES = {
    "AC": {"implement": 15, "document": 5, "test": 3},
    "AT": {"implement": 5, "document": 3, "test": 1},
    "AU": {"implement": 12, "document": 4, "test": 3},
    "CA": {"implement": 8, "document": 5, "test": 3},
    "CM": {"implement": 15, "document": 5, "test": 3},
    "CP": {"implement": 12, "document": 8, "test": 5},
    "IA": {"implement": 12, "document": 4, "test": 3},
    "IR": {"implement": 8, "document": 6, "test": 4},
    "MA": {"implement": 5, "document": 3, "test": 1},
    "MP": {"implement": 5, "document": 3, "test": 1},
    "PE": {"implement": 3, "document": 3, "test": 1},
    "PL": {"implement": 5, "document": 5, "test": 1},
    "PS": {"implement": 5, "document": 3, "test": 1},
    "RA": {"implement": 10, "document": 5, "test": 3},
    "SA": {"implement": 8, "document": 5, "test": 2},
    "SC": {"implement": 20, "document": 6, "test": 5},
    "SI": {"implement": 15, "document": 5, "test": 4},
    "SR": {"implement": 8, "document": 5, "test": 2},
}

DEFAULT_EFFORT = {"implement": 8, "document": 4, "test": 2}


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


# --- Input parsers ---


def load_implementation_status_yaml(filepath: Path) -> dict[str, dict]:
    """
    Load implementation status from a YAML file.

    Expected format:
        controls:
          AC-1:
            status: implemented
            notes: "Fully documented and operational"
          AC-2:
            status: partial
            notes: "MFA deployed, but inactive account disabling not automated"
    """
    import yaml

    data = yaml.safe_load(filepath.read_text())
    controls = data.get("controls", {})

    result = {}
    for control_id, info in controls.items():
        cid = control_id.upper().strip()
        if isinstance(info, str):
            result[cid] = {"status": info.lower().strip(), "notes": ""}
        elif isinstance(info, dict):
            result[cid] = {
                "status": info.get("status", "not_implemented").lower().strip(),
                "notes": info.get("notes", ""),
                "components": info.get("components", []),
                "responsible": info.get("responsible", ""),
            }
        else:
            result[cid] = {"status": "not_implemented", "notes": ""}

    return result


def load_implementation_status_csv(filepath: Path) -> dict[str, dict]:
    """Load implementation status from CSV. Expected columns: control_id, status, notes"""
    result = {}
    with open(filepath, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cid = row.get("control_id", "").upper().strip()
            if cid:
                result[cid] = {
                    "status": row.get("status", "not_implemented").lower().strip(),
                    "notes": row.get("notes", ""),
                }
    return result


def load_implementation_status_oscal(filepath: Path) -> dict[str, dict]:
    """Load implementation status from an OSCAL SSP JSON file."""
    data = json.loads(filepath.read_text())
    ssp = data.get("system-security-plan", {})
    control_impl = ssp.get("control-implementation", {})
    impl_reqs = control_impl.get("implemented-requirements", [])

    result = {}
    for req in impl_reqs:
        cid = req.get("control-id", "").upper()
        if not cid:
            continue

        status = "not_implemented"
        notes_parts = []

        for prop in req.get("props", []):
            if prop.get("name") == "implementation-status":
                status = prop.get("value", "not_implemented").lower()

        by_components = req.get("by-components", [])
        if by_components:
            component_statuses = []
            for bc in by_components:
                desc = bc.get("description", "")
                if desc:
                    notes_parts.append(desc)
                impl_status = bc.get("implementation-status", {})
                if isinstance(impl_status, dict):
                    component_statuses.append(impl_status.get("state", ""))
                elif isinstance(impl_status, str):
                    component_statuses.append(impl_status)

            if component_statuses:
                if all(s == "implemented" for s in component_statuses):
                    status = "implemented"
                elif any(s == "implemented" for s in component_statuses):
                    status = "partial"
                elif any(s == "planned" for s in component_statuses):
                    status = "planned"

        stmt_desc = req.get("description", "")
        if stmt_desc:
            notes_parts.insert(0, stmt_desc)

        result[cid] = {
            "status": status,
            "notes": " | ".join(notes_parts)[:500],
        }

    return result


def load_implementation_status(filepath: Path) -> dict[str, dict]:
    """Load implementation status from YAML, CSV, or OSCAL SSP."""
    suffix = filepath.suffix.lower()
    if suffix in (".yaml", ".yml"):
        return load_implementation_status_yaml(filepath)
    elif suffix == ".csv":
        return load_implementation_status_csv(filepath)
    elif suffix == ".json":
        return load_implementation_status_oscal(filepath)
    else:
        raise ValueError(f"Unsupported input format: {suffix}. Use .yaml, .csv, or .json (OSCAL SSP)")


def load_inheritance_map(filepath: Path) -> dict[str, str]:
    """Load control inheritance mapping from YAML."""
    import yaml

    data = yaml.safe_load(filepath.read_text())
    controls = data.get("controls", {})
    return {k.upper(): v.lower() for k, v in controls.items()}


# --- Analysis engine ---


def analyze_gaps(
    baseline_controls: list[dict],
    implementation_status: dict[str, dict | str],
    inheritance_map: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Perform gap analysis comparing baseline controls against implementation status.

    Args:
        baseline_controls: List of control dicts with 'id', 'title', 'family_id'
        implementation_status: Map of control_id to status. Accepts either:
            - dict format: {"AC-1": {"status": "implemented", "notes": "..."}}
            - string shorthand: {"AC-1": "implemented"}
        inheritance_map: Optional map of control_id to inheritance type
            ("inherited", "shared", "customer")

    Returns comprehensive analysis including per-control results, family summaries,
    overall scores, and remediation estimates.
    """
    inheritance = inheritance_map or {}
    timestamp = datetime.now(timezone.utc).isoformat()

    control_results = []
    for control in baseline_controls:
        cid = control["id"]
        family = control["family_id"]

        impl = implementation_status.get(cid, {"status": "not_implemented", "notes": ""})
        # Support both dict {"status": "implemented"} and plain string "implemented"
        if isinstance(impl, str):
            status = impl
            impl = {"status": impl, "notes": ""}
        else:
            status = impl.get("status", "not_implemented")

        inherit_status = inheritance.get(cid, "customer")
        if inherit_status == "inherited" and status == "not_implemented":
            status = "inherited"
        elif inherit_status == "shared" and status == "not_implemented":
            status = "partial"

        is_gap = status not in ("implemented", "inherited", "na")
        priority = _calculate_priority(cid, family, status)

        control_results.append({
            "control_id": cid,
            "title": control["title"],
            "family_id": family,
            "family_name": CONTROL_FAMILIES.get(family, "Unknown"),
            "status": status,
            "status_description": IMPLEMENTATION_STATUSES.get(status, status),
            "inheritance": inherit_status,
            "is_gap": is_gap,
            "priority": priority,
            "notes": impl.get("notes", ""),
        })

    family_summaries = _compute_family_summaries(control_results)

    total = len(control_results)
    implemented = sum(1 for c in control_results if c["status"] == "implemented")
    inherited = sum(1 for c in control_results if c["status"] == "inherited")
    partial = sum(1 for c in control_results if c["status"] == "partial")
    planned = sum(1 for c in control_results if c["status"] == "planned")
    not_implemented = sum(1 for c in control_results if c["status"] == "not_implemented")
    na = sum(1 for c in control_results if c["status"] == "na")

    compliance_score = round(((implemented + inherited + na) / total) * 100, 1) if total > 0 else 0
    coverage_score = round(((implemented + inherited + partial + na) / total) * 100, 1) if total > 0 else 0

    gaps = [c for c in control_results if c["is_gap"]]
    critical_gaps = [g for g in gaps if g["priority"] == "critical"]
    high_gaps = [g for g in gaps if g["priority"] == "high"]

    effort = _estimate_remediation_effort(gaps)

    return {
        "metadata": {
            "generated_at": timestamp,
            "toolkit_version": "0.1.0",
            "baseline": None,
            "total_controls": total,
        },
        "overall": {
            "compliance_score": compliance_score,
            "coverage_score": coverage_score,
            "total_controls": total,
            "implemented": implemented,
            "inherited": inherited,
            "partial": partial,
            "planned": planned,
            "not_implemented": not_implemented,
            "not_applicable": na,
            "total_gaps": len(gaps),
            "critical_gaps": len(critical_gaps),
            "high_gaps": len(high_gaps),
        },
        "effort_estimate": effort,
        "family_summaries": family_summaries,
        "controls": control_results,
        "critical_gaps": critical_gaps,
        "high_gaps": high_gaps,
    }


def _calculate_priority(control_id: str, family: str, status: str) -> str:
    """Calculate remediation priority for a gap."""
    federal_mandate_controls = {
        "SC-13", "SC-8", "SC-28", "IA-2", "IA-8", "RA-5", "SI-2",
        "SC-20", "SC-21", "SC-22",
    }

    if status in ("implemented", "inherited", "na"):
        return "none"

    if control_id in federal_mandate_controls and status == "not_implemented":
        return "critical"

    high_scrutiny = {"AC", "SC", "SI", "AU", "IA", "CM", "IR", "CA"}

    if family in high_scrutiny:
        if status == "not_implemented":
            return "critical" if family in ("SC", "IA") else "high"
        elif status == "partial":
            return "high"
        elif status == "planned":
            return "medium"
    else:
        if status == "not_implemented":
            return "high"
        elif status == "partial":
            return "medium"
        elif status == "planned":
            return "low"

    return "medium"


def _compute_family_summaries(control_results: list[dict]) -> list[dict]:
    """Compute compliance summary per control family."""
    families: dict[str, dict] = {}

    for c in control_results:
        fam = c["family_id"]
        if fam not in families:
            families[fam] = {
                "family_id": fam,
                "family_name": c["family_name"],
                "total": 0, "implemented": 0, "inherited": 0,
                "partial": 0, "planned": 0, "not_implemented": 0,
                "na": 0, "gaps": 0,
            }

        families[fam]["total"] += 1
        status = c["status"]
        if status in families[fam]:
            families[fam][status] += 1
        if c["is_gap"]:
            families[fam]["gaps"] += 1

    summaries = []
    for fam_data in families.values():
        total = fam_data["total"]
        done = fam_data["implemented"] + fam_data["inherited"] + fam_data["na"]
        fam_data["compliance_pct"] = round((done / total) * 100, 1) if total > 0 else 0
        summaries.append(fam_data)

    return sorted(summaries, key=lambda x: x["compliance_pct"])


def _estimate_remediation_effort(gaps: list[dict]) -> dict[str, Any]:
    """Estimate remediation effort in person-days."""
    total_implement = 0
    total_document = 0
    total_test = 0
    family_effort: dict[str, int] = {}

    for gap in gaps:
        family = gap["family_id"]
        effort = EFFORT_ESTIMATES.get(family, DEFAULT_EFFORT)

        multiplier = {"not_implemented": 1.0, "partial": 0.5, "planned": 0.7}.get(gap["status"], 1.0)

        impl = round(effort["implement"] * multiplier)
        doc = round(effort["document"] * multiplier)
        test = round(effort["test"] * multiplier)

        total_implement += impl
        total_document += doc
        total_test += test
        family_effort[family] = family_effort.get(family, 0) + impl + doc + test

    total = total_implement + total_document + total_test

    return {
        "total_person_days": total,
        "implementation_days": total_implement,
        "documentation_days": total_document,
        "testing_days": total_test,
        "estimated_weeks": round(total / 5, 1),
        "estimated_months": round(total / 22, 1),
        "by_family": dict(sorted(family_effort.items(), key=lambda x: x[1], reverse=True)),
        "note": "Estimates are rough averages. Actual effort depends on system complexity, team experience, and existing infrastructure.",
    }


# --- Output formatters ---


def output_summary(analysis: dict, baseline: str) -> str:
    """Format a concise summary for stdout."""
    overall = analysis["overall"]
    effort = analysis["effort_estimate"]

    lines = [
        f"\n{'=' * 70}",
        f"  FedRAMP {baseline.upper()} Gap Analysis Summary",
        f"{'=' * 70}",
        f"",
        f"  Compliance Score:    {overall['compliance_score']}%",
        f"  Coverage Score:      {overall['coverage_score']}% (includes partial)",
        f"",
        f"  Total Controls:      {overall['total_controls']}",
        f"  Implemented:         {overall['implemented']}",
        f"  Inherited:           {overall['inherited']}",
        f"  Partial:             {overall['partial']}",
        f"  Planned:             {overall['planned']}",
        f"  Not Implemented:     {overall['not_implemented']}",
        f"  Not Applicable:      {overall['not_applicable']}",
        f"",
        f"  Total Gaps:          {overall['total_gaps']}",
        f"  Critical Gaps:       {overall['critical_gaps']}",
        f"  High Priority Gaps:  {overall['high_gaps']}",
        f"",
        f"  Estimated Effort:    {effort['total_person_days']} person-days (~{effort['estimated_months']} months)",
        f"{'=' * 70}",
    ]

    lines.append("\n  Compliance by Control Family:")
    lines.append(f"  {'Family':<6} {'Name':<42} {'Score':>6} {'Gaps':>5}")
    lines.append(f"  {'-' * 62}")

    for fam in analysis["family_summaries"]:
        score = f"{fam['compliance_pct']}%"
        lines.append(f"  {fam['family_id']:<6} {fam['family_name']:<42} {score:>6} {fam['gaps']:>5}")

    if analysis["critical_gaps"]:
        lines.append(f"\n  CRITICAL GAPS (require immediate attention):")
        for gap in analysis["critical_gaps"][:10]:
            lines.append(f"    {gap['control_id']:<12} {gap['title'][:50]}")

    lines.append("")
    return "\n".join(lines)


def output_html(analysis: dict, baseline: str, output_path: Path):
    """Generate an HTML gap analysis dashboard."""
    from scripts.utils.report_generators import generate_html_report

    overall = analysis["overall"]
    effort = analysis["effort_estimate"]

    score = overall["compliance_score"]
    score_class = "score-high" if score >= 80 else "score-medium" if score >= 50 else "score-low"

    summary_html = f"""
    <div style="display:flex;gap:2rem;flex-wrap:wrap;margin:1rem 0;">
        <div style="background:#fff;padding:1.5rem;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1);min-width:200px;">
            <div style="font-size:2.5rem;font-weight:bold;" class="{score_class}">{score}%</div>
            <div>Compliance Score</div>
        </div>
        <div style="background:#fff;padding:1.5rem;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1);min-width:200px;">
            <div style="font-size:2.5rem;font-weight:bold;">{overall['total_gaps']}</div>
            <div>Total Gaps ({overall['critical_gaps']} critical)</div>
        </div>
        <div style="background:#fff;padding:1.5rem;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1);min-width:200px;">
            <div style="font-size:2.5rem;font-weight:bold;">{effort['estimated_months']}mo</div>
            <div>Estimated Effort ({effort['total_person_days']} person-days)</div>
        </div>
    </div>
    <table>
        <tr><th>Status</th><th>Count</th><th>%</th></tr>
        <tr><td class="status-implemented">Implemented</td><td>{overall['implemented']}</td><td>{round(overall['implemented']/max(overall['total_controls'],1)*100,1)}%</td></tr>
        <tr><td class="status-inherited">Inherited</td><td>{overall['inherited']}</td><td>{round(overall['inherited']/max(overall['total_controls'],1)*100,1)}%</td></tr>
        <tr><td class="status-partial">Partial</td><td>{overall['partial']}</td><td>{round(overall['partial']/max(overall['total_controls'],1)*100,1)}%</td></tr>
        <tr><td>Planned</td><td>{overall['planned']}</td><td>{round(overall['planned']/max(overall['total_controls'],1)*100,1)}%</td></tr>
        <tr><td class="status-not-implemented">Not Implemented</td><td>{overall['not_implemented']}</td><td>{round(overall['not_implemented']/max(overall['total_controls'],1)*100,1)}%</td></tr>
    </table>"""

    family_rows = ""
    for fam in analysis["family_summaries"]:
        pct = fam["compliance_pct"]
        bar_color = "#2e7d32" if pct >= 80 else "#f57f17" if pct >= 50 else "#c62828"
        family_rows += f"""<tr>
            <td>{fam['family_id']}</td><td>{fam['family_name']}</td>
            <td>{fam['total']}</td><td>{fam['implemented']}</td><td>{fam['inherited']}</td><td>{fam['gaps']}</td>
            <td><div style="display:flex;align-items:center;gap:8px;">
                <div style="background:#eee;border-radius:4px;width:100px;height:16px;">
                    <div style="background:{bar_color};border-radius:4px;width:{pct}%;height:100%;"></div>
                </div>{pct}%</div></td></tr>"""

    family_html = f"""<table>
        <tr><th>Family</th><th>Name</th><th>Total</th><th>Impl</th><th>Inherit</th><th>Gaps</th><th>Compliance</th></tr>
        {family_rows}</table>"""

    critical_rows = ""
    for gap in analysis["critical_gaps"]:
        critical_rows += f"""<tr><td><strong>{gap['control_id']}</strong></td><td>{gap['title']}</td>
            <td>{gap['family_id']}</td><td class="status-not-implemented">{gap['status']}</td>
            <td>{gap['notes'][:100] if gap['notes'] else '-'}</td></tr>"""

    critical_html = f"""<table><tr><th>Control</th><th>Title</th><th>Family</th><th>Status</th><th>Notes</th></tr>
        {critical_rows}</table>""" if critical_rows else "<p>No critical gaps found.</p>"

    sections = [
        {"heading": "Overview", "body": summary_html},
        {"heading": "Compliance by Control Family", "body": family_html},
        {"heading": f"Critical Gaps ({len(analysis['critical_gaps'])})", "body": critical_html},
    ]

    generate_html_report(
        title=f"FedRAMP {baseline.upper()} Gap Analysis",
        content_sections=sections,
        output_path=output_path,
        metadata={"Baseline": baseline.upper(), "Total Controls": str(overall["total_controls"]),
                   "Compliance Score": f"{score}%", "Analysis Date": analysis["metadata"]["generated_at"]},
    )


def output_excel(analysis: dict, baseline: str, output_path: Path):
    """Generate an Excel gap analysis workbook."""
    from scripts.utils.report_generators import generate_excel_report

    overall = analysis["overall"]
    summary_rows = [
        {"Metric": k, "Value": v} for k, v in [
            ("Baseline", baseline.upper()), ("Total Controls", overall["total_controls"]),
            ("Compliance Score", f"{overall['compliance_score']}%"),
            ("Implemented", overall["implemented"]), ("Inherited", overall["inherited"]),
            ("Partial", overall["partial"]), ("Planned", overall["planned"]),
            ("Not Implemented", overall["not_implemented"]),
            ("Total Gaps", overall["total_gaps"]), ("Critical Gaps", overall["critical_gaps"]),
            ("Est. Person-Days", analysis["effort_estimate"]["total_person_days"]),
        ]
    ]

    family_rows = [{
        "Family": f["family_id"], "Name": f["family_name"], "Total": f["total"],
        "Implemented": f["implemented"], "Inherited": f["inherited"], "Partial": f["partial"],
        "Not Implemented": f["not_implemented"], "Gaps": f["gaps"],
        "Compliance %": f"{f['compliance_pct']}%",
    } for f in analysis["family_summaries"]]

    control_rows = [{
        "Control ID": c["control_id"], "Title": c["title"], "Family": c["family_id"],
        "Status": c["status"], "Inheritance": c["inheritance"], "Priority": c["priority"],
        "Is Gap": "Yes" if c["is_gap"] else "No", "Notes": c["notes"][:200],
    } for c in analysis["controls"]]

    gap_rows = [{
        "Control ID": c["control_id"], "Title": c["title"], "Family": c["family_id"],
        "Status": c["status"], "Priority": c["priority"], "Notes": c["notes"][:200],
    } for c in analysis["controls"] if c["is_gap"]]

    generate_excel_report(
        title=f"FedRAMP {baseline.upper()} Gap Analysis",
        sheets_data={"Summary": summary_rows, "By Family": family_rows, "All Controls": control_rows, "Gaps": gap_rows},
        output_path=output_path,
    )


def output_json(analysis: dict, output_path: Path):
    """Write the full analysis as JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(analysis, indent=2, default=str))
    logger.info(f"JSON report written to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="FedRAMP Gap Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--baseline", "-b", choices=["low", "moderate", "high", "li-saas"], required=True)
    parser.add_argument("--input", "-i", type=Path, required=True, help="Implementation status file (.yaml/.csv/.json)")
    parser.add_argument("--inheritance-map", type=Path, help="Control inheritance mapping (.yaml)")
    parser.add_argument("--output-dir", "-o", type=Path, help="Output directory for reports")
    parser.add_argument("--summary-only", action="store_true", help="Print summary only, no files")
    parser.add_argument("--catalog-path", type=Path)
    parser.add_argument("--baselines-dir", type=Path)
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()
    setup_logging(args.verbose)

    if not args.input.exists():
        logger.error(f"Input file not found: {args.input}")
        sys.exit(1)

    try:
        logger.info(f"Loading {args.baseline.upper()} baseline...")
        catalog_data = load_catalog(args.catalog_path)
        all_controls = extract_controls_from_catalog(catalog_data)
        profile_data = load_baseline(args.baseline, args.baselines_dir)
        baseline_ids = extract_control_ids_from_profile(profile_data)
        baseline_controls = filter_catalog_by_baseline(all_controls, baseline_ids)
        validate_control_count(args.baseline, len(baseline_controls))

        logger.info(f"Loading implementation status from {args.input}...")
        impl_status = load_implementation_status(args.input)
        logger.info(f"Loaded status for {len(impl_status)} controls")

        inheritance = None
        if args.inheritance_map:
            logger.info(f"Loading inheritance map from {args.inheritance_map}...")
            inheritance = load_inheritance_map(args.inheritance_map)
            logger.info(f"Loaded inheritance data for {len(inheritance)} controls")

        logger.info("Running gap analysis...")
        analysis = analyze_gaps(baseline_controls, impl_status, inheritance)
        analysis["metadata"]["baseline"] = args.baseline.upper()

        summary = output_summary(analysis, args.baseline)
        print(summary)

        if args.output_dir and not args.summary_only:
            output_dir = args.output_dir
            output_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d")
            base = f"gap-analysis-{args.baseline}-{timestamp}"

            html_path = output_dir / f"{base}.html"
            output_html(analysis, args.baseline, html_path)
            print(f"  HTML report: {html_path}")

            xlsx_path = output_dir / f"{base}.xlsx"
            output_excel(analysis, args.baseline, xlsx_path)
            print(f"  Excel report: {xlsx_path}")

            json_path = output_dir / f"{base}.json"
            output_json(analysis, json_path)
            print(f"  JSON report: {json_path}")

    except FileNotFoundError as e:
        logger.error(str(e))
        print("\nHint: Run 'make baselines' to download required files.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
