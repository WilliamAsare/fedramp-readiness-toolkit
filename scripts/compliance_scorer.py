#!/usr/bin/env python3
"""
Compliance Scoring Dashboard

Aggregates compliance data from multiple sources (gap analysis, scan results,
POA&M status) into a unified posture score with trend tracking over time.

Stores historical data in SQLite for month-over-month trend analysis.
Outputs JSON data feeds and standalone HTML dashboards.

Usage:
    python scripts/compliance_scorer.py --gap-report gap.json --poam poam.json --output-dir reports/
    python scripts/compliance_scorer.py --gap-report gap.json --poam poam.json --threshold 85 --fail-below
    python scripts/compliance_scorer.py --trend --db compliance.db --output-dir reports/
"""

import argparse
import json
import logging
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

logger = logging.getLogger(__name__)


# --- Score computation ---


def compute_compliance_score(
    gap_report: dict | None = None,
    poam_data: dict | None = None,
    scan_summary: dict | None = None,
) -> dict[str, Any]:
    """
    Compute a unified compliance posture score.

    Weights:
        - Control implementation (from gap analysis): 60%
        - Vulnerability posture (from POA&M/scans): 25%
        - Documentation completeness: 15%

    These weights reflect what 3PAOs and the FedRAMP PMO actually care about.
    """
    scores = {"control_implementation": 0, "vulnerability_posture": 0, "documentation": 0}
    details = {}

    # Control implementation score (0-100)
    if gap_report:
        overall = gap_report.get("overall", {})
        scores["control_implementation"] = overall.get("compliance_score", 0)
        details["controls"] = {
            "total": overall.get("total_controls", 0),
            "implemented": overall.get("implemented", 0),
            "inherited": overall.get("inherited", 0),
            "partial": overall.get("partial", 0),
            "not_implemented": overall.get("not_implemented", 0),
            "critical_gaps": overall.get("critical_gaps", 0),
        }

    # Vulnerability posture score (0-100)
    if poam_data:
        summary = poam_data.get("summary", {})
        total_items = summary.get("total_items", 0)
        overdue = summary.get("overdue", 0)
        critical_high_overdue = summary.get("critical_high_overdue", 0)

        if total_items > 0:
            # Start at 100, deduct for issues
            vuln_score = 100
            vuln_score -= min(50, overdue * 5)  # Up to 50 points for overdue items
            vuln_score -= min(30, critical_high_overdue * 10)  # Up to 30 for critical/high overdue
            scores["vulnerability_posture"] = max(0, vuln_score)
        else:
            scores["vulnerability_posture"] = 100  # No vulns = perfect

        escalations = poam_data.get("escalation_triggers", [])
        details["vulnerability"] = {
            "total_items": total_items,
            "open": summary.get("open", 0),
            "overdue": overdue,
            "critical_high_overdue": critical_high_overdue,
            "escalation_triggers": len(escalations),
        }
    elif scan_summary:
        # Use raw scan data if no POA&M
        critical = scan_summary.get("critical_count", 0)
        high = scan_summary.get("high_count", 0)
        vuln_score = max(0, 100 - (critical * 15) - (high * 5))
        scores["vulnerability_posture"] = vuln_score

    # Documentation score (simplified heuristic)
    doc_score = 50  # Base
    if gap_report:
        # More controls with narratives = better docs
        total = gap_report.get("overall", {}).get("total_controls", 1)
        implemented = gap_report.get("overall", {}).get("implemented", 0)
        doc_score = min(100, round((implemented / total) * 100)) if total else 0
    scores["documentation"] = doc_score

    # Weighted composite
    composite = round(
        scores["control_implementation"] * 0.60
        + scores["vulnerability_posture"] * 0.25
        + scores["documentation"] * 0.15,
        1,
    )

    # Risk rating
    if composite >= 90:
        risk = "LOW"
    elif composite >= 70:
        risk = "MODERATE"
    elif composite >= 50:
        risk = "ELEVATED"
    else:
        risk = "HIGH"

    return {
        "composite_score": composite,
        "risk_rating": risk,
        "component_scores": scores,
        "details": details,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# --- Trend storage ---


def init_db(db_path: Path) -> sqlite3.Connection:
    """Initialize SQLite database for trend tracking."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS compliance_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            composite_score REAL,
            control_score REAL,
            vulnerability_score REAL,
            documentation_score REAL,
            risk_rating TEXT,
            total_controls INTEGER,
            total_gaps INTEGER,
            total_overdue INTEGER,
            raw_data TEXT
        )
    """)
    conn.commit()
    return conn


def store_score(conn: sqlite3.Connection, score: dict):
    """Store a compliance score snapshot."""
    details = score.get("details", {})
    controls = details.get("controls", {})
    vuln = details.get("vulnerability", {})

    conn.execute("""
        INSERT INTO compliance_scores
        (timestamp, composite_score, control_score, vulnerability_score,
         documentation_score, risk_rating, total_controls, total_gaps,
         total_overdue, raw_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        score["timestamp"],
        score["composite_score"],
        score["component_scores"]["control_implementation"],
        score["component_scores"]["vulnerability_posture"],
        score["component_scores"]["documentation"],
        score["risk_rating"],
        controls.get("total", 0),
        controls.get("critical_gaps", 0),
        vuln.get("overdue", 0),
        json.dumps(score),
    ))
    conn.commit()


def get_trend_data(conn: sqlite3.Connection, limit: int = 12) -> list[dict]:
    """Get historical score data for trend analysis."""
    cursor = conn.execute("""
        SELECT timestamp, composite_score, control_score, vulnerability_score,
               documentation_score, risk_rating, total_controls, total_gaps, total_overdue
        FROM compliance_scores
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    return [{
        "timestamp": r[0], "composite_score": r[1], "control_score": r[2],
        "vulnerability_score": r[3], "documentation_score": r[4],
        "risk_rating": r[5], "total_controls": r[6], "total_gaps": r[7],
        "total_overdue": r[8],
    } for r in reversed(rows)]


# --- Output ---


def output_score_json(score: dict, trend: list[dict] | None, output_path: Path):
    """Write score to JSON."""
    data = {"current": score}
    if trend:
        data["trend"] = trend
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(data, indent=2))


def output_score_html(score: dict, trend: list[dict] | None, output_path: Path):
    """Generate HTML compliance dashboard."""
    from scripts.utils.report_generators import generate_html_report

    composite = score["composite_score"]
    risk = score["risk_rating"]
    scores = score["component_scores"]
    risk_color = {"LOW": "#2e7d32", "MODERATE": "#f57f17", "ELEVATED": "#e65100", "HIGH": "#c62828"}.get(risk, "#333")

    overview = f"""
    <div style="display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0;">
        <div style="background:#f5f5f5;padding:2rem;border-radius:8px;min-width:200px;text-align:center;border-left:6px solid {risk_color};">
            <div style="font-size:3rem;font-weight:bold;color:{risk_color};">{composite}</div>
            <div style="font-size:1.2rem;">Composite Score</div>
            <div style="color:{risk_color};font-weight:bold;">{risk} RISK</div>
        </div>
        <div style="background:#e8f5e9;padding:1.5rem;border-radius:8px;min-width:160px;text-align:center;">
            <div style="font-size:2rem;font-weight:bold;">{scores['control_implementation']}</div>
            <div>Controls (60%)</div>
        </div>
        <div style="background:#e3f2fd;padding:1.5rem;border-radius:8px;min-width:160px;text-align:center;">
            <div style="font-size:2rem;font-weight:bold;">{scores['vulnerability_posture']}</div>
            <div>Vulns (25%)</div>
        </div>
        <div style="background:#f3e5f5;padding:1.5rem;border-radius:8px;min-width:160px;text-align:center;">
            <div style="font-size:2rem;font-weight:bold;">{scores['documentation']}</div>
            <div>Docs (15%)</div>
        </div>
    </div>"""

    sections = [{"heading": "Compliance Posture", "body": overview}]

    if trend and len(trend) > 1:
        trend_rows = ""
        for t in trend:
            t_risk = t["risk_rating"]
            t_color = {"LOW": "#2e7d32", "MODERATE": "#f57f17", "ELEVATED": "#e65100", "HIGH": "#c62828"}.get(t_risk, "#333")
            trend_rows += f"""<tr>
                <td>{t['timestamp'][:10]}</td>
                <td style="font-weight:bold;">{t['composite_score']}</td>
                <td>{t['control_score']}</td>
                <td>{t['vulnerability_score']}</td>
                <td style="color:{t_color};">{t_risk}</td>
            </tr>"""
        sections.append({
            "heading": "Trend",
            "body": f"""<table><tr><th>Date</th><th>Composite</th><th>Controls</th><th>Vulns</th><th>Risk</th></tr>{trend_rows}</table>""",
        })

    generate_html_report(
        title="FedRAMP Compliance Dashboard",
        content_sections=sections,
        output_path=output_path,
        metadata={"Score": str(composite), "Risk": risk, "Date": score["timestamp"][:10]},
    )


def print_score(score: dict):
    """Print score to console."""
    composite = score["composite_score"]
    risk = score["risk_rating"]
    scores = score["component_scores"]

    print(f"\n  Compliance Posture: {composite}/100 ({risk} RISK)")
    print(f"  {'='*45}")
    print(f"  Control Implementation:  {scores['control_implementation']}  (weight: 60%)")
    print(f"  Vulnerability Posture:   {scores['vulnerability_posture']}  (weight: 25%)")
    print(f"  Documentation:           {scores['documentation']}  (weight: 15%)")
    print()


# --- CLI ---


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def main():
    parser = argparse.ArgumentParser(description="FedRAMP Compliance Scoring Dashboard")
    parser.add_argument("--gap-report", "-g", type=Path, help="Gap analysis JSON report")
    parser.add_argument("--poam", "-p", type=Path, help="POA&M JSON")
    parser.add_argument("--scan-summary", type=Path, help="Scan aggregator JSON (alternative to POA&M)")
    parser.add_argument("--output-dir", "-o", type=Path)
    parser.add_argument("--db", type=Path, default=Path("compliance.db"), help="SQLite database for trend tracking")
    parser.add_argument("--threshold", type=float, help="Minimum score threshold")
    parser.add_argument("--fail-below", action="store_true", help="Exit 1 if below threshold")
    parser.add_argument("--trend", action="store_true", help="Show trend from database")
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()
    setup_logging(args.verbose)

    # Load inputs
    gap_report = None
    if args.gap_report and args.gap_report.exists():
        gap_report = json.loads(args.gap_report.read_text())

    poam_data = None
    if args.poam and args.poam.exists():
        poam_data = json.loads(args.poam.read_text())

    scan_summary = None
    if args.scan_summary and args.scan_summary.exists():
        data = json.loads(args.scan_summary.read_text())
        scan_summary = data.get("summary", data)

    if not any([gap_report, poam_data, scan_summary]) and not args.trend:
        logger.error("Provide at least one input (--gap-report, --poam, --scan-summary) or use --trend")
        sys.exit(2)

    # Compute score
    score = compute_compliance_score(gap_report, poam_data, scan_summary)
    print_score(score)

    # Store in database
    conn = init_db(args.db)
    if gap_report or poam_data or scan_summary:
        store_score(conn, score)

    # Get trend data
    trend = get_trend_data(conn) if args.trend or args.output_dir else None

    # Output
    if args.output_dir:
        ts = datetime.now().strftime("%Y%m%d")
        output_score_json(score, trend, args.output_dir / f"compliance-score-{ts}.json")
        output_score_html(score, trend, args.output_dir / f"compliance-dashboard-{ts}.html")
        print(f"  Reports written to {args.output_dir}/")

    conn.close()

    # Threshold check for CI/CD
    if args.threshold and args.fail_below:
        if score["composite_score"] < args.threshold:
            print(f"\n  FAIL: Score {score['composite_score']} below threshold {args.threshold}")
            sys.exit(1)


if __name__ == "__main__":
    main()
