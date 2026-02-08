#!/usr/bin/env python3
"""
OSCAL Catalog Parser & Explorer

The foundational script for the FedRAMP Readiness Toolkit. Parses the NIST SP 800-53
Rev 5 OSCAL catalog, resolves FedRAMP profiles, and provides filtering and export
capabilities for control exploration.

Usage:
    # List all Moderate baseline controls in a table
    python scripts/catalog_parser.py --baseline moderate --output-format table

    # Export Low baseline controls to CSV
    python scripts/catalog_parser.py --baseline low --output-format csv --output controls-low.csv

    # Filter by control family
    python scripts/catalog_parser.py --baseline moderate --family SC --output-format table

    # Search controls by keyword
    python scripts/catalog_parser.py --baseline moderate --search "encryption" --output-format table

    # Show details for a specific control
    python scripts/catalog_parser.py --control AC-2 --output-format detail

    # Export all baselines summary to JSON
    python scripts/catalog_parser.py --all-baselines --output-format json --output baselines-summary.json
"""

import argparse
import csv
import io
import json
import logging
import sys
from pathlib import Path

# Add project root to path for imports
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


def setup_logging(verbose: bool = False):
    """Configure logging based on verbosity flag."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
    )


def get_baseline_controls(
    baseline_level: str,
    catalog_path: Path | None = None,
    baselines_dir: Path | None = None,
) -> list[dict]:
    """
    Resolve a FedRAMP baseline and return the full control details.

    This is the main entry point for getting controls for a specific baseline.
    It loads the NIST catalog, loads the FedRAMP profile, extracts the selected
    control IDs, then pulls the full control details from the catalog.

    Args:
        baseline_level: 'low', 'moderate', 'high', or 'li-saas'
        catalog_path: Override path for NIST catalog
        baselines_dir: Override directory for FedRAMP baselines

    Returns:
        List of control dicts with full details from the catalog
    """
    # Load the NIST catalog (source of all control details)
    catalog_data = load_catalog(catalog_path)
    all_controls = extract_controls_from_catalog(catalog_data)
    logger.info(f"Loaded {len(all_controls)} total controls from NIST catalog")

    # Load the FedRAMP profile and extract selected control IDs
    profile_data = load_baseline(baseline_level, baselines_dir)
    baseline_ids = extract_control_ids_from_profile(profile_data)
    logger.info(f"FedRAMP {baseline_level.upper()} profile selects {len(baseline_ids)} controls")

    # Filter catalog controls to only those in the baseline
    baseline_controls = filter_catalog_by_baseline(all_controls, baseline_ids)

    # Validate count
    validate_control_count(baseline_level, len(baseline_controls))

    return baseline_controls


def filter_controls(
    controls: list[dict],
    family: str | None = None,
    search: str | None = None,
    control_id: str | None = None,
) -> list[dict]:
    """Apply optional filters to a list of controls."""
    filtered = controls

    if control_id:
        cid = control_id.upper()
        filtered = [c for c in filtered if c["id"] == cid]
        if not filtered:
            logger.warning(f"Control '{cid}' not found in the current baseline")

    if family:
        fam = family.upper()
        filtered = [c for c in filtered if c["family_id"] == fam]
        if not filtered:
            logger.warning(f"No controls found for family '{fam}' in the current baseline")

    if search:
        term = search.lower()
        filtered = [
            c for c in filtered
            if term in c["title"].lower()
            or term in c["id"].lower()
            or any(term in str(p).lower() for p in c.get("parts", []))
        ]
        if not filtered:
            logger.warning(f"No controls matching '{search}' in the current baseline")

    return filtered


def compute_family_summary(controls: list[dict]) -> list[dict]:
    """Compute per-family summary statistics."""
    family_counts: dict[str, int] = {}
    for c in controls:
        fam = c["family_id"]
        family_counts[fam] = family_counts.get(fam, 0) + 1

    summary = []
    for fam_id in sorted(family_counts.keys()):
        family_name = CONTROL_FAMILIES.get(fam_id, "Unknown")
        summary.append({
            "family_id": fam_id,
            "family_name": family_name,
            "control_count": family_counts[fam_id],
            "fedramp_active": fam_id in FEDRAMP_ACTIVE_FAMILIES,
        })

    return summary


# --- Output formatters ---


def format_table(controls: list[dict], show_params: bool = False) -> str:
    """Format controls as a rich table (falls back to plain text if rich is unavailable)."""
    try:
        from rich.console import Console
        from rich.table import Table

        table = Table(title=f"FedRAMP Controls ({len(controls)} total)", show_lines=False)
        table.add_column("ID", style="cyan", width=12)
        table.add_column("Title", style="white", width=50)
        table.add_column("Family", style="green", width=8)

        if show_params:
            table.add_column("Params", style="yellow", width=6)

        for c in controls:
            row = [c["id"], c["title"], c["family_id"]]
            if show_params:
                row.append(str(len(c.get("params", []))))
            table.add_row(*row)

        console = Console(file=io.StringIO())
        console.print(table)
        return console.file.getvalue()

    except ImportError:
        # Fallback to plain text table
        lines = [f"{'ID':<14} {'Title':<55} {'Family':<8}"]
        lines.append("-" * 80)
        for c in controls:
            lines.append(f"{c['id']:<14} {c['title'][:53]:<55} {c['family_id']:<8}")
        lines.append(f"\nTotal: {len(controls)} controls")
        return "\n".join(lines)


def format_family_summary_table(summary: list[dict], baseline_level: str) -> str:
    """Format family summary as a table."""
    try:
        from rich.console import Console
        from rich.table import Table

        total = sum(s["control_count"] for s in summary)
        table = Table(title=f"FedRAMP {baseline_level.upper()} Baseline — {total} Controls by Family")
        table.add_column("Family", style="cyan", width=8)
        table.add_column("Name", style="white", width=45)
        table.add_column("Controls", style="green", justify="right", width=10)
        table.add_column("FedRAMP Active", style="yellow", width=15)

        for s in summary:
            active = "Yes" if s["fedramp_active"] else "No (Agency)"
            table.add_row(s["family_id"], s["family_name"], str(s["control_count"]), active)

        table.add_row("", "TOTAL", str(total), "", style="bold")

        console = Console(file=io.StringIO())
        console.print(table)
        return console.file.getvalue()

    except ImportError:
        lines = [f"FedRAMP {baseline_level.upper()} Baseline — Controls by Family\n"]
        lines.append(f"{'Family':<8} {'Name':<45} {'Count':<10}")
        lines.append("-" * 65)
        total = 0
        for s in summary:
            lines.append(f"{s['family_id']:<8} {s['family_name']:<45} {s['control_count']:<10}")
            total += s["control_count"]
        lines.append("-" * 65)
        lines.append(f"{'TOTAL':<53} {total}")
        return "\n".join(lines)


def format_detail(controls: list[dict]) -> str:
    """Format control details with full descriptions and parameters."""
    lines = []
    for c in controls:
        lines.append(f"{'=' * 80}")
        lines.append(f"Control: {c['id']} — {c['title']}")
        lines.append(f"Family:  {c['family_id']} ({CONTROL_FAMILIES.get(c['family_id'], 'Unknown')})")
        lines.append(f"{'=' * 80}")

        # Statement prose
        for part in c.get("parts", []):
            if part.get("type") == "statement":
                text = part.get("text", "")
                if text:
                    lines.append(f"\nStatement:\n  {text}")
                for sp in part.get("sub_parts", []):
                    sp_text = sp.get("text", "")
                    if sp_text:
                        lines.append(f"  {sp.get('id', '')}: {sp_text}")
            elif part.get("type") == "guidance":
                text = part.get("text", "")
                if text:
                    lines.append(f"\nGuidance:\n  {text[:500]}{'...' if len(text) > 500 else ''}")

        # Parameters
        if c.get("params"):
            lines.append(f"\nParameters ({len(c['params'])}):")
            for p in c["params"]:
                label = p.get("label", "N/A")
                lines.append(f"  {p['id']}: {label}")
                if p.get("constraints"):
                    for constraint in p["constraints"]:
                        lines.append(f"    Constraint: {constraint}")
                if p.get("values"):
                    lines.append(f"    Values: {', '.join(p['values'])}")

        lines.append("")

    return "\n".join(lines)


def format_csv(controls: list[dict]) -> str:
    """Format controls as CSV."""
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["id", "title", "family_id", "family_title", "param_count"],
        extrasaction="ignore",
    )
    writer.writeheader()
    for c in controls:
        row = {
            "id": c["id"],
            "title": c["title"],
            "family_id": c["family_id"],
            "family_title": c["family_title"],
            "param_count": len(c.get("params", [])),
        }
        writer.writerow(row)
    return output.getvalue()


def format_json(controls: list[dict]) -> str:
    """Format controls as JSON."""
    # Simplify for export (remove deeply nested OSCAL structures)
    simplified = []
    for c in controls:
        simplified.append({
            "id": c["id"],
            "title": c["title"],
            "family_id": c["family_id"],
            "family_title": c["family_title"],
            "param_count": len(c.get("params", [])),
            "params": [
                {"id": p["id"], "label": p.get("label", "")}
                for p in c.get("params", [])
            ],
        })
    return json.dumps(simplified, indent=2)


def format_markdown(controls: list[dict]) -> str:
    """Format controls as Markdown table."""
    lines = [
        "| Control ID | Title | Family |",
        "|-----------|-------|--------|",
    ]
    for c in controls:
        title = c["title"].replace("|", "\\|")
        lines.append(f"| {c['id']} | {title} | {c['family_id']} |")
    lines.append(f"\n**Total: {len(controls)} controls**")
    return "\n".join(lines)


def all_baselines_summary(catalog_path: Path | None = None) -> str:
    """Generate a summary comparison across all FedRAMP baselines."""
    results = {}
    for level in ["li-saas", "low", "moderate", "high"]:
        try:
            controls = get_baseline_controls(level, catalog_path)
            summary = compute_family_summary(controls)
            results[level] = {
                "total_controls": len(controls),
                "families": {s["family_id"]: s["control_count"] for s in summary},
                "expected": EXPECTED_CONTROL_COUNTS.get(level),
                "valid": len(controls) == EXPECTED_CONTROL_COUNTS.get(level, -1),
            }
        except Exception as e:
            results[level] = {"error": str(e)}

    return json.dumps(results, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="FedRAMP OSCAL Catalog Parser — explore and export NIST 800-53 Rev 5 controls",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --baseline moderate --output-format table
  %(prog)s --baseline low --family AC --output-format csv --output ac-controls.csv
  %(prog)s --control SC-13 --output-format detail
  %(prog)s --baseline moderate --search "encryption" --output-format table
  %(prog)s --baseline moderate --summary --output-format table
  %(prog)s --all-baselines --output-format json
        """,
    )

    # Baseline selection
    parser.add_argument(
        "--baseline", "-b",
        choices=["low", "moderate", "high", "li-saas"],
        help="FedRAMP baseline level to resolve",
    )
    parser.add_argument(
        "--all-baselines",
        action="store_true",
        help="Generate summary across all baselines",
    )

    # Filtering
    parser.add_argument(
        "--family", "-f",
        help="Filter by control family (e.g., AC, SC, SI)",
    )
    parser.add_argument(
        "--control", "-c",
        help="Show details for a specific control ID (e.g., AC-2, SC-13)",
    )
    parser.add_argument(
        "--search", "-s",
        help="Search controls by keyword in title or description",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Show per-family summary instead of individual controls",
    )

    # Output
    parser.add_argument(
        "--output-format", "-F",
        choices=["table", "csv", "json", "markdown", "detail"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file path (default: stdout)",
    )

    # Configuration
    parser.add_argument(
        "--catalog-path",
        type=Path,
        help="Override path to NIST 800-53 Rev 5 OSCAL catalog JSON",
    )
    parser.add_argument(
        "--baselines-dir",
        type=Path,
        help="Override directory containing FedRAMP baseline JSON files",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()
    setup_logging(args.verbose)

    # Validate arguments
    if not args.baseline and not args.all_baselines and not args.control:
        parser.error("Specify --baseline, --all-baselines, or --control")

    try:
        # Handle all-baselines summary mode
        if args.all_baselines:
            output = all_baselines_summary(args.catalog_path)
            if args.output:
                Path(args.output).write_text(output)
                print(f"Baselines summary written to {args.output}")
            else:
                print(output)
            return

        # Default to moderate if only --control is specified
        baseline = args.baseline or "moderate"

        # Get baseline controls
        controls = get_baseline_controls(baseline, args.catalog_path, args.baselines_dir)

        # If showing summary
        if args.summary:
            summary = compute_family_summary(controls)
            output = format_family_summary_table(summary, baseline)
            if args.output:
                Path(args.output).write_text(output)
                print(f"Summary written to {args.output}")
            else:
                print(output)
            return

        # Apply filters
        controls = filter_controls(
            controls,
            family=args.family,
            search=args.search,
            control_id=args.control,
        )

        if not controls:
            print("No controls found matching the specified filters.")
            sys.exit(1)

        # Format output
        formatters = {
            "table": format_table,
            "csv": format_csv,
            "json": format_json,
            "markdown": format_markdown,
            "detail": format_detail,
        }

        formatter = formatters[args.output_format]
        output = formatter(controls)

        # Write output
        if args.output:
            Path(args.output).write_text(output)
            print(f"Output written to {args.output} ({len(controls)} controls)")
        else:
            print(output)

    except FileNotFoundError as e:
        logger.error(str(e))
        print(
            "\nHint: Run 'make baselines' to download the required FedRAMP baselines "
            "and NIST catalog files.",
            file=sys.stderr,
        )
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
