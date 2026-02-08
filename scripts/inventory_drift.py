#!/usr/bin/env python3
"""
Inventory Drift Detector

Compares the documented system inventory (from the SSP's Integrated Inventory
Workbook) against actual cloud infrastructure to detect drift. Inventory
drift is a common ConMon finding that can trigger FedRAMP escalation.

FedRAMP requires the Integrated Inventory Workbook to be updated monthly
and submitted as part of ConMon deliverables. When the documented inventory
doesn't match reality, your 3PAO will flag it.

Drift types detected:
    - Undocumented resources (in cloud but not in inventory)
    - Stale entries (in inventory but no longer in cloud)
    - Configuration changes (resource exists but config differs)

Inputs:
    - Documented inventory (YAML, CSV, or JSON)
    - Live inventory from cloud APIs (AWS/Azure/GCP) or a snapshot JSON

Outputs:
    - Drift report (JSON, CSV, HTML)
    - Updated inventory recommendation

Usage:
    python scripts/inventory_drift.py --documented inventory.yaml --live live-snapshot.json --output-dir reports/
    python scripts/inventory_drift.py --documented inventory.yaml --provider aws --output-dir reports/
"""

import argparse
import csv
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

logger = logging.getLogger(__name__)


# --- Data structures ---


def normalize_resource_id(resource_id: str) -> str:
    """Normalize resource IDs for comparison."""
    return resource_id.strip().lower()


def load_documented_inventory(filepath: Path) -> list[dict]:
    """
    Load documented inventory from YAML, CSV, or JSON.

    Expected fields per resource:
        - resource_id: unique identifier (ARN, resource ID, hostname)
        - resource_type: e.g., EC2, RDS, S3, Lambda
        - name: human-readable name
        - environment: production, staging, etc.
        - boundary: in-boundary, out-of-boundary
        - owner: responsible team/person
    """
    suffix = filepath.suffix.lower()

    if suffix in (".yaml", ".yml"):
        data = yaml.safe_load(filepath.read_text())
        items = data.get("inventory", data.get("resources", []))
    elif suffix == ".csv":
        with open(filepath, "r") as f:
            items = list(csv.DictReader(f))
    elif suffix == ".json":
        data = json.loads(filepath.read_text())
        items = data.get("inventory", data.get("resources", data)) if isinstance(data, dict) else data
    else:
        raise ValueError(f"Unsupported format: {suffix}")

    # Normalize
    for item in items:
        item["_normalized_id"] = normalize_resource_id(item.get("resource_id", item.get("id", "")))

    logger.info(f"Loaded {len(items)} documented resources from {filepath.name}")
    return items


def load_live_inventory(filepath: Path | None = None, provider: str | None = None) -> list[dict]:
    """
    Load live inventory from a snapshot file or cloud API.

    For API-based collection, requires cloud credentials. Falls back to
    snapshot file if API isn't available.
    """
    if filepath and filepath.exists():
        data = json.loads(filepath.read_text())
        items = data.get("inventory", data.get("resources", data)) if isinstance(data, dict) else data
        for item in items:
            item["_normalized_id"] = normalize_resource_id(item.get("resource_id", item.get("id", "")))
        logger.info(f"Loaded {len(items)} live resources from {filepath.name}")
        return items

    if provider == "aws":
        return _collect_aws_inventory()
    elif provider == "azure":
        return _collect_azure_inventory()
    elif provider == "gcp":
        return _collect_gcp_inventory()
    else:
        logger.error("Provide either --live snapshot file or --provider for API collection")
        return []


def _collect_aws_inventory() -> list[dict]:
    """Collect resource inventory from AWS."""
    try:
        import boto3
    except ImportError:
        logger.error("boto3 not installed. Run: pip install 'fedramp-readiness-toolkit[aws]'")
        return []

    session = boto3.Session()
    resources = []

    # EC2 instances
    try:
        ec2 = session.client("ec2")
        instances = ec2.describe_instances()
        for reservation in instances.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                name = ""
                for tag in inst.get("Tags", []):
                    if tag["Key"] == "Name":
                        name = tag["Value"]

                resources.append({
                    "resource_id": inst["InstanceId"],
                    "resource_type": "EC2",
                    "name": name,
                    "state": inst.get("State", {}).get("Name", ""),
                    "instance_type": inst.get("InstanceType", ""),
                    "vpc_id": inst.get("VpcId", ""),
                    "subnet_id": inst.get("SubnetId", ""),
                    "_normalized_id": normalize_resource_id(inst["InstanceId"]),
                })
    except Exception as e:
        logger.warning(f"Could not collect EC2 inventory: {e}")

    # RDS instances
    try:
        rds = session.client("rds")
        dbs = rds.describe_db_instances()
        for db in dbs.get("DBInstances", []):
            resources.append({
                "resource_id": db["DBInstanceIdentifier"],
                "resource_type": "RDS",
                "name": db["DBInstanceIdentifier"],
                "engine": db.get("Engine", ""),
                "instance_class": db.get("DBInstanceClass", ""),
                "encrypted": db.get("StorageEncrypted", False),
                "_normalized_id": normalize_resource_id(db["DBInstanceIdentifier"]),
            })
    except Exception as e:
        logger.warning(f"Could not collect RDS inventory: {e}")

    # S3 buckets
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            resources.append({
                "resource_id": bucket["Name"],
                "resource_type": "S3",
                "name": bucket["Name"],
                "created": str(bucket.get("CreationDate", "")),
                "_normalized_id": normalize_resource_id(bucket["Name"]),
            })
    except Exception as e:
        logger.warning(f"Could not collect S3 inventory: {e}")

    # Lambda functions
    try:
        lam = session.client("lambda")
        functions = lam.list_functions().get("Functions", [])
        for fn in functions:
            resources.append({
                "resource_id": fn["FunctionArn"],
                "resource_type": "Lambda",
                "name": fn["FunctionName"],
                "runtime": fn.get("Runtime", ""),
                "_normalized_id": normalize_resource_id(fn["FunctionArn"]),
            })
    except Exception as e:
        logger.warning(f"Could not collect Lambda inventory: {e}")

    logger.info(f"Collected {len(resources)} resources from AWS")
    return resources


def _collect_azure_inventory() -> list[dict]:
    """Collect from Azure (stub for expansion)."""
    logger.warning("Azure inventory collection not yet implemented. Use --live with a snapshot file.")
    return []


def _collect_gcp_inventory() -> list[dict]:
    """Collect from GCP (stub for expansion)."""
    logger.warning("GCP inventory collection not yet implemented. Use --live with a snapshot file.")
    return []


# --- Drift detection ---


def detect_drift(documented: list[dict], live: list[dict]) -> dict[str, Any]:
    """
    Compare documented inventory against live inventory to find drift.

    Returns a drift report with:
        - undocumented: resources in live but not in documented inventory
        - stale: resources in documented but not in live inventory
        - matched: resources found in both (potential config differences)
    """
    doc_by_id = {r["_normalized_id"]: r for r in documented if r.get("_normalized_id")}
    live_by_id = {r["_normalized_id"]: r for r in live if r.get("_normalized_id")}

    doc_ids = set(doc_by_id.keys())
    live_ids = set(live_by_id.keys())

    undocumented_ids = live_ids - doc_ids
    stale_ids = doc_ids - live_ids
    matched_ids = doc_ids & live_ids

    undocumented = [
        {**live_by_id[rid], "drift_type": "undocumented", "issue": "Resource exists in cloud but not in documented inventory"}
        for rid in sorted(undocumented_ids)
    ]

    stale = [
        {**doc_by_id[rid], "drift_type": "stale", "issue": "Resource in inventory but not found in cloud"}
        for rid in sorted(stale_ids)
    ]

    matched = []
    config_drifts = []
    for rid in sorted(matched_ids):
        doc_resource = doc_by_id[rid]
        live_resource = live_by_id[rid]

        # Check for config differences (compare common fields)
        differences = []
        for key in ["resource_type", "name", "state", "instance_type", "engine", "encrypted"]:
            doc_val = str(doc_resource.get(key, "")).lower()
            live_val = str(live_resource.get(key, "")).lower()
            if doc_val and live_val and doc_val != live_val:
                differences.append({"field": key, "documented": doc_val, "actual": live_val})

        entry = {**live_resource, "drift_type": "matched"}
        if differences:
            entry["drift_type"] = "config_drift"
            entry["differences"] = differences
            entry["issue"] = f"Configuration changed: {', '.join(d['field'] for d in differences)}"
            config_drifts.append(entry)
        else:
            matched.append(entry)

    return {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "documented_count": len(documented),
            "live_count": len(live),
        },
        "summary": {
            "total_documented": len(documented),
            "total_live": len(live),
            "matched": len(matched),
            "undocumented": len(undocumented),
            "stale": len(stale),
            "config_drift": len(config_drifts),
            "drift_percentage": round(
                ((len(undocumented) + len(stale) + len(config_drifts)) /
                 max(len(documented) + len(undocumented), 1)) * 100, 1
            ),
        },
        "undocumented": undocumented,
        "stale": stale,
        "config_drift": config_drifts,
        "matched": matched,
    }


# --- Output ---


def output_drift_json(drift: dict, output_path: Path):
    """Write drift report to JSON."""
    # Remove _normalized_id from output
    clean = json.loads(json.dumps(drift, default=str))
    for section in ["undocumented", "stale", "config_drift", "matched"]:
        for item in clean.get(section, []):
            item.pop("_normalized_id", None)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(clean, indent=2))


def output_drift_csv(drift: dict, output_path: Path):
    """Write drift items to CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    all_items = (
        drift.get("undocumented", []) +
        drift.get("stale", []) +
        drift.get("config_drift", [])
    )

    if not all_items:
        return

    fields = ["resource_id", "resource_type", "name", "drift_type", "issue"]
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_items)


def output_drift_html(drift: dict, output_path: Path):
    """Generate HTML drift report."""
    from scripts.utils.report_generators import generate_html_report

    s = drift["summary"]
    drift_pct = s["drift_percentage"]
    color = "#2e7d32" if drift_pct < 5 else "#f57f17" if drift_pct < 15 else "#c62828"

    overview = f"""
    <div style="display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0;">
        <div style="background:#f5f5f5;padding:1.5rem;border-radius:8px;min-width:150px;text-align:center;border-left:6px solid {color};">
            <div style="font-size:2.5rem;font-weight:bold;color:{color};">{drift_pct}%</div>
            <div>Drift Rate</div>
        </div>
        <div style="background:#fff3e0;padding:1.5rem;border-radius:8px;min-width:130px;text-align:center;">
            <div style="font-size:2rem;font-weight:bold;">{s['undocumented']}</div><div>Undocumented</div>
        </div>
        <div style="background:#fce4ec;padding:1.5rem;border-radius:8px;min-width:130px;text-align:center;">
            <div style="font-size:2rem;font-weight:bold;">{s['stale']}</div><div>Stale</div>
        </div>
        <div style="background:#e3f2fd;padding:1.5rem;border-radius:8px;min-width:130px;text-align:center;">
            <div style="font-size:2rem;font-weight:bold;">{s['config_drift']}</div><div>Config Drift</div>
        </div>
        <div style="background:#e8f5e9;padding:1.5rem;border-radius:8px;min-width:130px;text-align:center;">
            <div style="font-size:2rem;font-weight:bold;">{s['matched']}</div><div>Matched</div>
        </div>
    </div>"""

    # Drift items table
    all_drift = drift.get("undocumented", []) + drift.get("stale", []) + drift.get("config_drift", [])
    rows = ""
    colors = {"undocumented": "#fff3e0", "stale": "#fce4ec", "config_drift": "#e3f2fd"}
    for item in all_drift[:100]:
        bg = colors.get(item.get("drift_type", ""), "#fff")
        rows += f"""<tr style="background:{bg};">
            <td>{item.get('resource_id', '')[:50]}</td>
            <td>{item.get('resource_type', '')}</td>
            <td>{item.get('name', '')[:30]}</td>
            <td>{item.get('drift_type', '')}</td>
            <td>{item.get('issue', '')[:80]}</td></tr>"""

    items_html = f"""<table><tr><th>Resource ID</th><th>Type</th><th>Name</th><th>Drift</th><th>Issue</th></tr>
        {rows}</table>""" if rows else "<p>No drift detected.</p>"

    sections = [
        {"heading": "Overview", "body": overview},
        {"heading": f"Drift Items ({len(all_drift)})", "body": items_html},
    ]

    generate_html_report(
        title="Inventory Drift Report",
        content_sections=sections,
        output_path=output_path,
        metadata={"Drift Rate": f"{drift_pct}%", "Documented": str(s["total_documented"]), "Live": str(s["total_live"])},
    )


def print_drift_summary(drift: dict):
    """Print drift summary to console."""
    s = drift["summary"]
    print(f"\n  Inventory Drift Analysis")
    print(f"  {'='*40}")
    print(f"  Documented:    {s['total_documented']} resources")
    print(f"  Live:          {s['total_live']} resources")
    print(f"  Matched:       {s['matched']}")
    print(f"  Undocumented:  {s['undocumented']} (in cloud, not in inventory)")
    print(f"  Stale:         {s['stale']} (in inventory, not in cloud)")
    print(f"  Config drift:  {s['config_drift']}")
    print(f"  Drift rate:    {s['drift_percentage']}%")
    print()


# --- CLI ---


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def main():
    parser = argparse.ArgumentParser(description="FedRAMP Inventory Drift Detector")
    parser.add_argument("--documented", "-d", type=Path, required=True, help="Documented inventory file")
    parser.add_argument("--live", "-l", type=Path, help="Live inventory snapshot JSON")
    parser.add_argument("--provider", "-p", choices=["aws", "azure", "gcp"], help="Collect live inventory from API")
    parser.add_argument("--output-dir", "-o", type=Path, required=True)
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()
    setup_logging(args.verbose)

    documented = load_documented_inventory(args.documented)
    live = load_live_inventory(args.live, args.provider)

    if not live:
        logger.error("No live inventory data. Provide --live or --provider.")
        sys.exit(1)

    drift = detect_drift(documented, live)
    print_drift_summary(drift)

    ts = datetime.now().strftime("%Y%m%d")
    output_drift_json(drift, args.output_dir / f"drift-report-{ts}.json")
    output_drift_csv(drift, args.output_dir / f"drift-items-{ts}.csv")
    output_drift_html(drift, args.output_dir / f"drift-report-{ts}.html")
    print(f"  Reports written to {args.output_dir}/")


if __name__ == "__main__":
    main()
