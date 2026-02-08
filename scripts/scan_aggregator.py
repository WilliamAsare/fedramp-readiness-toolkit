#!/usr/bin/env python3
"""
Vulnerability Scan Aggregator

Normalizes and deduplicates vulnerability scan results from multiple scanners
(Nessus, Qualys, AWS Inspector, Trivy, Prowler) into a unified format for
FedRAMP ConMon deliverables and POA&M generation.

FedRAMP requires monthly vulnerability scans covering OS, web application,
database, and container layers. Most organizations use multiple scanners.
This script brings them all together.

Inputs:
    - Nessus CSV exports
    - Qualys XML exports
    - AWS Inspector JSON findings
    - Trivy JSON container scan results
    - Prowler JSON output

Outputs:
    - Unified findings JSON
    - ConMon summary CSV
    - Deduplicated findings by CVE

Usage:
    python scripts/scan_aggregator.py --input scans/ --output-dir reports/
    python scripts/scan_aggregator.py --input nessus.csv --input trivy.json --output-dir reports/
    python scripts/scan_aggregator.py --input scans/ --output-dir reports/ --deduplicate
"""

import argparse
import csv
import hashlib
import json
import logging
import sys
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

logger = logging.getLogger(__name__)


@dataclass
class VulnFinding:
    """Normalized vulnerability finding from any scanner."""

    finding_id: str
    scanner: str  # nessus, qualys, inspector, trivy, prowler
    cve_id: str | None  # CVE-YYYY-NNNN or None
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MODERATE, LOW, INFORMATIONAL
    cvss_score: float | None
    affected_resource: str  # hostname, image, ARN
    resource_type: str  # os, web_app, database, container, cloud_config
    plugin_id: str | None  # Scanner-specific ID
    first_seen: str  # ISO datetime
    last_seen: str  # ISO datetime
    status: str = "open"  # open, remediated, accepted, false_positive
    solution: str = ""
    references: list[str] = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("raw_data", None)
        return d


# --- Severity normalization ---

_SEVERITY_MAP = {
    "critical": "CRITICAL", "4": "CRITICAL",
    "high": "HIGH", "3": "HIGH",
    "medium": "MODERATE", "2": "MODERATE",
    "low": "LOW", "1": "LOW",
    "none": "INFORMATIONAL", "info": "INFORMATIONAL", "0": "INFORMATIONAL",
    "5": "CRITICAL",  # Qualys
    "untriaged": "MODERATE",
    "unknown": "INFORMATIONAL",
    "moderate": "MODERATE",
    "informational": "INFORMATIONAL",
}


def normalize_severity(severity: str) -> str:
    """Normalize severity string to FedRAMP standard levels."""
    return _SEVERITY_MAP.get(severity.lower().strip(), "MODERATE")


def _generate_finding_id(scanner: str, plugin_id: str | None, resource: str, cve: str | None) -> str:
    """Generate a deterministic finding ID for deduplication."""
    key = f"{scanner}:{plugin_id or ''}:{resource}:{cve or ''}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


# --- Scanner parsers ---


def parse_nessus_csv(filepath: Path) -> list[VulnFinding]:
    """Parse Nessus CSV export."""
    findings = []
    now = datetime.now(timezone.utc).isoformat()

    with open(filepath, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            severity_raw = row.get("Risk", row.get("Severity", "")).strip()
            if not severity_raw or severity_raw.lower() == "none":
                continue

            cve = row.get("CVE", "").strip() or None
            plugin_id = row.get("Plugin ID", "").strip()
            host = row.get("Host", row.get("IP Address", "unknown")).strip()
            port = row.get("Port", "").strip()
            resource = f"{host}:{port}" if port and port != "0" else host

            cvss_raw = row.get("CVSS", row.get("CVSS v3.0 Base Score", ""))
            try:
                cvss = float(cvss_raw) if cvss_raw else None
            except ValueError:
                cvss = None

            fid = _generate_finding_id("nessus", plugin_id, resource, cve)

            findings.append(VulnFinding(
                finding_id=fid, scanner="nessus",
                cve_id=cve if cve and cve.startswith("CVE-") else None,
                title=row.get("Name", row.get("Plugin Name", "Unknown")).strip(),
                description=row.get("Synopsis", row.get("Description", ""))[:500],
                severity=normalize_severity(severity_raw),
                cvss_score=cvss,
                affected_resource=resource, resource_type="os",
                plugin_id=plugin_id, first_seen=now, last_seen=now,
                solution=row.get("Solution", "")[:500],
                references=[r.strip() for r in row.get("See Also", "").split("\n") if r.strip()],
            ))

    logger.info(f"Parsed {len(findings)} findings from Nessus CSV: {filepath.name}")
    return findings


def parse_trivy_json(filepath: Path) -> list[VulnFinding]:
    """Parse Trivy JSON container scan output."""
    findings = []
    data = json.loads(filepath.read_text())
    now = datetime.now(timezone.utc).isoformat()

    for result in data.get("Results", []):
        target = result.get("Target", "unknown")

        for vuln in result.get("Vulnerabilities", []):
            cve = vuln.get("VulnerabilityID", "")
            cve_id = cve if cve.startswith("CVE-") else None
            severity_raw = vuln.get("Severity", "UNKNOWN")
            cvss_data = vuln.get("CVSS", {})

            cvss = None
            for source in cvss_data.values():
                if isinstance(source, dict) and "V3Score" in source:
                    cvss = source["V3Score"]
                    break

            pkg = vuln.get("PkgName", "unknown")
            installed = vuln.get("InstalledVersion", "")
            fixed = vuln.get("FixedVersion", "")
            resource = f"{target}:{pkg}@{installed}"

            fid = _generate_finding_id("trivy", cve, resource, cve_id)
            solution = f"Update {pkg} to {fixed}" if fixed else "No fix available"

            findings.append(VulnFinding(
                finding_id=fid, scanner="trivy",
                cve_id=cve_id,
                title=vuln.get("Title", f"{cve} in {pkg}"),
                description=vuln.get("Description", "")[:500],
                severity=normalize_severity(severity_raw),
                cvss_score=cvss,
                affected_resource=resource, resource_type="container",
                plugin_id=cve, first_seen=now, last_seen=now,
                solution=solution,
                references=vuln.get("References", [])[:5],
            ))

    logger.info(f"Parsed {len(findings)} findings from Trivy JSON: {filepath.name}")
    return findings


def parse_inspector_json(filepath: Path) -> list[VulnFinding]:
    """Parse AWS Inspector JSON findings."""
    findings = []
    data = json.loads(filepath.read_text())
    items = data if isinstance(data, list) else data.get("findings", [])

    for item in items:
        severity_raw = item.get("severity", "MEDIUM")
        cve = None
        for ref in item.get("referenceUrls", []):
            if "CVE-" in ref:
                cve = ref.split("/")[-1]
                break

        resource_id = "unknown"
        if item.get("resources"):
            resource_id = item["resources"][0].get("id", "unknown")

        fid = _generate_finding_id("inspector", item.get("findingArn", ""), resource_id, cve)

        findings.append(VulnFinding(
            finding_id=fid, scanner="inspector",
            cve_id=cve,
            title=item.get("title", "AWS Inspector Finding"),
            description=item.get("description", "")[:500],
            severity=normalize_severity(severity_raw),
            cvss_score=None,
            affected_resource=resource_id, resource_type="cloud_config",
            plugin_id=item.get("findingArn", ""),
            first_seen=item.get("firstObservedAt", ""),
            last_seen=item.get("lastObservedAt", ""),
            solution=item.get("remediation", {}).get("recommendation", {}).get("text", "")[:500],
        ))

    logger.info(f"Parsed {len(findings)} findings from Inspector JSON: {filepath.name}")
    return findings


def parse_prowler_json(filepath: Path) -> list[VulnFinding]:
    """Parse Prowler JSON/JSONL output."""
    findings = []
    raw_text = filepath.read_text()

    try:
        items = json.loads(raw_text)
        if isinstance(items, dict):
            items = [items]
    except json.JSONDecodeError:
        items = []
        for line in raw_text.strip().split("\n"):
            if line.strip():
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    for item in items:
        status = item.get("Status", item.get("status_code", "")).upper()
        if status in ("PASS", "INFO"):
            continue

        severity_raw = item.get("Severity", item.get("severity", "medium"))
        check_id = item.get("CheckID", item.get("check_id", ""))
        resource = item.get("ResourceId", item.get("resource_id", "unknown"))
        fid = _generate_finding_id("prowler", check_id, resource, None)

        findings.append(VulnFinding(
            finding_id=fid, scanner="prowler", cve_id=None,
            title=item.get("CheckTitle", item.get("check_title", check_id)),
            description=item.get("StatusExtended", item.get("status_extended", ""))[:500],
            severity=normalize_severity(severity_raw),
            cvss_score=None,
            affected_resource=resource, resource_type="cloud_config",
            plugin_id=check_id,
            first_seen=item.get("Timestamp", item.get("timestamp", "")),
            last_seen=item.get("Timestamp", item.get("timestamp", "")),
            solution=item.get("Remediation", {}).get("Recommendation", {}).get("Text", "")[:500],
        ))

    logger.info(f"Parsed {len(findings)} findings from Prowler JSON: {filepath.name}")
    return findings


# --- Aggregation ---


def detect_scanner(filepath: Path) -> str | None:
    """Auto-detect scanner type from file content."""
    suffix = filepath.suffix.lower()
    name = filepath.name.lower()

    if suffix == ".csv" or "nessus" in name:
        return "nessus"
    if suffix == ".xml" or "qualys" in name:
        return "qualys"
    if suffix == ".json":
        try:
            data = json.loads(filepath.read_text()[:4000])
            if isinstance(data, dict):
                if "Results" in data:
                    return "trivy"
                if "findings" in data:
                    return "inspector"
                if "CheckID" in data or "check_id" in data:
                    return "prowler"
            elif isinstance(data, list) and data:
                first = data[0]
                if "findingArn" in first:
                    return "inspector"
                if "CheckID" in first or "check_id" in first:
                    return "prowler"
        except Exception:
            pass
    return None


_PARSERS = {
    "nessus": parse_nessus_csv,
    "trivy": parse_trivy_json,
    "inspector": parse_inspector_json,
    "prowler": parse_prowler_json,
}


def aggregate_findings(input_paths: list[Path], scanner_type: str | None = None) -> list[VulnFinding]:
    """Parse and aggregate findings from multiple scan files."""
    all_findings = []

    for path in input_paths:
        if path.is_dir():
            for child in sorted(path.iterdir()):
                if child.is_file() and child.suffix.lower() in (".csv", ".xml", ".json"):
                    all_findings.extend(aggregate_findings([child], scanner_type))
            continue

        if not path.exists():
            logger.warning(f"File not found, skipping: {path}")
            continue

        detected = scanner_type or detect_scanner(path)
        if not detected or detected not in _PARSERS:
            logger.warning(f"Cannot parse {path.name} (detected: {detected}), skipping")
            continue

        try:
            all_findings.extend(_PARSERS[detected](path))
        except Exception as e:
            logger.error(f"Error parsing {path.name}: {e}")

    return all_findings


def deduplicate_findings(findings: list[VulnFinding]) -> list[VulnFinding]:
    """
    Deduplicate findings across scanners using CVE ID matching.
    Findings without CVEs are kept as-is since we can't confirm duplicates.
    """
    by_cve: dict[str, list[VulnFinding]] = {}
    no_cve = []

    for f in findings:
        if f.cve_id:
            key = f"{f.cve_id}:{f.affected_resource}"
            by_cve.setdefault(key, []).append(f)
        else:
            no_cve.append(f)

    deduped = []
    for dupes in by_cve.values():
        best = max(dupes, key=lambda x: len(x.description) + len(x.solution))
        scanners = sorted(set(d.scanner for d in dupes))
        if len(scanners) > 1:
            best.scanner = "+".join(scanners)
        deduped.append(best)

    deduped.extend(no_cve)
    logger.info(f"Deduplicated {len(findings)} to {len(deduped)} findings")
    return deduped


def compute_scan_summary(findings: list[VulnFinding]) -> dict[str, Any]:
    """Compute summary statistics."""
    by_severity = {}
    by_scanner = {}
    by_type = {}

    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_scanner[f.scanner] = by_scanner.get(f.scanner, 0) + 1
        by_type[f.resource_type] = by_type.get(f.resource_type, 0) + 1

    return {
        "total_findings": len(findings),
        "by_severity": dict(sorted(by_severity.items())),
        "by_scanner": dict(sorted(by_scanner.items())),
        "by_resource_type": dict(sorted(by_type.items())),
        "critical_count": by_severity.get("CRITICAL", 0),
        "high_count": by_severity.get("HIGH", 0),
        "moderate_count": by_severity.get("MODERATE", 0),
        "low_count": by_severity.get("LOW", 0),
        "unique_cves": len(set(f.cve_id for f in findings if f.cve_id)),
        "unique_resources": len(set(f.affected_resource for f in findings)),
    }


# --- Output ---


def output_findings_json(findings: list[VulnFinding], summary: dict, output_path: Path):
    """Write unified findings to JSON."""
    data = {
        "metadata": {"generated_at": datetime.now(timezone.utc).isoformat(), "toolkit_version": "0.1.0"},
        "summary": summary,
        "findings": [f.to_dict() for f in findings],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(data, indent=2, default=str))


def output_conmon_csv(findings: list[VulnFinding], output_path: Path):
    """Write ConMon summary CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "finding_id", "scanner", "cve_id", "title", "severity",
        "cvss_score", "affected_resource", "resource_type",
        "first_seen", "last_seen", "status", "solution",
    ]
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for finding in sorted(findings, key=lambda x: (
            {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3}.get(x.severity, 4),
        )):
            writer.writerow(finding.to_dict())


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def main():
    parser = argparse.ArgumentParser(description="Aggregate vulnerability scans from multiple scanners")
    parser.add_argument("--input", "-i", action="append", type=Path, required=True)
    parser.add_argument("--scanner", choices=list(_PARSERS.keys()))
    parser.add_argument("--output-dir", "-o", type=Path, required=True)
    parser.add_argument("--deduplicate", "-d", action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()
    setup_logging(args.verbose)

    findings = aggregate_findings(args.input, args.scanner)
    if args.deduplicate:
        findings = deduplicate_findings(findings)

    summary = compute_scan_summary(findings)

    print(f"\n  Scan Aggregation: {summary['total_findings']} findings")
    print(f"  Critical: {summary['critical_count']} | High: {summary['high_count']} "
          f"| Moderate: {summary['moderate_count']} | Low: {summary['low_count']}")

    ts = datetime.now().strftime("%Y%m%d")
    output_findings_json(findings, summary, args.output_dir / f"scan-findings-{ts}.json")
    output_conmon_csv(findings, args.output_dir / f"scan-findings-{ts}.csv")
    print(f"  Reports written to {args.output_dir}/")


if __name__ == "__main__":
    main()
