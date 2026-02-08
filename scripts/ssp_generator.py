#!/usr/bin/env python3
"""
SSP Generator

Generates a FedRAMP System Security Plan from structured inputs:
- System metadata in YAML (boundary, components, data flows, FIPS 199 categorization)
- Control implementation narratives in Markdown (one per control family)
- Inheritance mapping from inheritance_mapper.py

Outputs OSCAL SSP JSON and optionally an HTML rendering for human review.
Uses compliance-trestle's agile authoring model: edit in Markdown fragments,
assemble into valid OSCAL.

Usage:
    python scripts/ssp_generator.py --metadata system.yaml --controls-dir controls/ --baseline moderate --output ssp.json
    python scripts/ssp_generator.py --metadata system.yaml --controls-dir controls/ --baseline moderate --output ssp.json --html ssp.html
"""

import argparse
import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.utils.oscal_helpers import (
    CONTROL_FAMILIES,
    extract_control_ids_from_profile,
    extract_controls_from_catalog,
    filter_catalog_by_baseline,
    load_baseline,
    load_catalog,
)

logger = logging.getLogger(__name__)


# --- System metadata schema ---


def load_system_metadata(filepath: Path) -> dict:
    """
    Load system metadata from YAML.

    Expected structure:
        system:
          name: "My Cloud Service"
          abbreviation: "MCS"
          version: "1.0"
          fips199_level: moderate
          authorization_type: agency
          description: "A SaaS platform for..."

        boundary:
          description: "The authorization boundary encompasses..."
          components:
            - name: "Web Application"
              type: software
              description: "React frontend served via CloudFront"
            - name: "API Service"
              type: software
              description: "Python FastAPI backend on ECS Fargate"
            - name: "Database"
              type: software
              description: "Amazon RDS PostgreSQL"
          external_services:
            - name: "AWS GovCloud"
              fedramp_authorized: true
              authorization_id: "F1234567890"
            - name: "SendGrid"
              fedramp_authorized: true

        responsible_parties:
          system_owner:
            name: "Jane Smith"
            title: "CISO"
            email: "jane@example.com"
          authorizing_official:
            name: "Agency AO"
            organization: "Federal Agency"

        network:
          data_flow_description: "Data enters via HTTPS..."
          ports_and_protocols:
            - port: 443
              protocol: HTTPS
              direction: inbound
              purpose: "Web application access"
    """
    data = yaml.safe_load(filepath.read_text())
    if not data or "system" not in data:
        raise ValueError("Metadata file must contain a 'system' key")
    return data


# --- Control narrative loading ---


def load_control_narratives(controls_dir: Path) -> dict[str, dict[str, str]]:
    """
    Load control implementation narratives from Markdown files.

    Each file should be named by control family (e.g., AC.md, SC.md) and
    contain sections headed by control ID:

        ## AC-1

        The organization has developed, documented, and disseminated
        an access control policy...

        ## AC-2

        Account management is handled through AWS IAM...

    Returns: {control_id: {"narrative": text, "family": family_id}}
    """
    narratives = {}

    if not controls_dir.exists():
        logger.warning(f"Controls directory not found: {controls_dir}")
        return narratives

    for md_file in sorted(controls_dir.glob("*.md")):
        family_id = md_file.stem.upper()
        content = md_file.read_text()

        current_control = None
        current_text = []

        for line in content.split("\n"):
            # Detect control heading (## AC-1, ## AC-2(1), etc.)
            stripped = line.strip()
            if stripped.startswith("## ") and "-" in stripped:
                # Save previous control
                if current_control and current_text:
                    narratives[current_control] = {
                        "narrative": "\n".join(current_text).strip(),
                        "family": family_id,
                    }
                current_control = stripped[3:].strip().upper()
                current_text = []
            elif current_control is not None:
                current_text.append(line)

        # Save the last control
        if current_control and current_text:
            narratives[current_control] = {
                "narrative": "\n".join(current_text).strip(),
                "family": family_id,
            }

    logger.info(f"Loaded narratives for {len(narratives)} controls from {controls_dir}")
    return narratives


# --- OSCAL SSP generation ---


def generate_oscal_ssp(
    metadata: dict,
    baseline_controls: list[dict],
    narratives: dict[str, dict[str, str]],
    inheritance_map: dict[str, str] | None = None,
    baseline_name: str = "moderate",
) -> dict:
    """
    Generate an OSCAL-format System Security Plan.

    This creates a valid OSCAL SSP JSON structure that can be validated
    against FedRAMP Schematron rules.
    """
    now = datetime.now(timezone.utc).isoformat()
    ssp_uuid = str(uuid.uuid4())
    system_info = metadata.get("system", {})
    boundary = metadata.get("boundary", {})
    parties = metadata.get("responsible_parties", {})
    inheritance = inheritance_map or {}

    # Build component list
    components = []
    this_system_uuid = str(uuid.uuid4())
    components.append({
        "uuid": this_system_uuid,
        "type": "this-system",
        "title": system_info.get("name", "System"),
        "description": system_info.get("description", ""),
        "status": {"state": "operational"},
    })

    for comp in boundary.get("components", []):
        components.append({
            "uuid": str(uuid.uuid4()),
            "type": comp.get("type", "software"),
            "title": comp.get("name", ""),
            "description": comp.get("description", ""),
            "status": {"state": "operational"},
        })

    # Build implemented-requirements
    implemented_requirements = []
    for control in baseline_controls:
        cid = control["id"]
        impl_status = "implemented"
        inherit_type = inheritance.get(cid, "customer")

        narrative = narratives.get(cid, {}).get("narrative", "")
        if not narrative:
            if inherit_type == "inherited":
                narrative = f"This control is fully inherited from the FedRAMP-authorized cloud service provider."
                impl_status = "implemented"
            elif inherit_type == "shared":
                narrative = f"This control has shared responsibility. The underlying infrastructure aspects are inherited from the cloud provider. The CSP is responsible for application-level implementation."
                impl_status = "partial"
            else:
                narrative = "Implementation details pending documentation."
                impl_status = "planned"

        # Build the implemented-requirement entry
        req = {
            "uuid": str(uuid.uuid4()),
            "control-id": cid.lower(),
            "props": [
                {"name": "implementation-status", "ns": "https://fedramp.gov/ns/oscal", "value": impl_status},
            ],
            "responsible-roles": [{"role-id": "system-owner"}],
            "by-components": [{
                "component-uuid": this_system_uuid,
                "uuid": str(uuid.uuid4()),
                "description": narrative,
                "implementation-status": {"state": impl_status},
            }],
        }

        if inherit_type == "inherited":
            req["props"].append({
                "name": "leveraged-authorization-type",
                "ns": "https://fedramp.gov/ns/oscal",
                "value": "inherited",
            })

        implemented_requirements.append(req)

    # Build system characteristics
    system_characteristics = {
        "system-ids": [{"id": system_info.get("abbreviation", "SYS"), "identifier-type": "https://fedramp.gov"}],
        "system-name": system_info.get("name", "System"),
        "description": system_info.get("description", ""),
        "security-sensitivity-level": baseline_name,
        "system-information": {
            "information-types": [{
                "uuid": str(uuid.uuid4()),
                "title": "System Information",
                "description": "Information processed by the system",
                "categorizations": [{
                    "system": "https://doi.org/10.6028/NIST.SP.800-60v2r1",
                    "information-type-ids": ["C.3.5.8"],
                }],
                "confidentiality-impact": {"base": baseline_name},
                "integrity-impact": {"base": baseline_name},
                "availability-impact": {"base": baseline_name},
            }],
        },
        "security-impact-level": {
            "security-objective-confidentiality": baseline_name,
            "security-objective-integrity": baseline_name,
            "security-objective-availability": baseline_name,
        },
        "status": {"state": "operational"},
        "authorization-boundary": {
            "description": boundary.get("description", "Authorization boundary description pending."),
        },
    }

    # Build the full SSP
    ssp = {
        "system-security-plan": {
            "uuid": ssp_uuid,
            "metadata": {
                "title": f"System Security Plan: {system_info.get('name', 'System')}",
                "last-modified": now,
                "version": system_info.get("version", "1.0"),
                "oscal-version": "1.0.4",
                "roles": [
                    {"id": "system-owner", "title": "System Owner"},
                    {"id": "authorizing-official", "title": "Authorizing Official"},
                    {"id": "information-system-security-officer", "title": "ISSO"},
                ],
                "parties": [],
            },
            "import-profile": {
                "href": f"#fedramp-{baseline_name}-baseline",
            },
            "system-characteristics": system_characteristics,
            "system-implementation": {
                "users": [{
                    "uuid": str(uuid.uuid4()),
                    "title": "System Administrator",
                    "role-ids": ["system-owner"],
                    "authorized-privileges": [{
                        "title": "Full administrative access",
                        "functions-performed": ["System administration"],
                    }],
                }],
                "components": components,
            },
            "control-implementation": {
                "description": f"FedRAMP {baseline_name.upper()} control implementation for {system_info.get('name', 'System')}",
                "implemented-requirements": implemented_requirements,
            },
        }
    }

    # Add parties from metadata
    owner = parties.get("system_owner", {})
    if owner:
        ssp["system-security-plan"]["metadata"]["parties"].append({
            "uuid": str(uuid.uuid4()),
            "type": "person",
            "name": owner.get("name", ""),
            "email-addresses": [owner.get("email", "")] if owner.get("email") else [],
        })

    return ssp


# --- HTML rendering ---


def render_ssp_html(ssp: dict, output_path: Path):
    """Render SSP as an HTML document for human review."""
    from scripts.utils.report_generators import generate_html_report

    plan = ssp.get("system-security-plan", {})
    meta = plan.get("metadata", {})
    chars = plan.get("system-characteristics", {})
    impl = plan.get("control-implementation", {})

    # System overview section
    system_html = f"""
    <h3>{chars.get('system-name', 'System')}</h3>
    <p>{chars.get('description', '')}</p>
    <table>
        <tr><th>Attribute</th><th>Value</th></tr>
        <tr><td>Security Level</td><td>{chars.get('security-sensitivity-level', '')}</td></tr>
        <tr><td>Status</td><td>{chars.get('status', {}).get('state', '')}</td></tr>
        <tr><td>SSP Version</td><td>{meta.get('version', '')}</td></tr>
        <tr><td>Last Modified</td><td>{meta.get('last-modified', '')}</td></tr>
    </table>
    """

    # Components section
    components = plan.get("system-implementation", {}).get("components", [])
    comp_rows = ""
    for c in components:
        comp_rows += f"<tr><td>{c.get('title', '')}</td><td>{c.get('type', '')}</td><td>{c.get('description', '')[:80]}</td></tr>"

    comp_html = f"""<table>
        <tr><th>Component</th><th>Type</th><th>Description</th></tr>
        {comp_rows}</table>"""

    # Control implementations
    reqs = impl.get("implemented-requirements", [])
    ctrl_rows = ""
    for req in reqs[:50]:  # Limit for readability
        cid = req.get("control-id", "").upper()
        status = "planned"
        for prop in req.get("props", []):
            if prop.get("name") == "implementation-status":
                status = prop.get("value", "planned")

        desc = ""
        for bc in req.get("by-components", []):
            desc = bc.get("description", "")[:120]
            break

        status_class = {"implemented": "color:#2e7d32", "partial": "color:#f57f17", "planned": "color:#e65100"}.get(status, "")
        ctrl_rows += f'<tr><td><strong>{cid}</strong></td><td style="{status_class}">{status}</td><td>{desc}</td></tr>'

    ctrl_html = f"""<p>Showing first 50 of {len(reqs)} control implementations.</p>
        <table><tr><th>Control</th><th>Status</th><th>Description</th></tr>{ctrl_rows}</table>"""

    sections = [
        {"heading": "System Overview", "body": system_html},
        {"heading": f"System Components ({len(components)})", "body": comp_html},
        {"heading": f"Control Implementations ({len(reqs)})", "body": ctrl_html},
    ]

    generate_html_report(
        title=f"SSP: {chars.get('system-name', 'System')}",
        content_sections=sections,
        output_path=output_path,
        metadata={"Level": chars.get("security-sensitivity-level", ""), "Version": meta.get("version", "")},
    )


# --- Main ---


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def main():
    parser = argparse.ArgumentParser(description="FedRAMP SSP Generator")
    parser.add_argument("--metadata", "-m", type=Path, required=True, help="System metadata YAML")
    parser.add_argument("--controls-dir", "-c", type=Path, help="Directory with control narrative Markdown files")
    parser.add_argument("--baseline", "-b", choices=["low", "moderate", "high", "li-saas"], default="moderate")
    parser.add_argument("--inheritance-map", type=Path, help="Inheritance mapping YAML from inheritance_mapper.py")
    parser.add_argument("--output", "-o", type=Path, required=True, help="Output OSCAL SSP JSON path")
    parser.add_argument("--html", type=Path, help="Optional HTML rendering output")
    parser.add_argument("--catalog-path", type=Path)
    parser.add_argument("--baselines-dir", type=Path)
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()
    setup_logging(args.verbose)

    if not args.metadata.exists():
        logger.error(f"Metadata file not found: {args.metadata}")
        sys.exit(1)

    try:
        # Load inputs
        metadata = load_system_metadata(args.metadata)
        logger.info(f"Loaded system metadata: {metadata['system'].get('name', 'Unknown')}")

        narratives = {}
        if args.controls_dir:
            narratives = load_control_narratives(args.controls_dir)

        inheritance = None
        if args.inheritance_map:
            data = yaml.safe_load(args.inheritance_map.read_text())
            inheritance = {k.upper(): v for k, v in data.get("controls", {}).items()}
            logger.info(f"Loaded inheritance mapping for {len(inheritance)} controls")

        # Load baseline
        logger.info(f"Loading {args.baseline.upper()} baseline...")
        catalog_data = load_catalog(args.catalog_path)
        all_controls = extract_controls_from_catalog(catalog_data)
        profile_data = load_baseline(args.baseline, args.baselines_dir)
        baseline_ids = extract_control_ids_from_profile(profile_data)
        baseline_controls = filter_catalog_by_baseline(all_controls, baseline_ids)

        # Generate SSP
        logger.info("Generating OSCAL SSP...")
        ssp = generate_oscal_ssp(metadata, baseline_controls, narratives, inheritance, args.baseline)

        # Write output
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(ssp, indent=2))
        logger.info(f"OSCAL SSP written to {args.output}")

        # Count implementation statuses
        reqs = ssp["system-security-plan"]["control-implementation"]["implemented-requirements"]
        status_counts = {}
        for req in reqs:
            for prop in req.get("props", []):
                if prop.get("name") == "implementation-status":
                    s = prop["value"]
                    status_counts[s] = status_counts.get(s, 0) + 1

        print(f"\n  SSP generated: {metadata['system'].get('name', 'System')}")
        print(f"  Baseline: {args.baseline.upper()} ({len(reqs)} controls)")
        for status, count in sorted(status_counts.items()):
            print(f"  {status}: {count}")

        # HTML rendering
        if args.html:
            render_ssp_html(ssp, args.html)
            print(f"  HTML: {args.html}")

    except FileNotFoundError as e:
        logger.error(str(e))
        print("\nHint: Run 'make baselines' to download required files.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
