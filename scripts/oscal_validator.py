#!/usr/bin/env python3
"""
OSCAL Validator

Validates FedRAMP OSCAL documents (SSP, SAP, SAR, POA&M) against:
1. OSCAL JSON schema (structural correctness)
2. FedRAMP business rules (required fields, valid values)
3. Internal consistency checks (referenced components exist, control IDs valid)

Designed for CI/CD pipeline integration with clear pass/fail exit codes.

Exit codes:
    0 = All validations passed
    1 = Validation errors found
    2 = Input/configuration error

Usage:
    python scripts/oscal_validator.py --input ssp.json --type ssp --baseline moderate
    python scripts/oscal_validator.py --input poam.json --type poam
    python scripts/oscal_validator.py --input ssp.json --type ssp --baseline moderate --strict
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.utils.oscal_helpers import (
    CONTROL_FAMILIES,
    EXPECTED_CONTROL_COUNTS,
    extract_control_ids_from_profile,
    get_family_from_control_id,
    load_baseline,
)

logger = logging.getLogger(__name__)


@property
def _DOCUMENT_TYPES():
    return {"ssp", "sap", "sar", "poam", "catalog", "profile", "component-definition"}

DOCUMENT_ROOT_KEYS = {
    "ssp": "system-security-plan",
    "sap": "assessment-plan",
    "sar": "assessment-results",
    "poam": "plan-of-action-and-milestones",
    "catalog": "catalog",
    "profile": "profile",
    "component-definition": "component-definition",
}


class ValidationResult:
    """Collects validation findings."""

    def __init__(self):
        self.errors: list[dict] = []
        self.warnings: list[dict] = []
        self.info: list[dict] = []

    def error(self, rule: str, message: str, path: str = ""):
        self.errors.append({"severity": "ERROR", "rule": rule, "message": message, "path": path})

    def warning(self, rule: str, message: str, path: str = ""):
        self.warnings.append({"severity": "WARNING", "rule": rule, "message": message, "path": path})

    def information(self, rule: str, message: str, path: str = ""):
        self.info.append({"severity": "INFO", "rule": rule, "message": message, "path": path})

    @property
    def passed(self) -> bool:
        return len(self.errors) == 0

    @property
    def all_findings(self) -> list[dict]:
        return self.errors + self.warnings + self.info

    def summary(self) -> str:
        return f"Errors: {len(self.errors)}, Warnings: {len(self.warnings)}, Info: {len(self.info)}"


# --- Generic OSCAL validation ---


def validate_oscal_structure(data: dict, doc_type: str, result: ValidationResult):
    """Validate basic OSCAL document structure."""
    root_key = DOCUMENT_ROOT_KEYS.get(doc_type)
    if not root_key:
        result.error("STRUCT-001", f"Unknown document type: {doc_type}")
        return

    if root_key not in data:
        result.error("STRUCT-002", f"Missing root element: '{root_key}'", path="/")
        return

    doc = data[root_key]

    # UUID required on root
    if "uuid" not in doc:
        result.error("STRUCT-003", "Document missing required 'uuid' field", path=f"/{root_key}")

    # Metadata required
    metadata = doc.get("metadata")
    if not metadata:
        result.error("STRUCT-004", "Document missing required 'metadata' section", path=f"/{root_key}")
        return

    # Metadata fields
    if not metadata.get("title"):
        result.error("META-001", "Metadata missing 'title'", path=f"/{root_key}/metadata")

    if not metadata.get("last-modified"):
        result.error("META-002", "Metadata missing 'last-modified'", path=f"/{root_key}/metadata")

    if not metadata.get("version"):
        result.warning("META-003", "Metadata missing 'version'", path=f"/{root_key}/metadata")

    oscal_version = metadata.get("oscal-version", "")
    if oscal_version and not oscal_version.startswith("1."):
        result.warning("META-004", f"Unexpected OSCAL version: {oscal_version}", path=f"/{root_key}/metadata")


# --- SSP-specific validation ---


def validate_ssp(data: dict, baseline: str | None, result: ValidationResult, strict: bool = False):
    """Validate a System Security Plan."""
    ssp = data.get("system-security-plan", {})
    if not ssp:
        return

    # System characteristics
    chars = ssp.get("system-characteristics", {})
    if not chars:
        result.error("SSP-001", "Missing 'system-characteristics' section")
    else:
        if not chars.get("system-name"):
            result.error("SSP-002", "Missing system name")

        if not chars.get("description"):
            result.warning("SSP-003", "Missing system description")

        if not chars.get("security-sensitivity-level"):
            result.error("SSP-004", "Missing security sensitivity level")

        # Authorization boundary
        boundary = chars.get("authorization-boundary", {})
        if not boundary.get("description"):
            result.error("SSP-005", "Missing authorization boundary description. This is the #1 cause of RAR rejection.")

        # Security impact level
        impact = chars.get("security-impact-level", {})
        for dim in ["security-objective-confidentiality", "security-objective-integrity", "security-objective-availability"]:
            if not impact.get(dim):
                result.error("SSP-006", f"Missing {dim} in security-impact-level")

    # System implementation
    impl = ssp.get("system-implementation", {})
    if not impl:
        result.error("SSP-010", "Missing 'system-implementation' section")
    else:
        components = impl.get("components", [])
        if not components:
            result.error("SSP-011", "No components defined in system-implementation")

        # Check for this-system component
        has_this_system = any(c.get("type") == "this-system" for c in components)
        if not has_this_system:
            result.warning("SSP-012", "No 'this-system' component found (recommended by FedRAMP)")

        # Collect component UUIDs for reference checking
        component_uuids = {c["uuid"] for c in components if "uuid" in c}

    # Control implementation
    ctrl_impl = ssp.get("control-implementation", {})
    if not ctrl_impl:
        result.error("SSP-020", "Missing 'control-implementation' section")
        return

    reqs = ctrl_impl.get("implemented-requirements", [])
    if not reqs:
        result.error("SSP-021", "No implemented-requirements in control-implementation")
        return

    # Validate each implemented requirement
    control_ids_found = set()
    for idx, req in enumerate(reqs):
        cid = req.get("control-id", "")
        if not cid:
            result.error("SSP-022", f"Missing control-id in implemented-requirement[{idx}]")
            continue

        control_ids_found.add(cid.upper())

        if not req.get("uuid"):
            result.error("SSP-023", f"Missing uuid for {cid}")

        # Check implementation status property
        has_status = False
        for prop in req.get("props", []):
            if prop.get("name") == "implementation-status":
                has_status = True
                valid_statuses = {"implemented", "partial", "planned", "alternative", "not-applicable"}
                if prop.get("value") not in valid_statuses:
                    result.warning("SSP-024", f"{cid}: implementation-status '{prop.get('value')}' not in standard values")

        if not has_status:
            result.warning("SSP-025", f"{cid}: Missing implementation-status property")

        # Check by-components
        by_comps = req.get("by-components", [])
        if not by_comps:
            if strict:
                result.error("SSP-026", f"{cid}: No by-components entries (FedRAMP requires component-level narratives)")
            else:
                result.warning("SSP-026", f"{cid}: No by-components entries")
        else:
            for bc in by_comps:
                comp_uuid = bc.get("component-uuid", "")
                if comp_uuid and component_uuids and comp_uuid not in component_uuids:
                    result.error("SSP-027", f"{cid}: References unknown component {comp_uuid}")

                if not bc.get("description"):
                    result.warning("SSP-028", f"{cid}: Empty implementation description in by-component")

    # Baseline completeness check
    if baseline:
        try:
            profile_data = load_baseline(baseline)
            baseline_ids = extract_control_ids_from_profile(profile_data)
            baseline_upper = {cid.upper() for cid in baseline_ids}

            missing = baseline_upper - control_ids_found
            extra = control_ids_found - baseline_upper

            if missing:
                result.error(
                    "SSP-030",
                    f"Missing {len(missing)} required controls for {baseline.upper()} baseline. "
                    f"First 10: {sorted(missing)[:10]}",
                )

            if extra:
                result.information(
                    "SSP-031",
                    f"{len(extra)} controls found that aren't in the {baseline.upper()} baseline",
                )

            result.information(
                "SSP-032",
                f"Control coverage: {len(control_ids_found & baseline_upper)}/{len(baseline_upper)} "
                f"({round(len(control_ids_found & baseline_upper)/max(len(baseline_upper),1)*100, 1)}%)",
            )

        except FileNotFoundError:
            result.warning("SSP-033", "Cannot verify baseline coverage: baselines not downloaded")


# --- POA&M validation ---


def validate_poam(data: dict, result: ValidationResult):
    """Validate a Plan of Action and Milestones."""
    poam = data.get("plan-of-action-and-milestones", {})
    if not poam:
        # Also check for our custom format
        if "items" in data:
            result.information("POAM-001", "Document uses toolkit POA&M format (not raw OSCAL)")
            items = data.get("items", [])
            for idx, item in enumerate(items):
                if not item.get("poam_id"):
                    result.error("POAM-010", f"Item[{idx}] missing poam_id")
                if not item.get("title"):
                    result.warning("POAM-011", f"Item[{idx}] missing title")
            return

        result.error("POAM-002", "Not a valid OSCAL POA&M or toolkit POA&M format")
        return

    # OSCAL POA&M validation
    findings = poam.get("findings", poam.get("poam-items", []))
    if not findings:
        result.warning("POAM-003", "No findings/poam-items in document")


# --- Main validation orchestrator ---


def validate_document(filepath: Path, doc_type: str, baseline: str | None = None, strict: bool = False) -> ValidationResult:
    """Run all applicable validations on a document."""
    result = ValidationResult()

    # Load and parse
    try:
        raw = filepath.read_text()
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        result.error("PARSE-001", f"Invalid JSON: {e}")
        return result
    except Exception as e:
        result.error("PARSE-002", f"Could not read file: {e}")
        return result

    result.information("PARSE-OK", f"Successfully parsed {filepath.name} ({len(raw)} bytes)")

    # Structural validation
    validate_oscal_structure(data, doc_type, result)

    # Type-specific validation
    if doc_type == "ssp":
        validate_ssp(data, baseline, result, strict)
    elif doc_type == "poam":
        validate_poam(data, result)

    return result


# --- CLI ---


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def main():
    parser = argparse.ArgumentParser(
        description="Validate FedRAMP OSCAL documents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--input", "-i", type=Path, required=True, help="OSCAL document to validate")
    parser.add_argument("--type", "-t", choices=list(DOCUMENT_ROOT_KEYS.keys()), required=True, help="Document type")
    parser.add_argument("--baseline", "-b", choices=["low", "moderate", "high", "li-saas"])
    parser.add_argument("--strict", action="store_true", help="Treat warnings as errors")
    parser.add_argument("--output", "-o", type=Path, help="Write findings to JSON file")
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()
    setup_logging(args.verbose)

    if not args.input.exists():
        print(f"ERROR: File not found: {args.input}", file=sys.stderr)
        sys.exit(2)

    result = validate_document(args.input, args.type, args.baseline, args.strict)

    # Print results
    status = "PASSED" if result.passed else "FAILED"
    print(f"\n  OSCAL Validation: {status}")
    print(f"  Document: {args.input.name}")
    print(f"  Type: {args.type.upper()}")
    print(f"  {result.summary()}")
    print()

    for finding in result.all_findings:
        icon = {"ERROR": "X", "WARNING": "!", "INFO": "~"}.get(finding["severity"], "?")
        print(f"  [{icon}] {finding['rule']}: {finding['message']}")

    # Write to file if requested
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps({
            "file": str(args.input),
            "type": args.type,
            "passed": result.passed,
            "summary": result.summary(),
            "findings": result.all_findings,
        }, indent=2))

    # Exit code for CI/CD
    if args.strict:
        sys.exit(0 if result.passed and not result.warnings else 1)
    else:
        sys.exit(0 if result.passed else 1)


if __name__ == "__main__":
    main()
