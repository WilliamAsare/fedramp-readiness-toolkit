"""
OSCAL parsing and manipulation utilities.

Provides helper functions for working with NIST OSCAL documents,
including catalog loading, profile resolution, and control extraction.
Works with both compliance-trestle models and raw JSON as fallback.
"""

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default paths relative to project root
PROJECT_ROOT = Path(__file__).parent.parent.parent
BASELINES_DIR = PROJECT_ROOT / "baselines"
CATALOG_PATH = BASELINES_DIR / "catalogs" / "NIST_SP-800-53_rev5_catalog.json"

BASELINE_FILES = {
    "low": BASELINES_DIR / "json" / "FedRAMP_rev5_LOW-baseline.json",
    "moderate": BASELINES_DIR / "json" / "FedRAMP_rev5_MODERATE-baseline.json",
    "high": BASELINES_DIR / "json" / "FedRAMP_rev5_HIGH-baseline.json",
    "li-saas": BASELINES_DIR / "json" / "FedRAMP_rev5_LI-SaaS-baseline.json",
}

# Expected control counts per baseline for validation
EXPECTED_CONTROL_COUNTS = {
    "low": 156,
    "moderate": 323,
    "high": 410,
    "li-saas": 156,
}

# NIST 800-53 Rev 5 Control Families
CONTROL_FAMILIES = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PE": "Physical and Environmental Protection",
    "PL": "Planning",
    "PM": "Program Management",
    "PS": "Personnel Security",
    "PT": "PII Processing and Transparency",
    "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "SR": "Supply Chain Risk Management",
}

# Families that FedRAMP operationally uses (excludes PM and PT)
FEDRAMP_ACTIVE_FAMILIES = {k: v for k, v in CONTROL_FAMILIES.items() if k not in ("PM", "PT")}


def load_json_file(filepath: Path) -> dict[str, Any]:
    """Load and parse a JSON file."""
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(
            f"File not found: {filepath}\n"
            f"Run 'make baselines' to download FedRAMP baselines and NIST catalog."
        )
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def load_catalog(catalog_path: Path | None = None) -> dict[str, Any]:
    """Load the NIST SP 800-53 Rev 5 OSCAL catalog."""
    path = catalog_path or CATALOG_PATH
    logger.info(f"Loading NIST catalog from {path}")
    return load_json_file(path)


def load_baseline(baseline_level: str, baselines_dir: Path | None = None) -> dict[str, Any]:
    """
    Load a FedRAMP OSCAL baseline profile.

    Args:
        baseline_level: One of 'low', 'moderate', 'high', 'li-saas'
        baselines_dir: Override directory for baseline files

    Returns:
        Parsed OSCAL profile JSON
    """
    level = baseline_level.lower().strip()
    if level not in BASELINE_FILES:
        raise ValueError(
            f"Invalid baseline level: '{level}'. "
            f"Must be one of: {', '.join(BASELINE_FILES.keys())}"
        )

    if baselines_dir:
        # Reconstruct path with custom baselines dir
        filename = BASELINE_FILES[level].name
        path = Path(baselines_dir) / "json" / filename
    else:
        path = BASELINE_FILES[level]

    logger.info(f"Loading FedRAMP {level.upper()} baseline from {path}")
    return load_json_file(path)


def extract_control_ids_from_profile(profile_data: dict[str, Any]) -> list[str]:
    """
    Extract control IDs selected by a FedRAMP profile.

    Navigates the OSCAL profile structure to find all controls
    included via 'include-controls' directives.

    Args:
        profile_data: Parsed OSCAL profile JSON

    Returns:
        Sorted list of control IDs (e.g., ['AC-1', 'AC-2', 'AC-2(1)', ...])
    """
    control_ids = []
    profile = profile_data.get("profile", {})
    imports = profile.get("imports", [])

    for imp in imports:
        include_controls = imp.get("include-controls", [])
        for ic in include_controls:
            matching = ic.get("with-ids", [])
            control_ids.extend(matching)

    # Deduplicate and sort
    unique_ids = sorted(set(control_ids), key=_control_sort_key)
    return unique_ids


def extract_controls_from_catalog(catalog_data: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Extract all controls from the NIST 800-53 Rev 5 OSCAL catalog.

    Walks the catalog structure to find all controls and control enhancements
    across all groups (families).

    Returns:
        List of control dicts with keys: id, title, family, class, params, parts
    """
    controls = []
    catalog = catalog_data.get("catalog", {})
    groups = catalog.get("groups", [])

    for group in groups:
        family_id = group.get("id", "").upper()
        family_title = group.get("title", "")

        for control in group.get("controls", []):
            controls.append(_parse_control(control, family_id, family_title))

            # Also extract control enhancements (sub-controls)
            for enhancement in control.get("controls", []):
                controls.append(_parse_control(enhancement, family_id, family_title))

    return controls


def _parse_control(control: dict, family_id: str, family_title: str) -> dict[str, Any]:
    """Parse a single OSCAL control into a simplified dict."""
    control_id = control.get("id", "")

    # Extract parameters
    params = []
    for param in control.get("params", []):
        param_info = {
            "id": param.get("id", ""),
            "label": param.get("label", ""),
        }
        # Get FedRAMP-specific constraints or values if present
        if "constraints" in param:
            param_info["constraints"] = [c.get("description", "") for c in param["constraints"]]
        if "guidelines" in param:
            param_info["guidelines"] = [g.get("prose", "") for g in param["guidelines"]]
        if "select" in param:
            param_info["select"] = param["select"]
        if "values" in param:
            param_info["values"] = param["values"]
        params.append(param_info)

    # Extract prose from parts
    prose_parts = []
    for part in control.get("parts", []):
        if part.get("name") == "statement":
            prose_parts.append(_extract_prose(part))
        elif part.get("name") == "guidance":
            prose_parts.append({"type": "guidance", "text": part.get("prose", "")})

    return {
        "id": control_id.upper(),
        "title": control.get("title", ""),
        "family_id": family_id,
        "family_title": family_title,
        "class": control.get("class", ""),
        "params": params,
        "parts": prose_parts,
        "props": control.get("props", []),
    }


def _extract_prose(part: dict, depth: int = 0) -> dict[str, Any]:
    """Recursively extract prose text from OSCAL parts."""
    result = {
        "type": part.get("name", ""),
        "text": part.get("prose", ""),
        "id": part.get("id", ""),
    }
    if "parts" in part:
        result["sub_parts"] = [_extract_prose(p, depth + 1) for p in part["parts"]]
    return result


def get_family_from_control_id(control_id: str) -> str:
    """Extract family abbreviation from a control ID (e.g., 'AC-2(1)' -> 'AC')."""
    return control_id.split("-")[0].upper()


def _control_sort_key(control_id: str) -> tuple:
    """
    Generate a sort key for control IDs to get natural ordering.
    e.g., AC-1, AC-2, AC-2(1), AC-2(2), AC-3, ... not AC-1, AC-10, AC-11, AC-2
    """
    import re

    # Split into family, number, and optional enhancement
    match = re.match(r"([A-Z]{2})-(\d+)(?:\((\d+)\))?", control_id.upper())
    if match:
        family = match.group(1)
        number = int(match.group(2))
        enhancement = int(match.group(3)) if match.group(3) else 0
        return (family, number, enhancement)
    return (control_id, 0, 0)


def filter_catalog_by_baseline(
    catalog_controls: list[dict[str, Any]],
    baseline_control_ids: list[str],
) -> list[dict[str, Any]]:
    """
    Filter catalog controls to only those included in a FedRAMP baseline.

    Args:
        catalog_controls: All controls from the NIST catalog
        baseline_control_ids: Control IDs from the FedRAMP profile

    Returns:
        Controls that are in both the catalog and the baseline
    """
    baseline_set = {cid.upper() for cid in baseline_control_ids}
    return [c for c in catalog_controls if c["id"].upper() in baseline_set]


def validate_control_count(baseline_level: str, actual_count: int) -> bool:
    """
    Validate that the resolved control count matches expected FedRAMP baselines.

    This is a critical sanity check. If counts don't match, something is wrong
    with profile resolution or baseline data.
    """
    expected = EXPECTED_CONTROL_COUNTS.get(baseline_level.lower())
    if expected is None:
        logger.warning(f"No expected count for baseline '{baseline_level}'")
        return True

    if actual_count != expected:
        logger.error(
            f"Control count mismatch for {baseline_level.upper()} baseline: "
            f"expected {expected}, got {actual_count}. "
            f"Check baseline file integrity."
        )
        return False

    logger.info(f"Control count validated: {baseline_level.upper()} = {actual_count} ✓")
    return True
