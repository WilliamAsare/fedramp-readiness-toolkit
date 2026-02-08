#!/usr/bin/env python3
"""
FedRAMP Control Inheritance Mapper

Maps which FedRAMP controls are inherited from FedRAMP-authorized IaaS/PaaS providers
(AWS GovCloud, Azure Government, GCP Assured Workloads). This is the second most
important script in the toolkit — it answers "what do we actually have to build
versus what we get from our cloud provider?"

Inheriting controls from authorized infrastructure is one of the most effective
ways to reduce FedRAMP scope and cost. AWS GovCloud, Azure Government, and GCP
Assured Workloads each carry their own FedRAMP High P-ATO, meaning CSPs building
on top of them can inherit a significant chunk of controls.

For each control in a FedRAMP baseline, this script determines:
    - Fully Inherited: The cloud provider handles this entirely
    - Shared: Both the provider and CSP have responsibilities
    - Customer Responsible: The CSP must implement this completely

Inputs:
    - FedRAMP baseline (Low/Moderate/High)
    - Cloud provider (aws, azure, gcp)
    - Optional: custom CRM overrides in YAML

Outputs:
    - Responsibility matrix (YAML, JSON, CSV, Markdown, HTML)
    - Integration-ready YAML for the gap_analysis.py --inheritance-map flag
    - Summary statistics showing how many controls fall into each category

Usage:
    python scripts/inheritance_mapper.py --baseline moderate --provider aws
    python scripts/inheritance_mapper.py --baseline moderate --provider aws --output-format yaml --output crm.yaml
    python scripts/inheritance_mapper.py --baseline high --provider azure --output-format html --output crm.html
    python scripts/inheritance_mapper.py --baseline moderate --provider gcp --custom-overrides overrides.yaml
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

# --- Default Inheritance Mappings ---
# These represent typical inheritance patterns for SaaS applications built on top
# of FedRAMP High authorized cloud providers. Real-world mappings vary based on
# deployment architecture, so these should be treated as starting points.
#
# Key:
#   inherited  = Provider handles entirely; CSP documents inheritance in SSP
#   shared     = Both provider and CSP have responsibilities
#   customer   = CSP must fully implement, document, and maintain
#
# Sources: AWS GovCloud CRM, Azure Government compliance docs, GCP Assured Workloads
# docs, and common 3PAO interpretation patterns.

# Family-level defaults when we don't have control-specific data.
# These are conservative (lean toward "customer" or "shared" when in doubt).

_FAMILY_DEFAULTS = {
    "aws": {
        "AC": "shared",       # IAM is shared; org policy is customer
        "AT": "customer",     # Training is always the CSP's job
        "AU": "shared",       # CloudTrail/CloudWatch infra is inherited; config is customer
        "CA": "customer",     # Assessment and authorization is the CSP's responsibility
        "CM": "shared",       # AWS Config/SSM exist; what you do with them is on you
        "CP": "shared",       # AWS infra redundancy inherited; app-level DR is customer
        "IA": "shared",       # IAM infra inherited; identity policies are customer
        "IR": "shared",       # AWS incident process inherited; CSP incident response is customer
        "MA": "inherited",    # Physical maintenance is provider on IaaS/PaaS
        "MP": "inherited",    # Media protection at data center level
        "PE": "inherited",    # Physical/environmental is fully provider
        "PL": "customer",     # Planning is always customer
        "PS": "customer",     # Personnel security is always customer
        "RA": "shared",       # AWS Inspector/GuardDuty exist; running them is on you
        "SA": "shared",       # AWS provides secure services; CSP manages their own dev lifecycle
        "SC": "shared",       # TLS/KMS infra inherited; config and boundary are customer
        "SI": "shared",       # AWS provides patching infra; CSP applies patches
        "SR": "shared",       # AWS has supply chain program; CSP has their own dependencies
    },
    "azure": {
        "AC": "shared",
        "AT": "customer",
        "AU": "shared",
        "CA": "customer",
        "CM": "shared",
        "CP": "shared",
        "IA": "shared",
        "IR": "shared",
        "MA": "inherited",
        "MP": "inherited",
        "PE": "inherited",
        "PL": "customer",
        "PS": "customer",
        "RA": "shared",
        "SA": "shared",
        "SC": "shared",
        "SI": "shared",
        "SR": "shared",
    },
    "gcp": {
        "AC": "shared",
        "AT": "customer",
        "AU": "shared",
        "CA": "customer",
        "CM": "shared",
        "CP": "shared",
        "IA": "shared",
        "IR": "shared",
        "MA": "inherited",
        "MP": "inherited",
        "PE": "inherited",
        "PL": "customer",
        "PS": "customer",
        "RA": "shared",
        "SA": "shared",
        "SC": "shared",
        "SI": "shared",
        "SR": "shared",
    },
}

# Control-level overrides where the responsibility differs from the family default.
# These are the controls where the answer is well-established across 3PAOs.
# Format: {provider: {control_id: responsibility}}

_CONTROL_OVERRIDES = {
    "aws": {
        # Physical/Environmental — fully inherited from AWS data centers
        "PE-1": "inherited", "PE-2": "inherited", "PE-3": "inherited",
        "PE-4": "inherited", "PE-5": "inherited", "PE-6": "inherited",
        "PE-8": "inherited", "PE-9": "inherited", "PE-10": "inherited",
        "PE-11": "inherited", "PE-12": "inherited", "PE-13": "inherited",
        "PE-14": "inherited", "PE-15": "inherited", "PE-16": "inherited",
        "PE-17": "inherited",

        # Media Protection — physical media is inherited
        "MP-1": "shared",  # Policy is customer; implementation is shared
        "MP-2": "inherited", "MP-3": "inherited", "MP-4": "inherited",
        "MP-5": "inherited", "MP-6": "inherited", "MP-7": "shared",

        # Maintenance — physical maintenance fully inherited
        "MA-1": "shared",  # Policy is customer
        "MA-2": "inherited", "MA-3": "inherited", "MA-4": "inherited",
        "MA-5": "inherited", "MA-6": "inherited",

        # Access Control — specific controls
        "AC-1": "customer",   # Policy is always customer
        "AC-2": "shared",     # AWS IAM exists; account management process is customer
        "AC-3": "shared",     # IAM enforcement inherited; resource policies are customer
        "AC-4": "shared",     # VPC/SG inherited; flow rules are customer
        "AC-5": "customer",   # Separation of duties is organizational
        "AC-6": "shared",     # IAM least privilege enforcement tools exist; config is customer
        "AC-7": "shared",     # AWS supports lockout; config is customer
        "AC-8": "customer",   # System use notification is customer
        "AC-14": "shared",    # Permitted actions without identification
        "AC-17": "shared",    # Remote access
        "AC-18": "inherited", # Wireless — N/A for cloud, or inherited
        "AC-19": "shared",    # Mobile device access
        "AC-20": "customer",  # Use of external systems
        "AC-22": "customer",  # Publicly accessible content

        # Audit — CloudTrail/CloudWatch infra inherited
        "AU-1": "customer",   # Audit policy is customer
        "AU-2": "shared",     # Audit events: AWS logs infra events; CSP defines app events
        "AU-3": "shared",     # Content of audit records
        "AU-4": "shared",     # Audit log storage capacity
        "AU-5": "shared",     # Response to audit processing failures
        "AU-6": "customer",   # Audit review/analysis (CSP must actually review logs)
        "AU-7": "shared",     # Audit record reduction
        "AU-8": "inherited",  # Time stamps (NTP from AWS)
        "AU-9": "shared",     # Protection of audit information
        "AU-11": "shared",    # Audit record retention
        "AU-12": "shared",    # Audit record generation

        # System/Comms Protection
        "SC-1": "customer",   # Policy
        "SC-5": "shared",     # DoS protection (AWS Shield inherited; app-level is customer)
        "SC-7": "shared",     # Boundary protection (VPC inherited; config is customer)
        "SC-8": "shared",     # Transmission confidentiality (TLS infra inherited; config customer)
        "SC-12": "shared",    # Crypto key management (KMS inherited; key policies customer)
        "SC-13": "shared",    # Crypto protection (FIPS modules inherited; usage is customer)
        "SC-17": "shared",    # PKI certificates
        "SC-20": "shared",    # DNSSEC
        "SC-21": "shared",    # DNSSEC validation
        "SC-22": "shared",    # DNS architecture
        "SC-28": "shared",    # Protection of info at rest (encryption infra inherited; config customer)

        # Incident Response — AWS has their own IR; CSP needs their own
        "IR-1": "customer",   # Policy
        "IR-2": "customer",   # IR training
        "IR-3": "customer",   # IR testing
        "IR-4": "shared",     # IR handling (AWS handles infra incidents; CSP handles app incidents)
        "IR-5": "customer",   # IR monitoring
        "IR-6": "shared",     # IR reporting (AWS reports to US-CERT for infra; CSP for app)
        "IR-7": "shared",     # IR assistance
        "IR-8": "customer",   # IR plan

        # Config Management
        "CM-1": "customer",   # Policy
        "CM-2": "shared",     # Baseline configs (AWS provides AMIs; CSP configures)
        "CM-3": "customer",   # Config change control (for CSP's own system)
        "CM-4": "customer",   # Impact analysis
        "CM-5": "shared",     # Access restrictions for change
        "CM-6": "shared",     # Config settings (CIS benchmarks; CSP applies)
        "CM-7": "shared",     # Least functionality
        "CM-8": "shared",     # System component inventory
        "CM-10": "customer",  # Software usage restrictions
        "CM-11": "customer",  # User-installed software

        # Identification/Authentication
        "IA-1": "customer",   # Policy
        "IA-2": "shared",     # User identification (IAM inherited; federation is customer)
        "IA-3": "shared",     # Device identification
        "IA-4": "shared",     # Identifier management
        "IA-5": "shared",     # Authenticator management
        "IA-6": "inherited",  # Authentication feedback (handled by AWS console/API)
        "IA-7": "inherited",  # Crypto module auth (FIPS validated modules in AWS)
        "IA-8": "shared",     # Non-organizational user ID (PIV/CAC federation)

        # Contingency Planning
        "CP-1": "customer",   # Policy
        "CP-2": "customer",   # CP plan (CSP owns their DR plan)
        "CP-3": "customer",   # CP training
        "CP-4": "customer",   # CP testing
        "CP-6": "shared",     # Alternate storage (S3 cross-region inherited; config customer)
        "CP-7": "shared",     # Alternate processing (multi-AZ/region inherited; arch customer)
        "CP-8": "shared",     # Telecommunications (AWS backbone inherited)
        "CP-9": "shared",     # System backup (AWS backup services exist; CSP configures)
        "CP-10": "shared",    # System recovery

        # Risk Assessment
        "RA-1": "customer",
        "RA-2": "customer",   # Security categorization
        "RA-3": "customer",   # Risk assessment
        "RA-5": "shared",     # Vulnerability monitoring (AWS Inspector exists; CSP runs it)

        # System and Info Integrity
        "SI-1": "customer",
        "SI-2": "shared",     # Flaw remediation (AWS patches infra; CSP patches app)
        "SI-3": "shared",     # Malicious code protection
        "SI-4": "shared",     # System monitoring (GuardDuty/CloudWatch exist; CSP configures)
        "SI-5": "shared",     # Security alerts
        "SI-12": "customer",  # Information management

        # Personnel Security — always customer
        "PS-1": "customer", "PS-2": "customer", "PS-3": "customer",
        "PS-4": "customer", "PS-5": "customer", "PS-6": "customer",
        "PS-7": "customer", "PS-8": "customer",

        # Planning — always customer
        "PL-1": "customer", "PL-2": "customer", "PL-4": "customer",

        # Awareness/Training — always customer
        "AT-1": "customer", "AT-2": "customer", "AT-3": "customer", "AT-4": "customer",

        # System Acquisition
        "SA-1": "customer", "SA-2": "customer", "SA-3": "customer",
        "SA-4": "shared",     # Acquisition process (AWS provides docs; CSP manages their vendors)
        "SA-5": "shared",     # System documentation
        "SA-9": "shared",     # External system services
        "SA-10": "shared",    # Developer config management
        "SA-11": "shared",    # Developer testing

        # Supply Chain
        "SR-1": "shared",  # Policy and procedures
        "SR-2": "shared",  # Supply chain risk plan
        "SR-3": "shared",  # Supply chain controls
        "SR-5": "customer", # Acquisition strategies
        "SR-11": "shared", # Component authenticity

        # CA — mostly customer
        "CA-1": "customer", "CA-2": "customer", "CA-3": "shared",
        "CA-5": "customer", "CA-6": "customer", "CA-7": "shared",
        "CA-8": "customer", "CA-9": "shared",
    },
    "azure": {
        # Azure has very similar patterns to AWS for a SaaS deployment.
        # Major differences noted inline.
        "PE-1": "inherited", "PE-2": "inherited", "PE-3": "inherited",
        "PE-4": "inherited", "PE-5": "inherited", "PE-6": "inherited",
        "PE-8": "inherited", "PE-9": "inherited", "PE-10": "inherited",
        "PE-11": "inherited", "PE-12": "inherited", "PE-13": "inherited",
        "PE-14": "inherited", "PE-15": "inherited", "PE-16": "inherited",

        "MP-2": "inherited", "MP-3": "inherited", "MP-4": "inherited",
        "MP-5": "inherited", "MP-6": "inherited",

        "MA-2": "inherited", "MA-3": "inherited", "MA-4": "inherited",
        "MA-5": "inherited", "MA-6": "inherited",

        "AC-1": "customer", "AC-2": "shared", "AC-3": "shared",
        "AC-5": "customer", "AC-8": "customer", "AC-22": "customer",

        "AU-1": "customer", "AU-6": "customer", "AU-8": "inherited",

        "SC-1": "customer", "SC-5": "shared", "SC-7": "shared",
        "SC-8": "shared", "SC-13": "shared", "SC-28": "shared",

        "IR-1": "customer", "IR-2": "customer", "IR-3": "customer",
        "IR-8": "customer",

        "CM-1": "customer", "CM-3": "customer", "CM-4": "customer",

        "IA-1": "customer", "IA-2": "shared", "IA-6": "inherited",
        "IA-7": "inherited", "IA-8": "shared",

        "CP-1": "customer", "CP-2": "customer", "CP-3": "customer",
        "CP-4": "customer",

        "PS-1": "customer", "PS-2": "customer", "PS-3": "customer",
        "PS-4": "customer", "PS-5": "customer", "PS-6": "customer",
        "PS-7": "customer", "PS-8": "customer",

        "PL-1": "customer", "PL-2": "customer", "PL-4": "customer",
        "AT-1": "customer", "AT-2": "customer", "AT-3": "customer",
        "AT-4": "customer",

        "RA-1": "customer", "RA-2": "customer", "RA-3": "customer",
        "RA-5": "shared",

        "SI-1": "customer", "SI-2": "shared", "SI-4": "shared",

        "CA-1": "customer", "CA-2": "customer", "CA-5": "customer",
        "CA-6": "customer",

        "SA-1": "customer", "SA-2": "customer", "SA-3": "customer",
        "SR-1": "shared", "SR-2": "shared", "SR-5": "customer",
    },
    "gcp": {
        # GCP Assured Workloads provides similar coverage.
        "PE-1": "inherited", "PE-2": "inherited", "PE-3": "inherited",
        "PE-4": "inherited", "PE-5": "inherited", "PE-6": "inherited",
        "PE-8": "inherited", "PE-9": "inherited", "PE-10": "inherited",
        "PE-11": "inherited", "PE-12": "inherited", "PE-13": "inherited",
        "PE-14": "inherited", "PE-15": "inherited", "PE-16": "inherited",

        "MP-2": "inherited", "MP-3": "inherited", "MP-4": "inherited",
        "MP-5": "inherited", "MP-6": "inherited",

        "MA-2": "inherited", "MA-3": "inherited", "MA-4": "inherited",
        "MA-5": "inherited", "MA-6": "inherited",

        "AC-1": "customer", "AC-2": "shared", "AC-3": "shared",
        "AC-5": "customer", "AC-8": "customer", "AC-22": "customer",

        "AU-1": "customer", "AU-6": "customer", "AU-8": "inherited",

        "SC-1": "customer", "SC-5": "shared", "SC-7": "shared",
        "SC-8": "shared", "SC-13": "shared", "SC-28": "shared",

        "IR-1": "customer", "IR-2": "customer", "IR-3": "customer",
        "IR-8": "customer",

        "CM-1": "customer", "CM-3": "customer", "CM-4": "customer",

        "IA-1": "customer", "IA-2": "shared", "IA-6": "inherited",
        "IA-7": "inherited", "IA-8": "shared",

        "CP-1": "customer", "CP-2": "customer", "CP-3": "customer",
        "CP-4": "customer",

        "PS-1": "customer", "PS-2": "customer", "PS-3": "customer",
        "PS-4": "customer", "PS-5": "customer", "PS-6": "customer",
        "PS-7": "customer", "PS-8": "customer",

        "PL-1": "customer", "PL-2": "customer", "PL-4": "customer",
        "AT-1": "customer", "AT-2": "customer", "AT-3": "customer",
        "AT-4": "customer",

        "RA-1": "customer", "RA-2": "customer", "RA-3": "customer",
        "RA-5": "shared",

        "SI-1": "customer", "SI-2": "shared", "SI-4": "shared",

        "CA-1": "customer", "CA-2": "customer", "CA-5": "customer",
        "CA-6": "customer",

        "SA-1": "customer", "SA-2": "customer", "SA-3": "customer",
        "SR-1": "shared", "SR-2": "shared", "SR-5": "customer",
    },
}

# Descriptions explaining what "shared" means for each family
_SHARED_NOTES = {
    "AC": "Cloud provider manages IAM infrastructure and enforcement mechanisms. CSP defines access policies, manages user accounts, and configures authorization rules for their application.",
    "AU": "Cloud provider captures infrastructure-level audit events and provides logging services. CSP configures audit scope for application, manages log analysis, and performs reviews.",
    "CA": "Cloud provider maintains their own authorization. CSP performs their own security assessments and manages system interconnections.",
    "CM": "Cloud provider manages infrastructure configuration. CSP maintains application configuration baselines, change control, and component inventory.",
    "CP": "Cloud provider manages infrastructure redundancy and availability. CSP designs and tests application-level disaster recovery and continuity.",
    "IA": "Cloud provider manages IAM service and supports federated authentication. CSP configures identity policies, MFA enforcement, and agency PIV/CAC integration.",
    "IR": "Cloud provider handles infrastructure-level security incidents and US-CERT reporting. CSP maintains application-level incident response plan, training, and testing.",
    "RA": "Cloud provider offers vulnerability scanning tools. CSP runs scans, analyzes results, remediates findings within SLA, and manages risk assessment.",
    "SA": "Cloud provider documents their services and security capabilities. CSP manages their own development lifecycle, vendor assessment, and system documentation.",
    "SC": "Cloud provider supplies FIPS-validated cryptographic modules and network infrastructure. CSP configures TLS, encryption policies, boundary rules, and DNSSEC.",
    "SI": "Cloud provider patches underlying infrastructure and provides monitoring tools. CSP patches their application stack, configures monitoring, and manages malware protection.",
    "SR": "Cloud provider manages supply chain for their infrastructure. CSP manages their own software dependencies, vendor relationships, and SBOM.",
}


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


# --- Core mapping logic ---


def get_inheritance_for_control(
    control_id: str,
    provider: str,
    custom_overrides: dict[str, str] | None = None,
) -> str:
    """
    Determine inheritance status for a single control.

    Resolution order:
    1. Custom overrides (user-provided)
    2. Control-specific override (from _CONTROL_OVERRIDES)
    3. Family-level default (from _FAMILY_DEFAULTS)
    4. "customer" as ultimate fallback
    """
    cid = control_id.upper()
    provider = provider.lower()

    # 1. Custom overrides take priority
    if custom_overrides and cid in custom_overrides:
        return custom_overrides[cid]

    # 2. Control-specific override
    provider_overrides = _CONTROL_OVERRIDES.get(provider, {})
    if cid in provider_overrides:
        return provider_overrides[cid]

    # 3. For enhancements (e.g., AC-2(1)), check if the base control has an override
    if "(" in cid:
        base_control = cid.split("(")[0]
        if base_control in provider_overrides:
            return provider_overrides[base_control]

    # 4. Family-level default
    family = get_family_from_control_id(cid)
    family_defaults = _FAMILY_DEFAULTS.get(provider, {})
    if family in family_defaults:
        return family_defaults[family]

    # 5. Conservative fallback
    return "customer"


def map_baseline_inheritance(
    baseline_controls: list[dict],
    provider: str,
    custom_overrides: dict[str, str] | None = None,
) -> list[dict]:
    """
    Map inheritance for all controls in a FedRAMP baseline.

    Returns a list of dicts with control details and inheritance classification.
    """
    results = []

    for control in baseline_controls:
        cid = control["id"]
        family = control["family_id"]
        responsibility = get_inheritance_for_control(cid, provider, custom_overrides)

        # Add contextual notes for shared controls
        notes = ""
        if responsibility == "shared":
            notes = _SHARED_NOTES.get(family, "Both provider and CSP share responsibility.")
        elif responsibility == "inherited":
            notes = f"Fully inherited from {provider.upper()} FedRAMP High authorized infrastructure."
        elif responsibility == "customer":
            notes = "CSP must fully implement, document, and maintain this control."

        results.append({
            "control_id": cid,
            "title": control["title"],
            "family_id": family,
            "family_name": CONTROL_FAMILIES.get(family, "Unknown"),
            "responsibility": responsibility,
            "provider": provider,
            "notes": notes,
        })

    return results


def compute_inheritance_summary(mapped_controls: list[dict]) -> dict[str, Any]:
    """Compute summary statistics from mapped controls."""
    total = len(mapped_controls)
    inherited = sum(1 for c in mapped_controls if c["responsibility"] == "inherited")
    shared = sum(1 for c in mapped_controls if c["responsibility"] == "shared")
    customer = sum(1 for c in mapped_controls if c["responsibility"] == "customer")

    # Per-family breakdown
    family_breakdown = {}
    for c in mapped_controls:
        fam = c["family_id"]
        if fam not in family_breakdown:
            family_breakdown[fam] = {
                "family_id": fam,
                "family_name": c["family_name"],
                "total": 0, "inherited": 0, "shared": 0, "customer": 0,
            }
        family_breakdown[fam]["total"] += 1
        family_breakdown[fam][c["responsibility"]] += 1

    families = sorted(family_breakdown.values(), key=lambda x: x["inherited"], reverse=True)

    return {
        "total_controls": total,
        "inherited": inherited,
        "shared": shared,
        "customer": customer,
        "inherited_pct": round((inherited / total) * 100, 1) if total else 0,
        "shared_pct": round((shared / total) * 100, 1) if total else 0,
        "customer_pct": round((customer / total) * 100, 1) if total else 0,
        "effective_scope_reduction": round(((inherited + shared * 0.5) / total) * 100, 1) if total else 0,
        "families": families,
    }


# --- Custom override loading ---


def load_custom_overrides(filepath: Path) -> dict[str, str]:
    """
    Load custom control inheritance overrides from YAML.

    Expected format:
        overrides:
          AC-2: customer        # We manage all account lifecycle ourselves
          SC-7: shared          # Using provider VPC but custom firewall rules
          PE-3: inherited       # All physical access handled by provider
    """
    import yaml

    data = yaml.safe_load(filepath.read_text())
    overrides = data.get("overrides", data.get("controls", {}))
    return {k.upper(): v.lower() for k, v in overrides.items()}


# --- Output formatters ---


def output_summary_text(summary: dict, provider: str, baseline: str) -> str:
    """Generate a text summary of inheritance mapping."""
    lines = [
        f"\n{'=' * 70}",
        f"  FedRAMP {baseline.upper()} Baseline — {provider.upper()} Inheritance Summary",
        f"{'=' * 70}",
        "",
        f"  Total controls in baseline:  {summary['total_controls']}",
        f"  Fully inherited:             {summary['inherited']} ({summary['inherited_pct']}%)",
        f"  Shared responsibility:       {summary['shared']} ({summary['shared_pct']}%)",
        f"  Customer responsible:        {summary['customer']} ({summary['customer_pct']}%)",
        f"  Effective scope reduction:   {summary['effective_scope_reduction']}%",
        "",
        f"  (Scope reduction = inherited + 50% of shared, representing",
        f"   the approximate effort reduction from using {provider.upper()})",
        "",
    ]

    # Family table
    lines.append(f"  {'Family':<8} {'Name':<42} {'Inher':>6} {'Share':>6} {'Cust':>6} {'Total':>6}")
    lines.append(f"  {'-'*74}")

    for fam in summary["families"]:
        lines.append(
            f"  {fam['family_id']:<8} {fam['family_name'][:40]:<42} "
            f"{fam['inherited']:>6} {fam['shared']:>6} {fam['customer']:>6} {fam['total']:>6}"
        )

    lines.append(f"  {'-'*74}")
    lines.append(
        f"  {'TOTAL':<8} {'':<42} "
        f"{summary['inherited']:>6} {summary['shared']:>6} {summary['customer']:>6} {summary['total_controls']:>6}"
    )
    lines.append("")

    return "\n".join(lines)


def output_gap_analysis_yaml(mapped_controls: list[dict], output_path: Path):
    """
    Export inheritance map in the YAML format expected by gap_analysis.py --inheritance-map.

    This is the key integration point: the inheritance mapper feeds directly into
    the gap analysis tool.
    """
    import yaml

    controls = {}
    for c in mapped_controls:
        controls[c["control_id"]] = c["responsibility"]

    data = {
        "# Generated by inheritance_mapper.py": None,
        "# Feed this into gap_analysis.py with --inheritance-map flag": None,
        "controls": controls,
    }

    # Write clean YAML without the comment keys
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        f.write(f"# Generated by inheritance_mapper.py on {datetime.now(timezone.utc).strftime('%Y-%m-%d')}\n")
        f.write(f"# Use with: python scripts/gap_analysis.py --inheritance-map {output_path}\n\n")
        yaml.dump({"controls": controls}, f, default_flow_style=False, sort_keys=True)

    logger.info(f"Gap analysis YAML written to {output_path}")


def output_full_yaml(mapped_controls: list[dict], summary: dict, provider: str, baseline: str, output_path: Path):
    """Export the complete inheritance mapping as YAML."""
    import yaml

    data = {
        "metadata": {
            "provider": provider,
            "baseline": baseline,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_controls": summary["total_controls"],
            "inherited": summary["inherited"],
            "shared": summary["shared"],
            "customer": summary["customer"],
        },
        "controls": {
            c["control_id"]: {
                "responsibility": c["responsibility"],
                "title": c["title"],
                "family": c["family_id"],
                "notes": c["notes"],
            }
            for c in mapped_controls
        },
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, width=120)

    logger.info(f"Full YAML mapping written to {output_path}")


def output_csv(mapped_controls: list[dict], output_path: Path):
    """Export as CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["control_id", "title", "family_id", "family_name", "responsibility", "provider", "notes"],
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(mapped_controls)

    logger.info(f"CSV mapping written to {output_path}")


def output_json(mapped_controls: list[dict], summary: dict, provider: str, baseline: str, output_path: Path):
    """Export as JSON."""
    data = {
        "metadata": {
            "provider": provider,
            "baseline": baseline,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "summary": summary,
        "controls": mapped_controls,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(data, indent=2, default=str))
    logger.info(f"JSON mapping written to {output_path}")


def output_markdown(mapped_controls: list[dict], summary: dict, provider: str, baseline: str) -> str:
    """Generate Markdown table."""
    lines = [
        f"# FedRAMP {baseline.upper()} — {provider.upper()} Inheritance Matrix",
        "",
        f"**Total controls:** {summary['total_controls']} | "
        f"**Inherited:** {summary['inherited']} ({summary['inherited_pct']}%) | "
        f"**Shared:** {summary['shared']} ({summary['shared_pct']}%) | "
        f"**Customer:** {summary['customer']} ({summary['customer_pct']}%)",
        "",
        "| Control | Title | Family | Responsibility |",
        "|---------|-------|--------|---------------|",
    ]

    for c in mapped_controls:
        resp = c["responsibility"]
        lines.append(f"| {c['control_id']} | {c['title'][:50]} | {c['family_id']} | {resp} |")

    return "\n".join(lines)


def output_html(mapped_controls: list[dict], summary: dict, provider: str, baseline: str, output_path: Path):
    """Generate HTML report."""
    from scripts.utils.report_generators import generate_html_report

    summary_html = f"""
    <div style="display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0;">
        <div style="background:#e8f5e9;padding:1.5rem;border-radius:8px;min-width:180px;text-align:center;">
            <div style="font-size:2.5rem;font-weight:bold;color:#2e7d32;">{summary['inherited']}</div>
            <div>Inherited ({summary['inherited_pct']}%)</div>
        </div>
        <div style="background:#e3f2fd;padding:1.5rem;border-radius:8px;min-width:180px;text-align:center;">
            <div style="font-size:2.5rem;font-weight:bold;color:#1565c0;">{summary['shared']}</div>
            <div>Shared ({summary['shared_pct']}%)</div>
        </div>
        <div style="background:#fff3e0;padding:1.5rem;border-radius:8px;min-width:180px;text-align:center;">
            <div style="font-size:2.5rem;font-weight:bold;color:#e65100;">{summary['customer']}</div>
            <div>Customer ({summary['customer_pct']}%)</div>
        </div>
        <div style="background:#f3e5f5;padding:1.5rem;border-radius:8px;min-width:180px;text-align:center;">
            <div style="font-size:2.5rem;font-weight:bold;color:#6a1b9a;">{summary['effective_scope_reduction']}%</div>
            <div>Scope Reduction</div>
        </div>
    </div>"""

    family_rows = ""
    for fam in summary["families"]:
        family_rows += f"""<tr>
            <td>{fam['family_id']}</td><td>{fam['family_name']}</td>
            <td>{fam['inherited']}</td><td>{fam['shared']}</td>
            <td>{fam['customer']}</td><td>{fam['total']}</td></tr>"""

    family_html = f"""<table>
        <tr><th>Family</th><th>Name</th><th>Inherited</th><th>Shared</th><th>Customer</th><th>Total</th></tr>
        {family_rows}</table>"""

    control_rows = ""
    colors = {"inherited": "#e8f5e9", "shared": "#e3f2fd", "customer": "#fff3e0"}
    for c in mapped_controls:
        bg = colors.get(c["responsibility"], "#fff")
        control_rows += f"""<tr style="background:{bg};">
            <td><strong>{c['control_id']}</strong></td><td>{c['title'][:60]}</td>
            <td>{c['family_id']}</td><td>{c['responsibility']}</td>
            <td style="font-size:0.85rem;">{c['notes'][:100]}</td></tr>"""

    controls_html = f"""<table>
        <tr><th>Control</th><th>Title</th><th>Family</th><th>Responsibility</th><th>Notes</th></tr>
        {control_rows}</table>"""

    sections = [
        {"heading": "Overview", "body": summary_html},
        {"heading": "By Control Family", "body": family_html},
        {"heading": "All Controls", "body": controls_html},
    ]

    generate_html_report(
        title=f"FedRAMP {baseline.upper()} — {provider.upper()} Inheritance Matrix",
        content_sections=sections,
        output_path=output_path,
        metadata={
            "Cloud Provider": provider.upper(),
            "Baseline": baseline.upper(),
            "Total Controls": str(summary["total_controls"]),
            "Scope Reduction": f"{summary['effective_scope_reduction']}%",
        },
    )


# --- CLI ---


def main():
    parser = argparse.ArgumentParser(
        description="FedRAMP Control Inheritance Mapper — see what your cloud provider covers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --baseline moderate --provider aws
  %(prog)s --baseline moderate --provider aws --output-format yaml --output crm.yaml
  %(prog)s --baseline moderate --provider aws --gap-analysis-output inheritance.yaml
  %(prog)s --baseline high --provider azure --output-format html --output crm.html
  %(prog)s --baseline moderate --provider gcp --custom-overrides overrides.yaml
        """,
    )

    parser.add_argument("--baseline", "-b", choices=["low", "moderate", "high", "li-saas"], required=True)
    parser.add_argument("--provider", "-p", choices=["aws", "azure", "gcp"], required=True)
    parser.add_argument("--custom-overrides", type=Path, help="YAML file with custom inheritance overrides")
    parser.add_argument(
        "--gap-analysis-output", type=Path,
        help="Output YAML for gap_analysis.py --inheritance-map flag",
    )
    parser.add_argument(
        "--output-format", "-F",
        choices=["summary", "yaml", "json", "csv", "markdown", "html"],
        default="summary",
    )
    parser.add_argument("--output", "-o", type=Path, help="Output file path")
    parser.add_argument("--catalog-path", type=Path)
    parser.add_argument("--baselines-dir", type=Path)
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()
    setup_logging(args.verbose)

    try:
        # Load baseline controls
        logger.info(f"Loading {args.baseline.upper()} baseline...")
        catalog_data = load_catalog(args.catalog_path)
        all_controls = extract_controls_from_catalog(catalog_data)
        profile_data = load_baseline(args.baseline, args.baselines_dir)
        baseline_ids = extract_control_ids_from_profile(profile_data)
        baseline_controls = filter_catalog_by_baseline(all_controls, baseline_ids)
        validate_control_count(args.baseline, len(baseline_controls))

        # Load custom overrides if provided
        custom = None
        if args.custom_overrides:
            if not args.custom_overrides.exists():
                logger.error(f"Custom overrides file not found: {args.custom_overrides}")
                sys.exit(1)
            custom = load_custom_overrides(args.custom_overrides)
            logger.info(f"Loaded {len(custom)} custom overrides")

        # Map inheritance
        logger.info(f"Mapping inheritance for {args.provider.upper()}...")
        mapped = map_baseline_inheritance(baseline_controls, args.provider, custom)
        summary = compute_inheritance_summary(mapped)

        # Always generate the gap analysis YAML if requested
        if args.gap_analysis_output:
            output_gap_analysis_yaml(mapped, args.gap_analysis_output)
            print(f"Gap analysis input written to {args.gap_analysis_output}")

        # Output in requested format
        if args.output_format == "summary" or not args.output:
            text = output_summary_text(summary, args.provider, args.baseline)
            print(text)

        if args.output and args.output_format != "summary":
            if args.output_format == "yaml":
                output_full_yaml(mapped, summary, args.provider, args.baseline, args.output)
            elif args.output_format == "json":
                output_json(mapped, summary, args.provider, args.baseline, args.output)
            elif args.output_format == "csv":
                output_csv(mapped, args.output)
            elif args.output_format == "markdown":
                md = output_markdown(mapped, summary, args.provider, args.baseline)
                args.output.write_text(md)
            elif args.output_format == "html":
                output_html(mapped, summary, args.provider, args.baseline, args.output)

            print(f"Report written to {args.output}")

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
