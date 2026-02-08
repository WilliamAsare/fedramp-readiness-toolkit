#!/usr/bin/env python3
"""
Multi-Cloud Evidence Collector

Automates collection of configuration evidence from AWS, Azure, and GCP
cloud provider APIs, mapped to FedRAMP control families. Timestamps all
evidence, computes integrity hashes, and organizes into an assessment-ready
directory structure.

This script collects evidence from the cloud providers' compliance and
security APIs. For providers that aren't configured, it generates a
collection manifest showing what needs to be gathered manually.

Usage:
    python scripts/evidence_collector.py --provider aws --families AC,SC,AU --output-dir evidence/
    python scripts/evidence_collector.py --provider aws --all-families --output-dir evidence/
    python scripts/evidence_collector.py --manifest-only --output-dir evidence/
"""

import argparse
import hashlib
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.utils.oscal_helpers import CONTROL_FAMILIES, FEDRAMP_ACTIVE_FAMILIES

logger = logging.getLogger(__name__)

# Evidence requirement definitions from config
_EVIDENCE_CONFIG_PATH = PROJECT_ROOT / "config" / "evidence-requirements.yaml"


def load_evidence_config() -> dict:
    """Load evidence requirements configuration."""
    if _EVIDENCE_CONFIG_PATH.exists():
        return yaml.safe_load(_EVIDENCE_CONFIG_PATH.read_text())
    return {"evidence_requirements": {}}


# --- Evidence collection framework ---


def compute_file_hash(filepath: Path) -> str:
    """Compute SHA-256 hash of a file for integrity verification."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def save_evidence(data: Any, filename: str, output_dir: Path, control_family: str) -> dict:
    """
    Save evidence artifact and return metadata record.

    Evidence is organized as: evidence/{date}/{control_family}/{filename}
    """
    date_str = datetime.now().strftime("%Y-%m-%d")
    evidence_dir = output_dir / date_str / control_family
    evidence_dir.mkdir(parents=True, exist_ok=True)

    filepath = evidence_dir / filename
    if isinstance(data, (dict, list)):
        filepath.write_text(json.dumps(data, indent=2, default=str))
    elif isinstance(data, str):
        filepath.write_text(data)
    elif isinstance(data, bytes):
        filepath.write_bytes(data)
    else:
        filepath.write_text(str(data))

    file_hash = compute_file_hash(filepath)

    return {
        "artifact": filename,
        "control_family": control_family,
        "filepath": str(filepath),
        "sha256": file_hash,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "size_bytes": filepath.stat().st_size,
    }


# --- AWS Evidence Collection ---


def collect_aws_evidence(families: list[str], output_dir: Path, profile: str | None = None, region: str = "us-gov-west-1") -> list[dict]:
    """
    Collect evidence from AWS APIs for specified control families.

    Requires boto3 and valid AWS credentials (profile or environment).
    """
    try:
        import boto3
    except ImportError:
        logger.error("boto3 not installed. Run: pip install 'fedramp-readiness-toolkit[aws]'")
        return []

    session = boto3.Session(profile_name=profile, region_name=region)
    artifacts = []

    collectors = {
        "AC": _collect_aws_ac,
        "AU": _collect_aws_au,
        "CM": _collect_aws_cm,
        "IA": _collect_aws_ia,
        "SC": _collect_aws_sc,
        "SI": _collect_aws_si,
    }

    for family in families:
        collector = collectors.get(family)
        if collector:
            try:
                logger.info(f"Collecting AWS evidence for {family}...")
                artifacts.extend(collector(session, output_dir))
            except Exception as e:
                logger.error(f"Error collecting {family} evidence: {e}")
                artifacts.append({
                    "artifact": f"{family}-collection-error.txt",
                    "control_family": family,
                    "error": str(e),
                    "collected_at": datetime.now(timezone.utc).isoformat(),
                })
        else:
            logger.info(f"No automated AWS collector for {family}. See manifest for manual items.")

    return artifacts


def _collect_aws_ac(session, output_dir: Path) -> list[dict]:
    """Collect Access Control evidence from AWS IAM."""
    iam = session.client("iam")
    artifacts = []

    # IAM user listing with MFA status
    users = iam.list_users().get("Users", [])
    user_details = []
    for user in users:
        username = user["UserName"]
        mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
        groups = iam.list_groups_for_user(UserName=username).get("Groups", [])
        user_details.append({
            "username": username,
            "user_id": user["UserId"],
            "created": user.get("CreateDate", ""),
            "password_last_used": user.get("PasswordLastUsed", ""),
            "mfa_enabled": len(mfa_devices) > 0,
            "mfa_device_count": len(mfa_devices),
            "groups": [g["GroupName"] for g in groups],
        })

    artifacts.append(save_evidence(user_details, "iam-users-mfa.json", output_dir, "AC"))

    # Password policy
    try:
        pwd_policy = iam.get_account_password_policy().get("PasswordPolicy", {})
        artifacts.append(save_evidence(pwd_policy, "password-policy.json", output_dir, "AC"))
    except iam.exceptions.NoSuchEntityException:
        artifacts.append(save_evidence({"error": "No password policy configured"}, "password-policy.json", output_dir, "AC"))

    # Account summary
    summary = iam.get_account_summary().get("SummaryMap", {})
    artifacts.append(save_evidence(summary, "account-summary.json", output_dir, "AC"))

    return artifacts


def _collect_aws_au(session, output_dir: Path) -> list[dict]:
    """Collect Audit evidence from CloudTrail."""
    ct = session.client("cloudtrail")
    artifacts = []

    trails = ct.describe_trails().get("trailList", [])
    trail_details = []
    for trail in trails:
        status = ct.get_trail_status(Name=trail["TrailARN"])
        trail_details.append({
            "name": trail.get("Name"),
            "arn": trail.get("TrailARN"),
            "is_multi_region": trail.get("IsMultiRegionTrail"),
            "log_file_validation": trail.get("LogFileValidationEnabled"),
            "s3_bucket": trail.get("S3BucketName"),
            "is_logging": status.get("IsLogging"),
            "latest_delivery": status.get("LatestDeliveryTime", ""),
        })

    artifacts.append(save_evidence(trail_details, "cloudtrail-config.json", output_dir, "AU"))
    return artifacts


def _collect_aws_cm(session, output_dir: Path) -> list[dict]:
    """Collect Configuration Management evidence from AWS Config."""
    config_client = session.client("config")
    artifacts = []

    try:
        rules = config_client.describe_config_rules().get("ConfigRules", [])
        rule_summary = [{
            "rule_name": r["ConfigRuleName"],
            "source": r.get("Source", {}).get("Owner", ""),
            "compliance_type": r.get("ConfigRuleState", ""),
        } for r in rules]
        artifacts.append(save_evidence(rule_summary, "config-rules.json", output_dir, "CM"))
    except Exception as e:
        logger.warning(f"Could not collect Config rules: {e}")

    return artifacts


def _collect_aws_ia(session, output_dir: Path) -> list[dict]:
    """Collect Identification/Authentication evidence."""
    iam = session.client("iam")
    artifacts = []

    # Credential report
    try:
        iam.generate_credential_report()
        import time
        time.sleep(3)
        report = iam.get_credential_report()
        content = report["Content"].decode("utf-8") if isinstance(report["Content"], bytes) else report["Content"]
        artifacts.append(save_evidence(content, "credential-report.csv", output_dir, "IA"))
    except Exception as e:
        logger.warning(f"Could not generate credential report: {e}")

    return artifacts


def _collect_aws_sc(session, output_dir: Path) -> list[dict]:
    """Collect System/Communications Protection evidence."""
    ec2 = session.client("ec2")
    artifacts = []

    # Security groups
    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        sg_summary = [{
            "group_id": sg["GroupId"],
            "group_name": sg["GroupName"],
            "vpc_id": sg.get("VpcId", ""),
            "inbound_rules": len(sg.get("IpPermissions", [])),
            "outbound_rules": len(sg.get("IpPermissionsEgress", [])),
        } for sg in sgs]
        artifacts.append(save_evidence(sg_summary, "security-groups.json", output_dir, "SC"))
    except Exception as e:
        logger.warning(f"Could not collect security groups: {e}")

    return artifacts


def _collect_aws_si(session, output_dir: Path) -> list[dict]:
    """Collect System/Info Integrity evidence from GuardDuty."""
    gd = session.client("guardduty")
    artifacts = []

    try:
        detectors = gd.list_detectors().get("DetectorIds", [])
        detector_details = []
        for det_id in detectors:
            det = gd.get_detector(DetectorId=det_id)
            detector_details.append({
                "detector_id": det_id,
                "status": det.get("Status", ""),
                "finding_publishing_frequency": det.get("FindingPublishingFrequency", ""),
            })
        artifacts.append(save_evidence(detector_details, "guardduty-config.json", output_dir, "SI"))
    except Exception as e:
        logger.warning(f"Could not collect GuardDuty config: {e}")

    return artifacts


# --- Evidence Manifest ---


def generate_evidence_manifest(families: list[str], provider: str | None, output_dir: Path) -> list[dict]:
    """
    Generate a manifest of all required evidence items.

    This is useful when you can't run automated collection (no API access)
    or when evidence requires manual gathering (policies, procedures, etc.).
    """
    config = load_evidence_config()
    requirements = config.get("evidence_requirements", {})

    manifest_items = []
    for family in families:
        family_req = requirements.get(family, {})
        evidence_types = family_req.get("evidence_types", [])

        for ev in evidence_types:
            api_key = f"{provider}_api" if provider else None
            api_call = ev.get(api_key, "N/A") if api_key else "N/A"
            is_manual = ev.get("manual", False)

            manifest_items.append({
                "control_family": family,
                "family_name": CONTROL_FAMILIES.get(family, "Unknown"),
                "evidence_type": ev.get("type", ""),
                "description": ev.get("description", ""),
                "collection_method": "manual" if is_manual else "automated",
                "api_call": api_call if not is_manual else "N/A",
                "status": "pending",
            })

    # Save manifest
    date_str = datetime.now().strftime("%Y-%m-%d")
    manifest_path = output_dir / date_str / "evidence-manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps({
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "provider": provider or "none",
            "families": families,
        },
        "items": manifest_items,
    }, indent=2))

    logger.info(f"Evidence manifest written to {manifest_path}")
    return manifest_items


# --- Main ---


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def main():
    parser = argparse.ArgumentParser(description="FedRAMP Evidence Collector")
    parser.add_argument("--provider", "-p", choices=["aws", "azure", "gcp"])
    parser.add_argument("--families", "-f", help="Comma-separated control families (e.g., AC,SC,AU)")
    parser.add_argument("--all-families", action="store_true")
    parser.add_argument("--output-dir", "-o", type=Path, required=True)
    parser.add_argument("--manifest-only", action="store_true", help="Generate manifest without collecting")
    parser.add_argument("--aws-profile", help="AWS profile name")
    parser.add_argument("--aws-region", default="us-gov-west-1")
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()
    setup_logging(args.verbose)

    families = list(FEDRAMP_ACTIVE_FAMILIES.keys()) if args.all_families else [
        f.strip().upper() for f in (args.families or "AC,AU,CM,IA,SC,SI").split(",")
    ]

    if args.manifest_only:
        items = generate_evidence_manifest(families, args.provider, args.output_dir)
        print(f"\n  Evidence manifest generated with {len(items)} items")
        manual = sum(1 for i in items if i["collection_method"] == "manual")
        auto = sum(1 for i in items if i["collection_method"] == "automated")
        print(f"  Automated: {auto} | Manual: {manual}")
        return

    if not args.provider:
        logger.error("--provider required for evidence collection (or use --manifest-only)")
        sys.exit(1)

    # Generate manifest first
    manifest = generate_evidence_manifest(families, args.provider, args.output_dir)

    # Collect evidence
    if args.provider == "aws":
        artifacts = collect_aws_evidence(families, args.output_dir, args.aws_profile, args.aws_region)
    else:
        logger.info(f"{args.provider.upper()} automated collection not yet implemented. Generating manifest only.")
        artifacts = []

    # Save collection report
    date_str = datetime.now().strftime("%Y-%m-%d")
    report = {
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "provider": args.provider,
            "families": families,
        },
        "artifacts_collected": len(artifacts),
        "manifest_items": len(manifest),
        "artifacts": artifacts,
    }
    report_path = args.output_dir / date_str / "collection-report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, default=str))

    print(f"\n  Evidence collection complete")
    print(f"  Artifacts collected: {len(artifacts)}")
    print(f"  Report: {report_path}")


if __name__ == "__main__":
    main()
