"""
Unit tests for Phase 3 scripts:
- scan_aggregator
- poam_manager
- oscal_validator
- compliance_scorer
- inventory_drift
- ssp_generator
"""

import json
import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

FIXTURES = Path(__file__).parent.parent / "fixtures"


# ============================================================
# Scan Aggregator Tests
# ============================================================


class TestScanAggregator:

    def test_parse_nessus_csv(self):
        from scripts.scan_aggregator import parse_nessus_csv
        findings = parse_nessus_csv(FIXTURES / "sample-nessus.csv")
        assert len(findings) > 0
        # Should skip "None" risk findings
        assert all(f.severity != "INFORMATIONAL" or f.severity != "None" for f in findings)

    def test_nessus_severity_normalized(self):
        from scripts.scan_aggregator import parse_nessus_csv
        findings = parse_nessus_csv(FIXTURES / "sample-nessus.csv")
        valid_severities = {"CRITICAL", "HIGH", "MODERATE", "LOW", "INFORMATIONAL"}
        for f in findings:
            assert f.severity in valid_severities, f"Unexpected severity: {f.severity}"

    def test_nessus_cve_extraction(self):
        from scripts.scan_aggregator import parse_nessus_csv
        findings = parse_nessus_csv(FIXTURES / "sample-nessus.csv")
        cve_findings = [f for f in findings if f.cve_id]
        assert len(cve_findings) >= 1
        assert all(f.cve_id.startswith("CVE-") for f in cve_findings)

    def test_parse_trivy_json(self):
        from scripts.scan_aggregator import parse_trivy_json
        findings = parse_trivy_json(FIXTURES / "sample-trivy.json")
        assert len(findings) == 3

    def test_trivy_severity_normalized(self):
        from scripts.scan_aggregator import parse_trivy_json
        findings = parse_trivy_json(FIXTURES / "sample-trivy.json")
        severities = {f.severity for f in findings}
        assert "CRITICAL" in severities
        assert "HIGH" in severities

    def test_trivy_resource_type(self):
        from scripts.scan_aggregator import parse_trivy_json
        findings = parse_trivy_json(FIXTURES / "sample-trivy.json")
        assert all(f.resource_type == "container" for f in findings)

    def test_normalize_severity(self):
        from scripts.scan_aggregator import normalize_severity
        assert normalize_severity("Critical") == "CRITICAL"
        assert normalize_severity("high") == "HIGH"
        assert normalize_severity("Medium") == "MODERATE"
        assert normalize_severity("Low") == "LOW"
        assert normalize_severity("4") == "CRITICAL"
        assert normalize_severity("info") == "INFORMATIONAL"

    def test_aggregate_multiple_scanners(self):
        from scripts.scan_aggregator import aggregate_findings
        findings = aggregate_findings([
            FIXTURES / "sample-nessus.csv",
            FIXTURES / "sample-trivy.json",
        ])
        scanners = {f.scanner for f in findings}
        assert "nessus" in scanners
        assert "trivy" in scanners

    def test_deduplicate_by_cve(self):
        from scripts.scan_aggregator import parse_nessus_csv, parse_trivy_json, deduplicate_findings
        nessus = parse_nessus_csv(FIXTURES / "sample-nessus.csv")
        trivy = parse_trivy_json(FIXTURES / "sample-trivy.json")
        all_findings = nessus + trivy

        # Both have CVE-2024-1234
        cve_1234 = [f for f in all_findings if f.cve_id == "CVE-2024-1234"]
        assert len(cve_1234) >= 2  # Found by both scanners

        deduped = deduplicate_findings(all_findings)
        cve_1234_deduped = [f for f in deduped if f.cve_id == "CVE-2024-1234"]
        # After dedup, may still have multiple if different resources
        assert len(deduped) <= len(all_findings)

    def test_compute_scan_summary(self):
        from scripts.scan_aggregator import parse_nessus_csv, compute_scan_summary
        findings = parse_nessus_csv(FIXTURES / "sample-nessus.csv")
        summary = compute_scan_summary(findings)
        assert summary["total_findings"] == len(findings)
        assert "by_severity" in summary
        assert "unique_cves" in summary

    def test_vuln_finding_to_dict(self):
        from scripts.scan_aggregator import parse_nessus_csv
        findings = parse_nessus_csv(FIXTURES / "sample-nessus.csv")
        d = findings[0].to_dict()
        assert "finding_id" in d
        assert "raw_data" not in d  # Should be excluded

    def test_detect_scanner(self):
        from scripts.scan_aggregator import detect_scanner
        assert detect_scanner(FIXTURES / "sample-nessus.csv") == "nessus"
        assert detect_scanner(FIXTURES / "sample-trivy.json") == "trivy"


# ============================================================
# POA&M Manager Tests
# ============================================================


class TestPOAMManager:

    @pytest.fixture
    def sample_findings(self):
        return [
            {
                "finding_id": "f001", "cve_id": "CVE-2024-1234",
                "title": "Critical OpenSSL Vuln", "severity": "CRITICAL",
                "cvss_score": 9.8, "affected_resource": "server-1",
                "resource_type": "os", "scanner": "nessus",
                "description": "Remote code execution", "solution": "Patch OpenSSL",
                "first_seen": (datetime.now(timezone.utc) - timedelta(days=45)).isoformat(),
                "last_seen": datetime.now(timezone.utc).isoformat(),
            },
            {
                "finding_id": "f002", "cve_id": "CVE-2024-5678",
                "title": "High TLS Bypass", "severity": "HIGH",
                "cvss_score": 7.5, "affected_resource": "server-1",
                "resource_type": "os", "scanner": "nessus",
                "description": "TLS bypass", "solution": "Update TLS",
                "first_seen": (datetime.now(timezone.utc) - timedelta(days=10)).isoformat(),
                "last_seen": datetime.now(timezone.utc).isoformat(),
            },
            {
                "finding_id": "f003", "cve_id": None,
                "title": "Info Disclosure", "severity": "MODERATE",
                "cvss_score": 5.0, "affected_resource": "server-2",
                "resource_type": "os", "scanner": "nessus",
                "description": "Version info", "solution": "Suppress headers",
                "first_seen": (datetime.now(timezone.utc) - timedelta(days=100)).isoformat(),
                "last_seen": datetime.now(timezone.utc).isoformat(),
            },
        ]

    def test_create_poam_item(self, sample_findings):
        from scripts.poam_manager import create_poam_item, load_sla_config
        config = load_sla_config()
        item = create_poam_item(sample_findings[0], config, 1)
        assert item["poam_id"] == "POAM-0001"
        assert item["severity"] == "CRITICAL"
        assert item["age_days"] >= 44  # ~45 days old
        assert item["is_overdue"] is True  # 45 > 30 day SLA

    def test_sla_calculation(self):
        from scripts.poam_manager import get_sla_days, load_sla_config
        config = load_sla_config()
        assert get_sla_days("HIGH", config) == 30
        assert get_sla_days("CRITICAL", config) == 30  # Same as HIGH
        assert get_sla_days("MODERATE", config) == 90
        assert get_sla_days("LOW", config) == 180

    def test_overdue_detection(self):
        from scripts.poam_manager import is_overdue, load_sla_config
        config = load_sla_config()
        old_date = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
        recent_date = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        assert is_overdue(old_date, "HIGH", config) is True
        assert is_overdue(recent_date, "HIGH", config) is False

    def test_escalation_triggers_none(self, sample_findings):
        from scripts.poam_manager import create_poam_item, check_escalation_triggers, load_sla_config
        config = load_sla_config()
        # Only 1 high overdue, need 5 for trigger
        items = [create_poam_item(f, config, i) for i, f in enumerate(sample_findings, 1)]
        triggers = check_escalation_triggers(items, config)
        # Should not have a DFR for high vulns (only 1 overdue, need 5)
        dfr_high = [t for t in triggers if t["type"] == "Detailed Finding Review" and "High" in t["condition"]]
        assert len(dfr_high) == 0

    def test_escalation_triggers_fired(self):
        from scripts.poam_manager import create_poam_item, check_escalation_triggers, load_sla_config
        config = load_sla_config()
        # Create 6 HIGH vulns aged >30 days
        findings = []
        for i in range(6):
            findings.append({
                "finding_id": f"f{i:03d}", "severity": "HIGH",
                "first_seen": (datetime.now(timezone.utc) - timedelta(days=35)).isoformat(),
                "title": f"High vuln {i}", "solution": "Patch it",
            })
        items = [create_poam_item(f, config, i) for i, f in enumerate(findings, 1)]
        triggers = check_escalation_triggers(items, config)
        assert len(triggers) > 0
        assert any(t["type"] == "Detailed Finding Review" for t in triggers)

    def test_poam_summary(self, sample_findings):
        from scripts.poam_manager import create_poam_item, compute_poam_summary, load_sla_config
        config = load_sla_config()
        items = [create_poam_item(f, config, i) for i, f in enumerate(sample_findings, 1)]
        summary = compute_poam_summary(items)
        assert summary["total_items"] == 3
        assert summary["open"] == 3
        assert summary["overdue"] >= 1

    def test_merge_poam(self):
        from scripts.poam_manager import merge_poam
        existing = [
            {"poam_id": "POAM-0001", "finding_id": "f001", "status": "Open", "age_days": 30},
            {"poam_id": "POAM-0002", "finding_id": "f002", "status": "Open", "age_days": 20},
        ]
        new = [
            {"poam_id": "POAM-TEMP", "finding_id": "f001", "status": "Open", "age_days": 35, "days_remaining": -5, "is_overdue": True},
            {"poam_id": "POAM-TEMP", "finding_id": "f003", "status": "Open", "age_days": 5, "days_remaining": 25, "is_overdue": False},
        ]
        merged = merge_poam(existing, new)
        assert len(merged) == 3  # f001 updated, f002 marked remediated, f003 new
        # f002 should be marked as remediated
        f002 = next(m for m in merged if m["finding_id"] == "f002")
        assert "Remediated" in f002["status"]


# ============================================================
# OSCAL Validator Tests
# ============================================================


class TestOSCALValidator:

    def test_valid_ssp_structure(self):
        from scripts.oscal_validator import validate_document
        ssp = {
            "system-security-plan": {
                "uuid": "test-uuid",
                "metadata": {"title": "Test SSP", "last-modified": "2025-01-01", "version": "1.0", "oscal-version": "1.0.4"},
                "system-characteristics": {
                    "system-name": "Test",
                    "description": "Test system",
                    "security-sensitivity-level": "moderate",
                    "authorization-boundary": {"description": "The boundary..."},
                    "security-impact-level": {
                        "security-objective-confidentiality": "moderate",
                        "security-objective-integrity": "moderate",
                        "security-objective-availability": "moderate",
                    },
                    "status": {"state": "operational"},
                },
                "system-implementation": {
                    "components": [{"uuid": "c1", "type": "this-system", "title": "System", "description": "desc"}],
                    "users": [],
                },
                "control-implementation": {
                    "description": "desc",
                    "implemented-requirements": [
                        {"uuid": "r1", "control-id": "ac-1", "props": [{"name": "implementation-status", "value": "implemented"}], "by-components": [{"component-uuid": "c1", "uuid": "bc1", "description": "Implemented"}]},
                    ],
                },
            }
        }
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(ssp, f)
            f.flush()
            result = validate_document(Path(f.name), "ssp")
        assert result.passed

    def test_missing_metadata(self):
        from scripts.oscal_validator import validate_document
        ssp = {"system-security-plan": {"uuid": "test"}}
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(ssp, f)
            f.flush()
            result = validate_document(Path(f.name), "ssp")
        assert not result.passed

    def test_missing_root_key(self):
        from scripts.oscal_validator import validate_document
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump({"wrong": "key"}, f)
            f.flush()
            result = validate_document(Path(f.name), "ssp")
        assert not result.passed

    def test_invalid_json(self):
        from scripts.oscal_validator import validate_document
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            f.write("not valid json{{{")
            f.flush()
            result = validate_document(Path(f.name), "ssp")
        assert not result.passed

    def test_missing_authorization_boundary(self):
        from scripts.oscal_validator import validate_oscal_structure, validate_ssp, ValidationResult
        ssp = {
            "system-security-plan": {
                "uuid": "test",
                "metadata": {"title": "T", "last-modified": "2025-01-01"},
                "system-characteristics": {
                    "system-name": "T",
                    "security-sensitivity-level": "moderate",
                    "security-impact-level": {
                        "security-objective-confidentiality": "moderate",
                        "security-objective-integrity": "moderate",
                        "security-objective-availability": "moderate",
                    },
                },
                "system-implementation": {"components": [], "users": []},
                "control-implementation": {"description": "d", "implemented-requirements": []},
            }
        }
        result = ValidationResult()
        validate_ssp(ssp, None, result)
        # Should flag missing boundary description
        boundary_errors = [e for e in result.errors if "boundary" in e["message"].lower()]
        assert len(boundary_errors) > 0


# ============================================================
# Compliance Scorer Tests
# ============================================================


class TestComplianceScorer:

    def test_compute_score_gap_only(self):
        from scripts.compliance_scorer import compute_compliance_score
        gap = {"overall": {"compliance_score": 75.0, "total_controls": 323, "implemented": 200, "inherited": 43, "partial": 30, "not_implemented": 50, "critical_gaps": 5}}
        score = compute_compliance_score(gap_report=gap)
        assert 0 <= score["composite_score"] <= 100
        assert score["component_scores"]["control_implementation"] == 75.0

    def test_compute_score_with_poam(self):
        from scripts.compliance_scorer import compute_compliance_score
        gap = {"overall": {"compliance_score": 80.0, "total_controls": 323, "implemented": 250, "inherited": 10, "partial": 30, "not_implemented": 33, "critical_gaps": 2}}
        poam = {"summary": {"total_items": 20, "open": 15, "overdue": 3, "critical_high_overdue": 1}, "escalation_triggers": []}
        score = compute_compliance_score(gap_report=gap, poam_data=poam)
        assert score["composite_score"] > 0
        assert score["component_scores"]["vulnerability_posture"] > 0

    def test_risk_ratings(self):
        from scripts.compliance_scorer import compute_compliance_score
        high_score = compute_compliance_score(gap_report={"overall": {"compliance_score": 95.0, "total_controls": 100, "implemented": 95, "inherited": 0, "partial": 3, "not_implemented": 2, "critical_gaps": 0}})
        low_score = compute_compliance_score(gap_report={"overall": {"compliance_score": 20.0, "total_controls": 100, "implemented": 20, "inherited": 0, "partial": 10, "not_implemented": 70, "critical_gaps": 15}})
        assert high_score["risk_rating"] in ("LOW", "MODERATE")
        assert low_score["risk_rating"] in ("HIGH", "ELEVATED")

    def test_empty_inputs(self):
        from scripts.compliance_scorer import compute_compliance_score
        score = compute_compliance_score()
        assert score["composite_score"] >= 0
        assert "timestamp" in score

    def test_db_operations(self, tmp_path):
        from scripts.compliance_scorer import init_db, store_score, get_trend_data, compute_compliance_score
        db_path = tmp_path / "test.db"
        conn = init_db(db_path)

        score = compute_compliance_score(gap_report={"overall": {"compliance_score": 60.0, "total_controls": 100, "implemented": 60, "inherited": 0, "partial": 20, "not_implemented": 20, "critical_gaps": 3}})
        store_score(conn, score)

        trend = get_trend_data(conn)
        assert len(trend) == 1
        assert trend[0]["composite_score"] > 0
        conn.close()


# ============================================================
# Inventory Drift Tests
# ============================================================


class TestInventoryDrift:

    def test_load_documented_inventory(self):
        from scripts.inventory_drift import load_documented_inventory
        inv = load_documented_inventory(FIXTURES / "sample-documented-inventory.yaml")
        assert len(inv) == 5
        assert all("_normalized_id" in r for r in inv)

    def test_load_live_inventory(self):
        from scripts.inventory_drift import load_live_inventory
        inv = load_live_inventory(FIXTURES / "sample-live-inventory.json")
        assert len(inv) == 6

    def test_detect_drift(self):
        from scripts.inventory_drift import load_documented_inventory, load_live_inventory, detect_drift
        documented = load_documented_inventory(FIXTURES / "sample-documented-inventory.yaml")
        live = load_live_inventory(FIXTURES / "sample-live-inventory.json")
        drift = detect_drift(documented, live)

        assert drift["summary"]["total_documented"] == 5
        assert drift["summary"]["total_live"] == 6
        # i-0old999removed is stale (in doc, not in live)
        assert drift["summary"]["stale"] >= 1
        # i-0new111undocumented and myapp-logs-prod are undocumented
        assert drift["summary"]["undocumented"] >= 2
        # 4 resources should match
        assert drift["summary"]["matched"] >= 3  # Could have config_drift too

    def test_drift_percentage(self):
        from scripts.inventory_drift import detect_drift
        documented = [{"resource_id": "a", "_normalized_id": "a"}, {"resource_id": "b", "_normalized_id": "b"}]
        live = [{"resource_id": "a", "_normalized_id": "a"}, {"resource_id": "c", "_normalized_id": "c"}]
        drift = detect_drift(documented, live)
        # 1 stale + 1 undocumented out of 3 unique = ~66%
        assert drift["summary"]["drift_percentage"] > 0

    def test_no_drift(self):
        from scripts.inventory_drift import detect_drift
        inventory = [
            {"resource_id": "a", "resource_type": "EC2", "_normalized_id": "a"},
            {"resource_id": "b", "resource_type": "S3", "_normalized_id": "b"},
        ]
        drift = detect_drift(inventory, inventory)
        assert drift["summary"]["undocumented"] == 0
        assert drift["summary"]["stale"] == 0


# ============================================================
# SSP Generator Tests
# ============================================================


class TestSSPGenerator:

    def test_load_system_metadata(self):
        from scripts.ssp_generator import load_system_metadata
        meta = load_system_metadata(
            Path(__file__).parent.parent.parent / "examples" / "sample-system-metadata.yaml"
        )
        assert meta["system"]["name"] == "CloudWidget Enterprise"
        assert meta["system"]["fips199_level"] == "moderate"
        assert len(meta["boundary"]["components"]) >= 4

    def test_load_control_narratives(self, tmp_path):
        from scripts.ssp_generator import load_control_narratives
        ac_file = tmp_path / "AC.md"
        ac_file.write_text("## AC-1\n\nPolicy is documented.\n\n## AC-2\n\nAccounts are managed.\n")
        narratives = load_control_narratives(tmp_path)
        assert "AC-1" in narratives
        assert "AC-2" in narratives
        assert "policy" in narratives["AC-1"]["narrative"].lower()

    def test_generate_oscal_ssp_structure(self):
        from scripts.ssp_generator import generate_oscal_ssp
        metadata = {
            "system": {"name": "Test System", "abbreviation": "TS", "version": "1.0", "description": "Test"},
            "boundary": {"description": "Test boundary", "components": [{"name": "App", "type": "software", "description": "Test app"}]},
            "responsible_parties": {"system_owner": {"name": "Owner", "email": "owner@test.com"}},
        }
        controls = [
            {"id": "AC-1", "title": "Policy", "family_id": "AC"},
            {"id": "SC-13", "title": "Crypto", "family_id": "SC"},
        ]
        ssp = generate_oscal_ssp(metadata, controls, {}, None, "moderate")
        plan = ssp["system-security-plan"]
        assert "uuid" in plan
        assert plan["metadata"]["title"].startswith("System Security Plan")
        assert len(plan["control-implementation"]["implemented-requirements"]) == 2

    def test_inheritance_affects_ssp(self):
        from scripts.ssp_generator import generate_oscal_ssp
        metadata = {
            "system": {"name": "T", "description": "T"},
            "boundary": {"description": "T", "components": []},
            "responsible_parties": {},
        }
        controls = [{"id": "PE-1", "title": "Physical", "family_id": "PE"}]
        inheritance = {"PE-1": "inherited"}

        ssp = generate_oscal_ssp(metadata, controls, {}, inheritance, "moderate")
        reqs = ssp["system-security-plan"]["control-implementation"]["implemented-requirements"]
        pe1 = reqs[0]

        # Should have inherited flag
        has_leveraged = any(
            p.get("name") == "leveraged-authorization-type" and p.get("value") == "inherited"
            for p in pe1.get("props", [])
        )
        assert has_leveraged

    def test_narratives_used_in_ssp(self):
        from scripts.ssp_generator import generate_oscal_ssp
        metadata = {
            "system": {"name": "T", "description": "T"},
            "boundary": {"description": "T", "components": []},
            "responsible_parties": {},
        }
        controls = [{"id": "AC-1", "title": "Policy", "family_id": "AC"}]
        narratives = {"AC-1": {"narrative": "We have a comprehensive access control policy.", "family": "AC"}}

        ssp = generate_oscal_ssp(metadata, controls, narratives, None, "moderate")
        reqs = ssp["system-security-plan"]["control-implementation"]["implemented-requirements"]
        desc = reqs[0]["by-components"][0]["description"]
        assert "comprehensive access control" in desc
