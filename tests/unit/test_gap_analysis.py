"""
Unit tests for the gap analysis tool.

Tests input parsing, analysis engine, priority calculation,
effort estimation, and output generation.
"""

import json
import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.gap_analysis import (
    IMPLEMENTATION_STATUSES,
    EFFORT_ESTIMATES,
    load_implementation_status_yaml,
    load_implementation_status_csv,
    load_implementation_status_oscal,
    load_implementation_status,
    load_inheritance_map,
    analyze_gaps,
    _calculate_priority,
    _compute_family_summaries,
    _estimate_remediation_effort,
    output_summary,
)


# --- Fixtures ---


@pytest.fixture
def sample_baseline_controls():
    """Minimal set of baseline controls for testing."""
    return [
        {"id": "AC-1", "title": "Policy and Procedures", "family_id": "AC"},
        {"id": "AC-2", "title": "Account Management", "family_id": "AC"},
        {"id": "AC-3", "title": "Access Enforcement", "family_id": "AC"},
        {"id": "SC-13", "title": "Cryptographic Protection", "family_id": "SC"},
        {"id": "SC-7", "title": "Boundary Protection", "family_id": "SC"},
        {"id": "IR-1", "title": "Policy and Procedures", "family_id": "IR"},
        {"id": "IR-4", "title": "Incident Handling", "family_id": "IR"},
        {"id": "PE-1", "title": "Policy and Procedures", "family_id": "PE"},
        {"id": "PE-3", "title": "Physical Access Control", "family_id": "PE"},
        {"id": "SI-2", "title": "Flaw Remediation", "family_id": "SI"},
    ]


@pytest.fixture
def sample_impl_status():
    """Sample implementation status covering various states."""
    return {
        "AC-1": {"status": "implemented", "notes": "Policy v3 approved"},
        "AC-2": {"status": "partial", "notes": "MFA deployed, deprovisioning manual"},
        "AC-3": {"status": "implemented", "notes": "RBAC enforced"},
        "SC-13": {"status": "implemented", "notes": "FIPS 140-2 modules in use"},
        "SC-7": {"status": "partial", "notes": "VPC configured, monitoring incomplete"},
        "IR-1": {"status": "not_implemented", "notes": "Policy not started"},
        "IR-4": {"status": "not_implemented", "notes": "No formal IR handling"},
        "PE-1": {"status": "inherited", "notes": "AWS data center"},
        "PE-3": {"status": "inherited", "notes": "AWS physical access"},
        # SI-2 intentionally missing — should default to not_implemented
    }


@pytest.fixture
def sample_inheritance():
    return {
        "PE-1": "inherited",
        "PE-3": "inherited",
        "SC-13": "shared",
        "IR-4": "shared",
    }


@pytest.fixture
def yaml_status_file(tmp_path):
    """Create a temp YAML status file."""
    content = """controls:
  AC-1:
    status: implemented
    notes: "Policy approved"
  AC-2:
    status: partial
    notes: "MFA deployed"
  SC-13: implemented
  IR-1:
    status: not_implemented
"""
    filepath = tmp_path / "status.yaml"
    filepath.write_text(content)
    return filepath


@pytest.fixture
def csv_status_file(tmp_path):
    """Create a temp CSV status file."""
    content = """control_id,status,notes
AC-1,implemented,Policy approved
AC-2,partial,MFA deployed
SC-13,implemented,FIPS validated
IR-1,not_implemented,Not started
"""
    filepath = tmp_path / "status.csv"
    filepath.write_text(content)
    return filepath


@pytest.fixture
def oscal_ssp_file(tmp_path):
    """Create a minimal OSCAL SSP JSON file."""
    ssp = {
        "system-security-plan": {
            "uuid": "test-ssp-uuid",
            "metadata": {"title": "Test SSP"},
            "control-implementation": {
                "description": "Test implementation",
                "implemented-requirements": [
                    {
                        "uuid": "req-1",
                        "control-id": "ac-1",
                        "props": [{"name": "implementation-status", "value": "implemented"}],
                        "description": "Fully implemented",
                    },
                    {
                        "uuid": "req-2",
                        "control-id": "ac-2",
                        "props": [{"name": "implementation-status", "value": "partial"}],
                        "description": "Partially done",
                    },
                    {
                        "uuid": "req-3",
                        "control-id": "sc-13",
                        "by-components": [
                            {
                                "component-uuid": "comp-1",
                                "description": "FIPS modules used",
                                "implementation-status": {"state": "implemented"},
                            }
                        ],
                    },
                ],
            },
        }
    }
    filepath = tmp_path / "ssp.json"
    filepath.write_text(json.dumps(ssp))
    return filepath


@pytest.fixture
def inheritance_file(tmp_path):
    content = """controls:
  PE-1: inherited
  PE-3: inherited
  SC-13: shared
"""
    filepath = tmp_path / "inheritance.yaml"
    filepath.write_text(content)
    return filepath


# --- Input parser tests ---


class TestYAMLParser:
    def test_loads_dict_format(self, yaml_status_file):
        result = load_implementation_status_yaml(yaml_status_file)
        assert "AC-1" in result
        assert result["AC-1"]["status"] == "implemented"
        assert result["AC-2"]["status"] == "partial"

    def test_loads_string_shorthand(self, yaml_status_file):
        result = load_implementation_status_yaml(yaml_status_file)
        assert result["SC-13"]["status"] == "implemented"

    def test_case_normalized(self, yaml_status_file):
        result = load_implementation_status_yaml(yaml_status_file)
        for key in result:
            assert key == key.upper()


class TestCSVParser:
    def test_loads_csv(self, csv_status_file):
        result = load_implementation_status_csv(csv_status_file)
        assert len(result) == 4
        assert result["AC-1"]["status"] == "implemented"
        assert result["IR-1"]["status"] == "not_implemented"


class TestOSCALParser:
    def test_loads_oscal_ssp(self, oscal_ssp_file):
        result = load_implementation_status_oscal(oscal_ssp_file)
        assert "AC-1" in result
        assert result["AC-1"]["status"] == "implemented"
        assert result["AC-2"]["status"] == "partial"

    def test_by_component_resolution(self, oscal_ssp_file):
        result = load_implementation_status_oscal(oscal_ssp_file)
        assert result["SC-13"]["status"] == "implemented"


class TestLoadDispatcher:
    def test_yaml_dispatched(self, yaml_status_file):
        result = load_implementation_status(yaml_status_file)
        assert "AC-1" in result

    def test_csv_dispatched(self, csv_status_file):
        result = load_implementation_status(csv_status_file)
        assert "AC-1" in result

    def test_json_dispatched(self, oscal_ssp_file):
        result = load_implementation_status(oscal_ssp_file)
        assert "AC-1" in result

    def test_unsupported_format(self, tmp_path):
        filepath = tmp_path / "status.txt"
        filepath.write_text("not a real format")
        with pytest.raises(ValueError, match="Unsupported"):
            load_implementation_status(filepath)


class TestInheritanceMap:
    def test_loads_inheritance(self, inheritance_file):
        result = load_inheritance_map(inheritance_file)
        assert result["PE-1"] == "inherited"
        assert result["SC-13"] == "shared"


# --- Analysis engine tests ---


class TestAnalyzeGaps:
    def test_returns_all_controls(self, sample_baseline_controls, sample_impl_status):
        result = analyze_gaps(sample_baseline_controls, sample_impl_status)
        assert len(result["controls"]) == len(sample_baseline_controls)

    def test_implemented_not_a_gap(self, sample_baseline_controls, sample_impl_status):
        result = analyze_gaps(sample_baseline_controls, sample_impl_status)
        ac1 = next(c for c in result["controls"] if c["control_id"] == "AC-1")
        assert ac1["status"] == "implemented"
        assert ac1["is_gap"] is False

    def test_inherited_not_a_gap(self, sample_baseline_controls, sample_impl_status):
        result = analyze_gaps(sample_baseline_controls, sample_impl_status)
        pe1 = next(c for c in result["controls"] if c["control_id"] == "PE-1")
        assert pe1["status"] == "inherited"
        assert pe1["is_gap"] is False

    def test_not_implemented_is_gap(self, sample_baseline_controls, sample_impl_status):
        result = analyze_gaps(sample_baseline_controls, sample_impl_status)
        ir1 = next(c for c in result["controls"] if c["control_id"] == "IR-1")
        assert ir1["status"] == "not_implemented"
        assert ir1["is_gap"] is True

    def test_partial_is_gap(self, sample_baseline_controls, sample_impl_status):
        result = analyze_gaps(sample_baseline_controls, sample_impl_status)
        ac2 = next(c for c in result["controls"] if c["control_id"] == "AC-2")
        assert ac2["status"] == "partial"
        assert ac2["is_gap"] is True

    def test_missing_control_defaults_to_not_implemented(self, sample_baseline_controls, sample_impl_status):
        result = analyze_gaps(sample_baseline_controls, sample_impl_status)
        si2 = next(c for c in result["controls"] if c["control_id"] == "SI-2")
        assert si2["status"] == "not_implemented"
        assert si2["is_gap"] is True

    def test_compliance_score_calculation(self, sample_baseline_controls, sample_impl_status):
        result = analyze_gaps(sample_baseline_controls, sample_impl_status)
        overall = result["overall"]
        # implemented: AC-1, AC-3, SC-13 = 3
        # inherited: PE-1, PE-3 = 2
        # Total passing: 5 out of 10 = 50%
        assert overall["compliance_score"] == 50.0

    def test_counts_add_up(self, sample_baseline_controls, sample_impl_status):
        result = analyze_gaps(sample_baseline_controls, sample_impl_status)
        o = result["overall"]
        total = o["implemented"] + o["inherited"] + o["partial"] + o["planned"] + o["not_implemented"] + o["not_applicable"]
        assert total == o["total_controls"]

    def test_inheritance_map_overrides_status(self, sample_baseline_controls, sample_impl_status, sample_inheritance):
        """Inheritance map should upgrade not_implemented to inherited/partial."""
        result = analyze_gaps(sample_baseline_controls, sample_impl_status, sample_inheritance)
        # IR-4 was not_implemented, inheritance says shared -> should become partial
        ir4 = next(c for c in result["controls"] if c["control_id"] == "IR-4")
        assert ir4["status"] == "partial"

    def test_metadata_present(self, sample_baseline_controls, sample_impl_status):
        result = analyze_gaps(sample_baseline_controls, sample_impl_status)
        assert "metadata" in result
        assert "generated_at" in result["metadata"]

    def test_family_summaries_present(self, sample_baseline_controls, sample_impl_status):
        result = analyze_gaps(sample_baseline_controls, sample_impl_status)
        assert "family_summaries" in result
        assert len(result["family_summaries"]) > 0

    def test_effort_estimate_present(self, sample_baseline_controls, sample_impl_status):
        result = analyze_gaps(sample_baseline_controls, sample_impl_status)
        assert "effort_estimate" in result
        assert "total_person_days" in result["effort_estimate"]
        assert result["effort_estimate"]["total_person_days"] > 0


# --- Priority calculation tests ---


class TestCalculatePriority:
    def test_implemented_has_no_priority(self):
        assert _calculate_priority("AC-1", "AC", "implemented") == "none"

    def test_inherited_has_no_priority(self):
        assert _calculate_priority("PE-1", "PE", "inherited") == "none"

    def test_federal_mandate_control_critical(self):
        """Federal mandate controls that aren't implemented should be critical."""
        assert _calculate_priority("SC-13", "SC", "not_implemented") == "critical"
        assert _calculate_priority("SC-8", "SC", "not_implemented") == "critical"
        assert _calculate_priority("IA-2", "IA", "not_implemented") == "critical"

    def test_high_scrutiny_not_implemented_is_high_or_critical(self):
        for family in ["AC", "AU", "CM", "IR", "CA"]:
            priority = _calculate_priority(f"{family}-1", family, "not_implemented")
            assert priority in ("critical", "high"), f"{family} should be high/critical"

    def test_sc_not_implemented_is_critical(self):
        """SC and IA families are critical when not implemented."""
        assert _calculate_priority("SC-7", "SC", "not_implemented") == "critical"
        assert _calculate_priority("IA-5", "IA", "not_implemented") == "critical"

    def test_low_scrutiny_planned_is_low(self):
        assert _calculate_priority("MA-1", "MA", "planned") == "low"


# --- Effort estimation tests ---


class TestEffortEstimation:
    def test_not_implemented_full_effort(self):
        gaps = [{"family_id": "AC", "status": "not_implemented"}]
        effort = _estimate_remediation_effort(gaps)
        assert effort["total_person_days"] > 0

    def test_partial_reduced_effort(self):
        full_gaps = [{"family_id": "AC", "status": "not_implemented"}]
        partial_gaps = [{"family_id": "AC", "status": "partial"}]
        full_effort = _estimate_remediation_effort(full_gaps)
        partial_effort = _estimate_remediation_effort(partial_gaps)
        assert partial_effort["total_person_days"] < full_effort["total_person_days"]

    def test_empty_gaps(self):
        effort = _estimate_remediation_effort([])
        assert effort["total_person_days"] == 0

    def test_months_calculated(self):
        gaps = [{"family_id": "SC", "status": "not_implemented"}] * 10
        effort = _estimate_remediation_effort(gaps)
        assert "estimated_months" in effort
        assert effort["estimated_months"] > 0


# --- Output tests ---


class TestOutputSummary:
    def test_summary_contains_key_metrics(self, sample_baseline_controls, sample_impl_status):
        analysis = analyze_gaps(sample_baseline_controls, sample_impl_status)
        text = output_summary(analysis, "moderate")
        assert "MODERATE" in text
        assert "Compliance Score" in text or "compliance" in text.lower()
        assert "Gap" in text or "gap" in text


# --- Edge case tests ---


class TestEdgeCases:
    def test_empty_implementation(self, sample_baseline_controls):
        """All controls should be not_implemented if no status provided."""
        result = analyze_gaps(sample_baseline_controls, {})
        assert result["overall"]["not_implemented"] == len(sample_baseline_controls)
        assert result["overall"]["compliance_score"] == 0

    def test_fully_implemented(self, sample_baseline_controls):
        """100% compliance when everything is implemented."""
        impl = {c["id"]: {"status": "implemented", "notes": ""} for c in sample_baseline_controls}
        result = analyze_gaps(sample_baseline_controls, impl)
        assert result["overall"]["compliance_score"] == 100.0
        assert result["overall"]["total_gaps"] == 0

    def test_all_inherited(self, sample_baseline_controls):
        """100% compliance when everything is inherited."""
        impl = {c["id"]: {"status": "inherited", "notes": ""} for c in sample_baseline_controls}
        result = analyze_gaps(sample_baseline_controls, impl)
        assert result["overall"]["compliance_score"] == 100.0
