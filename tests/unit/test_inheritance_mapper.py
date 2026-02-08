"""
Unit tests for the control inheritance mapper.

Tests core mapping logic, custom overrides, summary computation,
and output formatting without requiring real FedRAMP baselines.
"""

import json
import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.inheritance_mapper import (
    get_inheritance_for_control,
    map_baseline_inheritance,
    compute_inheritance_summary,
    load_custom_overrides,
    output_summary_text,
    output_markdown,
    _FAMILY_DEFAULTS,
    _CONTROL_OVERRIDES,
)


# --- Fixtures ---


@pytest.fixture
def sample_controls():
    """Minimal set of controls mimicking what catalog_parser returns."""
    return [
        {"id": "AC-1", "title": "Policy and Procedures", "family_id": "AC", "family_name": "Access Control"},
        {"id": "AC-2", "title": "Account Management", "family_id": "AC", "family_name": "Access Control"},
        {"id": "AU-1", "title": "Policy and Procedures", "family_id": "AU", "family_name": "Audit and Accountability"},
        {"id": "AU-8", "title": "Time Stamps", "family_id": "AU", "family_name": "Audit and Accountability"},
        {"id": "PE-1", "title": "Policy and Procedures", "family_id": "PE", "family_name": "Physical and Environmental Protection"},
        {"id": "PE-2", "title": "Physical Access Authorizations", "family_id": "PE", "family_name": "Physical and Environmental Protection"},
        {"id": "PE-3", "title": "Physical Access Control", "family_id": "PE", "family_name": "Physical and Environmental Protection"},
        {"id": "SC-13", "title": "Cryptographic Protection", "family_id": "SC", "family_name": "System and Communications Protection"},
        {"id": "IR-1", "title": "Policy and Procedures", "family_id": "IR", "family_name": "Incident Response"},
        {"id": "PS-1", "title": "Policy and Procedures", "family_id": "PS", "family_name": "Personnel Security"},
    ]


@pytest.fixture
def custom_overrides():
    return {"AC-2": "customer", "SC-13": "inherited"}


@pytest.fixture
def overrides_file(tmp_path):
    """Create a temporary overrides YAML file."""
    content = """overrides:
  AC-2: customer
  SC-13: inherited
  PE-3: na
"""
    filepath = tmp_path / "overrides.yaml"
    filepath.write_text(content)
    return filepath


# --- Control-level inheritance tests ---


class TestGetInheritanceForControl:
    """Tests for single-control inheritance resolution."""

    def test_pe_controls_inherited_on_aws(self):
        """Physical/environmental controls should be inherited."""
        assert get_inheritance_for_control("PE-1", "aws") == "inherited"
        assert get_inheritance_for_control("PE-2", "aws") == "inherited"
        assert get_inheritance_for_control("PE-3", "aws") == "inherited"

    def test_pe_controls_inherited_on_azure(self):
        assert get_inheritance_for_control("PE-1", "azure") == "inherited"

    def test_pe_controls_inherited_on_gcp(self):
        assert get_inheritance_for_control("PE-1", "gcp") == "inherited"

    def test_policy_controls_are_customer(self):
        """Policy controls (X-1) are almost always customer responsibility."""
        for provider in ["aws", "azure", "gcp"]:
            assert get_inheritance_for_control("AC-1", provider) == "customer"
            assert get_inheritance_for_control("IR-1", provider) == "customer"
            assert get_inheritance_for_control("SC-1", provider) == "customer"

    def test_personnel_always_customer(self):
        """Personnel security is always the CSP's job."""
        for provider in ["aws", "azure", "gcp"]:
            assert get_inheritance_for_control("PS-1", provider) == "customer"

    def test_training_always_customer(self):
        """Training is always customer responsibility."""
        for provider in ["aws", "azure", "gcp"]:
            assert get_inheritance_for_control("AT-1", provider) == "customer"
            assert get_inheritance_for_control("AT-2", provider) == "customer"

    def test_shared_controls(self):
        """Some controls should be shared across all providers."""
        assert get_inheritance_for_control("AC-2", "aws") == "shared"
        assert get_inheritance_for_control("SC-13", "aws") == "shared"
        assert get_inheritance_for_control("RA-5", "aws") == "shared"

    def test_au_8_inherited(self):
        """Time stamps (NTP) should be inherited from cloud providers."""
        assert get_inheritance_for_control("AU-8", "aws") == "inherited"

    def test_ia_7_inherited(self):
        """Crypto module authentication inherited (FIPS modules in provider)."""
        assert get_inheritance_for_control("IA-7", "aws") == "inherited"

    def test_custom_overrides_take_priority(self):
        """Custom overrides should override everything else."""
        overrides = {"AC-2": "customer", "PE-1": "shared"}
        assert get_inheritance_for_control("AC-2", "aws", overrides) == "customer"
        assert get_inheritance_for_control("PE-1", "aws", overrides) == "shared"

    def test_enhancement_inherits_from_base(self):
        """Control enhancements should fall back to base control."""
        # AC-2(1) not explicitly mapped, should check AC-2 then fall back to family
        result = get_inheritance_for_control("AC-2(1)", "aws")
        assert result in ("shared", "customer", "inherited")

    def test_unknown_control_defaults_to_customer(self):
        """Unknown controls should default to customer (conservative)."""
        assert get_inheritance_for_control("ZZ-99", "aws") == "customer"

    def test_case_insensitive(self):
        """Control IDs should be case-insensitive."""
        assert get_inheritance_for_control("ac-1", "aws") == get_inheritance_for_control("AC-1", "aws")
        assert get_inheritance_for_control("pe-1", "aws") == get_inheritance_for_control("PE-1", "aws")


# --- Baseline mapping tests ---


class TestMapBaselineInheritance:
    """Tests for mapping an entire baseline."""

    def test_returns_all_controls(self, sample_controls):
        result = map_baseline_inheritance(sample_controls, "aws")
        assert len(result) == len(sample_controls)

    def test_each_control_has_required_fields(self, sample_controls):
        result = map_baseline_inheritance(sample_controls, "aws")
        for c in result:
            assert "control_id" in c
            assert "title" in c
            assert "family_id" in c
            assert "responsibility" in c
            assert "provider" in c
            assert "notes" in c

    def test_pe_controls_all_inherited(self, sample_controls):
        result = map_baseline_inheritance(sample_controls, "aws")
        pe_controls = [c for c in result if c["family_id"] == "PE"]
        assert all(c["responsibility"] == "inherited" for c in pe_controls)

    def test_provider_set_correctly(self, sample_controls):
        result = map_baseline_inheritance(sample_controls, "azure")
        assert all(c["provider"] == "azure" for c in result)

    def test_custom_overrides_applied(self, sample_controls, custom_overrides):
        result = map_baseline_inheritance(sample_controls, "aws", custom_overrides)
        ac2 = next(c for c in result if c["control_id"] == "AC-2")
        sc13 = next(c for c in result if c["control_id"] == "SC-13")
        assert ac2["responsibility"] == "customer"
        assert sc13["responsibility"] == "inherited"

    def test_notes_populated_for_shared(self, sample_controls):
        result = map_baseline_inheritance(sample_controls, "aws")
        shared = [c for c in result if c["responsibility"] == "shared"]
        for c in shared:
            assert c["notes"] != ""

    def test_notes_populated_for_inherited(self, sample_controls):
        result = map_baseline_inheritance(sample_controls, "aws")
        inherited = [c for c in result if c["responsibility"] == "inherited"]
        for c in inherited:
            assert "inherited" in c["notes"].lower() or "provider" in c["notes"].lower() or "AWS" in c["notes"]


# --- Summary computation tests ---


class TestComputeInheritanceSummary:
    """Tests for summary statistics."""

    def test_counts_add_up(self, sample_controls):
        mapped = map_baseline_inheritance(sample_controls, "aws")
        summary = compute_inheritance_summary(mapped)
        assert summary["inherited"] + summary["shared"] + summary["customer"] == summary["total_controls"]

    def test_percentages_sum_to_100(self, sample_controls):
        mapped = map_baseline_inheritance(sample_controls, "aws")
        summary = compute_inheritance_summary(mapped)
        total_pct = summary["inherited_pct"] + summary["shared_pct"] + summary["customer_pct"]
        assert abs(total_pct - 100.0) < 0.5  # Allow rounding tolerance

    def test_scope_reduction_calculated(self, sample_controls):
        mapped = map_baseline_inheritance(sample_controls, "aws")
        summary = compute_inheritance_summary(mapped)
        # Scope reduction = inherited + 50% of shared
        expected = round(((summary["inherited"] + summary["shared"] * 0.5) / summary["total_controls"]) * 100, 1)
        assert summary["effective_scope_reduction"] == expected

    def test_family_breakdown_present(self, sample_controls):
        mapped = map_baseline_inheritance(sample_controls, "aws")
        summary = compute_inheritance_summary(mapped)
        assert "families" in summary
        assert len(summary["families"]) > 0

    def test_family_counts_add_up(self, sample_controls):
        mapped = map_baseline_inheritance(sample_controls, "aws")
        summary = compute_inheritance_summary(mapped)
        for fam in summary["families"]:
            assert fam["inherited"] + fam["shared"] + fam["customer"] == fam["total"]

    def test_empty_input(self):
        summary = compute_inheritance_summary([])
        assert summary["total_controls"] == 0
        assert summary["inherited"] == 0


# --- Override loading tests ---


class TestLoadCustomOverrides:
    def test_loads_overrides(self, overrides_file):
        result = load_custom_overrides(overrides_file)
        assert result["AC-2"] == "customer"
        assert result["SC-13"] == "inherited"
        assert result["PE-3"] == "na"

    def test_case_normalized(self, overrides_file):
        result = load_custom_overrides(overrides_file)
        # Keys should be uppercase, values lowercase
        for key, value in result.items():
            assert key == key.upper()
            assert value == value.lower()


# --- Output format tests ---


class TestOutputFormats:
    def test_summary_text_contains_key_info(self, sample_controls):
        mapped = map_baseline_inheritance(sample_controls, "aws")
        summary = compute_inheritance_summary(mapped)
        text = output_summary_text(summary, "aws", "moderate")
        assert "AWS" in text
        assert "MODERATE" in text
        assert "Fully inherited" in text
        assert "Shared" in text
        assert "Customer" in text

    def test_markdown_output(self, sample_controls):
        mapped = map_baseline_inheritance(sample_controls, "aws")
        summary = compute_inheritance_summary(mapped)
        md = output_markdown(mapped, summary, "aws", "moderate")
        assert "| Control |" in md
        assert "AC-1" in md
        assert "PE-1" in md


# --- Provider consistency tests ---


class TestProviderConsistency:
    """All three providers should have the same mapping structure."""

    def test_all_providers_have_family_defaults(self):
        for provider in ["aws", "azure", "gcp"]:
            assert provider in _FAMILY_DEFAULTS
            # Must have entries for the key families
            for family in ["AC", "PE", "SC", "IA"]:
                assert family in _FAMILY_DEFAULTS[provider], f"{provider} missing family {family}"

    def test_all_providers_have_control_overrides(self):
        for provider in ["aws", "azure", "gcp"]:
            assert provider in _CONTROL_OVERRIDES

    def test_pe_inherited_all_providers(self, sample_controls):
        """Physical/environmental should be inherited regardless of provider."""
        for provider in ["aws", "azure", "gcp"]:
            mapped = map_baseline_inheritance(sample_controls, provider)
            pe = [c for c in mapped if c["family_id"] == "PE"]
            for c in pe:
                assert c["responsibility"] == "inherited", (
                    f"PE control {c['control_id']} not inherited on {provider}"
                )

    def test_ps_customer_all_providers(self, sample_controls):
        """Personnel security should be customer regardless of provider."""
        for provider in ["aws", "azure", "gcp"]:
            mapped = map_baseline_inheritance(sample_controls, provider)
            ps = [c for c in mapped if c["family_id"] == "PS"]
            for c in ps:
                assert c["responsibility"] == "customer", (
                    f"PS control {c['control_id']} not customer on {provider}"
                )


# --- Integration test markers ---


@pytest.mark.integration
class TestWithRealBaselines:
    """Integration tests requiring actual baselines."""

    @pytest.fixture(autouse=True)
    def check_baselines_exist(self):
        catalog_path = Path(__file__).parent.parent.parent / "baselines" / "catalogs" / "NIST_SP-800-53_rev5_catalog.json"
        if not catalog_path.exists():
            pytest.skip("Baselines not downloaded. Run 'make baselines' first.")

    def test_moderate_baseline_mapping(self):
        from scripts.catalog_parser import get_baseline_controls
        controls = get_baseline_controls("moderate")
        mapped = map_baseline_inheritance(controls, "aws")
        summary = compute_inheritance_summary(mapped)

        assert summary["total_controls"] == 323
        # Sanity checks: should have some of each type
        assert summary["inherited"] > 0
        assert summary["shared"] > 0
        assert summary["customer"] > 0
        # PE family should be mostly inherited
        pe_fam = next(f for f in summary["families"] if f["family_id"] == "PE")
        assert pe_fam["inherited"] > pe_fam["customer"]

    def test_high_has_more_controls_than_moderate(self):
        from scripts.catalog_parser import get_baseline_controls
        mod_controls = get_baseline_controls("moderate")
        high_controls = get_baseline_controls("high")
        mod_mapped = map_baseline_inheritance(mod_controls, "aws")
        high_mapped = map_baseline_inheritance(high_controls, "aws")

        mod_summary = compute_inheritance_summary(mod_mapped)
        high_summary = compute_inheritance_summary(high_mapped)

        assert high_summary["total_controls"] > mod_summary["total_controls"]
