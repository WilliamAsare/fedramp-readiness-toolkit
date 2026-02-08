"""
Unit tests for the OSCAL catalog parser and helpers.

These tests validate core parsing logic using test fixtures.
They don't require the actual NIST catalog or FedRAMP baselines.
"""

import json
import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scripts.utils.oscal_helpers import (
    CONTROL_FAMILIES,
    EXPECTED_CONTROL_COUNTS,
    FEDRAMP_ACTIVE_FAMILIES,
    extract_control_ids_from_profile,
    extract_controls_from_catalog,
    filter_catalog_by_baseline,
    get_family_from_control_id,
    validate_control_count,
)


# --- Test fixtures ---

@pytest.fixture
def sample_catalog():
    """Minimal OSCAL catalog structure for testing."""
    return {
        "catalog": {
            "uuid": "test-uuid",
            "metadata": {"title": "Test Catalog"},
            "groups": [
                {
                    "id": "ac",
                    "title": "Access Control",
                    "controls": [
                        {
                            "id": "ac-1",
                            "title": "Policy and Procedures",
                            "class": "SP800-53",
                            "params": [
                                {"id": "ac-1_prm_1", "label": "organization-defined personnel"},
                                {"id": "ac-1_prm_2", "label": "organization-defined frequency"},
                            ],
                            "parts": [
                                {
                                    "id": "ac-1_smt",
                                    "name": "statement",
                                    "prose": "Develop and maintain access control policy.",
                                }
                            ],
                            "controls": [  # enhancements
                            ],
                        },
                        {
                            "id": "ac-2",
                            "title": "Account Management",
                            "class": "SP800-53",
                            "params": [],
                            "parts": [],
                            "controls": [
                                {
                                    "id": "ac-2.1",
                                    "title": "Automated System Account Management",
                                    "class": "SP800-53",
                                    "params": [],
                                    "parts": [],
                                },
                            ],
                        },
                    ],
                },
                {
                    "id": "sc",
                    "title": "System and Communications Protection",
                    "controls": [
                        {
                            "id": "sc-1",
                            "title": "Policy and Procedures",
                            "class": "SP800-53",
                            "params": [],
                            "parts": [],
                            "controls": [],
                        },
                        {
                            "id": "sc-13",
                            "title": "Cryptographic Protection",
                            "class": "SP800-53",
                            "params": [
                                {"id": "sc-13_prm_1", "label": "organization-defined cryptographic uses"},
                            ],
                            "parts": [
                                {
                                    "id": "sc-13_smt",
                                    "name": "statement",
                                    "prose": "Implement FIPS-validated cryptography.",
                                }
                            ],
                            "controls": [],
                        },
                    ],
                },
            ],
        }
    }


@pytest.fixture
def sample_profile():
    """Minimal OSCAL profile structure for testing."""
    return {
        "profile": {
            "uuid": "test-profile-uuid",
            "metadata": {"title": "Test FedRAMP Profile"},
            "imports": [
                {
                    "href": "NIST_SP-800-53_rev5_catalog.json",
                    "include-controls": [
                        {
                            "with-ids": ["ac-1", "ac-2", "sc-1", "sc-13"]
                        }
                    ],
                }
            ],
        }
    }


# --- Tests for oscal_helpers ---


class TestControlFamilies:
    """Tests for control family constants."""

    def test_all_20_families_present(self):
        assert len(CONTROL_FAMILIES) == 20

    def test_fedramp_active_excludes_pm_pt(self):
        assert "PM" not in FEDRAMP_ACTIVE_FAMILIES
        assert "PT" not in FEDRAMP_ACTIVE_FAMILIES
        assert len(FEDRAMP_ACTIVE_FAMILIES) == 18

    def test_key_families_present(self):
        for family in ["AC", "SC", "SI", "AU", "IA", "CM", "IR", "CA", "SR"]:
            assert family in CONTROL_FAMILIES

    def test_sr_family_present(self):
        """SR (Supply Chain Risk Management) is new in Rev 5 and must be present."""
        assert "SR" in CONTROL_FAMILIES
        assert "Supply Chain" in CONTROL_FAMILIES["SR"]


class TestExpectedControlCounts:
    """Tests for expected baseline control counts."""

    def test_expected_counts_defined(self):
        assert EXPECTED_CONTROL_COUNTS["low"] == 156
        assert EXPECTED_CONTROL_COUNTS["moderate"] == 323
        assert EXPECTED_CONTROL_COUNTS["high"] == 410
        assert EXPECTED_CONTROL_COUNTS["li-saas"] == 156

    def test_moderate_is_largest_non_high(self):
        assert EXPECTED_CONTROL_COUNTS["moderate"] > EXPECTED_CONTROL_COUNTS["low"]
        assert EXPECTED_CONTROL_COUNTS["high"] > EXPECTED_CONTROL_COUNTS["moderate"]


class TestExtractControlIds:
    """Tests for profile control ID extraction."""

    def test_extracts_ids_from_profile(self, sample_profile):
        ids = extract_control_ids_from_profile(sample_profile)
        assert len(ids) == 4
        assert "ac-1" in ids
        assert "sc-13" in ids

    def test_empty_profile(self):
        empty = {"profile": {"imports": []}}
        ids = extract_control_ids_from_profile(empty)
        assert ids == []

    def test_deduplicates_ids(self):
        profile = {
            "profile": {
                "imports": [
                    {"include-controls": [{"with-ids": ["ac-1", "ac-1", "ac-2"]}]},
                ]
            }
        }
        ids = extract_control_ids_from_profile(profile)
        assert len(ids) == 2


class TestExtractControlsFromCatalog:
    """Tests for catalog control extraction."""

    def test_extracts_all_controls(self, sample_catalog):
        controls = extract_controls_from_catalog(sample_catalog)
        # ac-1, ac-2, ac-2.1 (enhancement), sc-1, sc-13 = 5
        assert len(controls) == 5

    def test_control_has_required_fields(self, sample_catalog):
        controls = extract_controls_from_catalog(sample_catalog)
        for c in controls:
            assert "id" in c
            assert "title" in c
            assert "family_id" in c
            assert "params" in c

    def test_extracts_enhancements(self, sample_catalog):
        controls = extract_controls_from_catalog(sample_catalog)
        ids = [c["id"] for c in controls]
        assert "AC-2.1" in ids  # enhancement of AC-2

    def test_extracts_params(self, sample_catalog):
        controls = extract_controls_from_catalog(sample_catalog)
        ac1 = next(c for c in controls if c["id"] == "AC-1")
        assert len(ac1["params"]) == 2


class TestFilterCatalogByBaseline:
    """Tests for baseline filtering."""

    def test_filters_correctly(self, sample_catalog):
        all_controls = extract_controls_from_catalog(sample_catalog)
        baseline_ids = ["ac-1", "sc-13"]
        filtered = filter_catalog_by_baseline(all_controls, baseline_ids)
        assert len(filtered) == 2
        ids = {c["id"] for c in filtered}
        assert ids == {"AC-1", "SC-13"}

    def test_case_insensitive(self, sample_catalog):
        all_controls = extract_controls_from_catalog(sample_catalog)
        filtered = filter_catalog_by_baseline(all_controls, ["AC-1", "ac-1"])
        assert len(filtered) == 1


class TestGetFamilyFromControlId:
    """Tests for control ID parsing."""

    def test_simple_control(self):
        assert get_family_from_control_id("AC-1") == "AC"

    def test_enhancement(self):
        assert get_family_from_control_id("AC-2(1)") == "AC"

    def test_lowercase_input(self):
        assert get_family_from_control_id("sc-13") == "SC"


class TestValidateControlCount:
    """Tests for control count validation."""

    def test_valid_count(self):
        assert validate_control_count("moderate", 323) is True

    def test_invalid_count(self):
        assert validate_control_count("moderate", 300) is False

    def test_unknown_baseline(self):
        assert validate_control_count("unknown", 100) is True


# --- Integration test markers ---


@pytest.mark.integration
class TestWithRealBaselines:
    """
    Integration tests that require actual NIST catalog and FedRAMP baselines.
    Run with: pytest -m integration

    These will be skipped if baselines haven't been downloaded.
    """

    @pytest.fixture(autouse=True)
    def check_baselines_exist(self):
        catalog_path = Path(__file__).parent.parent.parent / "baselines" / "catalogs" / "NIST_SP-800-53_rev5_catalog.json"
        if not catalog_path.exists():
            pytest.skip("Baselines not downloaded. Run 'make baselines' first.")

    def test_low_baseline_count(self):
        from scripts.catalog_parser import get_baseline_controls
        controls = get_baseline_controls("low")
        assert len(controls) == 156

    def test_moderate_baseline_count(self):
        from scripts.catalog_parser import get_baseline_controls
        controls = get_baseline_controls("moderate")
        assert len(controls) == 323

    def test_high_baseline_count(self):
        from scripts.catalog_parser import get_baseline_controls
        controls = get_baseline_controls("high")
        assert len(controls) == 410
