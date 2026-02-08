"""
Cloud provider abstraction layer.

Provides a unified interface for querying compliance and security data
from AWS, Azure, and GCP. Each provider implements the same interface
so the evidence collector and compliance scorer can work across clouds.

This module is a stub for Phase 1. Full implementation comes in Phase 3
when the evidence collector is built.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ComplianceFinding:
    """Normalized compliance finding from any cloud provider."""

    provider: str  # aws, azure, gcp
    control_id: str  # NIST 800-53 control ID (e.g., AC-2)
    resource_id: str  # Cloud resource identifier
    resource_type: str  # e.g., EC2 Instance, Storage Account
    status: str  # PASS, FAIL, WARNING, NOT_APPLICABLE
    title: str
    description: str
    severity: str  # HIGH, MODERATE, LOW
    timestamp: datetime = field(default_factory=datetime.now)
    raw_finding: dict = field(default_factory=dict)


@dataclass
class EvidenceArtifact:
    """A collected evidence artifact with integrity metadata."""

    control_id: str
    artifact_type: str  # config_snapshot, scan_result, policy_document
    filepath: Path
    sha256_hash: str
    collected_at: datetime
    provider: str
    description: str


class CloudProvider(ABC):
    """Abstract base class for cloud provider integrations."""

    @abstractmethod
    def get_compliance_findings(self, control_ids: list[str] | None = None) -> list[ComplianceFinding]:
        """Fetch compliance findings, optionally filtered by control IDs."""
        ...

    @abstractmethod
    def collect_evidence(self, control_family: str, output_dir: Path) -> list[EvidenceArtifact]:
        """Collect evidence artifacts for a control family."""
        ...

    @abstractmethod
    def get_resource_inventory(self) -> list[dict[str, Any]]:
        """Get complete resource inventory for the boundary."""
        ...


class AWSProvider(CloudProvider):
    """
    AWS compliance integration.

    Uses Security Hub, AWS Config, and service-specific APIs.
    Requires: pip install fedramp-readiness-toolkit[aws]
    """

    def __init__(self, profile: str | None = None, region: str = "us-gov-west-1"):
        self.profile = profile
        self.region = region
        self._client = None
        logger.info(f"AWS provider initialized (region: {region})")

    def get_compliance_findings(self, control_ids=None):
        # Phase 3 implementation
        raise NotImplementedError("AWS evidence collection is planned for Phase 3")

    def collect_evidence(self, control_family, output_dir):
        raise NotImplementedError("AWS evidence collection is planned for Phase 3")

    def get_resource_inventory(self):
        raise NotImplementedError("AWS inventory is planned for Phase 3")


class AzureProvider(CloudProvider):
    """
    Azure compliance integration.

    Uses Azure Policy, Defender for Cloud, and resource management APIs.
    Requires: pip install fedramp-readiness-toolkit[azure]
    """

    def __init__(self, subscription_id: str | None = None):
        self.subscription_id = subscription_id
        logger.info("Azure provider initialized")

    def get_compliance_findings(self, control_ids=None):
        raise NotImplementedError("Azure evidence collection is planned for Phase 3")

    def collect_evidence(self, control_family, output_dir):
        raise NotImplementedError("Azure evidence collection is planned for Phase 3")

    def get_resource_inventory(self):
        raise NotImplementedError("Azure inventory is planned for Phase 3")


class GCPProvider(CloudProvider):
    """
    GCP compliance integration.

    Uses Security Command Center, Asset Inventory, and Cloud Logging.
    Requires: pip install fedramp-readiness-toolkit[gcp]
    """

    def __init__(self, project_id: str | None = None):
        self.project_id = project_id
        logger.info("GCP provider initialized")

    def get_compliance_findings(self, control_ids=None):
        raise NotImplementedError("GCP evidence collection is planned for Phase 3")

    def collect_evidence(self, control_family, output_dir):
        raise NotImplementedError("GCP evidence collection is planned for Phase 3")

    def get_resource_inventory(self):
        raise NotImplementedError("GCP inventory is planned for Phase 3")


def get_provider(provider_name: str, **kwargs) -> CloudProvider:
    """Factory function to get the appropriate cloud provider."""
    providers = {
        "aws": AWSProvider,
        "azure": AzureProvider,
        "gcp": GCPProvider,
    }
    if provider_name.lower() not in providers:
        raise ValueError(f"Unknown provider: {provider_name}. Must be one of: {list(providers.keys())}")
    return providers[provider_name.lower()](**kwargs)
