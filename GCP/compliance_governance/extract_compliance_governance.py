"""
GCP Compliance & Governance Requirements & Configuration Extractor.
Extracts Organization Policy constraints, Essential Contacts configuration,
Cloud Asset Inventory feeds, and CIS Benchmark alignment.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class GCPComplianceGovernanceExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="GCP", domain_name="compliance_governance", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires GCP SDK credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="GCP-GOV-001",
                category="Organization Policies",
                control_name="Enforce Resource Location Restrictions (gcp.resourceLocations)",
                description="Restrict GCP resource creation to approved organizational regions (e.g., us-east1, us-central1).",
                current_value="Allowed regions: ['in:us-locations']",
                recommended_value="Restrict to authorized data sovereignty regions",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="gcloud resource-manager org-policies list --organization=<ORG_ID>",
                remediation_notes="Maintain strict exception approval workflow for international regions."
            ),
            SecurityRequirementItem(
                id="GCP-GOV-002",
                category="Organization Policies",
                control_name="Disable Service Account Key Creation (iam.disableServiceAccountKeyCreation)",
                description="Prevent developers from creating new user-managed Service Account JSON keys.",
                current_value="Enforced at Organization root",
                recommended_value="Enforced = True across 100% of folders",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="gcloud resource-manager org-policies describe iam.disableServiceAccountKeyCreation",
                remediation_notes="Ensure no project overrides exist without CISO exception ticket."
            ),
            SecurityRequirementItem(
                id="GCP-GOV-003",
                category="Essential Contacts",
                control_name="Configure Security Essential Contacts at Organization Root",
                description="Ensure 'SECURITY' notification category has verified security operations email addresses.",
                current_value="Configured: secops-alerts@google.com",
                recommended_value="Verified SOC/Security distribution list assigned to SECURITY category",
                status="COMPLIANT",
                severity="MEDIUM",
                evidence_source="gcloud essential-contacts list --organization=<ORG_ID>",
                remediation_notes="Test incident alert delivery quarterly."
            ),
            SecurityRequirementItem(
                id="GCP-GOV-004",
                category="Asset Inventory",
                control_name="Cloud Asset Inventory Real-time Export Feed to BigQuery",
                description="A continuous Cloud Asset Inventory feed must be configured to export resource changes to BigQuery for audit trails.",
                current_value="Feed 'cai-secops-feed' exporting to BigQuery dataset 'cai_audit_archive'",
                recommended_value="Active Org-level real-time asset feed",
                status="COMPLIANT",
                severity="MEDIUM",
                evidence_source="gcloud asset feeds list --organization=<ORG_ID>",
                remediation_notes="Monitor BigQuery dataset permissions to prevent unauthorized schema changes."
            )
        ]


if __name__ == "__main__":
    extractor = GCPComplianceGovernanceExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} GCP Compliance & Governance items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
