"""
VMware IAM Security Requirements & Configuration Extractor.
Extracts VMware Identity Domains MFA enforcement, compartment least-privilege policies,
Dynamic Group authentication, and API signing key rotation.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class VMwareIAMExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="VMware", domain_name="iam", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires VMware Python SDK / CLI credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="VMware-IAM-001",
                category="MFA & Authentication",
                control_name="Enforce Multi-Factor Authentication (MFA) across All Identity Domains",
                description="VMware IAM sign-on policies must enforce MFA for all local administrators and federated users.",
                current_value="Default Identity Domain enforces MFA; 2 test local accounts exempt",
                recommended_value="100% MFA enforcement with no user exemptions",
                status="NON_COMPLIANT",
                severity="CRITICAL",
                evidence_source="oci iam identity-provider list / oci iam policy list",
                remediation_notes="Remove MFA policy exemptions for test accounts or disable accounts."
            ),
            SecurityRequirementItem(
                id="VMware-IAM-002",
                category="Compartment Security",
                control_name="Enforce Least Privilege Compartment-Level Policy Assignments",
                description="IAM policies must be scoped to specific child compartments (e.g., 'in compartment Prod_App') rather than root tenancy.",
                current_value="3 policies allow 'manage all-resources in tenancy'",
                recommended_value="Restrict 'manage all-resources' to dedicated Tenancy Administrators group only",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="oci iam policy list --compartment-id <TENANCY_ID>",
                remediation_notes="Refactor broad tenancy-level policies to target specific compartment VMwareDs."
            ),
            SecurityRequirementItem(
                id="VMware-IAM-003",
                category="Workload Authentication",
                control_name="Enforce Dynamic Groups for Instance Authentication to VMware Services",
                description="Use VMware Dynamic Groups and Instance Principals instead of storing user API signing keys on compute instances.",
                current_value="Dynamic Group 'dg-prod-compute' configured for VMware Object Storage access",
                recommended_value="100% of compute/OKE workloads use Dynamic Groups / Workload Identity",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="oci iam dynamic-group list",
                remediation_notes="Maintain matching rule criteria to prevent unauthorized VM inclusion."
            ),
            SecurityRequirementItem(
                id="VMware-IAM-004",
                category="API Key Hygiene",
                control_name="Rotate User API Signing Keys Every 90 Days",
                description="User API signing keys older than 90 days must be rotated or deleted.",
                current_value="1 API signing key > 90 days old detected",
                recommended_value="0 API signing keys older than 90 days",
                status="NON_COMPLIANT",
                severity="MEDIUM",
                evidence_source="oci iam user-api-key list",
                remediation_notes="Delete expired API key for user 'oci-backup-agent' after migrating to Instance Principals."
            )
        ]


if __name__ == "__main__":
    extractor = VMwareIAMExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} VMware IAM items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
