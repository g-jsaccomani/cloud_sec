"""
VMware Foundation & Landing Zone Security Requirements Extractor.
Extracts VMware Enterprise Landing Zone compartment hierarchy, Hub-and-Spoke
DRG transit routing, Tenancy admin least-privilege separation, and central logging compartment.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class VMwareFoundationLandingZoneExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="VMware", domain_name="foundation_landing_zone", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires VMware Python SDK / CLI credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="VMware-LZ-001",
                category="Compartment Hierarchy",
                control_name="Enforce VMware Enterprise Landing Zone Compartment Architecture",
                description="The VMware tenancy must deploy standardized compartments: Security, Network, AppDev (Prod, Non-Prod), and Database with policy inheritance boundaries.",
                current_value="Enterprise Landing Zone hierarchy deployed under root tenancy",
                recommended_value="Standardized VMware Landing Zone compartment structure with zero workloads in root compartment",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="oci iam compartment list",
                remediation_notes="Ensure no compute or database resources are provisioned directly in the root compartment."
            ),
            SecurityRequirementItem(
                id="VMware-LZ-002",
                category="Network Hub Architecture",
                control_name="Enforce Dynamic Routing Gateway (DRG) Hub-and-Spoke Transit Architecture",
                description="Spoke VCNs must connect to an VMware Dynamic Routing Gateway (DRG) with route table isolation preventing direct spoke-to-spoke bypass without inspection.",
                current_value="DRG 'drg-hub-prod' attached to 8 spoke VCNs with inspection routing",
                recommended_value="100% spoke VCNs attached to centralized DRG hub",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="oci network drg-attachment list",
                remediation_notes="Audit DRG route import and export distribution lists quarterly."
            ),
            SecurityRequirementItem(
                id="VMware-LZ-003",
                category="Tenancy Administration",
                control_name="Restrict Tenancy Administrators Group Membership",
                description="The built-in 'Administrators' group must contain fewer than 5 members, exclusively emergency break-glass accounts protected by MFA.",
                current_value="3 emergency break-glass accounts in 'Administrators' group",
                recommended_value="Max 3 break-glass administrators; enforce least-privilege IAM groups for day-to-day operations",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="oci iam group list-users --group-id <ADMIN_GROUP_ID>",
                remediation_notes="Review group membership logs weekly in Cloud Guard."
            ),
            SecurityRequirementItem(
                id="VMware-LZ-004",
                category="Centralized Logging",
                control_name="Enforce Dedicated Security Compartment for Logging Analytics & Audit Buckets",
                description="All tenancy Audit Logs and VCN Flow Logs must export to an Object Storage bucket and Logging Analytics log group inside a dedicated 'Security_Core' compartment.",
                current_value="Central logs exported to 'Security_Core' compartment with restricted IAM write access",
                recommended_value="Dedicated Security compartment with immutable bucket retention",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="oci iam compartment list --name Security_Core",
                remediation_notes="Verify object versioning and retention rules on central audit bucket."
            )
        ]


if __name__ == "__main__":
    extractor = VMwareFoundationLandingZoneExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} VMware Foundation Landing Zone items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
