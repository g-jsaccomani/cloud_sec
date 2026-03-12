"""
OCI Compliance & Governance Requirements & Configuration Extractor.
Extracts OCI Security Zones posture, Compartment Quotas, Tag Namespaces,
and CIS OCI Foundations Benchmark alignment.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class OCIComplianceGovernanceExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="OCI", domain_name="compliance_governance", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires OCI Python SDK / CLI credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="OCI-GOV-001",
                category="Security Zones",
                control_name="Enforce Maximum Security Zone Recipes on Production Compartments",
                description="Production compartments must reside inside an OCI Security Zone enforcing immutable security policies (e.g., prevent public buckets, require CMEK).",
                current_value="Compartment 'Prod_Core' assigned to Maximum Security Zone recipe",
                recommended_value="All production compartments enrolled in Security Zone guardrails",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="oci cloud-guard security-zone list",
                remediation_notes="Audit security zone policy violations in Cloud Guard dashboard."
            ),
            SecurityRequirementItem(
                id="OCI-GOV-002",
                category="Resource Tagging",
                control_name="Enforce Tag Namespace Defaults for Security Classification & Cost Tracking",
                description="Tag Namespaces must define mandatory keys ('SecurityClass', 'Owner', 'Project') automatically applied upon resource creation.",
                current_value="Tag Namespace 'EnterpriseSec' active with Tag Defaults on root compartment",
                recommended_value="Mandatory Tag Defaults enforced across 100% of compartments",
                status="COMPLIANT",
                severity="LOW",
                evidence_source="oci iam tag-namespace list / oci iam tag-default list",
                remediation_notes="Maintain tag retirement rules to prevent deprecated key sprawl."
            ),
            SecurityRequirementItem(
                id="OCI-GOV-003",
                category="CIS Benchmarks",
                control_name="Align Tenancy with CIS Oracle Cloud Infrastructure Foundations Benchmark",
                description="The tenancy must continuously evaluate against the CIS OCI Foundations Benchmark v2.0 in Cloud Guard.",
                current_value="CIS Foundations compliance score = 86%",
                recommended_value="Target CIS Foundations score >= 90%",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="oci cloud-guard problem list",
                remediation_notes="Remediate open IAM password policy and VCN flow log benchmark findings."
            ),
            SecurityRequirementItem(
                id="OCI-GOV-004",
                category="Resource Quotas & Limits",
                control_name="Enforce Compartment Quota Policies to Prevent Unauthorized Compute/GPU Proliferation",
                description="Quota policies must restrict high-cost GPU and bare-metal compute instances in non-production compartments.",
                current_value="Quota policy 'zero-gpu-nonprod' active",
                recommended_value="Explicit compute quota caps defined for Dev, QA, and Sandbox compartments",
                status="COMPLIANT",
                severity="MEDIUM",
                evidence_source="oci limits quota list",
                remediation_notes="Review quota exception requests monthly."
            )
        ]


if __name__ == "__main__":
    extractor = OCIComplianceGovernanceExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} OCI Compliance & Governance items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
