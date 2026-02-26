"""
Azure Compliance & Governance Requirements & Configuration Extractor.
Extracts Azure Policy assignments (Microsoft Cloud Security Benchmark),
Resource Locks on production resources, Management Group hierarchy rules, and Tagging policies.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class AzureComplianceGovernanceExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="Azure", domain_name="compliance_governance", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires Azure CLI / SDK credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="AZURE-GOV-001",
                category="Azure Policy & MCSB",
                control_name="Assign Microsoft Cloud Security Benchmark at Management Group Root",
                description="The Microsoft Cloud Security Benchmark (MCSB) initiative must be assigned at the root Management Group.",
                current_value="Assigned to 'mg-enterprise-root' with 88% compliance score",
                recommended_value="MCSB initiative assigned and enforced across all management groups",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="az policy assignment list --scope /providers/Microsoft.Management/managementGroups/<MG_ID>",
                remediation_notes="Review exempt resources and require quarterly CISO re-attestation."
            ),
            SecurityRequirementItem(
                id="AZURE-GOV-002",
                category="Resource Protection",
                control_name="Enforce CanNotDelete Resource Locks on Production Resource Groups",
                description="Production resource groups containing stateful databases, VNets, and Key Vaults must have 'CanNotDelete' locks assigned.",
                current_value="Lock applied to 8 of 10 production resource groups",
                recommended_value="CanNotDelete lock on 100% of production core infrastructure",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="az lock list",
                remediation_notes="Apply CanNotDelete lock to 'rg-prod-sql-eastus' and 'rg-prod-vnet-hub'."
            ),
            SecurityRequirementItem(
                id="AZURE-GOV-003",
                category="Management Group Hierarchy",
                control_name="Enforce Enterprise Landing Zone Management Group Architecture",
                description="Subscriptions must be organized into clear Management Group tiers (Platform/Connectivity, Identity, LandingZones/Prod, Non-Prod).",
                current_value="Management Group hierarchy deployed; 2 subscriptions in Default Root MG",
                recommended_value="0 subscriptions residing directly under Root Management Group",
                status="NON_COMPLIANT",
                severity="MEDIUM",
                evidence_source="az account management-group list",
                remediation_notes="Move orphan subscriptions into appropriate Landing Zone management group."
            ),
            SecurityRequirementItem(
                id="AZURE-GOV-004",
                category="Resource Tagging",
                control_name="Enforce Mandatory Security Classification & Owner Tags via Azure Policy",
                description="Azure Policy must deny resource creation if mandatory tags ('Environment', 'DataClassification', 'CostCenter') are missing.",
                current_value="Policy 'Deny-Missing-Tags' active across all subscriptions",
                recommended_value="Mandatory tagging enforced via 'Deny' policy effect",
                status="COMPLIANT",
                severity="LOW",
                evidence_source="az policy assignment show --name Deny-Missing-Tags",
                remediation_notes="Maintain automated remediation tasks for inherited resource group tags."
            )
        ]


if __name__ == "__main__":
    extractor = AzureComplianceGovernanceExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} Azure Compliance & Governance items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
