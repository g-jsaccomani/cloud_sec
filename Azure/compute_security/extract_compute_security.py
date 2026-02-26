"""
Azure Compute Security Requirements & Configuration Extractor.
Extracts Azure VM Trusted Launch & Disk Encryption settings,
AKS Kubernetes private cluster posture, and Azure Bastion configuration.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class AzureComputeSecurityExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="Azure", domain_name="compute_security", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires Azure CLI / SDK credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="AZURE-COMP-001",
                category="Virtual Machines",
                control_name="Enforce Trusted Launch (Secure Boot & vTPM) on Azure VMs",
                description="Azure VMs must be deployed with Trusted Launch security type enabled (SecureBoot and vTPM = True).",
                current_value="14 VMs use Trusted Launch; 2 legacy VMs use Standard Gen1 type",
                recommended_value="100% Trusted Launch VMs",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="az vm list",
                remediation_notes="Plan migration of Gen1 legacy VMs 'vm-sql-legacy' and 'vm-ad-legacy' to Gen2 Trusted Launch."
            ),
            SecurityRequirementItem(
                id="AZURE-COMP-002",
                category="Virtual Machines",
                control_name="Enforce Azure Bastion for Secure Remote VM Administration",
                description="Remote RDP/SSH access to VMs must traverse an Azure Bastion host without public IP assignment on VMs.",
                current_value="Azure Bastion deployed in 'vnet-hub-prod'; 0 VMs have Public IPs assigned",
                recommended_value="100% Bastion-managed administrative access; 0 VM Public IPs",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="az network public-ip list / az network bastion list",
                remediation_notes="Require Entra ID native authentication for Bastion sessions."
            ),
            SecurityRequirementItem(
                id="AZURE-COMP-003",
                category="AKS Kubernetes Security",
                control_name="Enforce AKS Private Cluster with Azure AD / Entra ID RBAC",
                description="AKS clusters must be private (enablePrivateCluster = True) and use Microsoft Entra ID integration for RBAC.",
                current_value="Cluster 'aks-prod-01' is Private with Entra RBAC and Azure Policy Add-on enabled",
                recommended_value="Private Cluster = True, enableAzureRBAC = True",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="az aks show",
                remediation_notes="Disable local account admin access using 'az aks update --disable-local-accounts'."
            ),
            SecurityRequirementItem(
                id="AZURE-COMP-004",
                category="AKS Kubernetes Security",
                control_name="Enforce Azure Policy Add-on for AKS Pod Security Standards",
                description="AKS clusters must run the Azure Policy add-on to enforce Baseline/Restricted Pod Security Standards.",
                current_value="Azure Policy Add-on enabled on 100% of AKS clusters",
                recommended_value="Azure Policy Add-on active with Pod Security Restricted initiative",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="az aks show --query addonProfiles.azurepolicy",
                remediation_notes="Audit policy violations in Policy Compliance dashboard."
            )
        ]


if __name__ == "__main__":
    extractor = AzureComputeSecurityExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} Azure Compute Security items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
