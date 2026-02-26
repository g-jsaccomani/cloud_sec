"""
Azure AI & Machine Learning Security Requirements Extractor.
Extracts Azure OpenAI Private Endpoint configurations, Content Safety filters,
Machine Learning Studio customer-managed keys (CMK), and VNet isolation.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class AzureAISecurityExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="Azure", domain_name="ai_security", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires Azure CLI / SDK credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="AZURE-AI-001",
                category="Azure OpenAI Security",
                control_name="Enforce Private Endpoints & Disable Public Network Access on Azure OpenAI",
                description="Azure OpenAI instances must disable public network access (publicNetworkAccess=Disabled) and communicate exclusively via Private Endpoints.",
                current_value="All 4 Azure OpenAI resources use Private Endpoints with publicNetworkAccess=Disabled",
                recommended_value="100% Private Endpoints; Public Network Access = Disabled",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="az cognitiveservices account list",
                remediation_notes="Verify DNS integration with Private DNS Zone 'privatelink.openai.azure.com'."
            ),
            SecurityRequirementItem(
                id="AZURE-AI-002",
                category="AI Safety & Content Filtering",
                control_name="Enforce Azure AI Content Safety Filters against Prompt Injection & Jailbreaks",
                description="Azure OpenAI deployments must attach an AI Content Safety filter configured to block hate speech, jailbreaks, and prompt injection attempts.",
                current_value="Filter 'content-safety-strict' attached to production LLM deployments",
                recommended_value="AI Content Safety filter active on all model deployments",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="az cognitiveservices account deployment list",
                remediation_notes="Regularly review Content Safety block logs in Log Analytics."
            ),
            SecurityRequirementItem(
                id="AZURE-AI-003",
                category="Azure Machine Learning",
                control_name="Enforce Customer Managed Key (CMK) Encryption on Azure ML Workspaces",
                description="Azure Machine Learning workspaces must use Key Vault Customer Managed Keys to encrypt training metrics, datasets, and notebooks.",
                current_value="CMK encryption active on workspace 'ml-prod-workspace'; Microsoft-managed key on 'ml-dev'",
                recommended_value="Customer Managed Key (CMK) enforced across all ML workspaces",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="az ml workspace show",
                remediation_notes="Enable Key Vault CMK encryption on 'ml-dev' workspace."
            ),
            SecurityRequirementItem(
                id="AZURE-AI-004",
                category="Azure Machine Learning",
                control_name="Enforce Managed Virtual Network Isolation for Azure ML Compute",
                description="Azure Machine Learning compute instances and clusters must deploy behind a Managed Virtual Network with outbound FQDN rules.",
                current_value="Managed Virtual Network = 'AllowOnlyApprovedOutbound' on 100% of ML compute",
                recommended_value="Managed VNet Isolation enabled with restricted outbound rules",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="az ml compute list",
                remediation_notes="Audit custom FQDN outbound exceptions monthly."
            )
        ]


if __name__ == "__main__":
    extractor = AzureAISecurityExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} Azure AI Security items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
