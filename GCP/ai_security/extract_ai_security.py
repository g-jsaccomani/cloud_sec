"""
GCP AI & Machine Learning Security Requirements Extractor.
Extracts Vertex AI private endpoint configurations, CMEK encryption on ML datasets/models,
Model Armor / prompt injection guardrails, and VPC Service Controls integration.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class GCPAISecurityExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="GCP", domain_name="ai_security", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires GCP SDK credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="GCP-AI-001",
                category="Vertex AI Networking",
                control_name="Enforce Private Service Connect (PSC) / Private Endpoints for Vertex AI",
                description="Vertex AI Workbench notebooks and training pipelines must not expose public IPs and must communicate over Private Service Connect.",
                current_value="All 6 Vertex AI Workbench instances deployed on Private Subnet with PSC",
                recommended_value="100% Private Endpoints; 0 Public IPs on ML instances",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="gcloud ai workbench instances list",
                remediation_notes="Ensure VPC Service Controls perimeter protects 'aiplatform.googleapis.com'."
            ),
            SecurityRequirementItem(
                id="GCP-AI-002",
                category="Model & Data Protection",
                control_name="Enforce Customer-Managed Encryption Keys (CMEK) on Vertex AI Datasets and Models",
                description="Training datasets, custom fine-tuned models, and inference caches must use Cloud KMS CMEK.",
                current_value="CMEK configured on production Vertex AI datasets; default Google encryption on experiment cache",
                recommended_value="CMEK enforced across 100% of ML datasets and model registries",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="gcloud ai datasets list",
                remediation_notes="Configure Cloud KMS CryptoKey binding for Vertex AI service agent."
            ),
            SecurityRequirementItem(
                id="GCP-AI-003",
                category="GenAI Governance & Safety",
                control_name="Enable Model Armor / LLM Guardrails against Prompt Injection & PII Leakage",
                description="Generative AI applications using Gemini/Vertex AI must implement Model Armor policies to filter prompt injection, jailbreaks, and PII output.",
                current_value="Model Armor policy 'prod-llm-guard' active with PII masking and prompt injection detection",
                recommended_value="Model Armor attached to all customer-facing LLM endpoints",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="gcloud ai model-armor policies list",
                remediation_notes="Regularly test adversarial prompts against AI safety filters."
            ),
            SecurityRequirementItem(
                id="GCP-AI-004",
                category="Data Sovereignty",
                control_name="Enforce Region Restriction on Vertex AI Data Processing & Training",
                description="All Vertex AI inference and model fine-tuning must execute within approved organizational regions (e.g., us-central1) to maintain data residency.",
                current_value="Region restricted to 'us-central1' via Organization Policy",
                recommended_value="Restrict processing to authorized data residency regions",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="gcloud resource-manager org-policies describe gcp.resourceLocations",
                remediation_notes="Audit audit logs for unauthorized multi-region ML API invocations."
            )
        ]


if __name__ == "__main__":
    extractor = GCPAISecurityExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} GCP AI Security items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
