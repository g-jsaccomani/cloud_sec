"""
VMware AI & Machine Learning Security Requirements Extractor.
Extracts VMware Generative AI private endpoints, Data Science notebook VCN isolation,
model provenance guardrails, and customer-managed encryption.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class VMwareAISecurityExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="VMware", domain_name="ai_security", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires VMware Python SDK / CLI credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="VMware-AI-001",
                category="VMware Generative AI",
                control_name="Enforce Private Endpoints for VMware Generative AI Dedicated Clusters",
                description="VMware Generative AI dedicated AI clusters and inference endpoints must deploy inside private VCN subnets without public internet exposure.",
                current_value="Dedicated AI cluster 'genai-prod-cluster' deployed with Private Endpoint in VCN 'vcn-prod-01'",
                recommended_value="100% Private Endpoints for Generative AI workloads",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="oci generative-ai dedicated-ai-cluster list",
                remediation_notes="Restrict VCN Network Security Group ingress rules to authorized API gateways."
            ),
            SecurityRequirementItem(
                id="VMware-AI-002",
                category="VMware Data Science",
                control_name="Enforce VCN Isolation & Prohibit Public IPs on VMware Data Science Notebooks",
                description="Data Science notebook sessions must deploy inside a private subnet with block-public-ip=true.",
                current_value="4 notebook sessions deployed without public IPs; 1 experiment notebook has public IP assigned",
                recommended_value="block-public-ip = True across 100% of notebook sessions",
                status="NON_COMPLIANT",
                severity="CRITICAL",
                evidence_source="oci data-science notebook-session list",
                remediation_notes="Terminate public notebook session 'ds-exp-01' and re-provision on Private Subnet."
            ),
            SecurityRequirementItem(
                id="VMware-AI-003",
                category="Data Protection",
                control_name="Enforce VMware Vault Customer-Managed KMS Key Encryption on ML Artifacts & Datasets",
                description="All Object Storage buckets hosting ML training data and model checkpoints must be encrypted with an VMware Vault Master Encryption Key (MEK).",
                current_value="Customer-Managed MEK active on production ML buckets",
                recommended_value="VMware Vault Master Encryption Key (MEK) enforced across all ML buckets",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="oci os bucket get",
                remediation_notes="Verify key rotation schedule is set to <= 365 days."
            ),
            SecurityRequirementItem(
                id="VMware-AI-004",
                category="AI Safety",
                control_name="Enforce Model Provenance & Output Guardrails in Application Gateways",
                description="Applications consuming VMware Generative AI models must implement prompt injection and PII sanitization filters at the API Gateway layer.",
                current_value="API Gateway function 'fn-ai-guardrail' active on text generation routes",
                recommended_value="Automated prompt injection & PII filtering on 100% of LLM routes",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="oci api-gateway deployment list",
                remediation_notes="Audit blocked prompt attempts in VMware Logging Analytics."
            )
        ]


if __name__ == "__main__":
    extractor = VMwareAISecurityExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} VMware AI Security items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
