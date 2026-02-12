"""
AWS AI & Machine Learning Security Requirements Extractor.
Extracts Amazon Bedrock Guardrails, SageMaker VPC interface endpoints,
training data KMS encryption, and Bedrock model logging to CloudWatch/S3.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class AWSAISecurityExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="AWS", domain_name="ai_security", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires AWS boto3 / CLI credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="AWS-AI-001",
                category="Amazon Bedrock Security",
                control_name="Enforce Amazon Bedrock Guardrails for Content Safety & PII Redaction",
                description="Generative AI applications on Amazon Bedrock must enforce Guardrails to block harmful topics, hate speech, and redact PII in input/output.",
                current_value="Guardrail 'bedrock-enterprise-guard' active with PII masking and prompt attack filter",
                recommended_value="Bedrock Guardrails enforced on 100% of LLM invocations",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="aws bedrock list-guardrails",
                remediation_notes="Regularly evaluate guardrail latency and accuracy against benchmark prompt sets."
            ),
            SecurityRequirementItem(
                id="AWS-AI-002",
                category="Amazon SageMaker Security",
                control_name="Enforce VPC Endpoints (PrivateLink) on SageMaker Notebooks and Training Jobs",
                description="SageMaker Studio notebooks and training jobs must deploy in private VPC subnets with directAccessOnly=True and no public Internet egress.",
                current_value="4 SageMaker notebooks deployed in private VPC; 1 legacy notebook allows DirectInternetAccess=True",
                recommended_value="DirectInternetAccess=False across 100% of SageMaker resources",
                status="NON_COMPLIANT",
                severity="CRITICAL",
                evidence_source="aws sagemaker list-notebook-instances",
                remediation_notes="Reconfigure 'ml-notebook-test' to use VPC PrivateLink endpoints."
            ),
            SecurityRequirementItem(
                id="AWS-AI-003",
                category="Model & Data Encryption",
                control_name="Enforce Customer Managed KMS Key (CMK) on SageMaker Model Artifacts & S3 Training Data",
                description="All SageMaker model artifacts and S3 training data buckets must be encrypted with Customer Managed KMS Keys.",
                current_value="CMEK active on production S3 buckets; AWS-managed KMS key used on Dev artifacts",
                recommended_value="Customer Managed Key (CMK) enforced across all ML data stores",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="aws sagemaker list-models",
                remediation_notes="Update model artifact encryption parameter to reference enterprise KMS CMK ARN."
            ),
            SecurityRequirementItem(
                id="AWS-AI-004",
                category="Bedrock Auditing",
                control_name="Enable Comprehensive Model Invocation Logging in Amazon Bedrock",
                description="Amazon Bedrock must be configured to log all text/image model invocations to an encrypted CloudWatch Log Group and S3 archive.",
                current_value="Model invocation logging enabled -> CloudWatch Log Group '/aws/bedrock/audit'",
                recommended_value="Active Bedrock model logging with KMS encryption and >= 365 days retention",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="aws bedrock get-model-invocation-logging-configuration",
                remediation_notes="Configure CloudWatch Metric Alarm for excessive token usage or repeated guardrail blocks."
            )
        ]


if __name__ == "__main__":
    extractor = AWSAISecurityExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} AWS AI Security items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
