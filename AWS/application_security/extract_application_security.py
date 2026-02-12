"""
AWS Application & API Security Requirements Extractor.
Extracts API Gateway Cognito/Lambda authorizers, AWS Secrets Manager rotation,
ECR immutable image tags & Inspector scanning, and Lambda Code Signing.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class AWSApplicationSecurityExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="AWS", domain_name="application_security", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires AWS boto3 / CLI credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="AWS-APP-001",
                category="API Gateway Security",
                control_name="Enforce Cognito / Lambda JWT Authorizers on API Gateway Routes",
                description="REST and HTTP API Gateway endpoints must require authentication via AWS Cognito user pools or custom Lambda JWT authorizers.",
                current_value="100% of REST API routes require Cognito User Pool authorizer",
                recommended_value="Mandatory authorizer attached to all published API stages",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="aws apigateway get-authorizers",
                remediation_notes="Ensure API Gateway usage plans enforce strict rate limiting per API key."
            ),
            SecurityRequirementItem(
                id="AWS-APP-002",
                category="Secrets Management",
                control_name="Enforce Automatic Rotation for AWS Secrets Manager Secrets",
                description="Database credentials and API keys stored in Secrets Manager must have automatic rotation configured via AWS Lambda.",
                current_value="14 secrets stored; 3 secrets have automatic rotation disabled",
                recommended_value="Automatic rotation schedule <= 90 days enabled on 100% of secrets",
                status="NON_COMPLIANT",
                severity="CRITICAL",
                evidence_source="aws secretsmanager list-secrets",
                remediation_notes="Enable automatic rotation Lambda function for 'db-prod-sql-secret' and 'api-stripe-key'."
            ),
            SecurityRequirementItem(
                id="AWS-APP-003",
                category="Container Registry Security",
                control_name="Enforce ECR Immutable Image Tags & Amazon Inspector Vulnerability Scanning",
                description="Elastic Container Registry (ECR) repositories must enforce imageTagMutability=IMMUTABLE and continuous scanning via Amazon Inspector.",
                current_value="10 of 12 ECR repositories set to IMMUTABLE with Inspector enabled",
                recommended_value="100% ECR repositories IMMUTABLE with Inspector continuous scanning",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="aws ecr describe-repositories",
                remediation_notes="Update imageTagMutability to IMMUTABLE on 'dev-backend-repo' and 'qa-worker-repo'."
            ),
            SecurityRequirementItem(
                id="AWS-APP-004",
                category="Serverless Code Integrity",
                control_name="Enforce AWS Signer Code Signing on Lambda Functions",
                description="Production Lambda functions must require a trusted AWS Signer signing profile to prevent unauthorized code tampering.",
                current_value="Code signing configuration 'signer-prod-profile' enforced on 100% of production Lambdas",
                recommended_value="Mandatory code signing profile attached to Lambda execution environments",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="aws lambda list-code-signing-configs",
                remediation_notes="Rotate code signing certificates in accordance with enterprise PKI policies."
            )
        ]


if __name__ == "__main__":
    extractor = AWSApplicationSecurityExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} AWS Application Security items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
