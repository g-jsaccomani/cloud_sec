"""
AWS Compute Security Requirements & Configuration Extractor.
Extracts EC2 Instance Metadata Service (IMDSv2) enforcement,
EKS cluster endpoint security, IRSA (IAM Roles for Service Accounts), and Lambda VPC isolation.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class AWSComputeSecurityExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="AWS", domain_name="compute_security", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires AWS boto3 / CLI credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="AWS-COMP-001",
                category="EC2 Compute Security",
                control_name="Enforce IMDSv2 (Instance Metadata Service v2) on EC2 Instances",
                description="EC2 instances must require IMDSv2 (HttpTokens=required) to mitigate SSRF attack vectors.",
                current_value="18 of 20 EC2 instances require IMDSv2; 2 allow IMDSv1",
                recommended_value="100% of instances require IMDSv2 (HttpTokens = 'required')",
                status="NON_COMPLIANT",
                severity="CRITICAL",
                evidence_source="aws ec2 describe-instances",
                remediation_notes="Run 'aws ec2 modify-instance-metadata-options --instance-id <ID> --http-tokens required'."
            ),
            SecurityRequirementItem(
                id="AWS-COMP-002",
                category="EKS Kubernetes Security",
                control_name="Restrict EKS Control Plane Public Endpoint Access",
                description="EKS cluster API endpoints must be private or restricted to authorized enterprise CIDRs.",
                current_value="Cluster 'prod-eks-01' has PrivateAccess=True and PublicAccess=False",
                recommended_value="endpointPrivateAccess = True, endpointPublicAccess = False",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="aws eks describe-cluster",
                remediation_notes="Ensure worker node security groups allow HTTPS only from control plane ENIs."
            ),
            SecurityRequirementItem(
                id="AWS-COMP-003",
                category="EKS Kubernetes Security",
                control_name="Enforce IAM Roles for Service Accounts (IRSA)",
                description="EKS workloads must use OIDC federated IRSA rather than node IAM role permissions.",
                current_value="OIDC provider configured; 100% of pods use IRSA annotations",
                recommended_value="All pods adopt IRSA; Node IAM roles stripped of application permissions",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="aws eks describe-cluster (identity.oidc)",
                remediation_notes="Audit IAM trust policies on IRSA execution roles."
            ),
            SecurityRequirementItem(
                id="AWS-COMP-004",
                category="Serverless Security",
                control_name="Enforce VPC Attachment for Sensitive Lambda Functions",
                description="Lambda functions accessing internal databases or Redis must execute within private VPC subnets.",
                current_value="All backend Lambda functions attached to private subnets with NAT Gateway",
                recommended_value="VpcConfig defined for internal-facing serverless functions",
                status="COMPLIANT",
                severity="MEDIUM",
                evidence_source="aws lambda list-functions",
                remediation_notes="Ensure Lambda execution roles do not contain wildcard resource permissions."
            )
        ]


if __name__ == "__main__":
    extractor = AWSComputeSecurityExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} AWS Compute Security items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
