"""
AWS Data Protection Requirements & Configuration Extractor.
Extracts S3 Block Public Access settings, S3 default KMS encryption,
EBS default account encryption, and RDS storage encryption.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class AWSDataProtectionExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="AWS", domain_name="data_protection", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires AWS boto3 / CLI credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="AWS-DATA-001",
                category="S3 Storage Security",
                control_name="Enforce S3 Block Public Access at Account Level",
                description="The account-level S3 Block Public Access setting must have all 4 flags set to TRUE.",
                current_value="All 4 flags (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets) = TRUE",
                recommended_value="100% Account-level S3 Block Public Access = TRUE",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="aws s3control get-public-access-block",
                remediation_notes="Maintain AWS SCP to prevent disabling S3 Block Public Access."
            ),
            SecurityRequirementItem(
                id="AWS-DATA-002",
                category="S3 Storage Security",
                control_name="Enforce S3 Bucket Default Encryption with Customer Managed KMS Keys",
                description="All S3 buckets must be encrypted by default using AWS KMS Customer Managed Keys (CMK).",
                current_value="3 buckets using SSE-S3 default encryption instead of SSE-KMS",
                recommended_value="SSE-KMS with Customer Managed Key for all sensitive buckets",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="aws s3api get-bucket-encryption",
                remediation_notes="Update default bucket encryption on 'app-log-backup' to use KMS CMK."
            ),
            SecurityRequirementItem(
                id="AWS-DATA-003",
                category="EBS Storage Encryption",
                control_name="Enable EBS Default Encryption at Account Level",
                description="Account-level default EBS volume encryption must be enabled in all active regions.",
                current_value="Enabled in us-east-1 and us-west-2; Disabled in eu-central-1",
                recommended_value="EBS Default Encryption enabled across 100% of regions",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="aws ec2 get-ebs-encryption-by-default",
                remediation_notes="Run 'aws ec2 enable-ebs-encryption-by-default --region eu-central-1'."
            ),
            SecurityRequirementItem(
                id="AWS-DATA-004",
                category="Database Security",
                control_name="Enforce Storage Encryption & Auto-Minor Version Upgrade on RDS",
                description="RDS database instances must use KMS encryption at rest and have automatic minor upgrades enabled.",
                current_value="Encrypted with KMS = True on 100% of RDS instances",
                recommended_value="StorageEncrypted = True, AutoMinorVersionUpgrade = True",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="aws rds describe-db-instances",
                remediation_notes="Regularly audit database parameter groups for enforce_ssl = 1."
            )
        ]


if __name__ == "__main__":
    extractor = AWSDataProtectionExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} AWS Data Protection items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
