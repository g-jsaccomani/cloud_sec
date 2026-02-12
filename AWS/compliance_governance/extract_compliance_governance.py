"""
AWS Compliance & Governance Requirements & Configuration Extractor.
Extracts AWS Organizations Service Control Policies (SCPs),
AWS Backup Vault Lock rules, SSM Patch Manager compliance, and Resource Tagging policies.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class AWSComplianceGovernanceExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="AWS", domain_name="compliance_governance", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires AWS boto3 / CLI credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="AWS-GOV-001",
                category="Service Control Policies (SCPs)",
                control_name="Enforce SCP Preventing CloudTrail & GuardDuty Deactivation",
                description="An Organization-level SCP must deny 'cloudtrail:StopLogging', 'cloudtrail:DeleteTrail', and 'guardduty:DisableOrganizationAdminAccount'.",
                current_value="SCP 'scp-guardrails-core' attached to Root Organization OU",
                recommended_value="Active guardrail SCP enforced on all member accounts",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="aws organizations list-policies",
                remediation_notes="Verify SCP exceptions are restricted to emergency break-glass roles."
            ),
            SecurityRequirementItem(
                id="AWS-GOV-002",
                category="Service Control Policies (SCPs)",
                control_name="Enforce SCP Restricting Permitted AWS Regions",
                description="Restrict AWS region operations to authorized data residency regions (e.g., us-east-1, us-west-2).",
                current_value="SCP 'scp-region-lock' enforced on Production OU",
                recommended_value="Region restriction SCP active across all OUs",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="aws organizations list-targets-for-policy",
                remediation_notes="Audit global service exceptions (IAM, CloudFront, Route53)."
            ),
            SecurityRequirementItem(
                id="AWS-GOV-003",
                category="Data Backup Governance",
                control_name="Enforce Immutable AWS Backup Vault Lock",
                description="Production AWS Backup vaults must have Vault Lock in Compliance mode to prevent backup deletion by ransomware.",
                current_value="Vault 'prod-backup-vault' has Vault Lock active (MinRetentionDays = 30)",
                recommended_value="Vault Lock Compliance Mode enabled on all primary vaults",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="aws backup describe-backup-vault",
                remediation_notes="Ensure disaster recovery restoration tests occur semi-annually."
            ),
            SecurityRequirementItem(
                id="AWS-GOV-004",
                category="Patch Management",
                control_name="Enforce SSM Patch Manager Compliance for EC2 & Hybrid Servers",
                description="All managed nodes must report compliant against enterprise patch baseline within 7 days of release.",
                current_value="92% of EC2 instances compliant with 'Enterprise-AmazonLinux-Baseline'",
                recommended_value="100% patch compliance across all OS distributions",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="aws ssm list-compliance-summaries",
                remediation_notes="Schedule patch maintenance window for 8 non-compliant instances."
            )
        ]


if __name__ == "__main__":
    extractor = AWSComplianceGovernanceExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} AWS Compliance & Governance items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
