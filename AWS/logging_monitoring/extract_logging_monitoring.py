"""
AWS Logging & Monitoring Requirements & Configuration Extractor.
Extracts AWS CloudTrail multi-region trails, GuardDuty status,
AWS Config configuration recorders, and Security Hub enablement.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class AWSLoggingMonitoringExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="AWS", domain_name="logging_monitoring", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires AWS boto3 / CLI credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="AWS-LOG-001",
                category="CloudTrail Auditing",
                control_name="Enable Multi-Region CloudTrail with Log File Validation",
                description="An organizational multi-region trail must be enabled with log file validation and KMS encryption.",
                current_value="Org Trail 'org-security-trail' active; Log File Validation = TRUE",
                recommended_value="IsMultiRegionTrail = True, LogFileValidationEnabled = True",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="aws cloudtrail describe-trails",
                remediation_notes="Verify KMS key policy allows CloudTrail encryption across all accounts."
            ),
            SecurityRequirementItem(
                id="AWS-LOG-002",
                category="Threat Detection",
                control_name="Enable AWS GuardDuty across all Operating Regions",
                description="GuardDuty must be enabled with Kubernetes, S3, and RDS protection plans active.",
                current_value="Enabled in us-east-1 and us-west-2; S3 protection active",
                recommended_value="GuardDuty active in 100% of enabled regions with EKS/S3/RDS protection",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="aws guardduty list-detectors",
                remediation_notes="Forward GuardDuty findings via EventBridge to SIEM / PagerDuty."
            ),
            SecurityRequirementItem(
                id="AWS-LOG-003",
                category="Configuration Tracking",
                control_name="Enable AWS Config Continuous Recording for All Resources",
                description="AWS Config must record all supported resource types, including global IAM resources.",
                current_value="Config recorder active in us-east-1; missing in us-west-2",
                recommended_value="AWS Config enabled organization-wide with central aggregator",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="aws configservice describe-configuration-recorders",
                remediation_notes="Deploy AWS Config Aggregator in security logging account."
            ),
            SecurityRequirementItem(
                id="AWS-LOG-004",
                category="CSPM & Posture",
                control_name="Enable AWS Security Hub with CIS AWS Foundations Benchmark",
                description="Security Hub must be enabled in central security account with CIS Foundations standard active.",
                current_value="Security Hub active; CIS Foundations score = 84%",
                recommended_value="Security Hub enabled across all accounts; target CIS score >= 90%",
                status="COMPLIANT",
                severity="MEDIUM",
                evidence_source="aws securityhub describe-hub",
                remediation_notes="Address medium/high findings in IAM and S3 control groups."
            )
        ]


if __name__ == "__main__":
    extractor = AWSLoggingMonitoringExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} AWS Logging & Monitoring items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
