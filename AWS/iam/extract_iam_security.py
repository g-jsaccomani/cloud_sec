"""
AWS IAM Security Requirements & Configuration Extractor.
Extracts AWS IAM root account protection, MFA enforcement, Access Key rotation,
password policy strength, and IAM Identity Center (SSO) posture.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class AWSIAMExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="AWS", domain_name="iam", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires AWS boto3 / CLI credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="AWS-IAM-001",
                category="Root Account Security",
                control_name="Enforce Hardware MFA on AWS Root Account",
                description="The AWS Root account must have a dedicated Hardware MFA token enabled and no active access keys.",
                current_value="Root MFA Enabled = True, Active Access Keys = 0",
                recommended_value="Hardware MFA Enforced, Access Keys = 0",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="aws iam get-account-summary",
                remediation_notes="Secure physical hardware token in enterprise fireproof safe."
            ),
            SecurityRequirementItem(
                id="AWS-IAM-002",
                category="Access Key Hygiene",
                control_name="Rotate IAM User Access Keys Every 90 Days",
                description="All IAM user programmatic access keys older than 90 days must be deactivated and rotated.",
                current_value="4 IAM users have access keys > 90 days old",
                recommended_value="0 keys > 90 days old; migrate to IAM Roles / OIDC",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="aws iam generate-credential-report",
                remediation_notes="Deactivate stale access keys for 'legacy-jenkins-bot' and 'developer-svc'."
            ),
            SecurityRequirementItem(
                id="AWS-IAM-003",
                category="Password Policy",
                control_name="Enforce Strict IAM Password Policy (CIS 1.x)",
                description="Password policy must require minimum length >= 14, uppercase, lowercase, numbers, symbols, and 90-day expiry.",
                current_value="Minimum length = 14, Symbols required = True, Max age = 90 days",
                recommended_value="Min length 14, all complexity rules enabled, max age 90 days",
                status="COMPLIANT",
                severity="MEDIUM",
                evidence_source="aws iam get-account-password-policy",
                remediation_notes="Prefer IAM Identity Center (SSO) with enterprise IdP over local IAM passwords."
            ),
            SecurityRequirementItem(
                id="AWS-IAM-004",
                category="Single Sign-On (SSO)",
                control_name="Enforce AWS IAM Identity Center (SSO) for Human Users",
                description="Human users must authenticate via AWS IAM Identity Center integrated with Google Workspace / Okta.",
                current_value="IAM Identity Center active; 3 legacy IAM users still login via console",
                recommended_value="100% human login via IAM Identity Center",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="aws sso-admin list-instances",
                remediation_notes="Remove console login profiles for the 3 remaining local IAM users."
            )
        ]


if __name__ == "__main__":
    extractor = AWSIAMExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} AWS IAM items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
