"""
Azure IAM Security Requirements & Configuration Extractor.
Extracts Microsoft Entra ID Conditional Access policies,
Privileged Identity Management (PIM) rules, Subscription Owner limits, and MFA posture.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class AzureIAMExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="Azure", domain_name="iam", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires Azure CLI / SDK credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="AZURE-IAM-001",
                category="Microsoft Entra ID Security",
                control_name="Enforce Conditional Access Policy: MFA for All Administrators",
                description="Entra ID Conditional Access must enforce phishing-resistant MFA for all administrative roles.",
                current_value="Policy 'CA-Require-MFA-Admins' active; 1 break-glass account exempted",
                recommended_value="MFA enforced on 100% of admin roles with monitored break-glass exceptions",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="az ad policy conditional-access policy list",
                remediation_notes="Regularly test alert triggering on break-glass emergency account sign-ins."
            ),
            SecurityRequirementItem(
                id="AZURE-IAM-002",
                category="Privileged Identity Management (PIM)",
                control_name="Enforce Just-in-Time (JIT) Activation for Subscription Owner/Contributor Roles",
                description="No permanent Owner or Contributor assignments; administrators must activate access via PIM with ticket approval.",
                current_value="3 permanent Subscription Owner assignments detected",
                recommended_value="0 permanent Owner assignments; enforce PIM JIT activation",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="az role assignment list --role Owner",
                remediation_notes="Convert permanent Owner assignments to Eligible PIM assignments with 8-hour max duration."
            ),
            SecurityRequirementItem(
                id="AZURE-IAM-003",
                category="Legacy Authentication",
                control_name="Block Legacy Authentication Protocols in Entra ID",
                description="Conditional Access policy must explicitly block legacy protocols (POP, IMAP, SMTP Auth, older Office clients).",
                current_value="Policy 'CA-Block-Legacy-Auth' enabled in Report-Only mode",
                recommended_value="Policy enabled in Enforce mode",
                status="NON_COMPLIANT",
                severity="CRITICAL",
                evidence_source="az rest --method get --url https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
                remediation_notes="Switch 'CA-Block-Legacy-Auth' state from 'reportOnly' to 'enabled'."
            ),
            SecurityRequirementItem(
                id="AZURE-IAM-004",
                category="Service Principals & Identities",
                control_name="Enforce Managed Identities over Client Secrets for Azure Resources",
                description="Azure VMs, App Services, and Functions must use User-Assigned or System-Assigned Managed Identities instead of client secrets.",
                current_value="85% of services use Managed Identities; 3 App Services use client secrets",
                recommended_value="100% adoption of Managed Identities for intra-Azure service authentication",
                status="NON_COMPLIANT",
                severity="MEDIUM",
                evidence_source="az identity list",
                remediation_notes="Migrate legacy App Service database connections to Managed Identity with Entra Auth."
            )
        ]


if __name__ == "__main__":
    extractor = AzureIAMExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} Azure IAM items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
