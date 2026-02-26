"""
Azure Data Protection Requirements & Configuration Extractor.
Extracts Storage Account public access prevention, Key Vault soft-delete
& purge protection, Azure SQL Transparent Data Encryption (TDE), and Managed Disk encryption.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class AzureDataProtectionExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="Azure", domain_name="data_protection", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires Azure CLI / SDK credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="AZURE-DATA-001",
                category="Storage Account Security",
                control_name="Disable Blob Public Access on All Storage Accounts",
                description="Storage accounts must have 'allowBlobPublicAccess' set to false to prevent anonymous read access.",
                current_value="12 accounts have allowBlobPublicAccess = false; 1 account set to true",
                recommended_value="allowBlobPublicAccess = false across 100% of accounts",
                status="NON_COMPLIANT",
                severity="CRITICAL",
                evidence_source="az storage account list",
                remediation_notes="Run 'az storage account update --name <name> --allow-blob-public-access false'."
            ),
            SecurityRequirementItem(
                id="AZURE-DATA-002",
                category="Key Vault Security",
                control_name="Enforce Soft-Delete and Purge Protection on Azure Key Vaults",
                description="Key Vaults must have both soft-delete (90 days retention) and purge protection enabled.",
                current_value="Soft-delete enabled on 100% of vaults; Purge Protection disabled on 'kv-dev-keys'",
                recommended_value="Soft-Delete = True, Purge Protection = True",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="az keyvault list",
                remediation_notes="Enable purge protection on 'kv-dev-keys' to protect against malicious key deletion."
            ),
            SecurityRequirementItem(
                id="AZURE-DATA-003",
                category="Database Security",
                control_name="Enforce Transparent Data Encryption (TDE) with Customer Managed Keys on Azure SQL",
                description="Azure SQL databases must use TDE with Customer Managed Keys (CMK) stored in Azure Key Vault.",
                current_value="TDE enabled with Microsoft-managed keys",
                recommended_value="TDE enabled with Key Vault Customer-Managed Key (CMK)",
                status="MANUAL_REVIEW",
                severity="MEDIUM",
                evidence_source="az sql db tde show",
                remediation_notes="Evaluate requirement for Customer Managed Key TDE versus platform default encryption."
            ),
            SecurityRequirementItem(
                id="AZURE-DATA-004",
                category="Storage Security",
                control_name="Enforce Minimum TLS Version 1.2 on All Storage Accounts",
                description="Storage account connections must enforce minimumTlsVersion = 'TLS1_2'.",
                current_value="100% of Storage Accounts require TLS 1.2",
                recommended_value="minimumTlsVersion = 'TLS1_2'",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="az storage account list",
                remediation_notes="Verify client compatibility with TLS 1.3 as it becomes available."
            )
        ]


if __name__ == "__main__":
    extractor = AzureDataProtectionExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} Azure Data Protection items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
