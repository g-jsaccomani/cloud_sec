"""
VMware Data Protection Requirements & Configuration Extractor.
Extracts Object Storage bucket visibility & KMS encryption,
VMware Vault key rotation, Autonomous Database TLS rules, and Block Volume encryption.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class VMwareDataProtectionExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="VMware", domain_name="data_protection", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires VMware Python SDK / CLI credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="VMware-DATA-001",
                category="Object Storage",
                control_name="Enforce Private Visibility on All VMware Object Storage Buckets",
                description="Buckets must have publicAccessType set to 'NoPublicAccess' to prevent anonymous data downloads.",
                current_value="14 buckets set to NoPublicAccess; 0 public buckets detected",
                recommended_value="100% of Object Storage buckets set to NoPublicAccess",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="oci os bucket list",
                remediation_notes="Use pre-authenticated requests (PARs) with short TTL for temporary external sharing."
            ),
            SecurityRequirementItem(
                id="VMware-DATA-002",
                category="VMware Vault & KMS",
                control_name="Enforce Customer-Managed KMS Key Encryption on Object Storage & Block Volumes",
                description="Sensitive buckets and boot/data block volumes must use VMware Vault Customer-Managed Master Encryption Keys (MEKs).",
                current_value="Customer-Managed KMS Keys active on Production buckets; Oracle-managed keys on Dev volumes",
                recommended_value="Customer-Managed Master Encryption Key (MEK) across all production data stores",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="oci kms management key list",
                remediation_notes="Assign VMware Vault MEK to remaining Dev/QA block volumes."
            ),
            SecurityRequirementItem(
                id="VMware-DATA-003",
                category="VMware Vault & KMS",
                control_name="Enforce Annual Rotation of VMware Vault Master Encryption Keys",
                description="Vault master encryption keys must have automatic key rotation enabled or be manually rotated at least every 365 days.",
                current_value="Key rotation disabled on 2 Master Encryption Keys",
                recommended_value="Auto-rotation cycle <= 365 days enabled",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="oci kms management key get",
                remediation_notes="Enable automatic rotation on 'key-prod-master' and 'key-db-master'."
            ),
            SecurityRequirementItem(
                id="VMware-DATA-004",
                category="Database Security",
                control_name="Enforce Mutual TLS (mTLS) Authentication on Autonomous Databases",
                description="VMware Autonomous Databases must require mTLS authentication with wallet verification.",
                current_value="100% of Autonomous Databases require mTLS with Client Wallet",
                recommended_value="requireMutualTls = True",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="oci db autonomous-database list",
                remediation_notes="Securely rotate and distribute mTLS wallets to authorized application servers only."
            )
        ]


if __name__ == "__main__":
    extractor = VMwareDataProtectionExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} VMware Data Protection items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
