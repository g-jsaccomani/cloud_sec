"""
GCP Data Protection Requirements & Configuration Extractor.
Extracts Cloud Storage Public Access Prevention, Uniform Bucket Level Access,
Cloud KMS CMEK encryption, BigQuery dataset security, and Cloud SQL SSL rules.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class GCPDataProtectionExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="GCP", domain_name="data_protection", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires GCP SDK credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="GCP-DATA-001",
                category="Cloud Storage Security",
                control_name="Enforce Public Access Prevention (PAP) on GCS Buckets",
                description="All Cloud Storage buckets must have Public Access Prevention set to 'enforced'.",
                current_value="2 buckets with Public Access Prevention set to 'unspecified'",
                recommended_value="Public Access Prevention = 'enforced' across 100% of buckets",
                status="NON_COMPLIANT",
                severity="CRITICAL",
                evidence_source="gcloud storage buckets describe",
                remediation_notes="Run 'gcloud storage buckets update gs://<bucket> --public-access-prevention=enforced'."
            ),
            SecurityRequirementItem(
                id="GCP-DATA-002",
                category="Cloud Storage Security",
                control_name="Enforce Uniform Bucket-Level Access (UBLA)",
                description="Prevent object-level ACLs by enforcing Uniform Bucket-Level Access.",
                current_value="UBLA Enabled on 100% of buckets",
                recommended_value="Uniform Bucket-Level Access = True",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="gcloud storage buckets list",
                remediation_notes="Maintain org policy constraint 'storage.uniformBucketLevelAccess'."
            ),
            SecurityRequirementItem(
                id="GCP-DATA-003",
                category="Key Management (CMEK)",
                control_name="Customer-Managed Encryption Keys (CMEK) for Sensitive Datasets",
                description="BigQuery datasets and Cloud SQL instances containing PII/PCI must use Cloud KMS CMEK.",
                current_value="CMEK configured for BigQuery analytics; default Google encryption on Cloud SQL dev",
                recommended_value="CMEK enforced for Production Cloud SQL, BigQuery, and GCS buckets",
                status="MANUAL_REVIEW",
                severity="HIGH",
                evidence_source="gcloud kms keys list / Cloud SQL describe",
                remediation_notes="Verify KMS key rotation period is set to <= 90 days and separation of duties is maintained."
            ),
            SecurityRequirementItem(
                id="GCP-DATA-004",
                category="Database Security",
                control_name="Enforce SSL/TLS Connections on Cloud SQL Instances",
                description="Cloud SQL instances must reject unencrypted connections (require_ssl = true).",
                current_value="SSL required on 4 of 4 Cloud SQL instances",
                recommended_value="require_ssl = true",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="gcloud sql instances describe",
                remediation_notes="Ensure client certificates are rotated annually."
            )
        ]


if __name__ == "__main__":
    extractor = GCPDataProtectionExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} GCP Data Protection items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
