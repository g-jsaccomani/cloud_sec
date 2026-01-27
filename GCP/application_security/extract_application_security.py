"""
GCP Application & API Security Requirements Extractor.
Extracts Apigee / API Gateway authentication postures, Secret Manager CMEK & rotation,
Artifact Registry container vulnerability scanning, and Binary Authorization rules.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class GCPApplicationSecurityExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="GCP", domain_name="application_security", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires GCP SDK credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="GCP-APP-001",
                category="API Security",
                control_name="Enforce OAuth2 / JWT Authorization on Apigee / API Gateways",
                description="All external APIs must require valid OAuth2 access tokens or JWT signatures validated at the API Gateway edge.",
                current_value="100% of production API routes enforce JWT verification with short TTL (< 15 min)",
                recommended_value="Mandatory OAuth2 / JWT verification on all published API endpoints",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="gcloud api-gateway api-configs describe",
                remediation_notes="Implement Apigee rate-limiting and spike arrest policies."
            ),
            SecurityRequirementItem(
                id="GCP-APP-002",
                category="Secrets Management",
                control_name="Enforce Secret Manager for All Application Credentials & Auto-Rotation",
                description="Applications must fetch DB passwords and API tokens from GCP Secret Manager; no plain-text secrets in environment variables.",
                current_value="18 secrets stored in Secret Manager; 2 legacy services use plain-text env vars",
                recommended_value="100% Secret Manager adoption with Cloud Function automatic 90-day rotation",
                status="NON_COMPLIANT",
                severity="CRITICAL",
                evidence_source="gcloud secrets list",
                remediation_notes="Migrate legacy DB connection strings to Secret Manager and configure rotation schedule."
            ),
            SecurityRequirementItem(
                id="GCP-APP-003",
                category="DevSecOps & Supply Chain",
                control_name="Enable Artifact Registry Automatic Vulnerability Scanning",
                description="Container images pushed to Artifact Registry must undergo automatic vulnerability scanning for CVEs before deployment.",
                current_value="On-push vulnerability scanning active; 4 high CVEs detected in 'base-python-image'",
                recommended_value="Automatic CVE scanning enabled with CI/CD build break on Critical/High CVEs",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="gcloud artifacts docker images list",
                remediation_notes="Update base images and patch OpenSSL/Python dependencies."
            ),
            SecurityRequirementItem(
                id="GCP-APP-004",
                category="Container Runtime Security",
                control_name="Enforce Binary Authorization on GKE and Cloud Run",
                description="Only container images signed by authorized CI/CD attestors may be deployed to production GKE clusters and Cloud Run services.",
                current_value="Binary Authorization policy deployed in Report-Only mode on Cloud Run",
                recommended_value="Enforced Binary Authorization policy requiring valid CI/CD attestation",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="gcloud container binauthz policy describe",
                remediation_notes="Switch Binary Authorization mode from Report-Only to Enforce for production project."
            )
        ]


if __name__ == "__main__":
    extractor = GCPApplicationSecurityExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} GCP Application Security items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
