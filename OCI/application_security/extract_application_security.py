"""
OCI Application & API Security Requirements Extractor.
Extracts OCI API Gateway mTLS & JWT authorization, OCI Vault Secret management,
Container Registry image scanning, and WAF API protection.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class OCIApplicationSecurityExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="OCI", domain_name="application_security", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires OCI Python SDK / CLI credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="OCI-APP-001",
                category="API Gateway Security",
                control_name="Enforce JWT Validation and Mutual TLS (mTLS) on OCI API Gateway",
                description="Public and internal OCI API Gateway deployments must validate JWT signatures from OCI Identity Domains / Okta and enforce mTLS for high-security endpoints.",
                current_value="100% of API routes enforce JWT validation; mTLS active on financial transaction routes",
                recommended_value="Mandatory JWT validation and rate limiting across all API gateways",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="oci api-gateway deployment list",
                remediation_notes="Monitor API gateway 4xx/5xx authentication failure rates."
            ),
            SecurityRequirementItem(
                id="OCI-APP-002",
                category="Secrets Management",
                control_name="Enforce OCI Vault Secret Management & Eliminate Plain-Text Configs",
                description="Application credentials and TLS certificates must be stored in OCI Vault as secrets and retrieved via Dynamic Groups at runtime.",
                current_value="16 secrets managed in OCI Vault; 2 microservices use plain-text environment variables",
                recommended_value="100% OCI Vault secrets adoption with zero local plain-text storage",
                status="NON_COMPLIANT",
                severity="CRITICAL",
                evidence_source="oci vault secret list",
                remediation_notes="Refactor 'svc-legacy-db' and 'svc-email-sender' to read credentials from OCI Vault."
            ),
            SecurityRequirementItem(
                id="OCI-APP-003",
                category="Container Security",
                control_name="Enable OCI Vulnerability Scanning Service on Container Registry Repositories",
                description="OCI Container Registry (OCIR) repositories must have automated vulnerability scanning enabled to flag CVEs in container base images.",
                current_value="Vulnerability Scanning Service active on 8 of 10 OCIR repositories",
                recommended_value="Continuous CVE scanning active on 100% of OCIR repositories",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="oci vulnerability-scanning container-scan-recipe list",
                remediation_notes="Attach container scanning recipe to 'ocir-dev-tools' and 'ocir-sandbox-repo'."
            ),
            SecurityRequirementItem(
                id="OCI-APP-004",
                category="WAF & API Protection",
                control_name="Attach OCI WAF with API Rate Limiting and OWASP Rules to API Gateways",
                description="OCI Web Application Firewall (WAF) must protect API Gateway external load balancer endpoints against OWASP Top 10 API attacks.",
                current_value="WAF Policy 'waf-api-prod' attached to production API Gateway edge",
                recommended_value="WAF attached to 100% of public API endpoints",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="oci waf policy list",
                remediation_notes="Regularly review WAF bot management rules."
            )
        ]


if __name__ == "__main__":
    extractor = OCIApplicationSecurityExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} OCI Application Security items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
