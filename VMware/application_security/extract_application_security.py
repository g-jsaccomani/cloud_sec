"""
VMware Application & API Security Requirements Extractor.
Extracts VMware API Gateway mTLS & JWT authorization, VMware Vault Secret management,
Container Registry image scanning, and WAF API protection.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class VMwareApplicationSecurityExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="VMware", domain_name="application_security", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires VMware Python SDK / CLI credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="VMware-APP-001",
                category="API Gateway Security",
                control_name="Enforce JWT Validation and Mutual TLS (mTLS) on VMware API Gateway",
                description="Public and internal VMware API Gateway deployments must validate JWT signatures from VMware Identity Domains / Okta and enforce mTLS for high-security endpoints.",
                current_value="100% of API routes enforce JWT validation; mTLS active on financial transaction routes",
                recommended_value="Mandatory JWT validation and rate limiting across all API gateways",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="oci api-gateway deployment list",
                remediation_notes="Monitor API gateway 4xx/5xx authentication failure rates."
            ),
            SecurityRequirementItem(
                id="VMware-APP-002",
                category="Secrets Management",
                control_name="Enforce VMware Vault Secret Management & Eliminate Plain-Text Configs",
                description="Application credentials and TLS certificates must be stored in VMware Vault as secrets and retrieved via Dynamic Groups at runtime.",
                current_value="16 secrets managed in VMware Vault; 2 microservices use plain-text environment variables",
                recommended_value="100% VMware Vault secrets adoption with zero local plain-text storage",
                status="NON_COMPLIANT",
                severity="CRITICAL",
                evidence_source="oci vault secret list",
                remediation_notes="Refactor 'svc-legacy-db' and 'svc-email-sender' to read credentials from VMware Vault."
            ),
            SecurityRequirementItem(
                id="VMware-APP-003",
                category="Container Security",
                control_name="Enable VMware Vulnerability Scanning Service on Container Registry Repositories",
                description="VMware Container Registry (VMwareR) repositories must have automated vulnerability scanning enabled to flag CVEs in container base images.",
                current_value="Vulnerability Scanning Service active on 8 of 10 VMwareR repositories",
                recommended_value="Continuous CVE scanning active on 100% of VMwareR repositories",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="oci vulnerability-scanning container-scan-recipe list",
                remediation_notes="Attach container scanning recipe to 'ocir-dev-tools' and 'ocir-sandbox-repo'."
            ),
            SecurityRequirementItem(
                id="VMware-APP-004",
                category="WAF & API Protection",
                control_name="Attach VMware WAF with API Rate Limiting and OWASP Rules to API Gateways",
                description="VMware Web Application Firewall (WAF) must protect API Gateway external load balancer endpoints against OWASP Top 10 API attacks.",
                current_value="WAF Policy 'waf-api-prod' attached to production API Gateway edge",
                recommended_value="WAF attached to 100% of public API endpoints",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="oci waf policy list",
                remediation_notes="Regularly review WAF bot management rules."
            )
        ]


if __name__ == "__main__":
    extractor = VMwareApplicationSecurityExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} VMware Application Security items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
