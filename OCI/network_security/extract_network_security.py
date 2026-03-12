"""
OCI Network Security Requirements & Configuration Extractor.
Extracts VCN Security Lists, Network Security Groups (NSGs),
OCI Web Application Firewall (WAF) rules, and VCN Flow Logs enablement.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class OCINetworkSecurityExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="OCI", domain_name="network_security", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires OCI Python SDK / CLI credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="OCI-NET-001",
                category="Security Lists & NSGs",
                control_name="Prohibit 0.0.0.0/0 Ingress on SSH (22) and RDP (3389) in VCN Security Lists",
                description="Default and custom VCN Security Lists must not allow unrestricted ingress on administrative ports.",
                current_value="Default Security List in VCN 'vcn-prod-01' blocks 0.0.0.0/0 on 22/3389",
                recommended_value="0 Security Lists / NSGs permit 0.0.0.0/0 on ports 22/3389",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="oci network security-list list / oci network nsg list",
                remediation_notes="Use OCI Bastion service for administrative SSH/RDP sessions."
            ),
            SecurityRequirementItem(
                id="OCI-NET-002",
                category="Web Application Firewall",
                control_name="Enforce OCI WAF Edge Protection on Public HTTP/HTTPS Endpoints",
                description="Load balancers serving external web traffic must be protected by an OCI WAF policy with OWASP protection enabled.",
                current_value="WAF Policy 'waf-prod-portal' active on external Load Balancer",
                recommended_value="100% of public web endpoints protected by OCI WAF",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="oci waf policy list",
                remediation_notes="Monitor WAF bot management rules and rate limiting logs."
            ),
            SecurityRequirementItem(
                id="OCI-NET-003",
                category="Network Visibility",
                control_name="Enable VCN Flow Logs on All Production Subnets",
                description="VCN Flow Logs must be enabled and exporting to OCI Logging service for forensic network auditing.",
                current_value="Flow logs active on 6 of 8 subnets",
                recommended_value="100% VCN subnet flow log enablement",
                status="NON_COMPLIANT",
                severity="MEDIUM",
                evidence_source="oci logging log list",
                remediation_notes="Enable flow logs on 'sub-prod-db' and 'sub-mgmt' subnets."
            ),
            SecurityRequirementItem(
                id="OCI-NET-004",
                category="Private Connectivity",
                control_name="Enforce FastConnect Private Peering with BGP MD5 Authentication",
                description="On-premises connectivity via OCI FastConnect must use private peering with BGP MD5 authentication enabled.",
                current_value="FastConnect Private Peering active; BGP MD5 Auth enabled",
                recommended_value="Private Peering = True, BGP MD5 Authentication = Enabled",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="oci network fast-connect list",
                remediation_notes="Rotate BGP authentication keys annually."
            )
        ]


if __name__ == "__main__":
    extractor = OCINetworkSecurityExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} OCI Network Security items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
