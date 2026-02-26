"""
Azure Network Security Requirements & Configuration Extractor.
Extracts Network Security Group (NSG) rules, Azure Firewall IDPS enablement,
DDoS Protection plans, and Application Gateway WAF rules.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class AzureNetworkSecurityExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="Azure", domain_name="network_security", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires Azure CLI / SDK credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="AZURE-NET-001",
                category="Network Security Groups (NSGs)",
                control_name="Prohibit Ingress from Internet on RDP (3389) and SSH (22)",
                description="NSG inbound security rules must deny 0.0.0.0/0 on RDP and SSH ports.",
                current_value="NSG 'nsg-prod-app' denies all internet management traffic",
                recommended_value="0 NSGs allow unrestricted Internet access on ports 22/3389",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="az network nsg list",
                remediation_notes="Use Azure Bastion for remote administrative VM access."
            ),
            SecurityRequirementItem(
                id="AZURE-NET-002",
                category="Perimeter Security",
                control_name="Enforce Azure Firewall Premium with IDPS and TLS Inspection",
                description="Hub-and-spoke VNet architectures must route egress/ingress traffic through Azure Firewall Premium with IDPS enabled in Alert & Deny mode.",
                current_value="Azure Firewall Standard deployed without IDPS",
                recommended_value="Azure Firewall Premium with IDPS Mode = 'AlertAndDeny'",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="az network firewall list",
                remediation_notes="Upgrade Azure Firewall SKU from Standard to Premium and configure IDPS signatures."
            ),
            SecurityRequirementItem(
                id="AZURE-NET-003",
                category="DDoS Protection",
                control_name="Enable Azure DDoS Protection Standard on Production Virtual Networks",
                description="Production VNets hosting internet-facing endpoints must be enrolled in Azure DDoS Protection Standard.",
                current_value="DDoS Standard enabled on 'vnet-hub-prod'",
                recommended_value="DDoS Standard protection plan attached to all public VNets",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="az network ddos-protection list",
                remediation_notes="Review DDoS alert telemetry in Azure Monitor log workspace."
            ),
            SecurityRequirementItem(
                id="AZURE-NET-004",
                category="Web Application Firewall",
                control_name="Enable WAF in Prevention Mode on Application Gateway / Front Door",
                description="Application Gateways and Front Door endpoints must execute WAF in Prevention mode with OWASP Core Rule Set 3.2+.",
                current_value="App Gateway WAF in Prevention mode with CRS 3.2",
                recommended_value="WAF = Prevention mode across 100% of public HTTP/HTTPS listeners",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="az network application-gateway waf-config show",
                remediation_notes="Regularly review WAF firewall logs for false positives and custom exclusion rules."
            )
        ]


if __name__ == "__main__":
    extractor = AzureNetworkSecurityExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} Azure Network Security items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
