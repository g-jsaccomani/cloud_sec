"""
Azure Logging & Monitoring Requirements & Configuration Extractor.
Extracts Microsoft Defender for Cloud enablement, Log Analytics workspace retention,
Azure Activity Log diagnostic exports, and Azure Monitor alert rules.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class AzureLoggingMonitoringExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="Azure", domain_name="logging_monitoring", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires Azure CLI / SDK credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="AZURE-LOG-001",
                category="Defender for Cloud",
                control_name="Enable Microsoft Defender for Cloud on All Key Resource Types",
                description="Defender for Cloud plans must be set to 'Standard' / enabled for Servers, Kubernetes, Storage, Key Vault, and SQL.",
                current_value="Servers, Storage, and Kubernetes enabled; Key Vault plan set to 'Free'",
                recommended_value="Standard Defender plan active across all supported resource types",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="az security pricing list",
                remediation_notes="Enable Microsoft Defender for Key Vault to detect unusual cryptographic operations."
            ),
            SecurityRequirementItem(
                id="AZURE-LOG-002",
                category="Activity Logging",
                control_name="Export Azure Activity Log to Log Analytics & Event Hub SIEM",
                description="Subscription Activity Logs (Administrative, Security, ServiceHealth, Alert) must export to a central Log Analytics workspace.",
                current_value="Diagnostic setting 'export-to-siem' active on 100% of subscriptions",
                recommended_value="Continuous Activity Log export active with >= 365 days retention",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="az monitor diagnostic-settings list",
                remediation_notes="Monitor Event Hub ingestion pipeline for SIEM connectivity."
            ),
            SecurityRequirementItem(
                id="AZURE-LOG-003",
                category="Log Retention",
                control_name="Enforce Minimum 365-Day Retention on Security Log Analytics Workspace",
                description="The central security Log Analytics workspace must retain audit telemetry for at least 1 year.",
                current_value="Workspace 'law-secops-central' retention = 365 days",
                recommended_value="retentionInDays >= 365",
                status="COMPLIANT",
                severity="MEDIUM",
                evidence_source="az monitor log-analytics workspace show",
                remediation_notes="Use Azure Monitor Archive Logs for long-term multi-year compliance retention."
            ),
            SecurityRequirementItem(
                id="AZURE-LOG-004",
                category="Alerting",
                control_name="Configure Security Alert Notifications for Subscription Admins",
                description="Microsoft Defender for Cloud must be configured to send high/critical security alerts to subscription owners and security email contacts.",
                current_value="Alert notifications enabled for 'secops@domain.com'",
                recommended_value="High/Critical alerts emailed to Security Operations & Subscription Owners",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="az security contact list",
                remediation_notes="Test alert notification email routing quarterly."
            )
        ]


if __name__ == "__main__":
    extractor = AzureLoggingMonitoringExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} Azure Logging & Monitoring items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
