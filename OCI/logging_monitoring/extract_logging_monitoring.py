"""
OCI Logging & Monitoring Requirements & Configuration Extractor.
Extracts OCI Cloud Guard detector recipes, Audit Service log retention,
Service Connector Hub SIEM export, and Logging Analytics status.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class OCILoggingMonitoringExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="OCI", domain_name="logging_monitoring", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires OCI Python SDK / CLI credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="OCI-LOG-001",
                category="Cloud Guard CSPM",
                control_name="Enable OCI Cloud Guard at Root Tenancy with Configuration & Threat Detectors",
                description="Cloud Guard must be enabled at the root tenancy target with Configuration Detector and Threat Detector recipes active.",
                current_value="Cloud Guard enabled at Root Target; Oracle-managed detector recipes active",
                recommended_value="Cloud Guard active on Root Tenancy with customized Enterprise detector recipe",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="oci cloud-guard target list",
                remediation_notes="Tune detector thresholds to reduce low-severity noise."
            ),
            SecurityRequirementItem(
                id="OCI-LOG-002",
                category="Audit Logs",
                control_name="Enforce Minimum 365-Day Retention for OCI Audit Service Logs",
                description="The OCI Audit Service retention period must be configured for at least 365 days.",
                current_value="Audit retention currently configured to 90 days",
                recommended_value="Retention period = 365 days",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="oci audit config get",
                remediation_notes="Run 'oci audit config update --retention-period-days 365'."
            ),
            SecurityRequirementItem(
                id="OCI-LOG-003",
                category="SIEM Integration",
                control_name="Configure OCI Service Connector Hub to Export Security & Audit Logs to SIEM",
                description="A Service Connector must stream Audit and VCN Flow Logs to Kafka / Object Storage archive for enterprise SIEM ingestion.",
                current_value="Service Connector 'sch-siem-export' streaming Audit logs to Object Storage archive",
                recommended_value="Active Service Connector streaming 100% of audit and security events",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="oci sch service-connector list",
                remediation_notes="Verify Object Storage lifecycle policy archives logs to cold tier after 90 days."
            ),
            SecurityRequirementItem(
                id="OCI-LOG-004",
                category="Logging Analytics",
                control_name="Enable OCI Logging Analytics for Core Workloads",
                description="Workload log groups must be onboarded to OCI Logging Analytics for anomaly detection and machine learning threat correlation.",
                current_value="Logging Analytics enabled for database and compute log groups",
                recommended_value="Onboard all production application log groups",
                status="COMPLIANT",
                severity="MEDIUM",
                evidence_source="oci log-analytics log-group list",
                remediation_notes="Create saved searches for failed login spikes."
            )
        ]


if __name__ == "__main__":
    extractor = OCILoggingMonitoringExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} OCI Logging & Monitoring items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
