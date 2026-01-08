"""
GCP Logging & Monitoring Requirements & Configuration Extractor.
Extracts Cloud Audit Logs configurations, VPC Flow Logs enablement,
Security Command Center (SCC) status, and SIEM export log sinks.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class GCPLoggingMonitoringExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="GCP", domain_name="logging_monitoring", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires GCP SDK credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="GCP-LOG-001",
                category="Cloud Audit Logs",
                control_name="Enable Data Access Audit Logs Across All Services",
                description="Admin Activity, Data Access (ADMIN_READ, DATA_READ, DATA_WRITE), and System Event logs must be enabled.",
                current_value="Data Access logs enabled for Cloud Storage and BigQuery; missing for IAM",
                recommended_value="Enable Data Access audit logging for all core services",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="gcloud projects get-iam-policy (auditConfigs)",
                remediation_notes="Update auditConfigs in organization IAM policy to capture all read/write data events."
            ),
            SecurityRequirementItem(
                id="GCP-LOG-002",
                category="Log Archiving & SIEM",
                control_name="Centralized Security Log Sink to Cloud Storage / PubSub SIEM",
                description="An aggregated log sink must export security logs to a dedicated, immutable archive bucket or Pub/Sub SIEM feed.",
                current_value="Aggregated org sink 'siem-security-export' active -> Pub/Sub topic",
                recommended_value="Active aggregated sink with Bucket Lock / retention policy >= 365 days",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="gcloud logging sinks list --organization=<ORG_ID>",
                remediation_notes="Verify Pub/Sub dead-letter queue metrics and SIEM ingestion SLA."
            ),
            SecurityRequirementItem(
                id="GCP-LOG-003",
                category="Security Posture Management",
                control_name="Security Command Center (SCC) Premium Tier & Continuous Monitoring",
                description="Security Command Center must be active at Org level with Event Threat Detection and Security Health Analytics.",
                current_value="SCC Enterprise Tier active; Event Threat Detection enabled",
                recommended_value="SCC Enterprise/Premium active across all organization folders",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="gcloud scc settings describe",
                remediation_notes="Review unassigned critical findings weekly."
            ),
            SecurityRequirementItem(
                id="GCP-LOG-004",
                category="Network Visibility",
                control_name="VPC Flow Logs Enabled with Appropriate Sampling Rate",
                description="VPC Flow Logs should be enabled on all production subnets with metadata annotation.",
                current_value="Enabled on 8 of 10 subnets (aggregation interval 5s, sample rate 0.5)",
                recommended_value="100% subnet coverage for production VPCs",
                status="NON_COMPLIANT",
                severity="MEDIUM",
                evidence_source="gcloud compute networks subnets list",
                remediation_notes="Enable flow logs on remaining subnets for network forensic readiness."
            )
        ]


if __name__ == "__main__":
    extractor = GCPLoggingMonitoringExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} GCP Logging & Monitoring items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
