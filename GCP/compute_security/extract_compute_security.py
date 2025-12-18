"""
GCP Compute Security Requirements & Configuration Extractor.
Extracts Compute Engine Shielded VM status, OS Login enforcement,
GKE Private Cluster settings, and GKE Workload Identity.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class GCPComputeSecurityExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="GCP", domain_name="compute_security", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires GCP SDK credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="GCP-COMP-001",
                category="Compute Engine Security",
                control_name="Enforce Shielded VM (Secure Boot & vTPM) on all instances",
                description="All Compute Engine VMs must have Secure Boot, vTPM, and Integrity Monitoring enabled.",
                current_value="12 of 14 VMs have Shielded VM Secure Boot enabled",
                recommended_value="100% Shielded VMs with Secure Boot = True",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="gcloud compute instances list",
                remediation_notes="Enable Secure Boot on legacy instances 'vm-legacy-app-1' and 'vm-legacy-app-2'."
            ),
            SecurityRequirementItem(
                id="GCP-COMP-002",
                category="Compute Engine Security",
                control_name="Enforce OS Login for SSH Access Management",
                description="Project-wide metadata must enable OS Login (enable-oslogin = TRUE) to eliminate static SSH keys.",
                current_value="enable-oslogin = TRUE at project metadata level",
                recommended_value="enable-oslogin = TRUE across all projects",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="gcloud compute project-info describe",
                remediation_notes="Use OS Login with 2SV for elevated admin access."
            ),
            SecurityRequirementItem(
                id="GCP-COMP-003",
                category="GKE Kubernetes Security",
                control_name="Enforce GKE Private Cluster & Authorized Networks",
                description="GKE clusters must be private (no external IP on nodes) with master authorized networks enforced.",
                current_value="Cluster 'prod-gke-01' is Private with Authorized Networks = 10.100.0.0/20",
                recommended_value="Private Cluster = True, Control Plane Authorized Networks restricted",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="gcloud container clusters describe",
                remediation_notes="Ensure GKE Control Plane authorized networks do not allow 0.0.0.0/0."
            ),
            SecurityRequirementItem(
                id="GCP-COMP-004",
                category="GKE Kubernetes Security",
                control_name="Enforce GKE Workload Identity on all Node Pools",
                description="GKE workloads must use Workload Identity to interact with GCP APIs without node Service Account impersonation.",
                current_value="Enabled on cluster 'prod-gke-01' node pools",
                recommended_value="Workload Identity pool enabled on 100% of clusters",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="gcloud container clusters describe --format='value(workloadIdentityConfig)'",
                remediation_notes="Audit pod ServiceAccounts mapped to GCP ServiceAccounts."
            )
        ]


if __name__ == "__main__":
    extractor = GCPComputeSecurityExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} GCP Compute Security items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
