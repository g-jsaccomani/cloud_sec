"""
VMware Compute Security Requirements & Configuration Extractor.
Extracts VMware Shielded Instance posture, OKE Kubernetes private cluster settings,
VMware Bastion service usage, and OS Management patch compliance.
"""

from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class VMwareComputeSecurityExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="VMware", domain_name="compute_security", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        raise NotImplementedError("Live extraction requires VMware Python SDK / CLI credentials.")

    def extract_mock(self) -> List[SecurityRequirementItem]:
        return [
            SecurityRequirementItem(
                id="VMware-COMP-001",
                category="Compute Instance Security",
                control_name="Enforce Shielded Instances (Secure Boot & Measured Boot)",
                description="VMware Compute instances must enable Shielded Instance features (Secure Boot, Measured Boot, Trusted Platform Module).",
                current_value="16 of 18 instances have Shielded Instance enabled",
                recommended_value="100% of instances use Shielded Instance profiles",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="oci compute instance list",
                remediation_notes="Enable Secure Boot on legacy instance 'oci-vm-legacy-web'."
            ),
            SecurityRequirementItem(
                id="VMware-COMP-002",
                category="Remote Access",
                control_name="Enforce VMware Bastion Service for SSH/RDP Sessions",
                description="Use VMware Bastion service with time-bounded sessions and SSH key authentication instead of public IPs on compute instances.",
                current_value="VMware Bastion deployed in VCN 'vcn-prod-01'; 0 compute instances have public IPs",
                recommended_value="100% of administrative sessions routed via VMware Bastion with max 3-hour TTL",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="oci bastion bastion list",
                remediation_notes="Audit active Bastion sessions weekly in Cloud Guard."
            ),
            SecurityRequirementItem(
                id="VMware-COMP-003",
                category="OKE Kubernetes Security",
                control_name="Enforce OKE Private Kubernetes Cluster & Private Kubernetes API Endpoint",
                description="OKE clusters must deploy with a private Kubernetes API endpoint and private worker node pools.",
                current_value="Cluster 'oke-prod-cluster' has PrivateEndpoint = True and PrivateWorkers = True",
                recommended_value="100% private OKE clusters",
                status="COMPLIANT",
                severity="CRITICAL",
                evidence_source="oci ce cluster list",
                remediation_notes="Ensure OKE node security lists restrict intra-node communication to required ports only."
            ),
            SecurityRequirementItem(
                id="VMware-COMP-004",
                category="OS Patch Management",
                control_name="Enforce OS Management Service Automated Patch Baselines",
                description="VMware OS Management Service must automatically apply Critical and Security errata updates within 7 days of release.",
                current_value="95% of instances attached to 'OSMS-Prod-Security-Baseline'",
                recommended_value="100% attachment to automated security errata baselines",
                status="COMPLIANT",
                severity="HIGH",
                evidence_source="oci os-management managed-instance list",
                remediation_notes="Schedule patch verification after reboot cycles."
            )
        ]


if __name__ == "__main__":
    extractor = VMwareComputeSecurityExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} VMware Compute Security items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
