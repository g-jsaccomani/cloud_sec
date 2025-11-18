"""
GCP IAM Security Requirements & Configuration Extractor.
Extracts Identity & Access Management policies, Service Account key hygiene,
workload federation settings, and primitive role usage.
"""

import subprocess
import json
from typing import List
from common.base_extractor import BaseSecurityExtractor, SecurityRequirementItem


class GCPIAMExtractor(BaseSecurityExtractor):
    def __init__(self, use_mock: bool = False):
        super().__init__(cloud_provider="GCP", domain_name="iam", use_mock=use_mock)

    def extract_live(self) -> List[SecurityRequirementItem]:
        """Attempts to extract live IAM data using gcloud CLI / SDK."""
        items = []
        try:
            res = subprocess.run(
                ["gcloud", "projects", "get-iam-policy", "g-jsaccomani", "--format=json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10
            )
            policy = json.loads(res.stdout)
            bindings = policy.get("bindings", [])
            has_owner_primitive = any(b.get("role") == "roles/owner" and len(b.get("members", [])) > 2 for b in bindings)
            
            items.append(
                SecurityRequirementItem(
                    id="GCP-IAM-001",
                    category="Identity & Access Management",
                    control_name="Restrict Primitive Role Usage (roles/owner)",
                    description="Ensure fewer than 3 members are assigned the primitive roles/owner role.",
                    current_value=f"Owner count > 2: {has_owner_primitive}",
                    recommended_value="False (Use predefined/custom RBAC roles)",
                    status="NON_COMPLIANT" if has_owner_primitive else "COMPLIANT",
                    severity="HIGH",
                    evidence_source="gcloud projects get-iam-policy",
                    remediation_notes="Replace roles/owner with least-privilege roles such as roles/viewer or resource-specific admin roles."
                )
            )
        except Exception as e:
            self.logger.warning(f"Live gcloud call failed: {e}")
            raise e
        return items

    def extract_mock(self) -> List[SecurityRequirementItem]:
        """Returns comprehensive mock/sample security requirements for GCP IAM."""
        return [
            SecurityRequirementItem(
                id="GCP-IAM-001",
                category="Identity & Access Management",
                control_name="Restrict Primitive Role Usage (roles/owner, roles/editor)",
                description="Ensure primitive roles (Owner/Editor) are not assigned to standard user accounts.",
                current_value="3 users assigned roles/editor, 2 users assigned roles/owner",
                recommended_value="0 users on primitive roles; enforce Least Privilege RBAC",
                status="NON_COMPLIANT",
                severity="HIGH",
                evidence_source="GCP Cloud IAM Policy Export",
                remediation_notes="Migrate users from roles/editor to domain-specific roles (e.g., roles/storage.objectViewer, roles/compute.instanceAdmin)."
            ),
            SecurityRequirementItem(
                id="GCP-IAM-002",
                category="Service Account Security",
                control_name="Service Account Key Expiration & Rotation",
                description="User-managed service account keys older than 90 days must be disabled and rotated.",
                current_value="2 Service Account keys > 120 days old detected",
                recommended_value="No user-managed keys > 90 days; prefer Workload Identity Federation",
                status="NON_COMPLIANT",
                severity="CRITICAL",
                evidence_source="gcloud iam service-accounts keys list",
                remediation_notes="Adopt GKE Workload Identity or OIDC Federation to eliminate long-lived Service Account JSON keys."
            ),
            SecurityRequirementItem(
                id="GCP-IAM-003",
                category="Authentication & SSO",
                control_name="Enforce 2SV / MFA in Cloud Identity",
                description="All human administrators and users must have 2-Step Verification (MFA) enforced.",
                current_value="2SV Enforced for 95% of users (2 exceptions)",
                recommended_value="100% 2SV enforcement across all org units",
                status="NON_COMPLIANT",
                severity="CRITICAL",
                evidence_source="Google Admin SDK / Cloud Security Command Center",
                remediation_notes="Enable mandatory 2SV in Google Cloud Identity / Workspace admin console."
            ),
            SecurityRequirementItem(
                id="GCP-IAM-004",
                category="Workload Federation",
                control_name="Workload Identity Federation for External CI/CD",
                description="Use Workload Identity Federation instead of static JSON keys for GitHub Actions / GitLab CI.",
                current_value="Workload Identity Pool 'github-actions-pool' configured",
                recommended_value="100% of CI/CD pipelines use WIF without stored credentials",
                status="COMPLIANT",
                severity="MEDIUM",
                evidence_source="gcloud iam workload-identity-pools list",
                remediation_notes="Maintain pool attribute conditions to restrict access to specific GitHub repos."
            )
        ]


if __name__ == "__main__":
    extractor = GCPIAMExtractor(use_mock=True)
    items = extractor.run()
    print(f"Extracted {len(items)} GCP IAM items.")

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
