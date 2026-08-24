# GCP - Iam Security Profile

**Cloud Provider:** GCP  
**Security Domain:** iam  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `GCP-IAM-001` | **Restrict Primitive Role Usage (roles/owner, roles/editor)** | Identity & Access Management | HIGH | `3 users assigned roles/editor, 2 users assigned roles/owner` | `0 users on primitive roles; enforce Least Privilege RBAC` | **NON_COMPLIANT** |
| `GCP-IAM-002` | **Service Account Key Expiration & Rotation** | Service Account Security | CRITICAL | `2 Service Account keys > 120 days old detected` | `No user-managed keys > 90 days; prefer Workload Identity Federation` | **NON_COMPLIANT** |
| `GCP-IAM-003` | **Enforce 2SV / MFA in Cloud Identity** | Authentication & SSO | CRITICAL | `2SV Enforced for 95% of users (2 exceptions)` | `100% 2SV enforcement across all org units` | **NON_COMPLIANT** |
| `GCP-IAM-004` | **Workload Identity Federation for External CI/CD** | Workload Federation | MEDIUM | `Workload Identity Pool 'github-actions-pool' configured` | `100% of CI/CD pipelines use WIF without stored credentials` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `GCP-IAM-001`: Restrict Primitive Role Usage (roles/owner, roles/editor)
- **Category:** Identity & Access Management
- **Severity:** HIGH
- **Evidence Source:** `GCP Cloud IAM Policy Export`
- **Status:** NON_COMPLIANT
- **Description:** Ensure primitive roles (Owner/Editor) are not assigned to standard user accounts.
- **Current Setting:** `3 users assigned roles/editor, 2 users assigned roles/owner`
- **Security Recommendation:** `0 users on primitive roles; enforce Least Privilege RBAC`
- **Remediation & Migration Notes:** Migrate users from roles/editor to domain-specific roles (e.g., roles/storage.objectViewer, roles/compute.instanceAdmin).

### `GCP-IAM-002`: Service Account Key Expiration & Rotation
- **Category:** Service Account Security
- **Severity:** CRITICAL
- **Evidence Source:** `gcloud iam service-accounts keys list`
- **Status:** NON_COMPLIANT
- **Description:** User-managed service account keys older than 90 days must be disabled and rotated.
- **Current Setting:** `2 Service Account keys > 120 days old detected`
- **Security Recommendation:** `No user-managed keys > 90 days; prefer Workload Identity Federation`
- **Remediation & Migration Notes:** Adopt GKE Workload Identity or OIDC Federation to eliminate long-lived Service Account JSON keys.

### `GCP-IAM-003`: Enforce 2SV / MFA in Cloud Identity
- **Category:** Authentication & SSO
- **Severity:** CRITICAL
- **Evidence Source:** `Google Admin SDK / Cloud Security Command Center`
- **Status:** NON_COMPLIANT
- **Description:** All human administrators and users must have 2-Step Verification (MFA) enforced.
- **Current Setting:** `2SV Enforced for 95% of users (2 exceptions)`
- **Security Recommendation:** `100% 2SV enforcement across all org units`
- **Remediation & Migration Notes:** Enable mandatory 2SV in Google Cloud Identity / Workspace admin console.

### `GCP-IAM-004`: Workload Identity Federation for External CI/CD
- **Category:** Workload Federation
- **Severity:** MEDIUM
- **Evidence Source:** `gcloud iam workload-identity-pools list`
- **Status:** COMPLIANT
- **Description:** Use Workload Identity Federation instead of static JSON keys for GitHub Actions / GitLab CI.
- **Current Setting:** `Workload Identity Pool 'github-actions-pool' configured`
- **Security Recommendation:** `100% of CI/CD pipelines use WIF without stored credentials`
- **Remediation & Migration Notes:** Maintain pool attribute conditions to restrict access to specific GitHub repos.
