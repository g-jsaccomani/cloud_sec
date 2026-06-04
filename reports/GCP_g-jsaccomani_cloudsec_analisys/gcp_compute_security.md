# GCP - Compute Security Security Profile

**Cloud Provider:** GCP  
**Security Domain:** compute_security  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `GCP-COMP-001` | **Enforce Shielded VM (Secure Boot & vTPM) on all instances** | Compute Engine Security | HIGH | `12 of 14 VMs have Shielded VM Secure Boot enabled` | `100% Shielded VMs with Secure Boot = True` | **NON_COMPLIANT** |
| `GCP-COMP-002` | **Enforce OS Login for SSH Access Management** | Compute Engine Security | HIGH | `enable-oslogin = TRUE at project metadata level` | `enable-oslogin = TRUE across all projects` | **COMPLIANT** |
| `GCP-COMP-003` | **Enforce GKE Private Cluster & Authorized Networks** | GKE Kubernetes Security | CRITICAL | `Cluster 'prod-gke-01' is Private with Authorized Networks = 10.100.0.0/20` | `Private Cluster = True, Control Plane Authorized Networks restricted` | **COMPLIANT** |
| `GCP-COMP-004` | **Enforce GKE Workload Identity on all Node Pools** | GKE Kubernetes Security | HIGH | `Enabled on cluster 'prod-gke-01' node pools` | `Workload Identity pool enabled on 100% of clusters` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `GCP-COMP-001`: Enforce Shielded VM (Secure Boot & vTPM) on all instances
- **Category:** Compute Engine Security
- **Severity:** HIGH
- **Evidence Source:** `gcloud compute instances list`
- **Status:** NON_COMPLIANT
- **Description:** All Compute Engine VMs must have Secure Boot, vTPM, and Integrity Monitoring enabled.
- **Current Setting:** `12 of 14 VMs have Shielded VM Secure Boot enabled`
- **Security Recommendation:** `100% Shielded VMs with Secure Boot = True`
- **Remediation & Migration Notes:** Enable Secure Boot on legacy instances 'vm-legacy-app-1' and 'vm-legacy-app-2'.

### `GCP-COMP-002`: Enforce OS Login for SSH Access Management
- **Category:** Compute Engine Security
- **Severity:** HIGH
- **Evidence Source:** `gcloud compute project-info describe`
- **Status:** COMPLIANT
- **Description:** Project-wide metadata must enable OS Login (enable-oslogin = TRUE) to eliminate static SSH keys.
- **Current Setting:** `enable-oslogin = TRUE at project metadata level`
- **Security Recommendation:** `enable-oslogin = TRUE across all projects`
- **Remediation & Migration Notes:** Use OS Login with 2SV for elevated admin access.

### `GCP-COMP-003`: Enforce GKE Private Cluster & Authorized Networks
- **Category:** GKE Kubernetes Security
- **Severity:** CRITICAL
- **Evidence Source:** `gcloud container clusters describe`
- **Status:** COMPLIANT
- **Description:** GKE clusters must be private (no external IP on nodes) with master authorized networks enforced.
- **Current Setting:** `Cluster 'prod-gke-01' is Private with Authorized Networks = 10.100.0.0/20`
- **Security Recommendation:** `Private Cluster = True, Control Plane Authorized Networks restricted`
- **Remediation & Migration Notes:** Ensure GKE Control Plane authorized networks do not allow 0.0.0.0/0.

### `GCP-COMP-004`: Enforce GKE Workload Identity on all Node Pools
- **Category:** GKE Kubernetes Security
- **Severity:** HIGH
- **Evidence Source:** `gcloud container clusters describe --format='value(workloadIdentityConfig)'`
- **Status:** COMPLIANT
- **Description:** GKE workloads must use Workload Identity to interact with GCP APIs without node Service Account impersonation.
- **Current Setting:** `Enabled on cluster 'prod-gke-01' node pools`
- **Security Recommendation:** `Workload Identity pool enabled on 100% of clusters`
- **Remediation & Migration Notes:** Audit pod ServiceAccounts mapped to GCP ServiceAccounts.
