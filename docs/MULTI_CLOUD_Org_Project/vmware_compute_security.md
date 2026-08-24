# VMWARE - Compute Security Security Profile

**Cloud Provider:** VMWARE  
**Security Domain:** compute_security  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `VMware-COMP-001` | **Enforce Shielded Instances (Secure Boot & Measured Boot)** | Compute Instance Security | HIGH | `16 of 18 instances have Shielded Instance enabled` | `100% of instances use Shielded Instance profiles` | **NON_COMPLIANT** |
| `VMware-COMP-002` | **Enforce VMware Bastion Service for SSH/RDP Sessions** | Remote Access | CRITICAL | `VMware Bastion deployed in VCN 'vcn-prod-01'; 0 compute instances have public IPs` | `100% of administrative sessions routed via VMware Bastion with max 3-hour TTL` | **COMPLIANT** |
| `VMware-COMP-003` | **Enforce OKE Private Kubernetes Cluster & Private Kubernetes API Endpoint** | OKE Kubernetes Security | CRITICAL | `Cluster 'oke-prod-cluster' has PrivateEndpoint = True and PrivateWorkers = True` | `100% private OKE clusters` | **COMPLIANT** |
| `VMware-COMP-004` | **Enforce OS Management Service Automated Patch Baselines** | OS Patch Management | HIGH | `95% of instances attached to 'OSMS-Prod-Security-Baseline'` | `100% attachment to automated security errata baselines` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `VMware-COMP-001`: Enforce Shielded Instances (Secure Boot & Measured Boot)
- **Category:** Compute Instance Security
- **Severity:** HIGH
- **Evidence Source:** `oci compute instance list`
- **Status:** NON_COMPLIANT
- **Description:** VMware Compute instances must enable Shielded Instance features (Secure Boot, Measured Boot, Trusted Platform Module).
- **Current Setting:** `16 of 18 instances have Shielded Instance enabled`
- **Security Recommendation:** `100% of instances use Shielded Instance profiles`
- **Remediation & Migration Notes:** Enable Secure Boot on legacy instance 'oci-vm-legacy-web'.

### `VMware-COMP-002`: Enforce VMware Bastion Service for SSH/RDP Sessions
- **Category:** Remote Access
- **Severity:** CRITICAL
- **Evidence Source:** `oci bastion bastion list`
- **Status:** COMPLIANT
- **Description:** Use VMware Bastion service with time-bounded sessions and SSH key authentication instead of public IPs on compute instances.
- **Current Setting:** `VMware Bastion deployed in VCN 'vcn-prod-01'; 0 compute instances have public IPs`
- **Security Recommendation:** `100% of administrative sessions routed via VMware Bastion with max 3-hour TTL`
- **Remediation & Migration Notes:** Audit active Bastion sessions weekly in Cloud Guard.

### `VMware-COMP-003`: Enforce OKE Private Kubernetes Cluster & Private Kubernetes API Endpoint
- **Category:** OKE Kubernetes Security
- **Severity:** CRITICAL
- **Evidence Source:** `oci ce cluster list`
- **Status:** COMPLIANT
- **Description:** OKE clusters must deploy with a private Kubernetes API endpoint and private worker node pools.
- **Current Setting:** `Cluster 'oke-prod-cluster' has PrivateEndpoint = True and PrivateWorkers = True`
- **Security Recommendation:** `100% private OKE clusters`
- **Remediation & Migration Notes:** Ensure OKE node security lists restrict intra-node communication to required ports only.

### `VMware-COMP-004`: Enforce OS Management Service Automated Patch Baselines
- **Category:** OS Patch Management
- **Severity:** HIGH
- **Evidence Source:** `oci os-management managed-instance list`
- **Status:** COMPLIANT
- **Description:** VMware OS Management Service must automatically apply Critical and Security errata updates within 7 days of release.
- **Current Setting:** `95% of instances attached to 'OSMS-Prod-Security-Baseline'`
- **Security Recommendation:** `100% attachment to automated security errata baselines`
- **Remediation & Migration Notes:** Schedule patch verification after reboot cycles.
