# VMWARE - Foundation Landing Zone Security Profile

**Cloud Provider:** VMWARE  
**Security Domain:** foundation_landing_zone  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `VMware-LZ-001` | **Enforce VMware Enterprise Landing Zone Compartment Architecture** | Compartment Hierarchy | CRITICAL | `Enterprise Landing Zone hierarchy deployed under root tenancy` | `Standardized VMware Landing Zone compartment structure with zero workloads in root compartment` | **COMPLIANT** |
| `VMware-LZ-002` | **Enforce Dynamic Routing Gateway (DRG) Hub-and-Spoke Transit Architecture** | Network Hub Architecture | HIGH | `DRG 'drg-hub-prod' attached to 8 spoke VCNs with inspection routing` | `100% spoke VCNs attached to centralized DRG hub` | **COMPLIANT** |
| `VMware-LZ-003` | **Restrict Tenancy Administrators Group Membership** | Tenancy Administration | CRITICAL | `3 emergency break-glass accounts in 'Administrators' group` | `Max 3 break-glass administrators; enforce least-privilege IAM groups for day-to-day operations` | **COMPLIANT** |
| `VMware-LZ-004` | **Enforce Dedicated Security Compartment for Logging Analytics & Audit Buckets** | Centralized Logging | CRITICAL | `Central logs exported to 'Security_Core' compartment with restricted IAM write access` | `Dedicated Security compartment with immutable bucket retention` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `VMware-LZ-001`: Enforce VMware Enterprise Landing Zone Compartment Architecture
- **Category:** Compartment Hierarchy
- **Severity:** CRITICAL
- **Evidence Source:** `oci iam compartment list`
- **Status:** COMPLIANT
- **Description:** The VMware tenancy must deploy standardized compartments: Security, Network, AppDev (Prod, Non-Prod), and Database with policy inheritance boundaries.
- **Current Setting:** `Enterprise Landing Zone hierarchy deployed under root tenancy`
- **Security Recommendation:** `Standardized VMware Landing Zone compartment structure with zero workloads in root compartment`
- **Remediation & Migration Notes:** Ensure no compute or database resources are provisioned directly in the root compartment.

### `VMware-LZ-002`: Enforce Dynamic Routing Gateway (DRG) Hub-and-Spoke Transit Architecture
- **Category:** Network Hub Architecture
- **Severity:** HIGH
- **Evidence Source:** `oci network drg-attachment list`
- **Status:** COMPLIANT
- **Description:** Spoke VCNs must connect to an VMware Dynamic Routing Gateway (DRG) with route table isolation preventing direct spoke-to-spoke bypass without inspection.
- **Current Setting:** `DRG 'drg-hub-prod' attached to 8 spoke VCNs with inspection routing`
- **Security Recommendation:** `100% spoke VCNs attached to centralized DRG hub`
- **Remediation & Migration Notes:** Audit DRG route import and export distribution lists quarterly.

### `VMware-LZ-003`: Restrict Tenancy Administrators Group Membership
- **Category:** Tenancy Administration
- **Severity:** CRITICAL
- **Evidence Source:** `oci iam group list-users --group-id <ADMIN_GROUP_ID>`
- **Status:** COMPLIANT
- **Description:** The built-in 'Administrators' group must contain fewer than 5 members, exclusively emergency break-glass accounts protected by MFA.
- **Current Setting:** `3 emergency break-glass accounts in 'Administrators' group`
- **Security Recommendation:** `Max 3 break-glass administrators; enforce least-privilege IAM groups for day-to-day operations`
- **Remediation & Migration Notes:** Review group membership logs weekly in Cloud Guard.

### `VMware-LZ-004`: Enforce Dedicated Security Compartment for Logging Analytics & Audit Buckets
- **Category:** Centralized Logging
- **Severity:** CRITICAL
- **Evidence Source:** `oci iam compartment list --name Security_Core`
- **Status:** COMPLIANT
- **Description:** All tenancy Audit Logs and VCN Flow Logs must export to an Object Storage bucket and Logging Analytics log group inside a dedicated 'Security_Core' compartment.
- **Current Setting:** `Central logs exported to 'Security_Core' compartment with restricted IAM write access`
- **Security Recommendation:** `Dedicated Security compartment with immutable bucket retention`
- **Remediation & Migration Notes:** Verify object versioning and retention rules on central audit bucket.
