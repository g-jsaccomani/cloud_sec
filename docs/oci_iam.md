# OCI - Iam Security Profile

**Cloud Provider:** OCI  
**Security Domain:** iam  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `OCI-IAM-001` | **Enforce Multi-Factor Authentication (MFA) across All Identity Domains** | MFA & Authentication | CRITICAL | `Default Identity Domain enforces MFA; 2 test local accounts exempt` | `100% MFA enforcement with no user exemptions` | **NON_COMPLIANT** |
| `OCI-IAM-002` | **Enforce Least Privilege Compartment-Level Policy Assignments** | Compartment Security | HIGH | `3 policies allow 'manage all-resources in tenancy'` | `Restrict 'manage all-resources' to dedicated Tenancy Administrators group only` | **NON_COMPLIANT** |
| `OCI-IAM-003` | **Enforce Dynamic Groups for Instance Authentication to OCI Services** | Workload Authentication | HIGH | `Dynamic Group 'dg-prod-compute' configured for OCI Object Storage access` | `100% of compute/OKE workloads use Dynamic Groups / Workload Identity` | **COMPLIANT** |
| `OCI-IAM-004` | **Rotate User API Signing Keys Every 90 Days** | API Key Hygiene | MEDIUM | `1 API signing key > 90 days old detected` | `0 API signing keys older than 90 days` | **NON_COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `OCI-IAM-001`: Enforce Multi-Factor Authentication (MFA) across All Identity Domains
- **Category:** MFA & Authentication
- **Severity:** CRITICAL
- **Evidence Source:** `oci iam identity-provider list / oci iam policy list`
- **Status:** NON_COMPLIANT
- **Description:** OCI IAM sign-on policies must enforce MFA for all local administrators and federated users.
- **Current Setting:** `Default Identity Domain enforces MFA; 2 test local accounts exempt`
- **Security Recommendation:** `100% MFA enforcement with no user exemptions`
- **Remediation & Migration Notes:** Remove MFA policy exemptions for test accounts or disable accounts.

### `OCI-IAM-002`: Enforce Least Privilege Compartment-Level Policy Assignments
- **Category:** Compartment Security
- **Severity:** HIGH
- **Evidence Source:** `oci iam policy list --compartment-id <TENANCY_ID>`
- **Status:** NON_COMPLIANT
- **Description:** IAM policies must be scoped to specific child compartments (e.g., 'in compartment Prod_App') rather than root tenancy.
- **Current Setting:** `3 policies allow 'manage all-resources in tenancy'`
- **Security Recommendation:** `Restrict 'manage all-resources' to dedicated Tenancy Administrators group only`
- **Remediation & Migration Notes:** Refactor broad tenancy-level policies to target specific compartment OCIDs.

### `OCI-IAM-003`: Enforce Dynamic Groups for Instance Authentication to OCI Services
- **Category:** Workload Authentication
- **Severity:** HIGH
- **Evidence Source:** `oci iam dynamic-group list`
- **Status:** COMPLIANT
- **Description:** Use OCI Dynamic Groups and Instance Principals instead of storing user API signing keys on compute instances.
- **Current Setting:** `Dynamic Group 'dg-prod-compute' configured for OCI Object Storage access`
- **Security Recommendation:** `100% of compute/OKE workloads use Dynamic Groups / Workload Identity`
- **Remediation & Migration Notes:** Maintain matching rule criteria to prevent unauthorized VM inclusion.

### `OCI-IAM-004`: Rotate User API Signing Keys Every 90 Days
- **Category:** API Key Hygiene
- **Severity:** MEDIUM
- **Evidence Source:** `oci iam user-api-key list`
- **Status:** NON_COMPLIANT
- **Description:** User API signing keys older than 90 days must be rotated or deleted.
- **Current Setting:** `1 API signing key > 90 days old detected`
- **Security Recommendation:** `0 API signing keys older than 90 days`
- **Remediation & Migration Notes:** Delete expired API key for user 'oci-backup-agent' after migrating to Instance Principals.
