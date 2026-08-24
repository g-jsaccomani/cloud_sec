# OCI - Compliance Governance Security Profile

**Cloud Provider:** OCI  
**Security Domain:** compliance_governance  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `OCI-GOV-001` | **Enforce Maximum Security Zone Recipes on Production Compartments** | Security Zones | CRITICAL | `Compartment 'Prod_Core' assigned to Maximum Security Zone recipe` | `All production compartments enrolled in Security Zone guardrails` | **COMPLIANT** |
| `OCI-GOV-002` | **Enforce Tag Namespace Defaults for Security Classification & Cost Tracking** | Resource Tagging | LOW | `Tag Namespace 'EnterpriseSec' active with Tag Defaults on root compartment` | `Mandatory Tag Defaults enforced across 100% of compartments` | **COMPLIANT** |
| `OCI-GOV-003` | **Align Tenancy with CIS Oracle Cloud Infrastructure Foundations Benchmark** | CIS Benchmarks | HIGH | `CIS Foundations compliance score = 86%` | `Target CIS Foundations score >= 90%` | **NON_COMPLIANT** |
| `OCI-GOV-004` | **Enforce Compartment Quota Policies to Prevent Unauthorized Compute/GPU Proliferation** | Resource Quotas & Limits | MEDIUM | `Quota policy 'zero-gpu-nonprod' active` | `Explicit compute quota caps defined for Dev, QA, and Sandbox compartments` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `OCI-GOV-001`: Enforce Maximum Security Zone Recipes on Production Compartments
- **Category:** Security Zones
- **Severity:** CRITICAL
- **Evidence Source:** `oci cloud-guard security-zone list`
- **Status:** COMPLIANT
- **Description:** Production compartments must reside inside an OCI Security Zone enforcing immutable security policies (e.g., prevent public buckets, require CMEK).
- **Current Setting:** `Compartment 'Prod_Core' assigned to Maximum Security Zone recipe`
- **Security Recommendation:** `All production compartments enrolled in Security Zone guardrails`
- **Remediation & Migration Notes:** Audit security zone policy violations in Cloud Guard dashboard.

### `OCI-GOV-002`: Enforce Tag Namespace Defaults for Security Classification & Cost Tracking
- **Category:** Resource Tagging
- **Severity:** LOW
- **Evidence Source:** `oci iam tag-namespace list / oci iam tag-default list`
- **Status:** COMPLIANT
- **Description:** Tag Namespaces must define mandatory keys ('SecurityClass', 'Owner', 'Project') automatically applied upon resource creation.
- **Current Setting:** `Tag Namespace 'EnterpriseSec' active with Tag Defaults on root compartment`
- **Security Recommendation:** `Mandatory Tag Defaults enforced across 100% of compartments`
- **Remediation & Migration Notes:** Maintain tag retirement rules to prevent deprecated key sprawl.

### `OCI-GOV-003`: Align Tenancy with CIS Oracle Cloud Infrastructure Foundations Benchmark
- **Category:** CIS Benchmarks
- **Severity:** HIGH
- **Evidence Source:** `oci cloud-guard problem list`
- **Status:** NON_COMPLIANT
- **Description:** The tenancy must continuously evaluate against the CIS OCI Foundations Benchmark v2.0 in Cloud Guard.
- **Current Setting:** `CIS Foundations compliance score = 86%`
- **Security Recommendation:** `Target CIS Foundations score >= 90%`
- **Remediation & Migration Notes:** Remediate open IAM password policy and VCN flow log benchmark findings.

### `OCI-GOV-004`: Enforce Compartment Quota Policies to Prevent Unauthorized Compute/GPU Proliferation
- **Category:** Resource Quotas & Limits
- **Severity:** MEDIUM
- **Evidence Source:** `oci limits quota list`
- **Status:** COMPLIANT
- **Description:** Quota policies must restrict high-cost GPU and bare-metal compute instances in non-production compartments.
- **Current Setting:** `Quota policy 'zero-gpu-nonprod' active`
- **Security Recommendation:** `Explicit compute quota caps defined for Dev, QA, and Sandbox compartments`
- **Remediation & Migration Notes:** Review quota exception requests monthly.
