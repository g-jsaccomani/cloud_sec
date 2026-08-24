# GCP - Foundation Landing Zone Security Profile

**Cloud Provider:** GCP  
**Security Domain:** foundation_landing_zone  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `GCP-LZ-001` | **Enforce Google Enterprise Foundations Blueprint Folder Hierarchy** | Organization Hierarchy | CRITICAL | `4 top-level folders configured according to Google Enterprise Blueprint` | `Standardized 4-tier folder hierarchy with dedicated IAM inheritance boundaries` | **COMPLIANT** |
| `GCP-LZ-002` | **Enforce Shared VPC Architecture for Centralized Network Management** | Network Architecture | HIGH | `Shared VPC Host 'proj-net-hub-01' attached to 14 production service projects` | `100% of production workloads reside inside Shared VPC subnets` | **COMPLIANT** |
| `GCP-LZ-003` | **Enforce VPC Service Controls (VPC-SC) Perimeters around Sensitive Data Services** | VPC Service Controls | CRITICAL | `VPC-SC Perimeter 'perimeter-prod-core' active in Enforce mode` | `VPC-SC perimeter active across 100% of production projects` | **COMPLIANT** |
| `GCP-LZ-004` | **Centralized Billing Data Export to SecOps BigQuery Dataset** | Billing & Resource Tracking | MEDIUM | `Billing export active -> 'billing_secops_archive.gcp_billing_export_v1'` | `Active BigQuery billing export with alert rules for cost spikes > 50%` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `GCP-LZ-001`: Enforce Google Enterprise Foundations Blueprint Folder Hierarchy
- **Category:** Organization Hierarchy
- **Severity:** CRITICAL
- **Evidence Source:** `gcloud resource-manager folders list --organization=<ORG_ID>`
- **Status:** COMPLIANT
- **Description:** The GCP Organization must deploy standardized top-level folders: Common, SharedServices, Production, Non-Production, and Sandbox.
- **Current Setting:** `4 top-level folders configured according to Google Enterprise Blueprint`
- **Security Recommendation:** `Standardized 4-tier folder hierarchy with dedicated IAM inheritance boundaries`
- **Remediation & Migration Notes:** Prevent creation of ad-hoc root-level projects outside designated folders.

### `GCP-LZ-002`: Enforce Shared VPC Architecture for Centralized Network Management
- **Category:** Network Architecture
- **Severity:** HIGH
- **Evidence Source:** `gcloud compute shared-vpc list-associated-resources proj-net-hub-01`
- **Status:** COMPLIANT
- **Description:** Workload projects must attach to a Shared VPC managed by a centralized networking/security host project.
- **Current Setting:** `Shared VPC Host 'proj-net-hub-01' attached to 14 production service projects`
- **Security Recommendation:** `100% of production workloads reside inside Shared VPC subnets`
- **Remediation & Migration Notes:** Review subnet IAM permissions for Service Project admins.

### `GCP-LZ-003`: Enforce VPC Service Controls (VPC-SC) Perimeters around Sensitive Data Services
- **Category:** VPC Service Controls
- **Severity:** CRITICAL
- **Evidence Source:** `gcloud access-context-manager perimeters list --policy=<POLICY_ID>`
- **Status:** COMPLIANT
- **Description:** VPC Service Controls must prevent data exfiltration by enforcing service perimeters around BigQuery, Cloud Storage, and Cloud SQL.
- **Current Setting:** `VPC-SC Perimeter 'perimeter-prod-core' active in Enforce mode`
- **Security Recommendation:** `VPC-SC perimeter active across 100% of production projects`
- **Remediation & Migration Notes:** Maintain minimal ingress/egress rules using Access Levels.

### `GCP-LZ-004`: Centralized Billing Data Export to SecOps BigQuery Dataset
- **Category:** Billing & Resource Tracking
- **Severity:** MEDIUM
- **Evidence Source:** `gcloud beta billing accounts describe <ACCOUNT_ID>`
- **Status:** COMPLIANT
- **Description:** Detailed billing and resource usage exports must be routed to an immutable BigQuery dataset for anomaly and cost-abuse detection.
- **Current Setting:** `Billing export active -> 'billing_secops_archive.gcp_billing_export_v1'`
- **Security Recommendation:** `Active BigQuery billing export with alert rules for cost spikes > 50%`
- **Remediation & Migration Notes:** Monitor anomaly alerts in Cloud Billing budget notifications.
