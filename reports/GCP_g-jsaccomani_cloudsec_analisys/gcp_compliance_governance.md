# GCP - Compliance Governance Security Profile

**Cloud Provider:** GCP  
**Security Domain:** compliance_governance  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `GCP-GOV-001` | **Enforce Resource Location Restrictions (gcp.resourceLocations)** | Organization Policies | HIGH | `Allowed regions: ['in:us-locations']` | `Restrict to authorized data sovereignty regions` | **COMPLIANT** |
| `GCP-GOV-002` | **Disable Service Account Key Creation (iam.disableServiceAccountKeyCreation)** | Organization Policies | CRITICAL | `Enforced at Organization root` | `Enforced = True across 100% of folders` | **COMPLIANT** |
| `GCP-GOV-003` | **Configure Security Essential Contacts at Organization Root** | Essential Contacts | MEDIUM | `Configured: secops-alerts@google.com` | `Verified SOC/Security distribution list assigned to SECURITY category` | **COMPLIANT** |
| `GCP-GOV-004` | **Cloud Asset Inventory Real-time Export Feed to BigQuery** | Asset Inventory | MEDIUM | `Feed 'cai-secops-feed' exporting to BigQuery dataset 'cai_audit_archive'` | `Active Org-level real-time asset feed` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `GCP-GOV-001`: Enforce Resource Location Restrictions (gcp.resourceLocations)
- **Category:** Organization Policies
- **Severity:** HIGH
- **Evidence Source:** `gcloud resource-manager org-policies list --organization=<ORG_ID>`
- **Status:** COMPLIANT
- **Description:** Restrict GCP resource creation to approved organizational regions (e.g., us-east1, us-central1).
- **Current Setting:** `Allowed regions: ['in:us-locations']`
- **Security Recommendation:** `Restrict to authorized data sovereignty regions`
- **Remediation & Migration Notes:** Maintain strict exception approval workflow for international regions.

### `GCP-GOV-002`: Disable Service Account Key Creation (iam.disableServiceAccountKeyCreation)
- **Category:** Organization Policies
- **Severity:** CRITICAL
- **Evidence Source:** `gcloud resource-manager org-policies describe iam.disableServiceAccountKeyCreation`
- **Status:** COMPLIANT
- **Description:** Prevent developers from creating new user-managed Service Account JSON keys.
- **Current Setting:** `Enforced at Organization root`
- **Security Recommendation:** `Enforced = True across 100% of folders`
- **Remediation & Migration Notes:** Ensure no project overrides exist without CISO exception ticket.

### `GCP-GOV-003`: Configure Security Essential Contacts at Organization Root
- **Category:** Essential Contacts
- **Severity:** MEDIUM
- **Evidence Source:** `gcloud essential-contacts list --organization=<ORG_ID>`
- **Status:** COMPLIANT
- **Description:** Ensure 'SECURITY' notification category has verified security operations email addresses.
- **Current Setting:** `Configured: secops-alerts@google.com`
- **Security Recommendation:** `Verified SOC/Security distribution list assigned to SECURITY category`
- **Remediation & Migration Notes:** Test incident alert delivery quarterly.

### `GCP-GOV-004`: Cloud Asset Inventory Real-time Export Feed to BigQuery
- **Category:** Asset Inventory
- **Severity:** MEDIUM
- **Evidence Source:** `gcloud asset feeds list --organization=<ORG_ID>`
- **Status:** COMPLIANT
- **Description:** A continuous Cloud Asset Inventory feed must be configured to export resource changes to BigQuery for audit trails.
- **Current Setting:** `Feed 'cai-secops-feed' exporting to BigQuery dataset 'cai_audit_archive'`
- **Security Recommendation:** `Active Org-level real-time asset feed`
- **Remediation & Migration Notes:** Monitor BigQuery dataset permissions to prevent unauthorized schema changes.
