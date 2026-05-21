# GCP - Data Protection Security Profile

**Cloud Provider:** GCP  
**Security Domain:** data_protection  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `GCP-DATA-001` | **Enforce Public Access Prevention (PAP) on GCS Buckets** | Cloud Storage Security | CRITICAL | `2 buckets with Public Access Prevention set to 'unspecified'` | `Public Access Prevention = 'enforced' across 100% of buckets` | **NON_COMPLIANT** |
| `GCP-DATA-002` | **Enforce Uniform Bucket-Level Access (UBLA)** | Cloud Storage Security | HIGH | `UBLA Enabled on 100% of buckets` | `Uniform Bucket-Level Access = True` | **COMPLIANT** |
| `GCP-DATA-003` | **Customer-Managed Encryption Keys (CMEK) for Sensitive Datasets** | Key Management (CMEK) | HIGH | `CMEK configured for BigQuery analytics; default Google encryption on Cloud SQL dev` | `CMEK enforced for Production Cloud SQL, BigQuery, and GCS buckets` | **MANUAL_REVIEW** |
| `GCP-DATA-004` | **Enforce SSL/TLS Connections on Cloud SQL Instances** | Database Security | HIGH | `SSL required on 4 of 4 Cloud SQL instances` | `require_ssl = true` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `GCP-DATA-001`: Enforce Public Access Prevention (PAP) on GCS Buckets
- **Category:** Cloud Storage Security
- **Severity:** CRITICAL
- **Evidence Source:** `gcloud storage buckets describe`
- **Status:** NON_COMPLIANT
- **Description:** All Cloud Storage buckets must have Public Access Prevention set to 'enforced'.
- **Current Setting:** `2 buckets with Public Access Prevention set to 'unspecified'`
- **Security Recommendation:** `Public Access Prevention = 'enforced' across 100% of buckets`
- **Remediation & Migration Notes:** Run 'gcloud storage buckets update gs://<bucket> --public-access-prevention=enforced'.

### `GCP-DATA-002`: Enforce Uniform Bucket-Level Access (UBLA)
- **Category:** Cloud Storage Security
- **Severity:** HIGH
- **Evidence Source:** `gcloud storage buckets list`
- **Status:** COMPLIANT
- **Description:** Prevent object-level ACLs by enforcing Uniform Bucket-Level Access.
- **Current Setting:** `UBLA Enabled on 100% of buckets`
- **Security Recommendation:** `Uniform Bucket-Level Access = True`
- **Remediation & Migration Notes:** Maintain org policy constraint 'storage.uniformBucketLevelAccess'.

### `GCP-DATA-003`: Customer-Managed Encryption Keys (CMEK) for Sensitive Datasets
- **Category:** Key Management (CMEK)
- **Severity:** HIGH
- **Evidence Source:** `gcloud kms keys list / Cloud SQL describe`
- **Status:** MANUAL_REVIEW
- **Description:** BigQuery datasets and Cloud SQL instances containing PII/PCI must use Cloud KMS CMEK.
- **Current Setting:** `CMEK configured for BigQuery analytics; default Google encryption on Cloud SQL dev`
- **Security Recommendation:** `CMEK enforced for Production Cloud SQL, BigQuery, and GCS buckets`
- **Remediation & Migration Notes:** Verify KMS key rotation period is set to <= 90 days and separation of duties is maintained.

### `GCP-DATA-004`: Enforce SSL/TLS Connections on Cloud SQL Instances
- **Category:** Database Security
- **Severity:** HIGH
- **Evidence Source:** `gcloud sql instances describe`
- **Status:** COMPLIANT
- **Description:** Cloud SQL instances must reject unencrypted connections (require_ssl = true).
- **Current Setting:** `SSL required on 4 of 4 Cloud SQL instances`
- **Security Recommendation:** `require_ssl = true`
- **Remediation & Migration Notes:** Ensure client certificates are rotated annually.
