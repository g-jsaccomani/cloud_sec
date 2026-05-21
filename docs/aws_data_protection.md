# AWS - Data Protection Security Profile

**Cloud Provider:** AWS  
**Security Domain:** data_protection  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `AWS-DATA-001` | **Enforce S3 Block Public Access at Account Level** | S3 Storage Security | CRITICAL | `All 4 flags (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets) = TRUE` | `100% Account-level S3 Block Public Access = TRUE` | **COMPLIANT** |
| `AWS-DATA-002` | **Enforce S3 Bucket Default Encryption with Customer Managed KMS Keys** | S3 Storage Security | HIGH | `3 buckets using SSE-S3 default encryption instead of SSE-KMS` | `SSE-KMS with Customer Managed Key for all sensitive buckets` | **NON_COMPLIANT** |
| `AWS-DATA-003` | **Enable EBS Default Encryption at Account Level** | EBS Storage Encryption | HIGH | `Enabled in us-east-1 and us-west-2; Disabled in eu-central-1` | `EBS Default Encryption enabled across 100% of regions` | **NON_COMPLIANT** |
| `AWS-DATA-004` | **Enforce Storage Encryption & Auto-Minor Version Upgrade on RDS** | Database Security | HIGH | `Encrypted with KMS = True on 100% of RDS instances` | `StorageEncrypted = True, AutoMinorVersionUpgrade = True` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `AWS-DATA-001`: Enforce S3 Block Public Access at Account Level
- **Category:** S3 Storage Security
- **Severity:** CRITICAL
- **Evidence Source:** `aws s3control get-public-access-block`
- **Status:** COMPLIANT
- **Description:** The account-level S3 Block Public Access setting must have all 4 flags set to TRUE.
- **Current Setting:** `All 4 flags (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets) = TRUE`
- **Security Recommendation:** `100% Account-level S3 Block Public Access = TRUE`
- **Remediation & Migration Notes:** Maintain AWS SCP to prevent disabling S3 Block Public Access.

### `AWS-DATA-002`: Enforce S3 Bucket Default Encryption with Customer Managed KMS Keys
- **Category:** S3 Storage Security
- **Severity:** HIGH
- **Evidence Source:** `aws s3api get-bucket-encryption`
- **Status:** NON_COMPLIANT
- **Description:** All S3 buckets must be encrypted by default using AWS KMS Customer Managed Keys (CMK).
- **Current Setting:** `3 buckets using SSE-S3 default encryption instead of SSE-KMS`
- **Security Recommendation:** `SSE-KMS with Customer Managed Key for all sensitive buckets`
- **Remediation & Migration Notes:** Update default bucket encryption on 'app-log-backup' to use KMS CMK.

### `AWS-DATA-003`: Enable EBS Default Encryption at Account Level
- **Category:** EBS Storage Encryption
- **Severity:** HIGH
- **Evidence Source:** `aws ec2 get-ebs-encryption-by-default`
- **Status:** NON_COMPLIANT
- **Description:** Account-level default EBS volume encryption must be enabled in all active regions.
- **Current Setting:** `Enabled in us-east-1 and us-west-2; Disabled in eu-central-1`
- **Security Recommendation:** `EBS Default Encryption enabled across 100% of regions`
- **Remediation & Migration Notes:** Run 'aws ec2 enable-ebs-encryption-by-default --region eu-central-1'.

### `AWS-DATA-004`: Enforce Storage Encryption & Auto-Minor Version Upgrade on RDS
- **Category:** Database Security
- **Severity:** HIGH
- **Evidence Source:** `aws rds describe-db-instances`
- **Status:** COMPLIANT
- **Description:** RDS database instances must use KMS encryption at rest and have automatic minor upgrades enabled.
- **Current Setting:** `Encrypted with KMS = True on 100% of RDS instances`
- **Security Recommendation:** `StorageEncrypted = True, AutoMinorVersionUpgrade = True`
- **Remediation & Migration Notes:** Regularly audit database parameter groups for enforce_ssl = 1.
