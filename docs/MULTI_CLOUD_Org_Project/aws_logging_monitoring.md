# AWS - Logging Monitoring Security Profile

**Cloud Provider:** AWS  
**Security Domain:** logging_monitoring  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `AWS-LOG-001` | **Enable Multi-Region CloudTrail with Log File Validation** | CloudTrail Auditing | CRITICAL | `Org Trail 'org-security-trail' active; Log File Validation = TRUE` | `IsMultiRegionTrail = True, LogFileValidationEnabled = True` | **COMPLIANT** |
| `AWS-LOG-002` | **Enable AWS GuardDuty across all Operating Regions** | Threat Detection | HIGH | `Enabled in us-east-1 and us-west-2; S3 protection active` | `GuardDuty active in 100% of enabled regions with EKS/S3/RDS protection` | **COMPLIANT** |
| `AWS-LOG-003` | **Enable AWS Config Continuous Recording for All Resources** | Configuration Tracking | HIGH | `Config recorder active in us-east-1; missing in us-west-2` | `AWS Config enabled organization-wide with central aggregator` | **NON_COMPLIANT** |
| `AWS-LOG-004` | **Enable AWS Security Hub with CIS AWS Foundations Benchmark** | CSPM & Posture | MEDIUM | `Security Hub active; CIS Foundations score = 84%` | `Security Hub enabled across all accounts; target CIS score >= 90%` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `AWS-LOG-001`: Enable Multi-Region CloudTrail with Log File Validation
- **Category:** CloudTrail Auditing
- **Severity:** CRITICAL
- **Evidence Source:** `aws cloudtrail describe-trails`
- **Status:** COMPLIANT
- **Description:** An organizational multi-region trail must be enabled with log file validation and KMS encryption.
- **Current Setting:** `Org Trail 'org-security-trail' active; Log File Validation = TRUE`
- **Security Recommendation:** `IsMultiRegionTrail = True, LogFileValidationEnabled = True`
- **Remediation & Migration Notes:** Verify KMS key policy allows CloudTrail encryption across all accounts.

### `AWS-LOG-002`: Enable AWS GuardDuty across all Operating Regions
- **Category:** Threat Detection
- **Severity:** HIGH
- **Evidence Source:** `aws guardduty list-detectors`
- **Status:** COMPLIANT
- **Description:** GuardDuty must be enabled with Kubernetes, S3, and RDS protection plans active.
- **Current Setting:** `Enabled in us-east-1 and us-west-2; S3 protection active`
- **Security Recommendation:** `GuardDuty active in 100% of enabled regions with EKS/S3/RDS protection`
- **Remediation & Migration Notes:** Forward GuardDuty findings via EventBridge to SIEM / PagerDuty.

### `AWS-LOG-003`: Enable AWS Config Continuous Recording for All Resources
- **Category:** Configuration Tracking
- **Severity:** HIGH
- **Evidence Source:** `aws configservice describe-configuration-recorders`
- **Status:** NON_COMPLIANT
- **Description:** AWS Config must record all supported resource types, including global IAM resources.
- **Current Setting:** `Config recorder active in us-east-1; missing in us-west-2`
- **Security Recommendation:** `AWS Config enabled organization-wide with central aggregator`
- **Remediation & Migration Notes:** Deploy AWS Config Aggregator in security logging account.

### `AWS-LOG-004`: Enable AWS Security Hub with CIS AWS Foundations Benchmark
- **Category:** CSPM & Posture
- **Severity:** MEDIUM
- **Evidence Source:** `aws securityhub describe-hub`
- **Status:** COMPLIANT
- **Description:** Security Hub must be enabled in central security account with CIS Foundations standard active.
- **Current Setting:** `Security Hub active; CIS Foundations score = 84%`
- **Security Recommendation:** `Security Hub enabled across all accounts; target CIS score >= 90%`
- **Remediation & Migration Notes:** Address medium/high findings in IAM and S3 control groups.
