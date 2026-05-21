# AWS - Compliance Governance Security Profile

**Cloud Provider:** AWS  
**Security Domain:** compliance_governance  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `AWS-GOV-001` | **Enforce SCP Preventing CloudTrail & GuardDuty Deactivation** | Service Control Policies (SCPs) | CRITICAL | `SCP 'scp-guardrails-core' attached to Root Organization OU` | `Active guardrail SCP enforced on all member accounts` | **COMPLIANT** |
| `AWS-GOV-002` | **Enforce SCP Restricting Permitted AWS Regions** | Service Control Policies (SCPs) | HIGH | `SCP 'scp-region-lock' enforced on Production OU` | `Region restriction SCP active across all OUs` | **COMPLIANT** |
| `AWS-GOV-003` | **Enforce Immutable AWS Backup Vault Lock** | Data Backup Governance | CRITICAL | `Vault 'prod-backup-vault' has Vault Lock active (MinRetentionDays = 30)` | `Vault Lock Compliance Mode enabled on all primary vaults` | **COMPLIANT** |
| `AWS-GOV-004` | **Enforce SSM Patch Manager Compliance for EC2 & Hybrid Servers** | Patch Management | HIGH | `92% of EC2 instances compliant with 'Enterprise-AmazonLinux-Baseline'` | `100% patch compliance across all OS distributions` | **NON_COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `AWS-GOV-001`: Enforce SCP Preventing CloudTrail & GuardDuty Deactivation
- **Category:** Service Control Policies (SCPs)
- **Severity:** CRITICAL
- **Evidence Source:** `aws organizations list-policies`
- **Status:** COMPLIANT
- **Description:** An Organization-level SCP must deny 'cloudtrail:StopLogging', 'cloudtrail:DeleteTrail', and 'guardduty:DisableOrganizationAdminAccount'.
- **Current Setting:** `SCP 'scp-guardrails-core' attached to Root Organization OU`
- **Security Recommendation:** `Active guardrail SCP enforced on all member accounts`
- **Remediation & Migration Notes:** Verify SCP exceptions are restricted to emergency break-glass roles.

### `AWS-GOV-002`: Enforce SCP Restricting Permitted AWS Regions
- **Category:** Service Control Policies (SCPs)
- **Severity:** HIGH
- **Evidence Source:** `aws organizations list-targets-for-policy`
- **Status:** COMPLIANT
- **Description:** Restrict AWS region operations to authorized data residency regions (e.g., us-east-1, us-west-2).
- **Current Setting:** `SCP 'scp-region-lock' enforced on Production OU`
- **Security Recommendation:** `Region restriction SCP active across all OUs`
- **Remediation & Migration Notes:** Audit global service exceptions (IAM, CloudFront, Route53).

### `AWS-GOV-003`: Enforce Immutable AWS Backup Vault Lock
- **Category:** Data Backup Governance
- **Severity:** CRITICAL
- **Evidence Source:** `aws backup describe-backup-vault`
- **Status:** COMPLIANT
- **Description:** Production AWS Backup vaults must have Vault Lock in Compliance mode to prevent backup deletion by ransomware.
- **Current Setting:** `Vault 'prod-backup-vault' has Vault Lock active (MinRetentionDays = 30)`
- **Security Recommendation:** `Vault Lock Compliance Mode enabled on all primary vaults`
- **Remediation & Migration Notes:** Ensure disaster recovery restoration tests occur semi-annually.

### `AWS-GOV-004`: Enforce SSM Patch Manager Compliance for EC2 & Hybrid Servers
- **Category:** Patch Management
- **Severity:** HIGH
- **Evidence Source:** `aws ssm list-compliance-summaries`
- **Status:** NON_COMPLIANT
- **Description:** All managed nodes must report compliant against enterprise patch baseline within 7 days of release.
- **Current Setting:** `92% of EC2 instances compliant with 'Enterprise-AmazonLinux-Baseline'`
- **Security Recommendation:** `100% patch compliance across all OS distributions`
- **Remediation & Migration Notes:** Schedule patch maintenance window for 8 non-compliant instances.
