# AWS - Incident Response Dr Security Profile

**Cloud Provider:** AWS  
**Security Domain:** incident_response_dr  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `AWS-DR-001` | **Enforce Cross-Region Backup Copy in AWS Backup Plans** | Backup Resilience | CRITICAL | `Backup plan 'prod-daily-backup' copies snapshots to us-east-1 with 30-day retention` | `Cross-region copy enabled on 100% of production backup plans` | **COMPLIANT** |
| `AWS-DR-002` | **Configure Automated Forensic EC2 Snapshot Isolation IAM Roles** | Forensic Readiness | HIGH | `IAM Role 'ir-forensic-snapshot-role' active and tested with EventBridge automation` | `Automated IR snapshot isolation role active across all accounts` | **COMPLIANT** |
| `AWS-DR-003` | **Enforce AWS Elastic Disaster Recovery (DRS) Continuous Replication for Mission-Critical VMs** | Disaster Recovery Replication | HIGH | `DRS replication active on 6 Tier-0 database/app servers; 2 servers pending agent installation` | `100% DRS replication coverage for Tier-0 workloads` | **NON_COMPLIANT** |
| `AWS-DR-004` | **Enforce Emergency Break-Glass Account Monitoring & Alerting** | Incident Response Playbooks | CRITICAL | `EventBridge rule 'alert-break-glass-login' active` | `Real-time paging & SIEM alert on break-glass credential usage` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `AWS-DR-001`: Enforce Cross-Region Backup Copy in AWS Backup Plans
- **Category:** Backup Resilience
- **Severity:** CRITICAL
- **Evidence Source:** `aws backup list-backup-plans`
- **Status:** COMPLIANT
- **Description:** Primary backup plans must automatically copy recovery points to an alternate disaster recovery region (e.g., us-west-2 -> us-east-1).
- **Current Setting:** `Backup plan 'prod-daily-backup' copies snapshots to us-east-1 with 30-day retention`
- **Security Recommendation:** `Cross-region copy enabled on 100% of production backup plans`
- **Remediation & Migration Notes:** Verify KMS encryption key in target destination region supports automated restore.

### `AWS-DR-002`: Configure Automated Forensic EC2 Snapshot Isolation IAM Roles
- **Category:** Forensic Readiness
- **Severity:** HIGH
- **Evidence Source:** `aws iam get-role --role-name ir-forensic-snapshot-role`
- **Status:** COMPLIANT
- **Description:** Incident response accounts must have pre-authorized IAM roles enabling automated forensic disk snapshot creation upon GuardDuty/Security Hub critical alerts.
- **Current Setting:** `IAM Role 'ir-forensic-snapshot-role' active and tested with EventBridge automation`
- **Security Recommendation:** `Automated IR snapshot isolation role active across all accounts`
- **Remediation & Migration Notes:** Review KMS key permissions to ensure forensic team can mount isolated EBS snapshots.

### `AWS-DR-003`: Enforce AWS Elastic Disaster Recovery (DRS) Continuous Replication for Mission-Critical VMs
- **Category:** Disaster Recovery Replication
- **Severity:** HIGH
- **Evidence Source:** `aws drs describe-source-servers`
- **Status:** NON_COMPLIANT
- **Description:** Tier-0 stateful compute workloads must be enrolled in AWS Elastic Disaster Recovery (DRS) with RPO <= 5 minutes.
- **Current Setting:** `DRS replication active on 6 Tier-0 database/app servers; 2 servers pending agent installation`
- **Security Recommendation:** `100% DRS replication coverage for Tier-0 workloads`
- **Remediation & Migration Notes:** Install AWS DRS replication agent on 'db-prod-legacy-01' and 'app-core-auth'.

### `AWS-DR-004`: Enforce Emergency Break-Glass Account Monitoring & Alerting
- **Category:** Incident Response Playbooks
- **Severity:** CRITICAL
- **Evidence Source:** `aws events list-rules`
- **Status:** COMPLIANT
- **Description:** Use of emergency break-glass IAM roles/users must immediately trigger high-priority alerts in PagerDuty/SIEM via EventBridge.
- **Current Setting:** `EventBridge rule 'alert-break-glass-login' active`
- **Security Recommendation:** `Real-time paging & SIEM alert on break-glass credential usage`
- **Remediation & Migration Notes:** Test break-glass alert pipeline during semi-annual IR table-top exercises.
