# GCP - Incident Response Dr Security Profile

**Cloud Provider:** GCP  
**Security Domain:** incident_response_dr  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `GCP-DR-001` | **Enforce Backup and DR Service Immutable Vaults against Ransomware** | Immutable Backups | CRITICAL | `Backup Vault 'vault-prod-immutable' active with 30-day WORM lock` | `Immutable backup vault enforced across all stateful production projects` | **COMPLIANT** |
| `GCP-DR-002` | **Configure Automated Forensic Disk Snapshot Pipeline** | Forensic Readiness | HIGH | `Cloud Function 'secops-forensic-snapshot-bot' linked to SCC Critical alerts` | `Automated forensic snapshot capture active in 100% of projects` | **COMPLIANT** |
| `GCP-DR-003` | **Enforce Daily Resource Policy Snapshot Schedules on Compute Disks** | Snapshot Schedules | HIGH | `Snapshot schedule 'sched-daily-prod' attached to 14 of 16 VMs` | `100% disk coverage with automated snapshot schedules` | **NON_COMPLIANT** |
| `GCP-DR-004` | **Enforce Cross-Region Replication on Primary Cloud Storage Buckets** | Disaster Recovery Replication | MEDIUM | `Bucket 'gs://gs-prod-customer-data' configured as Dual-Region (us-east1, us-central1) with Turbo Replication` | `Dual-Region + Turbo Replication on all critical data stores` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `GCP-DR-001`: Enforce Backup and DR Service Immutable Vaults against Ransomware
- **Category:** Immutable Backups
- **Severity:** CRITICAL
- **Evidence Source:** `gcloud backup-dr backup-vaults list`
- **Status:** COMPLIANT
- **Description:** Production databases and stateful workloads must be backed up to an immutable Backup and DR Service vault with WORM retention.
- **Current Setting:** `Backup Vault 'vault-prod-immutable' active with 30-day WORM lock`
- **Security Recommendation:** `Immutable backup vault enforced across all stateful production projects`
- **Remediation & Migration Notes:** Test restoration of encrypted backups semi-annually.

### `GCP-DR-002`: Configure Automated Forensic Disk Snapshot Pipeline
- **Category:** Forensic Readiness
- **Severity:** HIGH
- **Evidence Source:** `gcloud functions describe secops-forensic-snapshot-bot`
- **Status:** COMPLIANT
- **Description:** Incident response workflows must be capable of automatically creating isolated, read-only forensic snapshots of VM disks upon SCC alert trigger.
- **Current Setting:** `Cloud Function 'secops-forensic-snapshot-bot' linked to SCC Critical alerts`
- **Security Recommendation:** `Automated forensic snapshot capture active in 100% of projects`
- **Remediation & Migration Notes:** Ensure forensic snapshots are stored in dedicated IR storage project.

### `GCP-DR-003`: Enforce Daily Resource Policy Snapshot Schedules on Compute Disks
- **Category:** Snapshot Schedules
- **Severity:** HIGH
- **Evidence Source:** `gcloud compute resource-policies list`
- **Status:** NON_COMPLIANT
- **Description:** All production VM boot and data disks must be attached to a Resource Policy snapshot schedule retaining backups for >= 14 days.
- **Current Setting:** `Snapshot schedule 'sched-daily-prod' attached to 14 of 16 VMs`
- **Security Recommendation:** `100% disk coverage with automated snapshot schedules`
- **Remediation & Migration Notes:** Attach 'sched-daily-prod' to unmanaged disks on 'vm-app-03' and 'vm-app-04'.

### `GCP-DR-004`: Enforce Cross-Region Replication on Primary Cloud Storage Buckets
- **Category:** Disaster Recovery Replication
- **Severity:** MEDIUM
- **Evidence Source:** `gcloud storage buckets describe gs://gs-prod-customer-data`
- **Status:** COMPLIANT
- **Description:** Business-critical Cloud Storage buckets must use Dual-Region or Multi-Region locations with Turbo Replication enabled.
- **Current Setting:** `Bucket 'gs://gs-prod-customer-data' configured as Dual-Region (us-east1, us-central1) with Turbo Replication`
- **Security Recommendation:** `Dual-Region + Turbo Replication on all critical data stores`
- **Remediation & Migration Notes:** Verify RPO < 15 minutes SLA under simulated region failover.
