# AZURE - Incident Response Dr Security Profile

**Cloud Provider:** AZURE  
**Security Domain:** incident_response_dr  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `AZURE-DR-001` | **Enforce Immutable Vault Protection on Azure Backup Recovery Services Vaults** | Immutable Backups | CRITICAL | `Vault 'rsv-prod-core' has ImmutabilityState = 'Locked' and SoftDelete = Enabled` | `ImmutabilityState = 'Locked' across all production backup vaults` | **COMPLIANT** |
| `AZURE-DR-002` | **Configure Automated Forensic Snapshot Isolation Runbooks in Azure Automation** | Forensic Readiness | HIGH | `Runbook 'IR-Forensic-Disk-Snapshot' linked to Defender Critical Alerts` | `Automated forensic runbook active across 100% of production subscriptions` | **COMPLIANT** |
| `AZURE-DR-003` | **Enforce Azure Site Recovery (ASR) with Customer Managed Keys for Critical VMs** | Disaster Recovery Replication | HIGH | `ASR replication active for 10 Tier-0 VMs; encryption uses Microsoft-managed key` | `ASR replication encrypted with Customer Managed Key (CMK)` | **NON_COMPLIANT** |
| `AZURE-DR-004` | **Enforce Emergency Break-Glass Accounts with Monitored Sign-in Alerts** | Incident Response Access | CRITICAL | `2 break-glass accounts configured; Sentinel alert 'Alert-BreakGlass-Usage' active` | `2 monitored break-glass accounts with quarterly password rotation in fireproof safe` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `AZURE-DR-001`: Enforce Immutable Vault Protection on Azure Backup Recovery Services Vaults
- **Category:** Immutable Backups
- **Severity:** CRITICAL
- **Evidence Source:** `az backup vault show`
- **Status:** COMPLIANT
- **Description:** Recovery Services and Backup vaults must enable Immutability (WORM) and Soft Delete (14+ days) to protect against ransomware backup deletion.
- **Current Setting:** `Vault 'rsv-prod-core' has ImmutabilityState = 'Locked' and SoftDelete = Enabled`
- **Security Recommendation:** `ImmutabilityState = 'Locked' across all production backup vaults`
- **Remediation & Migration Notes:** Verify backup restore points across paired geographic regions.

### `AZURE-DR-002`: Configure Automated Forensic Snapshot Isolation Runbooks in Azure Automation
- **Category:** Forensic Readiness
- **Severity:** HIGH
- **Evidence Source:** `az automation runbook list`
- **Status:** COMPLIANT
- **Description:** Incident response workflows must use Azure Automation runbooks to automatically snapshot and isolate VM disks upon Sentinel/Defender critical alert.
- **Current Setting:** `Runbook 'IR-Forensic-Disk-Snapshot' linked to Defender Critical Alerts`
- **Security Recommendation:** `Automated forensic runbook active across 100% of production subscriptions`
- **Remediation & Migration Notes:** Test forensic snapshot automation during quarterly incident response drills.

### `AZURE-DR-003`: Enforce Azure Site Recovery (ASR) with Customer Managed Keys for Critical VMs
- **Category:** Disaster Recovery Replication
- **Severity:** HIGH
- **Evidence Source:** `az site-recovery fabric list`
- **Status:** NON_COMPLIANT
- **Description:** Tier-0 VMs replicated via Azure Site Recovery must encrypt replication cache and target disks using Key Vault Customer Managed Keys.
- **Current Setting:** `ASR replication active for 10 Tier-0 VMs; encryption uses Microsoft-managed key`
- **Security Recommendation:** `ASR replication encrypted with Customer Managed Key (CMK)`
- **Remediation & Migration Notes:** Assign Key Vault CMK to Azure Site Recovery replication vault.

### `AZURE-DR-004`: Enforce Emergency Break-Glass Accounts with Monitored Sign-in Alerts
- **Category:** Incident Response Access
- **Severity:** CRITICAL
- **Evidence Source:** `az monitor metrics alert list`
- **Status:** COMPLIANT
- **Description:** Two emergency break-glass Entra ID global admin accounts must exist without Conditional Access MFA dependencies, monitored 24/7 by Azure Sentinel alerts.
- **Current Setting:** `2 break-glass accounts configured; Sentinel alert 'Alert-BreakGlass-Usage' active`
- **Security Recommendation:** `2 monitored break-glass accounts with quarterly password rotation in fireproof safe`
- **Remediation & Migration Notes:** Verify break-glass accounts are excluded from federation (native cloud-only accounts).
