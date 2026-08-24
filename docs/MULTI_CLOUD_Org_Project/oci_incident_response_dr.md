# OCI - Incident Response Dr Security Profile

**Cloud Provider:** OCI  
**Security Domain:** incident_response_dr  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `OCI-DR-001` | **Enforce Immutable Retention Rules on OCI Object Storage Backup Buckets** | Immutable Backups | CRITICAL | `Retention Rule active on 'bucket-prod-db-backups' with 30-day Compliance lock` | `Immutable Retention Rule enforced across all primary backup buckets` | **COMPLIANT** |
| `OCI-DR-002` | **Enforce Cross-Region Copy in Block Volume Backup Policies** | Volume Backups | CRITICAL | `Backup policy 'gold-crossregion-policy' attached to 18 production volumes` | `Gold cross-region backup policy attached to 100% of stateful volumes` | **COMPLIANT** |
| `OCI-DR-003` | **Configure OCI Full Stack Disaster Recovery (FSDR) for Tier-0 Applications** | Disaster Recovery Replication | HIGH | `FSDR DR Plan 'fsdr-prod-erp' deployed; last failover drill success = 45 days ago` | `Active FSDR DR Plan with semi-annual automated switchover drills` | **COMPLIANT** |
| `OCI-DR-004` | **Configure Automated Block Volume Forensic Cloning Runbooks** | Forensic Readiness | HIGH | `Runbook script 'oci-ir-clone-volume.py' tested and ready in SecOps repository` | `Automated volume cloning pipeline linked to Cloud Guard critical threats` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `OCI-DR-001`: Enforce Immutable Retention Rules on OCI Object Storage Backup Buckets
- **Category:** Immutable Backups
- **Severity:** CRITICAL
- **Evidence Source:** `oci os retention-rule list`
- **Status:** COMPLIANT
- **Description:** Buckets hosting database backups and disaster recovery images must apply an Object Storage Retention Rule in Governance or Compliance mode.
- **Current Setting:** `Retention Rule active on 'bucket-prod-db-backups' with 30-day Compliance lock`
- **Security Recommendation:** `Immutable Retention Rule enforced across all primary backup buckets`
- **Remediation & Migration Notes:** Verify time-lock restrictions before promoting rule from Governance to Compliance mode.

### `OCI-DR-002`: Enforce Cross-Region Copy in Block Volume Backup Policies
- **Category:** Volume Backups
- **Severity:** CRITICAL
- **Evidence Source:** `oci bv backup-policy-assignment list`
- **Status:** COMPLIANT
- **Description:** Production Block Volume and Boot Volume backup policies must automatically copy recovery snapshots to an alternate OCI geographic region.
- **Current Setting:** `Backup policy 'gold-crossregion-policy' attached to 18 production volumes`
- **Security Recommendation:** `Gold cross-region backup policy attached to 100% of stateful volumes`
- **Remediation & Migration Notes:** Audit volume attachments monthly to ensure no orphan volumes lack a backup policy.

### `OCI-DR-003`: Configure OCI Full Stack Disaster Recovery (FSDR) for Tier-0 Applications
- **Category:** Disaster Recovery Replication
- **Severity:** HIGH
- **Evidence Source:** `oci disaster-recovery dr-plan list`
- **Status:** COMPLIANT
- **Description:** Mission-critical applications must deploy an OCI Full Stack Disaster Recovery (FSDR) DR Plan with automated failover testing.
- **Current Setting:** `FSDR DR Plan 'fsdr-prod-erp' deployed; last failover drill success = 45 days ago`
- **Security Recommendation:** `Active FSDR DR Plan with semi-annual automated switchover drills`
- **Remediation & Migration Notes:** Review runbook script dependencies for database standby promotion.

### `OCI-DR-004`: Configure Automated Block Volume Forensic Cloning Runbooks
- **Category:** Forensic Readiness
- **Severity:** HIGH
- **Evidence Source:** `oci bv volume-clone create --help`
- **Status:** COMPLIANT
- **Description:** Security operations must maintain automated scripts to immediately clone VM boot/data volumes into an isolated forensic inspection compartment upon alert.
- **Current Setting:** `Runbook script 'oci-ir-clone-volume.py' tested and ready in SecOps repository`
- **Security Recommendation:** `Automated volume cloning pipeline linked to Cloud Guard critical threats`
- **Remediation & Migration Notes:** Ensure forensic inspection compartment blocks outbound internet access.
