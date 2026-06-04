# GCP - Logging Monitoring Security Profile

**Cloud Provider:** GCP  
**Security Domain:** logging_monitoring  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `GCP-LOG-001` | **Enable Data Access Audit Logs Across All Services** | Cloud Audit Logs | HIGH | `Data Access logs enabled for Cloud Storage and BigQuery; missing for IAM` | `Enable Data Access audit logging for all core services` | **NON_COMPLIANT** |
| `GCP-LOG-002` | **Centralized Security Log Sink to Cloud Storage / PubSub SIEM** | Log Archiving & SIEM | CRITICAL | `Aggregated org sink 'siem-security-export' active -> Pub/Sub topic` | `Active aggregated sink with Bucket Lock / retention policy >= 365 days` | **COMPLIANT** |
| `GCP-LOG-003` | **Security Command Center (SCC) Premium Tier & Continuous Monitoring** | Security Posture Management | HIGH | `SCC Enterprise Tier active; Event Threat Detection enabled` | `SCC Enterprise/Premium active across all organization folders` | **COMPLIANT** |
| `GCP-LOG-004` | **VPC Flow Logs Enabled with Appropriate Sampling Rate** | Network Visibility | MEDIUM | `Enabled on 8 of 10 subnets (aggregation interval 5s, sample rate 0.5)` | `100% subnet coverage for production VPCs` | **NON_COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `GCP-LOG-001`: Enable Data Access Audit Logs Across All Services
- **Category:** Cloud Audit Logs
- **Severity:** HIGH
- **Evidence Source:** `gcloud projects get-iam-policy (auditConfigs)`
- **Status:** NON_COMPLIANT
- **Description:** Admin Activity, Data Access (ADMIN_READ, DATA_READ, DATA_WRITE), and System Event logs must be enabled.
- **Current Setting:** `Data Access logs enabled for Cloud Storage and BigQuery; missing for IAM`
- **Security Recommendation:** `Enable Data Access audit logging for all core services`
- **Remediation & Migration Notes:** Update auditConfigs in organization IAM policy to capture all read/write data events.

### `GCP-LOG-002`: Centralized Security Log Sink to Cloud Storage / PubSub SIEM
- **Category:** Log Archiving & SIEM
- **Severity:** CRITICAL
- **Evidence Source:** `gcloud logging sinks list --organization=<ORG_ID>`
- **Status:** COMPLIANT
- **Description:** An aggregated log sink must export security logs to a dedicated, immutable archive bucket or Pub/Sub SIEM feed.
- **Current Setting:** `Aggregated org sink 'siem-security-export' active -> Pub/Sub topic`
- **Security Recommendation:** `Active aggregated sink with Bucket Lock / retention policy >= 365 days`
- **Remediation & Migration Notes:** Verify Pub/Sub dead-letter queue metrics and SIEM ingestion SLA.

### `GCP-LOG-003`: Security Command Center (SCC) Premium Tier & Continuous Monitoring
- **Category:** Security Posture Management
- **Severity:** HIGH
- **Evidence Source:** `gcloud scc settings describe`
- **Status:** COMPLIANT
- **Description:** Security Command Center must be active at Org level with Event Threat Detection and Security Health Analytics.
- **Current Setting:** `SCC Enterprise Tier active; Event Threat Detection enabled`
- **Security Recommendation:** `SCC Enterprise/Premium active across all organization folders`
- **Remediation & Migration Notes:** Review unassigned critical findings weekly.

### `GCP-LOG-004`: VPC Flow Logs Enabled with Appropriate Sampling Rate
- **Category:** Network Visibility
- **Severity:** MEDIUM
- **Evidence Source:** `gcloud compute networks subnets list`
- **Status:** NON_COMPLIANT
- **Description:** VPC Flow Logs should be enabled on all production subnets with metadata annotation.
- **Current Setting:** `Enabled on 8 of 10 subnets (aggregation interval 5s, sample rate 0.5)`
- **Security Recommendation:** `100% subnet coverage for production VPCs`
- **Remediation & Migration Notes:** Enable flow logs on remaining subnets for network forensic readiness.
