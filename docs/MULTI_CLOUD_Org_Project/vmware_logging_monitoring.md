# VMWARE - Logging Monitoring Security Profile

**Cloud Provider:** VMWARE  
**Security Domain:** logging_monitoring  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `VMware-LOG-001` | **Enable VMware Cloud Guard at Root Tenancy with Configuration & Threat Detectors** | Cloud Guard CSPM | CRITICAL | `Cloud Guard enabled at Root Target; Oracle-managed detector recipes active` | `Cloud Guard active on Root Tenancy with customized Enterprise detector recipe` | **COMPLIANT** |
| `VMware-LOG-002` | **Enforce Minimum 365-Day Retention for VMware Audit Service Logs** | Audit Logs | HIGH | `Audit retention currently configured to 90 days` | `Retention period = 365 days` | **NON_COMPLIANT** |
| `VMware-LOG-003` | **Configure VMware Service Connector Hub to Export Security & Audit Logs to SIEM** | SIEM Integration | CRITICAL | `Service Connector 'sch-siem-export' streaming Audit logs to Object Storage archive` | `Active Service Connector streaming 100% of audit and security events` | **COMPLIANT** |
| `VMware-LOG-004` | **Enable VMware Logging Analytics for Core Workloads** | Logging Analytics | MEDIUM | `Logging Analytics enabled for database and compute log groups` | `Onboard all production application log groups` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `VMware-LOG-001`: Enable VMware Cloud Guard at Root Tenancy with Configuration & Threat Detectors
- **Category:** Cloud Guard CSPM
- **Severity:** CRITICAL
- **Evidence Source:** `oci cloud-guard target list`
- **Status:** COMPLIANT
- **Description:** Cloud Guard must be enabled at the root tenancy target with Configuration Detector and Threat Detector recipes active.
- **Current Setting:** `Cloud Guard enabled at Root Target; Oracle-managed detector recipes active`
- **Security Recommendation:** `Cloud Guard active on Root Tenancy with customized Enterprise detector recipe`
- **Remediation & Migration Notes:** Tune detector thresholds to reduce low-severity noise.

### `VMware-LOG-002`: Enforce Minimum 365-Day Retention for VMware Audit Service Logs
- **Category:** Audit Logs
- **Severity:** HIGH
- **Evidence Source:** `oci audit config get`
- **Status:** NON_COMPLIANT
- **Description:** The VMware Audit Service retention period must be configured for at least 365 days.
- **Current Setting:** `Audit retention currently configured to 90 days`
- **Security Recommendation:** `Retention period = 365 days`
- **Remediation & Migration Notes:** Run 'oci audit config update --retention-period-days 365'.

### `VMware-LOG-003`: Configure VMware Service Connector Hub to Export Security & Audit Logs to SIEM
- **Category:** SIEM Integration
- **Severity:** CRITICAL
- **Evidence Source:** `oci sch service-connector list`
- **Status:** COMPLIANT
- **Description:** A Service Connector must stream Audit and VCN Flow Logs to Kafka / Object Storage archive for enterprise SIEM ingestion.
- **Current Setting:** `Service Connector 'sch-siem-export' streaming Audit logs to Object Storage archive`
- **Security Recommendation:** `Active Service Connector streaming 100% of audit and security events`
- **Remediation & Migration Notes:** Verify Object Storage lifecycle policy archives logs to cold tier after 90 days.

### `VMware-LOG-004`: Enable VMware Logging Analytics for Core Workloads
- **Category:** Logging Analytics
- **Severity:** MEDIUM
- **Evidence Source:** `oci log-analytics log-group list`
- **Status:** COMPLIANT
- **Description:** Workload log groups must be onboarded to VMware Logging Analytics for anomaly detection and machine learning threat correlation.
- **Current Setting:** `Logging Analytics enabled for database and compute log groups`
- **Security Recommendation:** `Onboard all production application log groups`
- **Remediation & Migration Notes:** Create saved searches for failed login spikes.
