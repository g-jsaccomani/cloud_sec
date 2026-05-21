# AZURE - Logging Monitoring Security Profile

**Cloud Provider:** AZURE  
**Security Domain:** logging_monitoring  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `AZURE-LOG-001` | **Enable Microsoft Defender for Cloud on All Key Resource Types** | Defender for Cloud | HIGH | `Servers, Storage, and Kubernetes enabled; Key Vault plan set to 'Free'` | `Standard Defender plan active across all supported resource types` | **NON_COMPLIANT** |
| `AZURE-LOG-002` | **Export Azure Activity Log to Log Analytics & Event Hub SIEM** | Activity Logging | CRITICAL | `Diagnostic setting 'export-to-siem' active on 100% of subscriptions` | `Continuous Activity Log export active with >= 365 days retention` | **COMPLIANT** |
| `AZURE-LOG-003` | **Enforce Minimum 365-Day Retention on Security Log Analytics Workspace** | Log Retention | MEDIUM | `Workspace 'law-secops-central' retention = 365 days` | `retentionInDays >= 365` | **COMPLIANT** |
| `AZURE-LOG-004` | **Configure Security Alert Notifications for Subscription Admins** | Alerting | HIGH | `Alert notifications enabled for 'secops@domain.com'` | `High/Critical alerts emailed to Security Operations & Subscription Owners` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `AZURE-LOG-001`: Enable Microsoft Defender for Cloud on All Key Resource Types
- **Category:** Defender for Cloud
- **Severity:** HIGH
- **Evidence Source:** `az security pricing list`
- **Status:** NON_COMPLIANT
- **Description:** Defender for Cloud plans must be set to 'Standard' / enabled for Servers, Kubernetes, Storage, Key Vault, and SQL.
- **Current Setting:** `Servers, Storage, and Kubernetes enabled; Key Vault plan set to 'Free'`
- **Security Recommendation:** `Standard Defender plan active across all supported resource types`
- **Remediation & Migration Notes:** Enable Microsoft Defender for Key Vault to detect unusual cryptographic operations.

### `AZURE-LOG-002`: Export Azure Activity Log to Log Analytics & Event Hub SIEM
- **Category:** Activity Logging
- **Severity:** CRITICAL
- **Evidence Source:** `az monitor diagnostic-settings list`
- **Status:** COMPLIANT
- **Description:** Subscription Activity Logs (Administrative, Security, ServiceHealth, Alert) must export to a central Log Analytics workspace.
- **Current Setting:** `Diagnostic setting 'export-to-siem' active on 100% of subscriptions`
- **Security Recommendation:** `Continuous Activity Log export active with >= 365 days retention`
- **Remediation & Migration Notes:** Monitor Event Hub ingestion pipeline for SIEM connectivity.

### `AZURE-LOG-003`: Enforce Minimum 365-Day Retention on Security Log Analytics Workspace
- **Category:** Log Retention
- **Severity:** MEDIUM
- **Evidence Source:** `az monitor log-analytics workspace show`
- **Status:** COMPLIANT
- **Description:** The central security Log Analytics workspace must retain audit telemetry for at least 1 year.
- **Current Setting:** `Workspace 'law-secops-central' retention = 365 days`
- **Security Recommendation:** `retentionInDays >= 365`
- **Remediation & Migration Notes:** Use Azure Monitor Archive Logs for long-term multi-year compliance retention.

### `AZURE-LOG-004`: Configure Security Alert Notifications for Subscription Admins
- **Category:** Alerting
- **Severity:** HIGH
- **Evidence Source:** `az security contact list`
- **Status:** COMPLIANT
- **Description:** Microsoft Defender for Cloud must be configured to send high/critical security alerts to subscription owners and security email contacts.
- **Current Setting:** `Alert notifications enabled for 'secops@domain.com'`
- **Security Recommendation:** `High/Critical alerts emailed to Security Operations & Subscription Owners`
- **Remediation & Migration Notes:** Test alert notification email routing quarterly.
