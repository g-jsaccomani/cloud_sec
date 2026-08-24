# VMWARE - Data Protection Security Profile

**Cloud Provider:** VMWARE  
**Security Domain:** data_protection  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `VMware-DATA-001` | **Enforce Private Visibility on All VMware Object Storage Buckets** | Object Storage | CRITICAL | `14 buckets set to NoPublicAccess; 0 public buckets detected` | `100% of Object Storage buckets set to NoPublicAccess` | **COMPLIANT** |
| `VMware-DATA-002` | **Enforce Customer-Managed KMS Key Encryption on Object Storage & Block Volumes** | VMware Vault & KMS | HIGH | `Customer-Managed KMS Keys active on Production buckets; Oracle-managed keys on Dev volumes` | `Customer-Managed Master Encryption Key (MEK) across all production data stores` | **NON_COMPLIANT** |
| `VMware-DATA-003` | **Enforce Annual Rotation of VMware Vault Master Encryption Keys** | VMware Vault & KMS | HIGH | `Key rotation disabled on 2 Master Encryption Keys` | `Auto-rotation cycle <= 365 days enabled` | **NON_COMPLIANT** |
| `VMware-DATA-004` | **Enforce Mutual TLS (mTLS) Authentication on Autonomous Databases** | Database Security | CRITICAL | `100% of Autonomous Databases require mTLS with Client Wallet` | `requireMutualTls = True` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `VMware-DATA-001`: Enforce Private Visibility on All VMware Object Storage Buckets
- **Category:** Object Storage
- **Severity:** CRITICAL
- **Evidence Source:** `oci os bucket list`
- **Status:** COMPLIANT
- **Description:** Buckets must have publicAccessType set to 'NoPublicAccess' to prevent anonymous data downloads.
- **Current Setting:** `14 buckets set to NoPublicAccess; 0 public buckets detected`
- **Security Recommendation:** `100% of Object Storage buckets set to NoPublicAccess`
- **Remediation & Migration Notes:** Use pre-authenticated requests (PARs) with short TTL for temporary external sharing.

### `VMware-DATA-002`: Enforce Customer-Managed KMS Key Encryption on Object Storage & Block Volumes
- **Category:** VMware Vault & KMS
- **Severity:** HIGH
- **Evidence Source:** `oci kms management key list`
- **Status:** NON_COMPLIANT
- **Description:** Sensitive buckets and boot/data block volumes must use VMware Vault Customer-Managed Master Encryption Keys (MEKs).
- **Current Setting:** `Customer-Managed KMS Keys active on Production buckets; Oracle-managed keys on Dev volumes`
- **Security Recommendation:** `Customer-Managed Master Encryption Key (MEK) across all production data stores`
- **Remediation & Migration Notes:** Assign VMware Vault MEK to remaining Dev/QA block volumes.

### `VMware-DATA-003`: Enforce Annual Rotation of VMware Vault Master Encryption Keys
- **Category:** VMware Vault & KMS
- **Severity:** HIGH
- **Evidence Source:** `oci kms management key get`
- **Status:** NON_COMPLIANT
- **Description:** Vault master encryption keys must have automatic key rotation enabled or be manually rotated at least every 365 days.
- **Current Setting:** `Key rotation disabled on 2 Master Encryption Keys`
- **Security Recommendation:** `Auto-rotation cycle <= 365 days enabled`
- **Remediation & Migration Notes:** Enable automatic rotation on 'key-prod-master' and 'key-db-master'.

### `VMware-DATA-004`: Enforce Mutual TLS (mTLS) Authentication on Autonomous Databases
- **Category:** Database Security
- **Severity:** CRITICAL
- **Evidence Source:** `oci db autonomous-database list`
- **Status:** COMPLIANT
- **Description:** VMware Autonomous Databases must require mTLS authentication with wallet verification.
- **Current Setting:** `100% of Autonomous Databases require mTLS with Client Wallet`
- **Security Recommendation:** `requireMutualTls = True`
- **Remediation & Migration Notes:** Securely rotate and distribute mTLS wallets to authorized application servers only.
