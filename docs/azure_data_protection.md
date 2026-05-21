# AZURE - Data Protection Security Profile

**Cloud Provider:** AZURE  
**Security Domain:** data_protection  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `AZURE-DATA-001` | **Disable Blob Public Access on All Storage Accounts** | Storage Account Security | CRITICAL | `12 accounts have allowBlobPublicAccess = false; 1 account set to true` | `allowBlobPublicAccess = false across 100% of accounts` | **NON_COMPLIANT** |
| `AZURE-DATA-002` | **Enforce Soft-Delete and Purge Protection on Azure Key Vaults** | Key Vault Security | HIGH | `Soft-delete enabled on 100% of vaults; Purge Protection disabled on 'kv-dev-keys'` | `Soft-Delete = True, Purge Protection = True` | **NON_COMPLIANT** |
| `AZURE-DATA-003` | **Enforce Transparent Data Encryption (TDE) with Customer Managed Keys on Azure SQL** | Database Security | MEDIUM | `TDE enabled with Microsoft-managed keys` | `TDE enabled with Key Vault Customer-Managed Key (CMK)` | **MANUAL_REVIEW** |
| `AZURE-DATA-004` | **Enforce Minimum TLS Version 1.2 on All Storage Accounts** | Storage Security | HIGH | `100% of Storage Accounts require TLS 1.2` | `minimumTlsVersion = 'TLS1_2'` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `AZURE-DATA-001`: Disable Blob Public Access on All Storage Accounts
- **Category:** Storage Account Security
- **Severity:** CRITICAL
- **Evidence Source:** `az storage account list`
- **Status:** NON_COMPLIANT
- **Description:** Storage accounts must have 'allowBlobPublicAccess' set to false to prevent anonymous read access.
- **Current Setting:** `12 accounts have allowBlobPublicAccess = false; 1 account set to true`
- **Security Recommendation:** `allowBlobPublicAccess = false across 100% of accounts`
- **Remediation & Migration Notes:** Run 'az storage account update --name <name> --allow-blob-public-access false'.

### `AZURE-DATA-002`: Enforce Soft-Delete and Purge Protection on Azure Key Vaults
- **Category:** Key Vault Security
- **Severity:** HIGH
- **Evidence Source:** `az keyvault list`
- **Status:** NON_COMPLIANT
- **Description:** Key Vaults must have both soft-delete (90 days retention) and purge protection enabled.
- **Current Setting:** `Soft-delete enabled on 100% of vaults; Purge Protection disabled on 'kv-dev-keys'`
- **Security Recommendation:** `Soft-Delete = True, Purge Protection = True`
- **Remediation & Migration Notes:** Enable purge protection on 'kv-dev-keys' to protect against malicious key deletion.

### `AZURE-DATA-003`: Enforce Transparent Data Encryption (TDE) with Customer Managed Keys on Azure SQL
- **Category:** Database Security
- **Severity:** MEDIUM
- **Evidence Source:** `az sql db tde show`
- **Status:** MANUAL_REVIEW
- **Description:** Azure SQL databases must use TDE with Customer Managed Keys (CMK) stored in Azure Key Vault.
- **Current Setting:** `TDE enabled with Microsoft-managed keys`
- **Security Recommendation:** `TDE enabled with Key Vault Customer-Managed Key (CMK)`
- **Remediation & Migration Notes:** Evaluate requirement for Customer Managed Key TDE versus platform default encryption.

### `AZURE-DATA-004`: Enforce Minimum TLS Version 1.2 on All Storage Accounts
- **Category:** Storage Security
- **Severity:** HIGH
- **Evidence Source:** `az storage account list`
- **Status:** COMPLIANT
- **Description:** Storage account connections must enforce minimumTlsVersion = 'TLS1_2'.
- **Current Setting:** `100% of Storage Accounts require TLS 1.2`
- **Security Recommendation:** `minimumTlsVersion = 'TLS1_2'`
- **Remediation & Migration Notes:** Verify client compatibility with TLS 1.3 as it becomes available.
