# AZURE - Iam Security Profile

**Cloud Provider:** AZURE  
**Security Domain:** iam  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `AZURE-IAM-001` | **Enforce Conditional Access Policy: MFA for All Administrators** | Microsoft Entra ID Security | CRITICAL | `Policy 'CA-Require-MFA-Admins' active; 1 break-glass account exempted` | `MFA enforced on 100% of admin roles with monitored break-glass exceptions` | **COMPLIANT** |
| `AZURE-IAM-002` | **Enforce Just-in-Time (JIT) Activation for Subscription Owner/Contributor Roles** | Privileged Identity Management (PIM) | HIGH | `3 permanent Subscription Owner assignments detected` | `0 permanent Owner assignments; enforce PIM JIT activation` | **NON_COMPLIANT** |
| `AZURE-IAM-003` | **Block Legacy Authentication Protocols in Entra ID** | Legacy Authentication | CRITICAL | `Policy 'CA-Block-Legacy-Auth' enabled in Report-Only mode` | `Policy enabled in Enforce mode` | **NON_COMPLIANT** |
| `AZURE-IAM-004` | **Enforce Managed Identities over Client Secrets for Azure Resources** | Service Principals & Identities | MEDIUM | `85% of services use Managed Identities; 3 App Services use client secrets` | `100% adoption of Managed Identities for intra-Azure service authentication` | **NON_COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `AZURE-IAM-001`: Enforce Conditional Access Policy: MFA for All Administrators
- **Category:** Microsoft Entra ID Security
- **Severity:** CRITICAL
- **Evidence Source:** `az ad policy conditional-access policy list`
- **Status:** COMPLIANT
- **Description:** Entra ID Conditional Access must enforce phishing-resistant MFA for all administrative roles.
- **Current Setting:** `Policy 'CA-Require-MFA-Admins' active; 1 break-glass account exempted`
- **Security Recommendation:** `MFA enforced on 100% of admin roles with monitored break-glass exceptions`
- **Remediation & Migration Notes:** Regularly test alert triggering on break-glass emergency account sign-ins.

### `AZURE-IAM-002`: Enforce Just-in-Time (JIT) Activation for Subscription Owner/Contributor Roles
- **Category:** Privileged Identity Management (PIM)
- **Severity:** HIGH
- **Evidence Source:** `az role assignment list --role Owner`
- **Status:** NON_COMPLIANT
- **Description:** No permanent Owner or Contributor assignments; administrators must activate access via PIM with ticket approval.
- **Current Setting:** `3 permanent Subscription Owner assignments detected`
- **Security Recommendation:** `0 permanent Owner assignments; enforce PIM JIT activation`
- **Remediation & Migration Notes:** Convert permanent Owner assignments to Eligible PIM assignments with 8-hour max duration.

### `AZURE-IAM-003`: Block Legacy Authentication Protocols in Entra ID
- **Category:** Legacy Authentication
- **Severity:** CRITICAL
- **Evidence Source:** `az rest --method get --url https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies`
- **Status:** NON_COMPLIANT
- **Description:** Conditional Access policy must explicitly block legacy protocols (POP, IMAP, SMTP Auth, older Office clients).
- **Current Setting:** `Policy 'CA-Block-Legacy-Auth' enabled in Report-Only mode`
- **Security Recommendation:** `Policy enabled in Enforce mode`
- **Remediation & Migration Notes:** Switch 'CA-Block-Legacy-Auth' state from 'reportOnly' to 'enabled'.

### `AZURE-IAM-004`: Enforce Managed Identities over Client Secrets for Azure Resources
- **Category:** Service Principals & Identities
- **Severity:** MEDIUM
- **Evidence Source:** `az identity list`
- **Status:** NON_COMPLIANT
- **Description:** Azure VMs, App Services, and Functions must use User-Assigned or System-Assigned Managed Identities instead of client secrets.
- **Current Setting:** `85% of services use Managed Identities; 3 App Services use client secrets`
- **Security Recommendation:** `100% adoption of Managed Identities for intra-Azure service authentication`
- **Remediation & Migration Notes:** Migrate legacy App Service database connections to Managed Identity with Entra Auth.
