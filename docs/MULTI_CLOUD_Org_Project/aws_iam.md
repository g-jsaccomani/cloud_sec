# AWS - Iam Security Profile

**Cloud Provider:** AWS  
**Security Domain:** iam  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `AWS-IAM-001` | **Enforce Hardware MFA on AWS Root Account** | Root Account Security | CRITICAL | `Root MFA Enabled = True, Active Access Keys = 0` | `Hardware MFA Enforced, Access Keys = 0` | **COMPLIANT** |
| `AWS-IAM-002` | **Rotate IAM User Access Keys Every 90 Days** | Access Key Hygiene | HIGH | `4 IAM users have access keys > 90 days old` | `0 keys > 90 days old; migrate to IAM Roles / OIDC` | **NON_COMPLIANT** |
| `AWS-IAM-003` | **Enforce Strict IAM Password Policy (CIS 1.x)** | Password Policy | MEDIUM | `Minimum length = 14, Symbols required = True, Max age = 90 days` | `Min length 14, all complexity rules enabled, max age 90 days` | **COMPLIANT** |
| `AWS-IAM-004` | **Enforce AWS IAM Identity Center (SSO) for Human Users** | Single Sign-On (SSO) | HIGH | `IAM Identity Center active; 3 legacy IAM users still login via console` | `100% human login via IAM Identity Center` | **NON_COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `AWS-IAM-001`: Enforce Hardware MFA on AWS Root Account
- **Category:** Root Account Security
- **Severity:** CRITICAL
- **Evidence Source:** `aws iam get-account-summary`
- **Status:** COMPLIANT
- **Description:** The AWS Root account must have a dedicated Hardware MFA token enabled and no active access keys.
- **Current Setting:** `Root MFA Enabled = True, Active Access Keys = 0`
- **Security Recommendation:** `Hardware MFA Enforced, Access Keys = 0`
- **Remediation & Migration Notes:** Secure physical hardware token in enterprise fireproof safe.

### `AWS-IAM-002`: Rotate IAM User Access Keys Every 90 Days
- **Category:** Access Key Hygiene
- **Severity:** HIGH
- **Evidence Source:** `aws iam generate-credential-report`
- **Status:** NON_COMPLIANT
- **Description:** All IAM user programmatic access keys older than 90 days must be deactivated and rotated.
- **Current Setting:** `4 IAM users have access keys > 90 days old`
- **Security Recommendation:** `0 keys > 90 days old; migrate to IAM Roles / OIDC`
- **Remediation & Migration Notes:** Deactivate stale access keys for 'legacy-jenkins-bot' and 'developer-svc'.

### `AWS-IAM-003`: Enforce Strict IAM Password Policy (CIS 1.x)
- **Category:** Password Policy
- **Severity:** MEDIUM
- **Evidence Source:** `aws iam get-account-password-policy`
- **Status:** COMPLIANT
- **Description:** Password policy must require minimum length >= 14, uppercase, lowercase, numbers, symbols, and 90-day expiry.
- **Current Setting:** `Minimum length = 14, Symbols required = True, Max age = 90 days`
- **Security Recommendation:** `Min length 14, all complexity rules enabled, max age 90 days`
- **Remediation & Migration Notes:** Prefer IAM Identity Center (SSO) with enterprise IdP over local IAM passwords.

### `AWS-IAM-004`: Enforce AWS IAM Identity Center (SSO) for Human Users
- **Category:** Single Sign-On (SSO)
- **Severity:** HIGH
- **Evidence Source:** `aws sso-admin list-instances`
- **Status:** NON_COMPLIANT
- **Description:** Human users must authenticate via AWS IAM Identity Center integrated with Google Workspace / Okta.
- **Current Setting:** `IAM Identity Center active; 3 legacy IAM users still login via console`
- **Security Recommendation:** `100% human login via IAM Identity Center`
- **Remediation & Migration Notes:** Remove console login profiles for the 3 remaining local IAM users.
