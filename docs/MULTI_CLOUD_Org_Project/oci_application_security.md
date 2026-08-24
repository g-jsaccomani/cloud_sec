# OCI - Application Security Security Profile

**Cloud Provider:** OCI  
**Security Domain:** application_security  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `OCI-APP-001` | **Enforce JWT Validation and Mutual TLS (mTLS) on OCI API Gateway** | API Gateway Security | CRITICAL | `100% of API routes enforce JWT validation; mTLS active on financial transaction routes` | `Mandatory JWT validation and rate limiting across all API gateways` | **COMPLIANT** |
| `OCI-APP-002` | **Enforce OCI Vault Secret Management & Eliminate Plain-Text Configs** | Secrets Management | CRITICAL | `16 secrets managed in OCI Vault; 2 microservices use plain-text environment variables` | `100% OCI Vault secrets adoption with zero local plain-text storage` | **NON_COMPLIANT** |
| `OCI-APP-003` | **Enable OCI Vulnerability Scanning Service on Container Registry Repositories** | Container Security | HIGH | `Vulnerability Scanning Service active on 8 of 10 OCIR repositories` | `Continuous CVE scanning active on 100% of OCIR repositories` | **NON_COMPLIANT** |
| `OCI-APP-004` | **Attach OCI WAF with API Rate Limiting and OWASP Rules to API Gateways** | WAF & API Protection | HIGH | `WAF Policy 'waf-api-prod' attached to production API Gateway edge` | `WAF attached to 100% of public API endpoints` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `OCI-APP-001`: Enforce JWT Validation and Mutual TLS (mTLS) on OCI API Gateway
- **Category:** API Gateway Security
- **Severity:** CRITICAL
- **Evidence Source:** `oci api-gateway deployment list`
- **Status:** COMPLIANT
- **Description:** Public and internal OCI API Gateway deployments must validate JWT signatures from OCI Identity Domains / Okta and enforce mTLS for high-security endpoints.
- **Current Setting:** `100% of API routes enforce JWT validation; mTLS active on financial transaction routes`
- **Security Recommendation:** `Mandatory JWT validation and rate limiting across all API gateways`
- **Remediation & Migration Notes:** Monitor API gateway 4xx/5xx authentication failure rates.

### `OCI-APP-002`: Enforce OCI Vault Secret Management & Eliminate Plain-Text Configs
- **Category:** Secrets Management
- **Severity:** CRITICAL
- **Evidence Source:** `oci vault secret list`
- **Status:** NON_COMPLIANT
- **Description:** Application credentials and TLS certificates must be stored in OCI Vault as secrets and retrieved via Dynamic Groups at runtime.
- **Current Setting:** `16 secrets managed in OCI Vault; 2 microservices use plain-text environment variables`
- **Security Recommendation:** `100% OCI Vault secrets adoption with zero local plain-text storage`
- **Remediation & Migration Notes:** Refactor 'svc-legacy-db' and 'svc-email-sender' to read credentials from OCI Vault.

### `OCI-APP-003`: Enable OCI Vulnerability Scanning Service on Container Registry Repositories
- **Category:** Container Security
- **Severity:** HIGH
- **Evidence Source:** `oci vulnerability-scanning container-scan-recipe list`
- **Status:** NON_COMPLIANT
- **Description:** OCI Container Registry (OCIR) repositories must have automated vulnerability scanning enabled to flag CVEs in container base images.
- **Current Setting:** `Vulnerability Scanning Service active on 8 of 10 OCIR repositories`
- **Security Recommendation:** `Continuous CVE scanning active on 100% of OCIR repositories`
- **Remediation & Migration Notes:** Attach container scanning recipe to 'ocir-dev-tools' and 'ocir-sandbox-repo'.

### `OCI-APP-004`: Attach OCI WAF with API Rate Limiting and OWASP Rules to API Gateways
- **Category:** WAF & API Protection
- **Severity:** HIGH
- **Evidence Source:** `oci waf policy list`
- **Status:** COMPLIANT
- **Description:** OCI Web Application Firewall (WAF) must protect API Gateway external load balancer endpoints against OWASP Top 10 API attacks.
- **Current Setting:** `WAF Policy 'waf-api-prod' attached to production API Gateway edge`
- **Security Recommendation:** `WAF attached to 100% of public API endpoints`
- **Remediation & Migration Notes:** Regularly review WAF bot management rules.
