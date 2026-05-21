# AZURE - Application Security Security Profile

**Cloud Provider:** AZURE  
**Security Domain:** application_security  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `AZURE-APP-001` | **Enforce OAuth2 / OpenID Connect Authorization on Azure API Management (APIM)** | API Management | CRITICAL | `100% of APIM APIs enforce 'validate-jwt' policy with Entra ID tenant validation` | `Mandatory OAuth2/JWT validation policy applied at global APIM scope` | **COMPLIANT** |
| `AZURE-APP-002` | **Enforce Automated Rotation & Expiration Dates on Key Vault Secrets** | Secrets Management | CRITICAL | `15 secrets have expiration date; 3 secrets lack expiration date or rotation` | `100% of secrets set expiration date and rotation policy` | **NON_COMPLIANT** |
| `AZURE-APP-003` | **Enable Defender for Containers Vulnerability Scanning on Azure Container Registry (ACR)** | Container Registry Security | HIGH | `Defender for Containers active on 'acrprodregistry01'; 0 critical CVEs found` | `Defender for Containers enabled across 100% of ACR instances` | **COMPLIANT** |
| `AZURE-APP-004` | **Enforce VNet Integration and Private Endpoints on Azure App Services** | PaaS Network Isolation | HIGH | `12 App Services use Private Endpoints; 2 Dev apps exposed on public IPs` | `100% Private Endpoints; Public Network Access = Disabled` | **NON_COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `AZURE-APP-001`: Enforce OAuth2 / OpenID Connect Authorization on Azure API Management (APIM)
- **Category:** API Management
- **Severity:** CRITICAL
- **Evidence Source:** `az apim api policy list`
- **Status:** COMPLIANT
- **Description:** APIM policies must validate OAuth2 access tokens or OpenID Connect signatures before forwarding traffic to backend APIs.
- **Current Setting:** `100% of APIM APIs enforce 'validate-jwt' policy with Entra ID tenant validation`
- **Security Recommendation:** `Mandatory OAuth2/JWT validation policy applied at global APIM scope`
- **Remediation & Migration Notes:** Ensure APIM rate-limit and quota-by-key policies are active.

### `AZURE-APP-002`: Enforce Automated Rotation & Expiration Dates on Key Vault Secrets
- **Category:** Secrets Management
- **Severity:** CRITICAL
- **Evidence Source:** `az keyvault secret list`
- **Status:** NON_COMPLIANT
- **Description:** All Key Vault secrets and certificates must define an expiration date and use Azure Event Grid automation for 90-day rotation.
- **Current Setting:** `15 secrets have expiration date; 3 secrets lack expiration date or rotation`
- **Security Recommendation:** `100% of secrets set expiration date and rotation policy`
- **Remediation & Migration Notes:** Set expiration dates on legacy secrets in 'kv-app-core'.

### `AZURE-APP-003`: Enable Defender for Containers Vulnerability Scanning on Azure Container Registry (ACR)
- **Category:** Container Registry Security
- **Severity:** HIGH
- **Evidence Source:** `az security pricing show --name ContainerRegistry`
- **Status:** COMPLIANT
- **Description:** ACR registries must have Defender for Containers enabled to scan container images for vulnerabilities upon push and continuously.
- **Current Setting:** `Defender for Containers active on 'acrprodregistry01'; 0 critical CVEs found`
- **Security Recommendation:** `Defender for Containers enabled across 100% of ACR instances`
- **Remediation & Migration Notes:** Integrate scan results into Azure DevOps build gates.

### `AZURE-APP-004`: Enforce VNet Integration and Private Endpoints on Azure App Services
- **Category:** PaaS Network Isolation
- **Severity:** HIGH
- **Evidence Source:** `az webapp list`
- **Status:** NON_COMPLIANT
- **Description:** App Services and Functions must enable VNet Integration for outbound traffic and disable public network access in favor of Private Endpoints.
- **Current Setting:** `12 App Services use Private Endpoints; 2 Dev apps exposed on public IPs`
- **Security Recommendation:** `100% Private Endpoints; Public Network Access = Disabled`
- **Remediation & Migration Notes:** Configure Private Endpoints for 'app-dev-test-1' and 'app-dev-test-2'.
