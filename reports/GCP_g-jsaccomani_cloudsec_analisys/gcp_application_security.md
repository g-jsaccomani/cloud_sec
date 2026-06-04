# GCP - Application Security Security Profile

**Cloud Provider:** GCP  
**Security Domain:** application_security  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `GCP-APP-001` | **Enforce OAuth2 / JWT Authorization on Apigee / API Gateways** | API Security | CRITICAL | `100% of production API routes enforce JWT verification with short TTL (< 15 min)` | `Mandatory OAuth2 / JWT verification on all published API endpoints` | **COMPLIANT** |
| `GCP-APP-002` | **Enforce Secret Manager for All Application Credentials & Auto-Rotation** | Secrets Management | CRITICAL | `18 secrets stored in Secret Manager; 2 legacy services use plain-text env vars` | `100% Secret Manager adoption with Cloud Function automatic 90-day rotation` | **NON_COMPLIANT** |
| `GCP-APP-003` | **Enable Artifact Registry Automatic Vulnerability Scanning** | DevSecOps & Supply Chain | HIGH | `On-push vulnerability scanning active; 4 high CVEs detected in 'base-python-image'` | `Automatic CVE scanning enabled with CI/CD build break on Critical/High CVEs` | **NON_COMPLIANT** |
| `GCP-APP-004` | **Enforce Binary Authorization on GKE and Cloud Run** | Container Runtime Security | HIGH | `Binary Authorization policy deployed in Report-Only mode on Cloud Run` | `Enforced Binary Authorization policy requiring valid CI/CD attestation` | **NON_COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `GCP-APP-001`: Enforce OAuth2 / JWT Authorization on Apigee / API Gateways
- **Category:** API Security
- **Severity:** CRITICAL
- **Evidence Source:** `gcloud api-gateway api-configs describe`
- **Status:** COMPLIANT
- **Description:** All external APIs must require valid OAuth2 access tokens or JWT signatures validated at the API Gateway edge.
- **Current Setting:** `100% of production API routes enforce JWT verification with short TTL (< 15 min)`
- **Security Recommendation:** `Mandatory OAuth2 / JWT verification on all published API endpoints`
- **Remediation & Migration Notes:** Implement Apigee rate-limiting and spike arrest policies.

### `GCP-APP-002`: Enforce Secret Manager for All Application Credentials & Auto-Rotation
- **Category:** Secrets Management
- **Severity:** CRITICAL
- **Evidence Source:** `gcloud secrets list`
- **Status:** NON_COMPLIANT
- **Description:** Applications must fetch DB passwords and API tokens from GCP Secret Manager; no plain-text secrets in environment variables.
- **Current Setting:** `18 secrets stored in Secret Manager; 2 legacy services use plain-text env vars`
- **Security Recommendation:** `100% Secret Manager adoption with Cloud Function automatic 90-day rotation`
- **Remediation & Migration Notes:** Migrate legacy DB connection strings to Secret Manager and configure rotation schedule.

### `GCP-APP-003`: Enable Artifact Registry Automatic Vulnerability Scanning
- **Category:** DevSecOps & Supply Chain
- **Severity:** HIGH
- **Evidence Source:** `gcloud artifacts docker images list`
- **Status:** NON_COMPLIANT
- **Description:** Container images pushed to Artifact Registry must undergo automatic vulnerability scanning for CVEs before deployment.
- **Current Setting:** `On-push vulnerability scanning active; 4 high CVEs detected in 'base-python-image'`
- **Security Recommendation:** `Automatic CVE scanning enabled with CI/CD build break on Critical/High CVEs`
- **Remediation & Migration Notes:** Update base images and patch OpenSSL/Python dependencies.

### `GCP-APP-004`: Enforce Binary Authorization on GKE and Cloud Run
- **Category:** Container Runtime Security
- **Severity:** HIGH
- **Evidence Source:** `gcloud container binauthz policy describe`
- **Status:** NON_COMPLIANT
- **Description:** Only container images signed by authorized CI/CD attestors may be deployed to production GKE clusters and Cloud Run services.
- **Current Setting:** `Binary Authorization policy deployed in Report-Only mode on Cloud Run`
- **Security Recommendation:** `Enforced Binary Authorization policy requiring valid CI/CD attestation`
- **Remediation & Migration Notes:** Switch Binary Authorization mode from Report-Only to Enforce for production project.
