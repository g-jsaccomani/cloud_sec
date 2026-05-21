# AWS - Application Security Security Profile

**Cloud Provider:** AWS  
**Security Domain:** application_security  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `AWS-APP-001` | **Enforce Cognito / Lambda JWT Authorizers on API Gateway Routes** | API Gateway Security | CRITICAL | `100% of REST API routes require Cognito User Pool authorizer` | `Mandatory authorizer attached to all published API stages` | **COMPLIANT** |
| `AWS-APP-002` | **Enforce Automatic Rotation for AWS Secrets Manager Secrets** | Secrets Management | CRITICAL | `14 secrets stored; 3 secrets have automatic rotation disabled` | `Automatic rotation schedule <= 90 days enabled on 100% of secrets` | **NON_COMPLIANT** |
| `AWS-APP-003` | **Enforce ECR Immutable Image Tags & Amazon Inspector Vulnerability Scanning** | Container Registry Security | HIGH | `10 of 12 ECR repositories set to IMMUTABLE with Inspector enabled` | `100% ECR repositories IMMUTABLE with Inspector continuous scanning` | **NON_COMPLIANT** |
| `AWS-APP-004` | **Enforce AWS Signer Code Signing on Lambda Functions** | Serverless Code Integrity | HIGH | `Code signing configuration 'signer-prod-profile' enforced on 100% of production Lambdas` | `Mandatory code signing profile attached to Lambda execution environments` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `AWS-APP-001`: Enforce Cognito / Lambda JWT Authorizers on API Gateway Routes
- **Category:** API Gateway Security
- **Severity:** CRITICAL
- **Evidence Source:** `aws apigateway get-authorizers`
- **Status:** COMPLIANT
- **Description:** REST and HTTP API Gateway endpoints must require authentication via AWS Cognito user pools or custom Lambda JWT authorizers.
- **Current Setting:** `100% of REST API routes require Cognito User Pool authorizer`
- **Security Recommendation:** `Mandatory authorizer attached to all published API stages`
- **Remediation & Migration Notes:** Ensure API Gateway usage plans enforce strict rate limiting per API key.

### `AWS-APP-002`: Enforce Automatic Rotation for AWS Secrets Manager Secrets
- **Category:** Secrets Management
- **Severity:** CRITICAL
- **Evidence Source:** `aws secretsmanager list-secrets`
- **Status:** NON_COMPLIANT
- **Description:** Database credentials and API keys stored in Secrets Manager must have automatic rotation configured via AWS Lambda.
- **Current Setting:** `14 secrets stored; 3 secrets have automatic rotation disabled`
- **Security Recommendation:** `Automatic rotation schedule <= 90 days enabled on 100% of secrets`
- **Remediation & Migration Notes:** Enable automatic rotation Lambda function for 'db-prod-sql-secret' and 'api-stripe-key'.

### `AWS-APP-003`: Enforce ECR Immutable Image Tags & Amazon Inspector Vulnerability Scanning
- **Category:** Container Registry Security
- **Severity:** HIGH
- **Evidence Source:** `aws ecr describe-repositories`
- **Status:** NON_COMPLIANT
- **Description:** Elastic Container Registry (ECR) repositories must enforce imageTagMutability=IMMUTABLE and continuous scanning via Amazon Inspector.
- **Current Setting:** `10 of 12 ECR repositories set to IMMUTABLE with Inspector enabled`
- **Security Recommendation:** `100% ECR repositories IMMUTABLE with Inspector continuous scanning`
- **Remediation & Migration Notes:** Update imageTagMutability to IMMUTABLE on 'dev-backend-repo' and 'qa-worker-repo'.

### `AWS-APP-004`: Enforce AWS Signer Code Signing on Lambda Functions
- **Category:** Serverless Code Integrity
- **Severity:** HIGH
- **Evidence Source:** `aws lambda list-code-signing-configs`
- **Status:** COMPLIANT
- **Description:** Production Lambda functions must require a trusted AWS Signer signing profile to prevent unauthorized code tampering.
- **Current Setting:** `Code signing configuration 'signer-prod-profile' enforced on 100% of production Lambdas`
- **Security Recommendation:** `Mandatory code signing profile attached to Lambda execution environments`
- **Remediation & Migration Notes:** Rotate code signing certificates in accordance with enterprise PKI policies.
