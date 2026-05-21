# AWS - Ai Security Security Profile

**Cloud Provider:** AWS  
**Security Domain:** ai_security  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `AWS-AI-001` | **Enforce Amazon Bedrock Guardrails for Content Safety & PII Redaction** | Amazon Bedrock Security | CRITICAL | `Guardrail 'bedrock-enterprise-guard' active with PII masking and prompt attack filter` | `Bedrock Guardrails enforced on 100% of LLM invocations` | **COMPLIANT** |
| `AWS-AI-002` | **Enforce VPC Endpoints (PrivateLink) on SageMaker Notebooks and Training Jobs** | Amazon SageMaker Security | CRITICAL | `4 SageMaker notebooks deployed in private VPC; 1 legacy notebook allows DirectInternetAccess=True` | `DirectInternetAccess=False across 100% of SageMaker resources` | **NON_COMPLIANT** |
| `AWS-AI-003` | **Enforce Customer Managed KMS Key (CMK) on SageMaker Model Artifacts & S3 Training Data** | Model & Data Encryption | HIGH | `CMEK active on production S3 buckets; AWS-managed KMS key used on Dev artifacts` | `Customer Managed Key (CMK) enforced across all ML data stores` | **NON_COMPLIANT** |
| `AWS-AI-004` | **Enable Comprehensive Model Invocation Logging in Amazon Bedrock** | Bedrock Auditing | HIGH | `Model invocation logging enabled -> CloudWatch Log Group '/aws/bedrock/audit'` | `Active Bedrock model logging with KMS encryption and >= 365 days retention` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `AWS-AI-001`: Enforce Amazon Bedrock Guardrails for Content Safety & PII Redaction
- **Category:** Amazon Bedrock Security
- **Severity:** CRITICAL
- **Evidence Source:** `aws bedrock list-guardrails`
- **Status:** COMPLIANT
- **Description:** Generative AI applications on Amazon Bedrock must enforce Guardrails to block harmful topics, hate speech, and redact PII in input/output.
- **Current Setting:** `Guardrail 'bedrock-enterprise-guard' active with PII masking and prompt attack filter`
- **Security Recommendation:** `Bedrock Guardrails enforced on 100% of LLM invocations`
- **Remediation & Migration Notes:** Regularly evaluate guardrail latency and accuracy against benchmark prompt sets.

### `AWS-AI-002`: Enforce VPC Endpoints (PrivateLink) on SageMaker Notebooks and Training Jobs
- **Category:** Amazon SageMaker Security
- **Severity:** CRITICAL
- **Evidence Source:** `aws sagemaker list-notebook-instances`
- **Status:** NON_COMPLIANT
- **Description:** SageMaker Studio notebooks and training jobs must deploy in private VPC subnets with directAccessOnly=True and no public Internet egress.
- **Current Setting:** `4 SageMaker notebooks deployed in private VPC; 1 legacy notebook allows DirectInternetAccess=True`
- **Security Recommendation:** `DirectInternetAccess=False across 100% of SageMaker resources`
- **Remediation & Migration Notes:** Reconfigure 'ml-notebook-test' to use VPC PrivateLink endpoints.

### `AWS-AI-003`: Enforce Customer Managed KMS Key (CMK) on SageMaker Model Artifacts & S3 Training Data
- **Category:** Model & Data Encryption
- **Severity:** HIGH
- **Evidence Source:** `aws sagemaker list-models`
- **Status:** NON_COMPLIANT
- **Description:** All SageMaker model artifacts and S3 training data buckets must be encrypted with Customer Managed KMS Keys.
- **Current Setting:** `CMEK active on production S3 buckets; AWS-managed KMS key used on Dev artifacts`
- **Security Recommendation:** `Customer Managed Key (CMK) enforced across all ML data stores`
- **Remediation & Migration Notes:** Update model artifact encryption parameter to reference enterprise KMS CMK ARN.

### `AWS-AI-004`: Enable Comprehensive Model Invocation Logging in Amazon Bedrock
- **Category:** Bedrock Auditing
- **Severity:** HIGH
- **Evidence Source:** `aws bedrock get-model-invocation-logging-configuration`
- **Status:** COMPLIANT
- **Description:** Amazon Bedrock must be configured to log all text/image model invocations to an encrypted CloudWatch Log Group and S3 archive.
- **Current Setting:** `Model invocation logging enabled -> CloudWatch Log Group '/aws/bedrock/audit'`
- **Security Recommendation:** `Active Bedrock model logging with KMS encryption and >= 365 days retention`
- **Remediation & Migration Notes:** Configure CloudWatch Metric Alarm for excessive token usage or repeated guardrail blocks.
