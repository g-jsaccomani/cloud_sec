# GCP - Ai Security Security Profile

**Cloud Provider:** GCP  
**Security Domain:** ai_security  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `GCP-AI-001` | **Enforce Private Service Connect (PSC) / Private Endpoints for Vertex AI** | Vertex AI Networking | CRITICAL | `All 6 Vertex AI Workbench instances deployed on Private Subnet with PSC` | `100% Private Endpoints; 0 Public IPs on ML instances` | **COMPLIANT** |
| `GCP-AI-002` | **Enforce Customer-Managed Encryption Keys (CMEK) on Vertex AI Datasets and Models** | Model & Data Protection | HIGH | `CMEK configured on production Vertex AI datasets; default Google encryption on experiment cache` | `CMEK enforced across 100% of ML datasets and model registries` | **NON_COMPLIANT** |
| `GCP-AI-003` | **Enable Model Armor / LLM Guardrails against Prompt Injection & PII Leakage** | GenAI Governance & Safety | CRITICAL | `Model Armor policy 'prod-llm-guard' active with PII masking and prompt injection detection` | `Model Armor attached to all customer-facing LLM endpoints` | **COMPLIANT** |
| `GCP-AI-004` | **Enforce Region Restriction on Vertex AI Data Processing & Training** | Data Sovereignty | HIGH | `Region restricted to 'us-central1' via Organization Policy` | `Restrict processing to authorized data residency regions` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `GCP-AI-001`: Enforce Private Service Connect (PSC) / Private Endpoints for Vertex AI
- **Category:** Vertex AI Networking
- **Severity:** CRITICAL
- **Evidence Source:** `gcloud ai workbench instances list`
- **Status:** COMPLIANT
- **Description:** Vertex AI Workbench notebooks and training pipelines must not expose public IPs and must communicate over Private Service Connect.
- **Current Setting:** `All 6 Vertex AI Workbench instances deployed on Private Subnet with PSC`
- **Security Recommendation:** `100% Private Endpoints; 0 Public IPs on ML instances`
- **Remediation & Migration Notes:** Ensure VPC Service Controls perimeter protects 'aiplatform.googleapis.com'.

### `GCP-AI-002`: Enforce Customer-Managed Encryption Keys (CMEK) on Vertex AI Datasets and Models
- **Category:** Model & Data Protection
- **Severity:** HIGH
- **Evidence Source:** `gcloud ai datasets list`
- **Status:** NON_COMPLIANT
- **Description:** Training datasets, custom fine-tuned models, and inference caches must use Cloud KMS CMEK.
- **Current Setting:** `CMEK configured on production Vertex AI datasets; default Google encryption on experiment cache`
- **Security Recommendation:** `CMEK enforced across 100% of ML datasets and model registries`
- **Remediation & Migration Notes:** Configure Cloud KMS CryptoKey binding for Vertex AI service agent.

### `GCP-AI-003`: Enable Model Armor / LLM Guardrails against Prompt Injection & PII Leakage
- **Category:** GenAI Governance & Safety
- **Severity:** CRITICAL
- **Evidence Source:** `gcloud ai model-armor policies list`
- **Status:** COMPLIANT
- **Description:** Generative AI applications using Gemini/Vertex AI must implement Model Armor policies to filter prompt injection, jailbreaks, and PII output.
- **Current Setting:** `Model Armor policy 'prod-llm-guard' active with PII masking and prompt injection detection`
- **Security Recommendation:** `Model Armor attached to all customer-facing LLM endpoints`
- **Remediation & Migration Notes:** Regularly test adversarial prompts against AI safety filters.

### `GCP-AI-004`: Enforce Region Restriction on Vertex AI Data Processing & Training
- **Category:** Data Sovereignty
- **Severity:** HIGH
- **Evidence Source:** `gcloud resource-manager org-policies describe gcp.resourceLocations`
- **Status:** COMPLIANT
- **Description:** All Vertex AI inference and model fine-tuning must execute within approved organizational regions (e.g., us-central1) to maintain data residency.
- **Current Setting:** `Region restricted to 'us-central1' via Organization Policy`
- **Security Recommendation:** `Restrict processing to authorized data residency regions`
- **Remediation & Migration Notes:** Audit audit logs for unauthorized multi-region ML API invocations.
