# OCI - Ai Security Security Profile

**Cloud Provider:** OCI  
**Security Domain:** ai_security  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `OCI-AI-001` | **Enforce Private Endpoints for OCI Generative AI Dedicated Clusters** | OCI Generative AI | CRITICAL | `Dedicated AI cluster 'genai-prod-cluster' deployed with Private Endpoint in VCN 'vcn-prod-01'` | `100% Private Endpoints for Generative AI workloads` | **COMPLIANT** |
| `OCI-AI-002` | **Enforce VCN Isolation & Prohibit Public IPs on OCI Data Science Notebooks** | OCI Data Science | CRITICAL | `4 notebook sessions deployed without public IPs; 1 experiment notebook has public IP assigned` | `block-public-ip = True across 100% of notebook sessions` | **NON_COMPLIANT** |
| `OCI-AI-003` | **Enforce OCI Vault Customer-Managed KMS Key Encryption on ML Artifacts & Datasets** | Data Protection | HIGH | `Customer-Managed MEK active on production ML buckets` | `OCI Vault Master Encryption Key (MEK) enforced across all ML buckets` | **COMPLIANT** |
| `OCI-AI-004` | **Enforce Model Provenance & Output Guardrails in Application Gateways** | AI Safety | HIGH | `API Gateway function 'fn-ai-guardrail' active on text generation routes` | `Automated prompt injection & PII filtering on 100% of LLM routes` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `OCI-AI-001`: Enforce Private Endpoints for OCI Generative AI Dedicated Clusters
- **Category:** OCI Generative AI
- **Severity:** CRITICAL
- **Evidence Source:** `oci generative-ai dedicated-ai-cluster list`
- **Status:** COMPLIANT
- **Description:** OCI Generative AI dedicated AI clusters and inference endpoints must deploy inside private VCN subnets without public internet exposure.
- **Current Setting:** `Dedicated AI cluster 'genai-prod-cluster' deployed with Private Endpoint in VCN 'vcn-prod-01'`
- **Security Recommendation:** `100% Private Endpoints for Generative AI workloads`
- **Remediation & Migration Notes:** Restrict VCN Network Security Group ingress rules to authorized API gateways.

### `OCI-AI-002`: Enforce VCN Isolation & Prohibit Public IPs on OCI Data Science Notebooks
- **Category:** OCI Data Science
- **Severity:** CRITICAL
- **Evidence Source:** `oci data-science notebook-session list`
- **Status:** NON_COMPLIANT
- **Description:** Data Science notebook sessions must deploy inside a private subnet with block-public-ip=true.
- **Current Setting:** `4 notebook sessions deployed without public IPs; 1 experiment notebook has public IP assigned`
- **Security Recommendation:** `block-public-ip = True across 100% of notebook sessions`
- **Remediation & Migration Notes:** Terminate public notebook session 'ds-exp-01' and re-provision on Private Subnet.

### `OCI-AI-003`: Enforce OCI Vault Customer-Managed KMS Key Encryption on ML Artifacts & Datasets
- **Category:** Data Protection
- **Severity:** HIGH
- **Evidence Source:** `oci os bucket get`
- **Status:** COMPLIANT
- **Description:** All Object Storage buckets hosting ML training data and model checkpoints must be encrypted with an OCI Vault Master Encryption Key (MEK).
- **Current Setting:** `Customer-Managed MEK active on production ML buckets`
- **Security Recommendation:** `OCI Vault Master Encryption Key (MEK) enforced across all ML buckets`
- **Remediation & Migration Notes:** Verify key rotation schedule is set to <= 365 days.

### `OCI-AI-004`: Enforce Model Provenance & Output Guardrails in Application Gateways
- **Category:** AI Safety
- **Severity:** HIGH
- **Evidence Source:** `oci api-gateway deployment list`
- **Status:** COMPLIANT
- **Description:** Applications consuming OCI Generative AI models must implement prompt injection and PII sanitization filters at the API Gateway layer.
- **Current Setting:** `API Gateway function 'fn-ai-guardrail' active on text generation routes`
- **Security Recommendation:** `Automated prompt injection & PII filtering on 100% of LLM routes`
- **Remediation & Migration Notes:** Audit blocked prompt attempts in OCI Logging Analytics.
