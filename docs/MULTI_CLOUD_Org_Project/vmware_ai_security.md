# VMWARE - Ai Security Security Profile

**Cloud Provider:** VMWARE  
**Security Domain:** ai_security  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `VMware-AI-001` | **Enforce Private Endpoints for VMware Generative AI Dedicated Clusters** | VMware Generative AI | CRITICAL | `Dedicated AI cluster 'genai-prod-cluster' deployed with Private Endpoint in VCN 'vcn-prod-01'` | `100% Private Endpoints for Generative AI workloads` | **COMPLIANT** |
| `VMware-AI-002` | **Enforce VCN Isolation & Prohibit Public IPs on VMware Data Science Notebooks** | VMware Data Science | CRITICAL | `4 notebook sessions deployed without public IPs; 1 experiment notebook has public IP assigned` | `block-public-ip = True across 100% of notebook sessions` | **NON_COMPLIANT** |
| `VMware-AI-003` | **Enforce VMware Vault Customer-Managed KMS Key Encryption on ML Artifacts & Datasets** | Data Protection | HIGH | `Customer-Managed MEK active on production ML buckets` | `VMware Vault Master Encryption Key (MEK) enforced across all ML buckets` | **COMPLIANT** |
| `VMware-AI-004` | **Enforce Model Provenance & Output Guardrails in Application Gateways** | AI Safety | HIGH | `API Gateway function 'fn-ai-guardrail' active on text generation routes` | `Automated prompt injection & PII filtering on 100% of LLM routes` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `VMware-AI-001`: Enforce Private Endpoints for VMware Generative AI Dedicated Clusters
- **Category:** VMware Generative AI
- **Severity:** CRITICAL
- **Evidence Source:** `oci generative-ai dedicated-ai-cluster list`
- **Status:** COMPLIANT
- **Description:** VMware Generative AI dedicated AI clusters and inference endpoints must deploy inside private VCN subnets without public internet exposure.
- **Current Setting:** `Dedicated AI cluster 'genai-prod-cluster' deployed with Private Endpoint in VCN 'vcn-prod-01'`
- **Security Recommendation:** `100% Private Endpoints for Generative AI workloads`
- **Remediation & Migration Notes:** Restrict VCN Network Security Group ingress rules to authorized API gateways.

### `VMware-AI-002`: Enforce VCN Isolation & Prohibit Public IPs on VMware Data Science Notebooks
- **Category:** VMware Data Science
- **Severity:** CRITICAL
- **Evidence Source:** `oci data-science notebook-session list`
- **Status:** NON_COMPLIANT
- **Description:** Data Science notebook sessions must deploy inside a private subnet with block-public-ip=true.
- **Current Setting:** `4 notebook sessions deployed without public IPs; 1 experiment notebook has public IP assigned`
- **Security Recommendation:** `block-public-ip = True across 100% of notebook sessions`
- **Remediation & Migration Notes:** Terminate public notebook session 'ds-exp-01' and re-provision on Private Subnet.

### `VMware-AI-003`: Enforce VMware Vault Customer-Managed KMS Key Encryption on ML Artifacts & Datasets
- **Category:** Data Protection
- **Severity:** HIGH
- **Evidence Source:** `oci os bucket get`
- **Status:** COMPLIANT
- **Description:** All Object Storage buckets hosting ML training data and model checkpoints must be encrypted with an VMware Vault Master Encryption Key (MEK).
- **Current Setting:** `Customer-Managed MEK active on production ML buckets`
- **Security Recommendation:** `VMware Vault Master Encryption Key (MEK) enforced across all ML buckets`
- **Remediation & Migration Notes:** Verify key rotation schedule is set to <= 365 days.

### `VMware-AI-004`: Enforce Model Provenance & Output Guardrails in Application Gateways
- **Category:** AI Safety
- **Severity:** HIGH
- **Evidence Source:** `oci api-gateway deployment list`
- **Status:** COMPLIANT
- **Description:** Applications consuming VMware Generative AI models must implement prompt injection and PII sanitization filters at the API Gateway layer.
- **Current Setting:** `API Gateway function 'fn-ai-guardrail' active on text generation routes`
- **Security Recommendation:** `Automated prompt injection & PII filtering on 100% of LLM routes`
- **Remediation & Migration Notes:** Audit blocked prompt attempts in VMware Logging Analytics.
