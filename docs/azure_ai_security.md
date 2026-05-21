# AZURE - Ai Security Security Profile

**Cloud Provider:** AZURE  
**Security Domain:** ai_security  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `AZURE-AI-001` | **Enforce Private Endpoints & Disable Public Network Access on Azure OpenAI** | Azure OpenAI Security | CRITICAL | `All 4 Azure OpenAI resources use Private Endpoints with publicNetworkAccess=Disabled` | `100% Private Endpoints; Public Network Access = Disabled` | **COMPLIANT** |
| `AZURE-AI-002` | **Enforce Azure AI Content Safety Filters against Prompt Injection & Jailbreaks** | AI Safety & Content Filtering | CRITICAL | `Filter 'content-safety-strict' attached to production LLM deployments` | `AI Content Safety filter active on all model deployments` | **COMPLIANT** |
| `AZURE-AI-003` | **Enforce Customer Managed Key (CMK) Encryption on Azure ML Workspaces** | Azure Machine Learning | HIGH | `CMK encryption active on workspace 'ml-prod-workspace'; Microsoft-managed key on 'ml-dev'` | `Customer Managed Key (CMK) enforced across all ML workspaces` | **NON_COMPLIANT** |
| `AZURE-AI-004` | **Enforce Managed Virtual Network Isolation for Azure ML Compute** | Azure Machine Learning | HIGH | `Managed Virtual Network = 'AllowOnlyApprovedOutbound' on 100% of ML compute` | `Managed VNet Isolation enabled with restricted outbound rules` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `AZURE-AI-001`: Enforce Private Endpoints & Disable Public Network Access on Azure OpenAI
- **Category:** Azure OpenAI Security
- **Severity:** CRITICAL
- **Evidence Source:** `az cognitiveservices account list`
- **Status:** COMPLIANT
- **Description:** Azure OpenAI instances must disable public network access (publicNetworkAccess=Disabled) and communicate exclusively via Private Endpoints.
- **Current Setting:** `All 4 Azure OpenAI resources use Private Endpoints with publicNetworkAccess=Disabled`
- **Security Recommendation:** `100% Private Endpoints; Public Network Access = Disabled`
- **Remediation & Migration Notes:** Verify DNS integration with Private DNS Zone 'privatelink.openai.azure.com'.

### `AZURE-AI-002`: Enforce Azure AI Content Safety Filters against Prompt Injection & Jailbreaks
- **Category:** AI Safety & Content Filtering
- **Severity:** CRITICAL
- **Evidence Source:** `az cognitiveservices account deployment list`
- **Status:** COMPLIANT
- **Description:** Azure OpenAI deployments must attach an AI Content Safety filter configured to block hate speech, jailbreaks, and prompt injection attempts.
- **Current Setting:** `Filter 'content-safety-strict' attached to production LLM deployments`
- **Security Recommendation:** `AI Content Safety filter active on all model deployments`
- **Remediation & Migration Notes:** Regularly review Content Safety block logs in Log Analytics.

### `AZURE-AI-003`: Enforce Customer Managed Key (CMK) Encryption on Azure ML Workspaces
- **Category:** Azure Machine Learning
- **Severity:** HIGH
- **Evidence Source:** `az ml workspace show`
- **Status:** NON_COMPLIANT
- **Description:** Azure Machine Learning workspaces must use Key Vault Customer Managed Keys to encrypt training metrics, datasets, and notebooks.
- **Current Setting:** `CMK encryption active on workspace 'ml-prod-workspace'; Microsoft-managed key on 'ml-dev'`
- **Security Recommendation:** `Customer Managed Key (CMK) enforced across all ML workspaces`
- **Remediation & Migration Notes:** Enable Key Vault CMK encryption on 'ml-dev' workspace.

### `AZURE-AI-004`: Enforce Managed Virtual Network Isolation for Azure ML Compute
- **Category:** Azure Machine Learning
- **Severity:** HIGH
- **Evidence Source:** `az ml compute list`
- **Status:** COMPLIANT
- **Description:** Azure Machine Learning compute instances and clusters must deploy behind a Managed Virtual Network with outbound FQDN rules.
- **Current Setting:** `Managed Virtual Network = 'AllowOnlyApprovedOutbound' on 100% of ML compute`
- **Security Recommendation:** `Managed VNet Isolation enabled with restricted outbound rules`
- **Remediation & Migration Notes:** Audit custom FQDN outbound exceptions monthly.
