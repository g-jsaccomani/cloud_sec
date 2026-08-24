# AZURE - Compliance Governance Security Profile

**Cloud Provider:** AZURE  
**Security Domain:** compliance_governance  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `AZURE-GOV-001` | **Assign Microsoft Cloud Security Benchmark at Management Group Root** | Azure Policy & MCSB | CRITICAL | `Assigned to 'mg-enterprise-root' with 88% compliance score` | `MCSB initiative assigned and enforced across all management groups` | **COMPLIANT** |
| `AZURE-GOV-002` | **Enforce CanNotDelete Resource Locks on Production Resource Groups** | Resource Protection | HIGH | `Lock applied to 8 of 10 production resource groups` | `CanNotDelete lock on 100% of production core infrastructure` | **NON_COMPLIANT** |
| `AZURE-GOV-003` | **Enforce Enterprise Landing Zone Management Group Architecture** | Management Group Hierarchy | MEDIUM | `Management Group hierarchy deployed; 2 subscriptions in Default Root MG` | `0 subscriptions residing directly under Root Management Group` | **NON_COMPLIANT** |
| `AZURE-GOV-004` | **Enforce Mandatory Security Classification & Owner Tags via Azure Policy** | Resource Tagging | LOW | `Policy 'Deny-Missing-Tags' active across all subscriptions` | `Mandatory tagging enforced via 'Deny' policy effect` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `AZURE-GOV-001`: Assign Microsoft Cloud Security Benchmark at Management Group Root
- **Category:** Azure Policy & MCSB
- **Severity:** CRITICAL
- **Evidence Source:** `az policy assignment list --scope /providers/Microsoft.Management/managementGroups/<MG_ID>`
- **Status:** COMPLIANT
- **Description:** The Microsoft Cloud Security Benchmark (MCSB) initiative must be assigned at the root Management Group.
- **Current Setting:** `Assigned to 'mg-enterprise-root' with 88% compliance score`
- **Security Recommendation:** `MCSB initiative assigned and enforced across all management groups`
- **Remediation & Migration Notes:** Review exempt resources and require quarterly CISO re-attestation.

### `AZURE-GOV-002`: Enforce CanNotDelete Resource Locks on Production Resource Groups
- **Category:** Resource Protection
- **Severity:** HIGH
- **Evidence Source:** `az lock list`
- **Status:** NON_COMPLIANT
- **Description:** Production resource groups containing stateful databases, VNets, and Key Vaults must have 'CanNotDelete' locks assigned.
- **Current Setting:** `Lock applied to 8 of 10 production resource groups`
- **Security Recommendation:** `CanNotDelete lock on 100% of production core infrastructure`
- **Remediation & Migration Notes:** Apply CanNotDelete lock to 'rg-prod-sql-eastus' and 'rg-prod-vnet-hub'.

### `AZURE-GOV-003`: Enforce Enterprise Landing Zone Management Group Architecture
- **Category:** Management Group Hierarchy
- **Severity:** MEDIUM
- **Evidence Source:** `az account management-group list`
- **Status:** NON_COMPLIANT
- **Description:** Subscriptions must be organized into clear Management Group tiers (Platform/Connectivity, Identity, LandingZones/Prod, Non-Prod).
- **Current Setting:** `Management Group hierarchy deployed; 2 subscriptions in Default Root MG`
- **Security Recommendation:** `0 subscriptions residing directly under Root Management Group`
- **Remediation & Migration Notes:** Move orphan subscriptions into appropriate Landing Zone management group.

### `AZURE-GOV-004`: Enforce Mandatory Security Classification & Owner Tags via Azure Policy
- **Category:** Resource Tagging
- **Severity:** LOW
- **Evidence Source:** `az policy assignment show --name Deny-Missing-Tags`
- **Status:** COMPLIANT
- **Description:** Azure Policy must deny resource creation if mandatory tags ('Environment', 'DataClassification', 'CostCenter') are missing.
- **Current Setting:** `Policy 'Deny-Missing-Tags' active across all subscriptions`
- **Security Recommendation:** `Mandatory tagging enforced via 'Deny' policy effect`
- **Remediation & Migration Notes:** Maintain automated remediation tasks for inherited resource group tags.
