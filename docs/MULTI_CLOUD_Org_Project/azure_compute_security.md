# AZURE - Compute Security Security Profile

**Cloud Provider:** AZURE  
**Security Domain:** compute_security  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `AZURE-COMP-001` | **Enforce Trusted Launch (Secure Boot & vTPM) on Azure VMs** | Virtual Machines | HIGH | `14 VMs use Trusted Launch; 2 legacy VMs use Standard Gen1 type` | `100% Trusted Launch VMs` | **NON_COMPLIANT** |
| `AZURE-COMP-002` | **Enforce Azure Bastion for Secure Remote VM Administration** | Virtual Machines | CRITICAL | `Azure Bastion deployed in 'vnet-hub-prod'; 0 VMs have Public IPs assigned` | `100% Bastion-managed administrative access; 0 VM Public IPs` | **COMPLIANT** |
| `AZURE-COMP-003` | **Enforce AKS Private Cluster with Azure AD / Entra ID RBAC** | AKS Kubernetes Security | CRITICAL | `Cluster 'aks-prod-01' is Private with Entra RBAC and Azure Policy Add-on enabled` | `Private Cluster = True, enableAzureRBAC = True` | **COMPLIANT** |
| `AZURE-COMP-004` | **Enforce Azure Policy Add-on for AKS Pod Security Standards** | AKS Kubernetes Security | HIGH | `Azure Policy Add-on enabled on 100% of AKS clusters` | `Azure Policy Add-on active with Pod Security Restricted initiative` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `AZURE-COMP-001`: Enforce Trusted Launch (Secure Boot & vTPM) on Azure VMs
- **Category:** Virtual Machines
- **Severity:** HIGH
- **Evidence Source:** `az vm list`
- **Status:** NON_COMPLIANT
- **Description:** Azure VMs must be deployed with Trusted Launch security type enabled (SecureBoot and vTPM = True).
- **Current Setting:** `14 VMs use Trusted Launch; 2 legacy VMs use Standard Gen1 type`
- **Security Recommendation:** `100% Trusted Launch VMs`
- **Remediation & Migration Notes:** Plan migration of Gen1 legacy VMs 'vm-sql-legacy' and 'vm-ad-legacy' to Gen2 Trusted Launch.

### `AZURE-COMP-002`: Enforce Azure Bastion for Secure Remote VM Administration
- **Category:** Virtual Machines
- **Severity:** CRITICAL
- **Evidence Source:** `az network public-ip list / az network bastion list`
- **Status:** COMPLIANT
- **Description:** Remote RDP/SSH access to VMs must traverse an Azure Bastion host without public IP assignment on VMs.
- **Current Setting:** `Azure Bastion deployed in 'vnet-hub-prod'; 0 VMs have Public IPs assigned`
- **Security Recommendation:** `100% Bastion-managed administrative access; 0 VM Public IPs`
- **Remediation & Migration Notes:** Require Entra ID native authentication for Bastion sessions.

### `AZURE-COMP-003`: Enforce AKS Private Cluster with Azure AD / Entra ID RBAC
- **Category:** AKS Kubernetes Security
- **Severity:** CRITICAL
- **Evidence Source:** `az aks show`
- **Status:** COMPLIANT
- **Description:** AKS clusters must be private (enablePrivateCluster = True) and use Microsoft Entra ID integration for RBAC.
- **Current Setting:** `Cluster 'aks-prod-01' is Private with Entra RBAC and Azure Policy Add-on enabled`
- **Security Recommendation:** `Private Cluster = True, enableAzureRBAC = True`
- **Remediation & Migration Notes:** Disable local account admin access using 'az aks update --disable-local-accounts'.

### `AZURE-COMP-004`: Enforce Azure Policy Add-on for AKS Pod Security Standards
- **Category:** AKS Kubernetes Security
- **Severity:** HIGH
- **Evidence Source:** `az aks show --query addonProfiles.azurepolicy`
- **Status:** COMPLIANT
- **Description:** AKS clusters must run the Azure Policy add-on to enforce Baseline/Restricted Pod Security Standards.
- **Current Setting:** `Azure Policy Add-on enabled on 100% of AKS clusters`
- **Security Recommendation:** `Azure Policy Add-on active with Pod Security Restricted initiative`
- **Remediation & Migration Notes:** Audit policy violations in Policy Compliance dashboard.
