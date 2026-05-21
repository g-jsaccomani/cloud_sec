# AZURE - Foundation Landing Zone Security Profile

**Cloud Provider:** AZURE  
**Security Domain:** foundation_landing_zone  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `AZURE-LZ-001` | **Enforce Azure CAF Enterprise-Scale Management Group Hierarchy** | Management Group Architecture | CRITICAL | `Enterprise-Scale Management Group hierarchy deployed under 'mg-enterprise-root'` | `Standardized CAF Enterprise-Scale hierarchy with policy inheritance` | **COMPLIANT** |
| `AZURE-LZ-002` | **Enforce Hub-and-Spoke / Azure Virtual WAN Centralized Transit Architecture** | Network Connectivity Hub | HIGH | `14 spoke VNets peered to 'vnet-hub-prod' with forced tunneling through Azure Firewall` | `100% of spoke VNets connected to Connectivity Hub with zero direct internet egress` | **COMPLIANT** |
| `AZURE-LZ-003` | **Enforce Subscription Democratization via Azure Landing Zone Vendoring** | Subscription Democracy | HIGH | `Dedicated subscriptions provisioned for 'AppCore-Prod', 'AppCore-Dev', and 'DataLake-Prod'` | `100% workload isolation via dedicated Landing Zone subscriptions` | **COMPLIANT** |
| `AZURE-LZ-004` | **Enforce Dedicated Management Subscription for Central Log Analytics Workspace** | Platform Operations | CRITICAL | `Log Analytics workspace 'law-secops-central' isolated in 'sub-platform-management'` | `Dedicated platform management subscription with least-privilege SOC access` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `AZURE-LZ-001`: Enforce Azure CAF Enterprise-Scale Management Group Hierarchy
- **Category:** Management Group Architecture
- **Severity:** CRITICAL
- **Evidence Source:** `az account management-group list`
- **Status:** COMPLIANT
- **Description:** The Azure tenant must deploy standardized Management Groups: Platform (Identity, Connectivity, Management), LandingZones (Prod, Non-Prod), and Decommissioned.
- **Current Setting:** `Enterprise-Scale Management Group hierarchy deployed under 'mg-enterprise-root'`
- **Security Recommendation:** `Standardized CAF Enterprise-Scale hierarchy with policy inheritance`
- **Remediation & Migration Notes:** Verify no resources or subscriptions exist directly under the Root Management Group.

### `AZURE-LZ-002`: Enforce Hub-and-Spoke / Azure Virtual WAN Centralized Transit Architecture
- **Category:** Network Connectivity Hub
- **Severity:** HIGH
- **Evidence Source:** `az network vnet peering list`
- **Status:** COMPLIANT
- **Description:** Spoke VNets in Landing Zone subscriptions must connect to a centralized Connectivity Hub VNet/vWAN with Azure Firewall inspection.
- **Current Setting:** `14 spoke VNets peered to 'vnet-hub-prod' with forced tunneling through Azure Firewall`
- **Security Recommendation:** `100% of spoke VNets connected to Connectivity Hub with zero direct internet egress`
- **Remediation & Migration Notes:** Audit User Defined Routes (UDRs) on spoke subnets for 0.0.0.0/0 pointing to firewall IP.

### `AZURE-LZ-003`: Enforce Subscription Democratization via Azure Landing Zone Vendoring
- **Category:** Subscription Democracy
- **Severity:** HIGH
- **Evidence Source:** `az account list`
- **Status:** COMPLIANT
- **Description:** Workloads must be separated into dedicated subscriptions per application/environment to isolate blast radiuses and billing.
- **Current Setting:** `Dedicated subscriptions provisioned for 'AppCore-Prod', 'AppCore-Dev', and 'DataLake-Prod'`
- **Security Recommendation:** `100% workload isolation via dedicated Landing Zone subscriptions`
- **Remediation & Migration Notes:** Use Azure Blueprints or Bicep modules for subscription vending.

### `AZURE-LZ-004`: Enforce Dedicated Management Subscription for Central Log Analytics Workspace
- **Category:** Platform Operations
- **Severity:** CRITICAL
- **Evidence Source:** `az account list --query [?name=='sub-platform-management']`
- **Status:** COMPLIANT
- **Description:** Security logs and Sentinel SIEM must reside in a dedicated Management/Platform subscription with restricted Entra ID RBAC.
- **Current Setting:** `Log Analytics workspace 'law-secops-central' isolated in 'sub-platform-management'`
- **Security Recommendation:** `Dedicated platform management subscription with least-privilege SOC access`
- **Remediation & Migration Notes:** Enforce MFA and PIM JIT for any write operations to the Management subscription.
