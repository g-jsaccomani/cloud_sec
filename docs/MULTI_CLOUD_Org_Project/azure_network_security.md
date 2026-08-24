# AZURE - Network Security Security Profile

**Cloud Provider:** AZURE  
**Security Domain:** network_security  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `AZURE-NET-001` | **Prohibit Ingress from Internet on RDP (3389) and SSH (22)** | Network Security Groups (NSGs) | CRITICAL | `NSG 'nsg-prod-app' denies all internet management traffic` | `0 NSGs allow unrestricted Internet access on ports 22/3389` | **COMPLIANT** |
| `AZURE-NET-002` | **Enforce Azure Firewall Premium with IDPS and TLS Inspection** | Perimeter Security | HIGH | `Azure Firewall Standard deployed without IDPS` | `Azure Firewall Premium with IDPS Mode = 'AlertAndDeny'` | **NON_COMPLIANT** |
| `AZURE-NET-003` | **Enable Azure DDoS Protection Standard on Production Virtual Networks** | DDoS Protection | HIGH | `DDoS Standard enabled on 'vnet-hub-prod'` | `DDoS Standard protection plan attached to all public VNets` | **COMPLIANT** |
| `AZURE-NET-004` | **Enable WAF in Prevention Mode on Application Gateway / Front Door** | Web Application Firewall | HIGH | `App Gateway WAF in Prevention mode with CRS 3.2` | `WAF = Prevention mode across 100% of public HTTP/HTTPS listeners` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `AZURE-NET-001`: Prohibit Ingress from Internet on RDP (3389) and SSH (22)
- **Category:** Network Security Groups (NSGs)
- **Severity:** CRITICAL
- **Evidence Source:** `az network nsg list`
- **Status:** COMPLIANT
- **Description:** NSG inbound security rules must deny 0.0.0.0/0 on RDP and SSH ports.
- **Current Setting:** `NSG 'nsg-prod-app' denies all internet management traffic`
- **Security Recommendation:** `0 NSGs allow unrestricted Internet access on ports 22/3389`
- **Remediation & Migration Notes:** Use Azure Bastion for remote administrative VM access.

### `AZURE-NET-002`: Enforce Azure Firewall Premium with IDPS and TLS Inspection
- **Category:** Perimeter Security
- **Severity:** HIGH
- **Evidence Source:** `az network firewall list`
- **Status:** NON_COMPLIANT
- **Description:** Hub-and-spoke VNet architectures must route egress/ingress traffic through Azure Firewall Premium with IDPS enabled in Alert & Deny mode.
- **Current Setting:** `Azure Firewall Standard deployed without IDPS`
- **Security Recommendation:** `Azure Firewall Premium with IDPS Mode = 'AlertAndDeny'`
- **Remediation & Migration Notes:** Upgrade Azure Firewall SKU from Standard to Premium and configure IDPS signatures.

### `AZURE-NET-003`: Enable Azure DDoS Protection Standard on Production Virtual Networks
- **Category:** DDoS Protection
- **Severity:** HIGH
- **Evidence Source:** `az network ddos-protection list`
- **Status:** COMPLIANT
- **Description:** Production VNets hosting internet-facing endpoints must be enrolled in Azure DDoS Protection Standard.
- **Current Setting:** `DDoS Standard enabled on 'vnet-hub-prod'`
- **Security Recommendation:** `DDoS Standard protection plan attached to all public VNets`
- **Remediation & Migration Notes:** Review DDoS alert telemetry in Azure Monitor log workspace.

### `AZURE-NET-004`: Enable WAF in Prevention Mode on Application Gateway / Front Door
- **Category:** Web Application Firewall
- **Severity:** HIGH
- **Evidence Source:** `az network application-gateway waf-config show`
- **Status:** COMPLIANT
- **Description:** Application Gateways and Front Door endpoints must execute WAF in Prevention mode with OWASP Core Rule Set 3.2+.
- **Current Setting:** `App Gateway WAF in Prevention mode with CRS 3.2`
- **Security Recommendation:** `WAF = Prevention mode across 100% of public HTTP/HTTPS listeners`
- **Remediation & Migration Notes:** Regularly review WAF firewall logs for false positives and custom exclusion rules.
