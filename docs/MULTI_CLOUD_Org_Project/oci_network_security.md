# OCI - Network Security Security Profile

**Cloud Provider:** OCI  
**Security Domain:** network_security  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `OCI-NET-001` | **Prohibit 0.0.0.0/0 Ingress on SSH (22) and RDP (3389) in VCN Security Lists** | Security Lists & NSGs | CRITICAL | `Default Security List in VCN 'vcn-prod-01' blocks 0.0.0.0/0 on 22/3389` | `0 Security Lists / NSGs permit 0.0.0.0/0 on ports 22/3389` | **COMPLIANT** |
| `OCI-NET-002` | **Enforce OCI WAF Edge Protection on Public HTTP/HTTPS Endpoints** | Web Application Firewall | HIGH | `WAF Policy 'waf-prod-portal' active on external Load Balancer` | `100% of public web endpoints protected by OCI WAF` | **COMPLIANT** |
| `OCI-NET-003` | **Enable VCN Flow Logs on All Production Subnets** | Network Visibility | MEDIUM | `Flow logs active on 6 of 8 subnets` | `100% VCN subnet flow log enablement` | **NON_COMPLIANT** |
| `OCI-NET-004` | **Enforce FastConnect Private Peering with BGP MD5 Authentication** | Private Connectivity | HIGH | `FastConnect Private Peering active; BGP MD5 Auth enabled` | `Private Peering = True, BGP MD5 Authentication = Enabled` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `OCI-NET-001`: Prohibit 0.0.0.0/0 Ingress on SSH (22) and RDP (3389) in VCN Security Lists
- **Category:** Security Lists & NSGs
- **Severity:** CRITICAL
- **Evidence Source:** `oci network security-list list / oci network nsg list`
- **Status:** COMPLIANT
- **Description:** Default and custom VCN Security Lists must not allow unrestricted ingress on administrative ports.
- **Current Setting:** `Default Security List in VCN 'vcn-prod-01' blocks 0.0.0.0/0 on 22/3389`
- **Security Recommendation:** `0 Security Lists / NSGs permit 0.0.0.0/0 on ports 22/3389`
- **Remediation & Migration Notes:** Use OCI Bastion service for administrative SSH/RDP sessions.

### `OCI-NET-002`: Enforce OCI WAF Edge Protection on Public HTTP/HTTPS Endpoints
- **Category:** Web Application Firewall
- **Severity:** HIGH
- **Evidence Source:** `oci waf policy list`
- **Status:** COMPLIANT
- **Description:** Load balancers serving external web traffic must be protected by an OCI WAF policy with OWASP protection enabled.
- **Current Setting:** `WAF Policy 'waf-prod-portal' active on external Load Balancer`
- **Security Recommendation:** `100% of public web endpoints protected by OCI WAF`
- **Remediation & Migration Notes:** Monitor WAF bot management rules and rate limiting logs.

### `OCI-NET-003`: Enable VCN Flow Logs on All Production Subnets
- **Category:** Network Visibility
- **Severity:** MEDIUM
- **Evidence Source:** `oci logging log list`
- **Status:** NON_COMPLIANT
- **Description:** VCN Flow Logs must be enabled and exporting to OCI Logging service for forensic network auditing.
- **Current Setting:** `Flow logs active on 6 of 8 subnets`
- **Security Recommendation:** `100% VCN subnet flow log enablement`
- **Remediation & Migration Notes:** Enable flow logs on 'sub-prod-db' and 'sub-mgmt' subnets.

### `OCI-NET-004`: Enforce FastConnect Private Peering with BGP MD5 Authentication
- **Category:** Private Connectivity
- **Severity:** HIGH
- **Evidence Source:** `oci network fast-connect list`
- **Status:** COMPLIANT
- **Description:** On-premises connectivity via OCI FastConnect must use private peering with BGP MD5 authentication enabled.
- **Current Setting:** `FastConnect Private Peering active; BGP MD5 Auth enabled`
- **Security Recommendation:** `Private Peering = True, BGP MD5 Authentication = Enabled`
- **Remediation & Migration Notes:** Rotate BGP authentication keys annually.
