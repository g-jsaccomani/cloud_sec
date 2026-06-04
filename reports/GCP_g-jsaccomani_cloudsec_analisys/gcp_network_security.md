# GCP - Network Security Security Profile

**Cloud Provider:** GCP  
**Security Domain:** network_security  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `GCP-NET-001` | **Restrict SSH/RDP from 0.0.0.0/0** | Firewall Rules | CRITICAL | `Rule 'allow-all-ssh' allows 0.0.0.0/0:22` | `Restrict SSH/RDP to IAP (Identity-Aware Proxy) CIDR: 35.235.240.0/20` | **NON_COMPLIANT** |
| `GCP-NET-002` | **Cloud Armor OWASP Top 10 Protection on Global Load Balancers** | WAF / Cloud Armor | HIGH | `Policy 'prod-edge-armor' attached with OWASP SQLi/XSS prevention enabled` | `Cloud Armor policy attached to all public backend services` | **COMPLIANT** |
| `GCP-NET-003` | **Enforce TLS 1.2+ minimum on SSL Policies** | Encryption in Transit | HIGH | `SSL Policy 'modern-tls-12' enforced (RESTRICTED profile)` | `Min TLS 1.2, MODERN or RESTRICTED cipher profile` | **COMPLIANT** |
| `GCP-NET-004` | **Enable Private Google Access on VPC Subnets** | Private Access | MEDIUM | `Enabled on 8 of 10 VPC subnets` | `Enabled on 100% of internal/workload subnets` | **NON_COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `GCP-NET-001`: Restrict SSH/RDP from 0.0.0.0/0
- **Category:** Firewall Rules
- **Severity:** CRITICAL
- **Evidence Source:** `gcloud compute firewall-rules list`
- **Status:** NON_COMPLIANT
- **Description:** Ensure no ingress firewall rule allows SSH (22) or RDP (3389) from the public Internet.
- **Current Setting:** `Rule 'allow-all-ssh' allows 0.0.0.0/0:22`
- **Security Recommendation:** `Restrict SSH/RDP to IAP (Identity-Aware Proxy) CIDR: 35.235.240.0/20`
- **Remediation & Migration Notes:** Delete 'allow-all-ssh' rule and mandate Cloud IAP TCP forwarding for remote administration.

### `GCP-NET-002`: Cloud Armor OWASP Top 10 Protection on Global Load Balancers
- **Category:** WAF / Cloud Armor
- **Severity:** HIGH
- **Evidence Source:** `gcloud compute security-policies list`
- **Status:** COMPLIANT
- **Description:** External HTTPS load balancers must have Cloud Armor policies attached with OWASP rulesets.
- **Current Setting:** `Policy 'prod-edge-armor' attached with OWASP SQLi/XSS prevention enabled`
- **Security Recommendation:** `Cloud Armor policy attached to all public backend services`
- **Remediation & Migration Notes:** Continue monitoring Cloud Armor rate limiting and bot management telemetry.

### `GCP-NET-003`: Enforce TLS 1.2+ minimum on SSL Policies
- **Category:** Encryption in Transit
- **Severity:** HIGH
- **Evidence Source:** `gcloud compute ssl-policies list`
- **Status:** COMPLIANT
- **Description:** Load balancers must use SSL policies that prohibit TLS 1.0/1.1 and insecure ciphers.
- **Current Setting:** `SSL Policy 'modern-tls-12' enforced (RESTRICTED profile)`
- **Security Recommendation:** `Min TLS 1.2, MODERN or RESTRICTED cipher profile`
- **Remediation & Migration Notes:** Regularly audit SSL certificate expiry and ensure managed HTTPS certificates are used.

### `GCP-NET-004`: Enable Private Google Access on VPC Subnets
- **Category:** Private Access
- **Severity:** MEDIUM
- **Evidence Source:** `gcloud compute networks subnets list`
- **Status:** NON_COMPLIANT
- **Description:** Subnets without external IPs must have Private Google Access enabled to reach GCP APIs securely.
- **Current Setting:** `Enabled on 8 of 10 VPC subnets`
- **Security Recommendation:** `Enabled on 100% of internal/workload subnets`
- **Remediation & Migration Notes:** Enable Private Google Access on 'subnet-dev-us-east1' and 'subnet-qa-eu-west1'.
