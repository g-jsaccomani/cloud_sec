# AWS - Network Security Security Profile

**Cloud Provider:** AWS  
**Security Domain:** network_security  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `AWS-NET-001` | **Prohibit Unrestricted SSH (22) and RDP (3389) in Security Groups** | Security Groups | CRITICAL | `Security Group 'sg-01a2b3c' allows 0.0.0.0/0 on port 22` | `No security groups allow 0.0.0.0/0 on SSH/RDP` | **NON_COMPLIANT** |
| `AWS-NET-002` | **Attach AWS WAFv2 Web ACL to CloudFront & ALB Endpoints** | Web Application Firewall | HIGH | `Web ACL 'prod-waf-acl' attached with AWSManagedRulesCommonRuleSet` | `WAFv2 Web ACL attached to 100% of public endpoints` | **COMPLIANT** |
| `AWS-NET-003` | **Enable VPC Flow Logs to CloudWatch / S3** | VPC Flow Logs | MEDIUM | `Enabled on 5 of 6 VPCs; missing on 'vpc-legacy-test'` | `100% VPC Flow Log enablement with 10-minute max aggregation interval` | **NON_COMPLIANT** |
| `AWS-NET-004` | **Enforce Default Deny on VPC Network Access Control Lists (NACLs)** | Network Routing | LOW | `Default allow-all NACLs in use across VPCs` | `Hardened subnet NACLs with explicit deny rules for high-risk ports` | **MANUAL_REVIEW** |

## Detailed Findings & Remediation Guidelines

### `AWS-NET-001`: Prohibit Unrestricted SSH (22) and RDP (3389) in Security Groups
- **Category:** Security Groups
- **Severity:** CRITICAL
- **Evidence Source:** `aws ec2 describe-security-groups`
- **Status:** NON_COMPLIANT
- **Description:** Security groups must not allow ingress from 0.0.0.0/0 to ports 22 or 3389.
- **Current Setting:** `Security Group 'sg-01a2b3c' allows 0.0.0.0/0 on port 22`
- **Security Recommendation:** `No security groups allow 0.0.0.0/0 on SSH/RDP`
- **Remediation & Migration Notes:** Revoke 0.0.0.0/0 ingress rule on 'sg-01a2b3c' and use AWS Systems Manager Session Manager.

### `AWS-NET-002`: Attach AWS WAFv2 Web ACL to CloudFront & ALB Endpoints
- **Category:** Web Application Firewall
- **Severity:** HIGH
- **Evidence Source:** `aws wafv2 list-web-acls`
- **Status:** COMPLIANT
- **Description:** Public CloudFront distributions and Application Load Balancers must be protected by AWS WAFv2 with managed rules.
- **Current Setting:** `Web ACL 'prod-waf-acl' attached with AWSManagedRulesCommonRuleSet`
- **Security Recommendation:** `WAFv2 Web ACL attached to 100% of public endpoints`
- **Remediation & Migration Notes:** Regularly test WAF rules against OWASP Top 10 automated scanners.

### `AWS-NET-003`: Enable VPC Flow Logs to CloudWatch / S3
- **Category:** VPC Flow Logs
- **Severity:** MEDIUM
- **Evidence Source:** `aws ec2 describe-flow-logs`
- **Status:** NON_COMPLIANT
- **Description:** VPC Flow Logs must be enabled for all VPCs to capture IP traffic to/from network interfaces.
- **Current Setting:** `Enabled on 5 of 6 VPCs; missing on 'vpc-legacy-test'`
- **Security Recommendation:** `100% VPC Flow Log enablement with 10-minute max aggregation interval`
- **Remediation & Migration Notes:** Create flow log destination to S3 security archive bucket for 'vpc-legacy-test'.

### `AWS-NET-004`: Enforce Default Deny on VPC Network Access Control Lists (NACLs)
- **Category:** Network Routing
- **Severity:** LOW
- **Evidence Source:** `aws ec2 describe-network-acls`
- **Status:** MANUAL_REVIEW
- **Description:** Custom NACLs must be configured to block known malicious IP blocks and prevent asymmetric routing bypass.
- **Current Setting:** `Default allow-all NACLs in use across VPCs`
- **Security Recommendation:** `Hardened subnet NACLs with explicit deny rules for high-risk ports`
- **Remediation & Migration Notes:** Review subnet boundaries and implement defense-in-depth NACL rules.
