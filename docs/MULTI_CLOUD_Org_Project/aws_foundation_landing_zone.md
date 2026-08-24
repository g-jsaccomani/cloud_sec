# AWS - Foundation Landing Zone Security Profile

**Cloud Provider:** AWS  
**Security Domain:** foundation_landing_zone  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `AWS-LZ-001` | **Enforce AWS Control Tower Landing Zone with Preventive & Detective Guardrails** | Control Tower & Guardrails | CRITICAL | `Control Tower Landing Zone v3.3 active; 14 mandatory and 6 strongly recommended guardrails enabled` | `Control Tower deployed with 100% OU enrollment` | **COMPLIANT** |
| `AWS-LZ-002` | **Enforce Dedicated Security Log Archive & Audit Accounts** | Account Architecture | CRITICAL | `Dedicated 'Log Archive' (998877665544) and 'Security Audit' accounts operational` | `Dedicated Log Archive & Security Audit accounts with zero workload deployment` | **COMPLIANT** |
| `AWS-LZ-003` | **Restrict AWS Resource Access Manager (RAM) Sharing to Within the Organization** | Resource Sharing | HIGH | `RAM Organization sharing enabled; external sharing disabled` | `enable-sharing-with-aws-organization = True; external sharing = False` | **COMPLIANT** |
| `AWS-LZ-004` | **Enforce Centralized Egress via Shared Network Inspection Hub** | Network Hub | HIGH | `Transit Gateway hub 'tgw-prod-hub' routing egress through AWS Network Firewall` | `100% of workload VPC egress inspected at centralized network hub` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `AWS-LZ-001`: Enforce AWS Control Tower Landing Zone with Preventive & Detective Guardrails
- **Category:** Control Tower & Guardrails
- **Severity:** CRITICAL
- **Evidence Source:** `aws controltower list-enabled-controls`
- **Status:** COMPLIANT
- **Description:** The AWS Organization must be managed by AWS Control Tower with mandatory preventive SCPs and detective AWS Config rules active across all OUs.
- **Current Setting:** `Control Tower Landing Zone v3.3 active; 14 mandatory and 6 strongly recommended guardrails enabled`
- **Security Recommendation:** `Control Tower deployed with 100% OU enrollment`
- **Remediation & Migration Notes:** Ensure new member accounts are provisioned exclusively via AWS Service Catalog Account Factory.

### `AWS-LZ-002`: Enforce Dedicated Security Log Archive & Audit Accounts
- **Category:** Account Architecture
- **Severity:** CRITICAL
- **Evidence Source:** `aws organizations list-accounts`
- **Status:** COMPLIANT
- **Description:** Centralized CloudTrail and AWS Config logs must be shipped to a dedicated Log Archive account with restricted IAM access.
- **Current Setting:** `Dedicated 'Log Archive' (998877665544) and 'Security Audit' accounts operational`
- **Security Recommendation:** `Dedicated Log Archive & Security Audit accounts with zero workload deployment`
- **Remediation & Migration Notes:** Verify SCP blocks root account login on Log Archive account.

### `AWS-LZ-003`: Restrict AWS Resource Access Manager (RAM) Sharing to Within the Organization
- **Category:** Resource Sharing
- **Severity:** HIGH
- **Evidence Source:** `aws ram get-resource-share-organizations`
- **Status:** COMPLIANT
- **Description:** AWS RAM must prohibit sharing Transit Gateways, Subnets, and Resolver Rules with external AWS accounts outside the organization.
- **Current Setting:** `RAM Organization sharing enabled; external sharing disabled`
- **Security Recommendation:** `enable-sharing-with-aws-organization = True; external sharing = False`
- **Remediation & Migration Notes:** Audit any explicit RAM invitations to third-party vendor accounts.

### `AWS-LZ-004`: Enforce Centralized Egress via Shared Network Inspection Hub
- **Category:** Network Hub
- **Severity:** HIGH
- **Evidence Source:** `aws ec2 describe-transit-gateways`
- **Status:** COMPLIANT
- **Description:** VPCs in workload accounts must route outbound Internet egress through a centralized AWS Network Firewall / Transit Gateway hub.
- **Current Setting:** `Transit Gateway hub 'tgw-prod-hub' routing egress through AWS Network Firewall`
- **Security Recommendation:** `100% of workload VPC egress inspected at centralized network hub`
- **Remediation & Migration Notes:** Monitor Network Firewall drop metrics and TLS SNI filtering rules.
