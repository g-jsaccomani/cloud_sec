# AWS - Compute Security Security Profile

**Cloud Provider:** AWS  
**Security Domain:** compute_security  
**Total Requirements Extracted:** 4  

## Summary of Extracted Controls

| ID | Control Name | Category | Severity | Current Value | Recommended | Status |
|---|---|---|---|---|---|---|
| `AWS-COMP-001` | **Enforce IMDSv2 (Instance Metadata Service v2) on EC2 Instances** | EC2 Compute Security | CRITICAL | `18 of 20 EC2 instances require IMDSv2; 2 allow IMDSv1` | `100% of instances require IMDSv2 (HttpTokens = 'required')` | **NON_COMPLIANT** |
| `AWS-COMP-002` | **Restrict EKS Control Plane Public Endpoint Access** | EKS Kubernetes Security | CRITICAL | `Cluster 'prod-eks-01' has PrivateAccess=True and PublicAccess=False` | `endpointPrivateAccess = True, endpointPublicAccess = False` | **COMPLIANT** |
| `AWS-COMP-003` | **Enforce IAM Roles for Service Accounts (IRSA)** | EKS Kubernetes Security | HIGH | `OIDC provider configured; 100% of pods use IRSA annotations` | `All pods adopt IRSA; Node IAM roles stripped of application permissions` | **COMPLIANT** |
| `AWS-COMP-004` | **Enforce VPC Attachment for Sensitive Lambda Functions** | Serverless Security | MEDIUM | `All backend Lambda functions attached to private subnets with NAT Gateway` | `VpcConfig defined for internal-facing serverless functions` | **COMPLIANT** |

## Detailed Findings & Remediation Guidelines

### `AWS-COMP-001`: Enforce IMDSv2 (Instance Metadata Service v2) on EC2 Instances
- **Category:** EC2 Compute Security
- **Severity:** CRITICAL
- **Evidence Source:** `aws ec2 describe-instances`
- **Status:** NON_COMPLIANT
- **Description:** EC2 instances must require IMDSv2 (HttpTokens=required) to mitigate SSRF attack vectors.
- **Current Setting:** `18 of 20 EC2 instances require IMDSv2; 2 allow IMDSv1`
- **Security Recommendation:** `100% of instances require IMDSv2 (HttpTokens = 'required')`
- **Remediation & Migration Notes:** Run 'aws ec2 modify-instance-metadata-options --instance-id <ID> --http-tokens required'.

### `AWS-COMP-002`: Restrict EKS Control Plane Public Endpoint Access
- **Category:** EKS Kubernetes Security
- **Severity:** CRITICAL
- **Evidence Source:** `aws eks describe-cluster`
- **Status:** COMPLIANT
- **Description:** EKS cluster API endpoints must be private or restricted to authorized enterprise CIDRs.
- **Current Setting:** `Cluster 'prod-eks-01' has PrivateAccess=True and PublicAccess=False`
- **Security Recommendation:** `endpointPrivateAccess = True, endpointPublicAccess = False`
- **Remediation & Migration Notes:** Ensure worker node security groups allow HTTPS only from control plane ENIs.

### `AWS-COMP-003`: Enforce IAM Roles for Service Accounts (IRSA)
- **Category:** EKS Kubernetes Security
- **Severity:** HIGH
- **Evidence Source:** `aws eks describe-cluster (identity.oidc)`
- **Status:** COMPLIANT
- **Description:** EKS workloads must use OIDC federated IRSA rather than node IAM role permissions.
- **Current Setting:** `OIDC provider configured; 100% of pods use IRSA annotations`
- **Security Recommendation:** `All pods adopt IRSA; Node IAM roles stripped of application permissions`
- **Remediation & Migration Notes:** Audit IAM trust policies on IRSA execution roles.

### `AWS-COMP-004`: Enforce VPC Attachment for Sensitive Lambda Functions
- **Category:** Serverless Security
- **Severity:** MEDIUM
- **Evidence Source:** `aws lambda list-functions`
- **Status:** COMPLIANT
- **Description:** Lambda functions accessing internal databases or Redis must execute within private VPC subnets.
- **Current Setting:** `All backend Lambda functions attached to private subnets with NAT Gateway`
- **Security Recommendation:** `VpcConfig defined for internal-facing serverless functions`
- **Remediation & Migration Notes:** Ensure Lambda execution roles do not contain wildcard resource permissions.
