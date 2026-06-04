# [GCP | Org: g-jsaccomani | Project: cloudsec_analysis] Cloud Security Architecture & Requirements Documentation

---
**Author:** Joabson Saccomani ([@jsaccomani](https://github.com/g-jsaccomani))  
**Role:** Cloud Security Consultant  
**LinkedIn:** [linkedin.com/in/jsaccomani](https://www.linkedin.com/in/jsaccomani)  
*Copyright © 2026 Google LLC / Joabson Saccomani. All rights reserved. Distributed under the Apache License 2.0.*


> **Executive Summary:** This document compiles the global security posture, architectural baselines, and control requirements for **Google Cloud Platform (GCP)** within the **`g-jsaccomani`** organization and **`cloudsec_analysis`** scope.

- **Cloud Provider:** `GCP`
- **Organization / Tenancy:** `g-jsaccomani`
- **Project / Subscription / Scope:** `cloudsec_analysis`
- **Total Controls Assessed:** `40`

---

## 1. Compliance & Security Posture Overview

### Distribution by Control Status
| Status | Total Controls |
|---|---|
| **COMPLIANT** | `25` |
| **MANUAL_REVIEW** | `1` |
| **NON_COMPLIANT** | `14` |

### Distribution by Severity
| Severity | Total Controls |
|---|---|
| **CRITICAL** | `14` |
| **HIGH** | `19` |
| **MEDIUM** | `7` |

---

## 2. Control Requirements by Security Domain

### 2.1 GCP — Security Controls (`40` evaluated)

| ID | Control Name | Domain | Severity | Current Value | Recommended Value | Status |
|---|---|---|---|---|---|---|
| `GCP-AI-001` | **Enforce Private Service Connect (PSC) / Private Endpoints for Vertex AI** | Vertex AI Networking | CRITICAL | `All 6 Vertex AI Workbench instances deployed on Private Subnet with PSC` | `100% Private Endpoints; 0 Public IPs on ML instances` | **COMPLIANT** |
| `GCP-AI-002` | **Enforce Customer-Managed Encryption Keys (CMEK) on Vertex AI Datasets and Models** | Model & Data Protection | HIGH | `CMEK configured on production Vertex AI datasets; default Google encryption on experiment cache` | `CMEK enforced across 100% of ML datasets and model registries` | **NON_COMPLIANT** |
| `GCP-AI-003` | **Enable Model Armor / LLM Guardrails against Prompt Injection & PII Leakage** | GenAI Governance & Safety | CRITICAL | `Model Armor policy 'prod-llm-guard' active with PII masking and prompt injection detection` | `Model Armor attached to all customer-facing LLM endpoints` | **COMPLIANT** |
| `GCP-AI-004` | **Enforce Region Restriction on Vertex AI Data Processing & Training** | Data Sovereignty | HIGH | `Region restricted to 'us-central1' via Organization Policy` | `Restrict processing to authorized data residency regions` | **COMPLIANT** |
| `GCP-APP-001` | **Enforce OAuth2 / JWT Authorization on Apigee / API Gateways** | API Security | CRITICAL | `100% of production API routes enforce JWT verification with short TTL (< 15 min)` | `Mandatory OAuth2 / JWT verification on all published API endpoints` | **COMPLIANT** |
| `GCP-APP-002` | **Enforce Secret Manager for All Application Credentials & Auto-Rotation** | Secrets Management | CRITICAL | `18 secrets stored in Secret Manager; 2 legacy services use plain-text env vars` | `100% Secret Manager adoption with Cloud Function automatic 90-day rotation` | **NON_COMPLIANT** |
| `GCP-APP-003` | **Enable Artifact Registry Automatic Vulnerability Scanning** | DevSecOps & Supply Chain | HIGH | `On-push vulnerability scanning active; 4 high CVEs detected in 'base-python-image'` | `Automatic CVE scanning enabled with CI/CD build break on Critical/High CVEs` | **NON_COMPLIANT** |
| `GCP-APP-004` | **Enforce Binary Authorization on GKE and Cloud Run** | Container Runtime Security | HIGH | `Binary Authorization policy deployed in Report-Only mode on Cloud Run` | `Enforced Binary Authorization policy requiring valid CI/CD attestation` | **NON_COMPLIANT** |
| `GCP-GOV-001` | **Enforce Resource Location Restrictions (gcp.resourceLocations)** | Organization Policies | HIGH | `Allowed regions: ['in:us-locations']` | `Restrict to authorized data sovereignty regions` | **COMPLIANT** |
| `GCP-GOV-002` | **Disable Service Account Key Creation (iam.disableServiceAccountKeyCreation)** | Organization Policies | CRITICAL | `Enforced at Organization root` | `Enforced = True across 100% of folders` | **COMPLIANT** |
| `GCP-GOV-003` | **Configure Security Essential Contacts at Organization Root** | Essential Contacts | MEDIUM | `Configured: secops-alerts@google.com` | `Verified SOC/Security distribution list assigned to SECURITY category` | **COMPLIANT** |
| `GCP-GOV-004` | **Cloud Asset Inventory Real-time Export Feed to BigQuery** | Asset Inventory | MEDIUM | `Feed 'cai-secops-feed' exporting to BigQuery dataset 'cai_audit_archive'` | `Active Org-level real-time asset feed` | **COMPLIANT** |
| `GCP-COMP-001` | **Enforce Shielded VM (Secure Boot & vTPM) on all instances** | Compute Engine Security | HIGH | `12 of 14 VMs have Shielded VM Secure Boot enabled` | `100% Shielded VMs with Secure Boot = True` | **NON_COMPLIANT** |
| `GCP-COMP-002` | **Enforce OS Login for SSH Access Management** | Compute Engine Security | HIGH | `enable-oslogin = TRUE at project metadata level` | `enable-oslogin = TRUE across all projects` | **COMPLIANT** |
| `GCP-COMP-003` | **Enforce GKE Private Cluster & Authorized Networks** | GKE Kubernetes Security | CRITICAL | `Cluster 'prod-gke-01' is Private with Authorized Networks = 10.100.0.0/20` | `Private Cluster = True, Control Plane Authorized Networks restricted` | **COMPLIANT** |
| `GCP-COMP-004` | **Enforce GKE Workload Identity on all Node Pools** | GKE Kubernetes Security | HIGH | `Enabled on cluster 'prod-gke-01' node pools` | `Workload Identity pool enabled on 100% of clusters` | **COMPLIANT** |
| `GCP-DATA-001` | **Enforce Public Access Prevention (PAP) on GCS Buckets** | Cloud Storage Security | CRITICAL | `2 buckets with Public Access Prevention set to 'unspecified'` | `Public Access Prevention = 'enforced' across 100% of buckets` | **NON_COMPLIANT** |
| `GCP-DATA-002` | **Enforce Uniform Bucket-Level Access (UBLA)** | Cloud Storage Security | HIGH | `UBLA Enabled on 100% of buckets` | `Uniform Bucket-Level Access = True` | **COMPLIANT** |
| `GCP-DATA-003` | **Customer-Managed Encryption Keys (CMEK) for Sensitive Datasets** | Key Management (CMEK) | HIGH | `CMEK configured for BigQuery analytics; default Google encryption on Cloud SQL dev` | `CMEK enforced for Production Cloud SQL, BigQuery, and GCS buckets` | **MANUAL_REVIEW** |
| `GCP-DATA-004` | **Enforce SSL/TLS Connections on Cloud SQL Instances** | Database Security | HIGH | `SSL required on 4 of 4 Cloud SQL instances` | `require_ssl = true` | **COMPLIANT** |
| `GCP-LZ-001` | **Enforce Google Enterprise Foundations Blueprint Folder Hierarchy** | Organization Hierarchy | CRITICAL | `4 top-level folders configured according to Google Enterprise Blueprint` | `Standardized 4-tier folder hierarchy with dedicated IAM inheritance boundaries` | **COMPLIANT** |
| `GCP-LZ-002` | **Enforce Shared VPC Architecture for Centralized Network Management** | Network Architecture | HIGH | `Shared VPC Host 'proj-net-hub-01' attached to 14 production service projects` | `100% of production workloads reside inside Shared VPC subnets` | **COMPLIANT** |
| `GCP-LZ-003` | **Enforce VPC Service Controls (VPC-SC) Perimeters around Sensitive Data Services** | VPC Service Controls | CRITICAL | `VPC-SC Perimeter 'perimeter-prod-core' active in Enforce mode` | `VPC-SC perimeter active across 100% of production projects` | **COMPLIANT** |
| `GCP-LZ-004` | **Centralized Billing Data Export to SecOps BigQuery Dataset** | Billing & Resource Tracking | MEDIUM | `Billing export active -> 'billing_secops_archive.gcp_billing_export_v1'` | `Active BigQuery billing export with alert rules for cost spikes > 50%` | **COMPLIANT** |
| `GCP-IAM-001` | **Restrict Primitive Role Usage (roles/owner, roles/editor)** | Identity & Access Management | HIGH | `3 users assigned roles/editor, 2 users assigned roles/owner` | `0 users on primitive roles; enforce Least Privilege RBAC` | **NON_COMPLIANT** |
| `GCP-IAM-002` | **Service Account Key Expiration & Rotation** | Service Account Security | CRITICAL | `2 Service Account keys > 120 days old detected` | `No user-managed keys > 90 days; prefer Workload Identity Federation` | **NON_COMPLIANT** |
| `GCP-IAM-003` | **Enforce 2SV / MFA in Cloud Identity** | Authentication & SSO | CRITICAL | `2SV Enforced for 95% of users (2 exceptions)` | `100% 2SV enforcement across all org units` | **NON_COMPLIANT** |
| `GCP-IAM-004` | **Workload Identity Federation for External CI/CD** | Workload Federation | MEDIUM | `Workload Identity Pool 'github-actions-pool' configured` | `100% of CI/CD pipelines use WIF without stored credentials` | **COMPLIANT** |
| `GCP-DR-001` | **Enforce Backup and DR Service Immutable Vaults against Ransomware** | Immutable Backups | CRITICAL | `Backup Vault 'vault-prod-immutable' active with 30-day WORM lock` | `Immutable backup vault enforced across all stateful production projects` | **COMPLIANT** |
| `GCP-DR-002` | **Configure Automated Forensic Disk Snapshot Pipeline** | Forensic Readiness | HIGH | `Cloud Function 'secops-forensic-snapshot-bot' linked to SCC Critical alerts` | `Automated forensic snapshot capture active in 100% of projects` | **COMPLIANT** |
| `GCP-DR-003` | **Enforce Daily Resource Policy Snapshot Schedules on Compute Disks** | Snapshot Schedules | HIGH | `Snapshot schedule 'sched-daily-prod' attached to 14 of 16 VMs` | `100% disk coverage with automated snapshot schedules` | **NON_COMPLIANT** |
| `GCP-DR-004` | **Enforce Cross-Region Replication on Primary Cloud Storage Buckets** | Disaster Recovery Replication | MEDIUM | `Bucket 'gs://gs-prod-customer-data' configured as Dual-Region (us-east1, us-central1) with Turbo Replication` | `Dual-Region + Turbo Replication on all critical data stores` | **COMPLIANT** |
| `GCP-LOG-001` | **Enable Data Access Audit Logs Across All Services** | Cloud Audit Logs | HIGH | `Data Access logs enabled for Cloud Storage and BigQuery; missing for IAM` | `Enable Data Access audit logging for all core services` | **NON_COMPLIANT** |
| `GCP-LOG-002` | **Centralized Security Log Sink to Cloud Storage / PubSub SIEM** | Log Archiving & SIEM | CRITICAL | `Aggregated org sink 'siem-security-export' active -> Pub/Sub topic` | `Active aggregated sink with Bucket Lock / retention policy >= 365 days` | **COMPLIANT** |
| `GCP-LOG-003` | **Security Command Center (SCC) Premium Tier & Continuous Monitoring** | Security Posture Management | HIGH | `SCC Enterprise Tier active; Event Threat Detection enabled` | `SCC Enterprise/Premium active across all organization folders` | **COMPLIANT** |
| `GCP-LOG-004` | **VPC Flow Logs Enabled with Appropriate Sampling Rate** | Network Visibility | MEDIUM | `Enabled on 8 of 10 subnets (aggregation interval 5s, sample rate 0.5)` | `100% subnet coverage for production VPCs` | **NON_COMPLIANT** |
| `GCP-NET-001` | **Restrict SSH/RDP from 0.0.0.0/0** | Firewall Rules | CRITICAL | `Rule 'allow-all-ssh' allows 0.0.0.0/0:22` | `Restrict SSH/RDP to IAP (Identity-Aware Proxy) CIDR: 35.235.240.0/20` | **NON_COMPLIANT** |
| `GCP-NET-002` | **Cloud Armor OWASP Top 10 Protection on Global Load Balancers** | WAF / Cloud Armor | HIGH | `Policy 'prod-edge-armor' attached with OWASP SQLi/XSS prevention enabled` | `Cloud Armor policy attached to all public backend services` | **COMPLIANT** |
| `GCP-NET-003` | **Enforce TLS 1.2+ minimum on SSL Policies** | Encryption in Transit | HIGH | `SSL Policy 'modern-tls-12' enforced (RESTRICTED profile)` | `Min TLS 1.2, MODERN or RESTRICTED cipher profile` | **COMPLIANT** |
| `GCP-NET-004` | **Enable Private Google Access on VPC Subnets** | Private Access | MEDIUM | `Enabled on 8 of 10 VPC subnets` | `Enabled on 100% of internal/workload subnets` | **NON_COMPLIANT** |

---

## 3. Remediation & Action Plan

1. **Critical / High Non-Compliant Items (`NON_COMPLIANT`)**: Must be remediated prior to workload production cutover.
2. **Manual Review Items (`MANUAL_REVIEW`)**: Require sign-off from the Security Architecture team in accordance with organizational data classification policies.
3. **Compliant Items (`COMPLIANT`)**: Require continuous monitoring via CSPM (Security Command Center) and automated CI/CD linting.

---

---
**Author:** Joabson Saccomani ([@jsaccomani](https://github.com/g-jsaccomani))  
**Role:** Cloud Security Consultant  
**LinkedIn:** [linkedin.com/in/jsaccomani](https://www.linkedin.com/in/jsaccomani)  
*Copyright © 2026 Google LLC / Joabson Saccomani. All rights reserved. Distributed under the Apache License 2.0.*

