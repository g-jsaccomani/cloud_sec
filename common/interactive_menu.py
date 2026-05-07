"""
Interactive Terminal Menu Wizard for Cloud Security Analysis.
Allows users to dynamically input connection/authentication info (in RAM only,
without storing on disk), navigate cloud provider and security tower menus,
specify custom report destination paths, and execute security auditing scripts interactively.
"""

import getpass
import os
import sys
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional


class MemoryAuthContext:
    """
    Securely manages temporary cloud authentication credentials in memory only.
    Injects temporary environment variables for SDK execution and wipes them
    immediately after execution finishes. Never writes anything to disk.
    """

    def __init__(self):
        self._temp_env_vars: Dict[str, str] = {}
        self.cloud_info: Dict[str, Dict[str, str]] = {}

    def set_secret(self, env_key: str, val: str):
        if val:
            self._temp_env_vars[env_key] = val
            os.environ[env_key] = val

    def clear_secrets(self):
        """Wipes all sensitive credentials from environment variables and memory."""
        for key in list(self._temp_env_vars.keys()):
            os.environ.pop(key, None)
        self._temp_env_vars.clear()
        self.cloud_info.clear()


def print_banner():
    print("=" * 72)
    print(" 🛡️  CLOUD SECURITY MIGRATION - MULTI-CLOUD AUDITING WIZARD")
    print("      Google Cloud (GCP) • AWS • Microsoft Azure • OCI • VMware")
    print("=" * 72)
    print(" [SECURITY NOTICE] No credentials entered in this interactive wizard")
    print(" will ever be written to disk or logs. All authentication is RAM-only.")
    print("=" * 72)


def select_clouds() -> List[str]:
    while True:
        print("\n=== [STEP 1] Select Target Cloud Provider(s) for Security Auditing ===")
        print(" [1] Google Cloud Platform (GCP)")
        print(" [2] Amazon Web Services (AWS)")
        print(" [3] Microsoft Azure (AZURE)")
        print(" [4] Oracle Cloud Infrastructure (OCI)")
        print(" [5] VMware Cloud / vSphere (VMWARE)")
        print(" [6] ALL Cloud Providers (ALL)")
        print(" [0] Exit")
        
        choice = input("\nEnter the corresponding number(s) separated by commas (e.g., 1,2): ").strip()
        if choice == "0":
            print("Exiting interactive wizard.")
            sys.exit(0)
        
        selected = []
        mapping = {"1": "GCP", "2": "AWS", "3": "AZURE", "4": "OCI", "5": "VMWARE", "6": "ALL"}
        parts = [p.strip() for p in choice.split(",")]
        for p in parts:
            if p in mapping:
                selected.append(mapping[p])
        
        if "ALL" in selected:
            return ["GCP", "AWS", "AZURE", "OCI", "VMWARE"]
        elif selected:
            return selected
        else:
            print("❌ Invalid option. Please try again.")


def collect_auth_info(clouds: List[str]) -> Tuple[MemoryAuthContext, str, str]:
    auth_ctx = MemoryAuthContext()
    print("\n=== [STEP 2] Authentication & Organizational Context (In-Memory Only) ===")
    print("TIP: Press ENTER to use default values or existing active CLI/SDK credentials.")

    org_name = input("  • Organization / Tenancy / Enterprise Name [e.g., g-jsaccomani, default: Org]: ").strip() or "Org"
    project_name = input("  • Project / Subscription / Scope Name [e.g., apigee_sec, default: Project]: ").strip() or "Project"

    for cloud in clouds:
        print(f"\n--- RAM-Only Connection Configuration for: {cloud} ---")
        if cloud == "GCP":
            org_id = input("    • GCP Organization ID [optional]: ").strip()
            project_id = input(f"    • GCP Project ID [{project_name}]: ").strip() or project_name
            sa_token = getpass.getpass("    • OAuth Token or Service Account JSON [in-memory, invisible]: ").strip()
            
            auth_ctx.cloud_info["GCP"] = {"org_id": org_id, "project_id": project_id}
            if sa_token:
                auth_ctx.set_secret("GOOGLE_OAUTH_ACCESS_TOKEN", sa_token)
            if project_id:
                auth_ctx.set_secret("CLOUDSDK_CORE_PROJECT", project_id)
                auth_ctx.set_secret("GOOGLE_CLOUD_PROJECT", project_id)

        elif cloud == "AWS":
            profile = input("    • AWS Profile [optional, default=default]: ").strip()
            region = input("    • AWS Region [optional, default=us-east-1]: ").strip()
            access_key = input("    • AWS Access Key ID [in-memory, optional]: ").strip()
            secret_key = getpass.getpass("    • AWS Secret Access Key [in-memory, invisible]: ").strip()
            session_token = getpass.getpass("    • AWS Session Token (MFA/SSO) [in-memory, invisible]: ").strip()

            auth_ctx.cloud_info["AWS"] = {"profile": profile, "region": region}
            if access_key:
                auth_ctx.set_secret("AWS_ACCESS_KEY_ID", access_key)
            if secret_key:
                auth_ctx.set_secret("AWS_SECRET_ACCESS_KEY", secret_key)
            if session_token:
                auth_ctx.set_secret("AWS_SESSION_TOKEN", session_token)
            if region:
                auth_ctx.set_secret("AWS_DEFAULT_REGION", region)
            if profile:
                auth_ctx.set_secret("AWS_PROFILE", profile)

        elif cloud == "AZURE":
            tenant_id = input("    • Azure Tenant ID [optional]: ").strip()
            sub_id = input(f"    • Azure Subscription ID [{project_name}]: ").strip() or project_name
            client_id = input("    • Azure Client ID (Service Principal) [optional]: ").strip()
            client_secret = getpass.getpass("    • Azure Client Secret [in-memory, invisible]: ").strip()

            auth_ctx.cloud_info["AZURE"] = {"tenant_id": tenant_id, "subscription_id": sub_id}
            if tenant_id:
                auth_ctx.set_secret("AZURE_TENANT_ID", tenant_id)
            if sub_id:
                auth_ctx.set_secret("AZURE_SUBSCRIPTION_ID", sub_id)
            if client_id:
                auth_ctx.set_secret("AZURE_CLIENT_ID", client_id)
            if client_secret:
                auth_ctx.set_secret("AZURE_CLIENT_SECRET", client_secret)

        
        elif cloud == "VMWARE":
            vcenter_url = input("    • vCenter URL [optional]: ").strip()
            username = input("    • VMware Username [optional]: ").strip()
            password = getpass.getpass("    • VMware Password [in-memory, invisible]: ").strip()
            
            auth_ctx.cloud_info["VMWARE"] = {"vcenter_url": vcenter_url}
            
            if password:
                auth_ctx.add_credential("VMWARE", "password", password)

        elif cloud == "OCI":
            tenancy_id = input(f"    • OCI Tenancy OCID [{org_name}]: ").strip() or org_name
            user_id = input("    • OCI User OCID [optional]: ").strip()
            region = input("    • OCI Region (e.g., us-ashburn-1) [optional]: ").strip()
            passphrase = getpass.getpass("    • OCI Key Passphrase [in-memory, invisible]: ").strip()

            auth_ctx.cloud_info["OCI"] = {"tenancy_id": tenancy_id, "region": region}
            if tenancy_id:
                auth_ctx.set_secret("OCI_TENANCY", tenancy_id)
            if user_id:
                auth_ctx.set_secret("OCI_USER", user_id)
            if region:
                auth_ctx.set_secret("OCI_REGION", region)
            if passphrase:
                auth_ctx.set_secret("OCI_PASSPHRASE", passphrase)

    return auth_ctx, org_name, project_name


def select_domains() -> List[str]:
    domain_menu = {
        "1": "iam",
        "2": "network_security",
        "3": "data_protection",
        "4": "logging_monitoring",
        "5": "compute_security",
        "6": "compliance_governance",
        "7": "ai_security",
        "8": "application_security",
        "9": "foundation_landing_zone",
        "10": "incident_response_dr"
    }

    while True:
        print("\n=== [STEP 3] Select Security Towers / Domains to Audit ===")
        print(" [0] ALL 10 Security Towers (Recommended)")
        print(" [1] IAM (Identity & Access Management)")
        print(" [2] Network Security (VPC, Firewalls, WAF, NSGs)")
        print(" [3] Data Protection (Storage PAP, CMEK/MEK, TDE, TLS)")
        print(" [4] Logging & Monitoring (CloudTrail, GuardDuty, SCC, SIEM)")
        print(" [5] Compute Security (Shielded VMs, GKE/EKS/AKS/OKE, Bastion)")
        print(" [6] Compliance & Governance (Org Policies, SCPs, CIS Benchmarks)")
        print(" [7] AI & Machine Learning Security (Vertex AI, Bedrock, Model Armor)")
        print(" [8] Application & API Security (Gateways OAuth2/JWT, Secrets, CVEs)")
        print(" [9] Foundation & Landing Zone (Hierarchy, Multi-Account, Shared VPC)")
        print(" [10] Incident Response & DR (Immutable Backups WORM, Forensic Pipeline)")

        choice = input("\nEnter the corresponding number(s) separated by commas (e.g., 1,2,7): ").strip()
        if choice == "0" or not choice:
            return list(domain_menu.values())

        selected = []
        parts = [p.strip() for p in choice.split(",")]
        for p in parts:
            if p in domain_menu:
                selected.append(domain_menu[p])

        if selected:
            return selected
        else:
            print("❌ Invalid option. Please try again.")


def select_execution_mode() -> bool:
    """Returns True if use_mock (offline/sample), False if live API/CLI mode."""
    while True:
        print("\n=== [STEP 4] Select Auditing & Execution Mode ===")
        print(" [1] CONNECTED / LIVE Mode - Query live cloud APIs via CLI/SDK credentials")
        print(" [2] SAMPLE / ARCHITECTURAL Mode - Generate baseline documentation report off-line")
        
        choice = input("\nSelect [1] or [2] (default = 2): ").strip()
        if choice == "1":
            return False
        elif choice == "2" or not choice:
            return True
        else:
            print("❌ Invalid option. Please try again.")


def select_output_directory() -> Path:
    print("\n=== [STEP 5] Report Destination Directory ===")
    print("TIP: Reports will be saved under 'reports/<CLOUD>_<ORG>_<PROJECT>/' by default.")
    custom_dir = input("  • Enter root destination directory for reports [default: ./reports]: ").strip()
    return Path(custom_dir) if custom_dir else Path("reports")


def run_interactive_wizard() -> Tuple[List[str], List[str], bool, MemoryAuthContext, str, str, Path]:
    print_banner()
    clouds = select_clouds()
    auth_ctx, org_name, project_name = collect_auth_info(clouds)
    domains = select_domains()
    use_mock = select_execution_mode()
    base_dir = select_output_directory()

    print("\n" + "=" * 72)
    print(" 📋 INTERACTIVE AUDIT EXECUTION SUMMARY:")
    print(f"  • Selected Cloud(s) : {', '.join(clouds)}")
    print(f"  • Organization      : {org_name}")
    print(f"  • Project / Scope   : {project_name}")
    print(f"  • Selected Towers   : {len(domains)} security domains")
    print(f"  • Audit Mode        : {'SAMPLE (MOCK)' if use_mock else 'LIVE / CONNECTED'}")
    print(f"  • Output Directory  : {base_dir.resolve()}")
    print("=" * 72)
    input("Press ENTER to start security extraction and generate documentation book...")

    return clouds, domains, use_mock, auth_ctx, org_name, project_name, base_dir


# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
