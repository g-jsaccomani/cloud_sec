#!/usr/bin/env python3
"""
Cloud Security Analysis - Unified Security Requirements Extractor & Documentation Builder.
Orchestrates security configuration extraction across GCP, AWS, Azure, OCI, and VMware,
and automatically generates complete Markdown documentation for security architecture.

Supports both Automated CLI/Cron Mode and an Interactive Menu-Driven Wizard.
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import List, Dict, Type, Optional

# Import Common Modules
from common.base_extractor import BaseSecurityExtractor
from common.report_builder import ReportBuilder
from common.interactive_menu import run_interactive_wizard, MemoryAuthContext

# Import GCP Extractors
from GCP.iam import GCPIAMExtractor
from GCP.network_security import GCPNetworkSecurityExtractor
from GCP.data_protection import GCPDataProtectionExtractor
from GCP.logging_monitoring import GCPLoggingMonitoringExtractor
from GCP.compute_security import GCPComputeSecurityExtractor
from GCP.compliance_governance import GCPComplianceGovernanceExtractor
from GCP.ai_security import GCPAISecurityExtractor
from GCP.application_security import GCPApplicationSecurityExtractor
from GCP.foundation_landing_zone import GCPFoundationLandingZoneExtractor
from GCP.incident_response_dr import GCPIncidentResponseDRExtractor

# Import AWS Extractors
from AWS.iam import AWSIAMExtractor
from AWS.network_security import AWSNetworkSecurityExtractor
from AWS.data_protection import AWSDataProtectionExtractor
from AWS.logging_monitoring import AWSLoggingMonitoringExtractor
from AWS.compute_security import AWSComputeSecurityExtractor
from AWS.compliance_governance import AWSComplianceGovernanceExtractor
from AWS.ai_security import AWSAISecurityExtractor
from AWS.application_security import AWSApplicationSecurityExtractor
from AWS.foundation_landing_zone import AWSFoundationLandingZoneExtractor
from AWS.incident_response_dr import AWSIncidentResponseDRExtractor

# Import Azure Extractors
from Azure.iam import AzureIAMExtractor
from Azure.network_security import AzureNetworkSecurityExtractor
from Azure.data_protection import AzureDataProtectionExtractor
from Azure.logging_monitoring import AzureLoggingMonitoringExtractor
from Azure.compute_security import AzureComputeSecurityExtractor
from Azure.compliance_governance import AzureComplianceGovernanceExtractor
from Azure.ai_security import AzureAISecurityExtractor
from Azure.application_security import AzureApplicationSecurityExtractor
from Azure.foundation_landing_zone import AzureFoundationLandingZoneExtractor
from Azure.incident_response_dr import AzureIncidentResponseDRExtractor


# Import VMware Extractors
from VMware.iam import VMwareIAMExtractor
from VMware.network_security import VMwareNetworkSecurityExtractor
from VMware.data_protection import VMwareDataProtectionExtractor
from VMware.logging_monitoring import VMwareLoggingMonitoringExtractor
from VMware.compute_security import VMwareComputeSecurityExtractor
from VMware.compliance_governance import VMwareComplianceGovernanceExtractor
from VMware.ai_security import VMwareAISecurityExtractor
from VMware.application_security import VMwareApplicationSecurityExtractor
from VMware.foundation_landing_zone import VMwareFoundationLandingZoneExtractor
from VMware.incident_response_dr import VMwareIncidentResponseDRExtractor

# Import OCI Extractors
from OCI.iam import OCIIAMExtractor
from OCI.network_security import OCINetworkSecurityExtractor
from OCI.data_protection import OCIDataProtectionExtractor
from OCI.logging_monitoring import OCILoggingMonitoringExtractor
from OCI.compute_security import OCIComputeSecurityExtractor
from OCI.compliance_governance import OCIComplianceGovernanceExtractor
from OCI.ai_security import OCIAISecurityExtractor
from OCI.application_security import OCIApplicationSecurityExtractor
from OCI.foundation_landing_zone import OCIFoundationLandingZoneExtractor
from OCI.incident_response_dr import OCIIncidentResponseDRExtractor


EXTRACTOR_REGISTRY: Dict[str, Dict[str, Type[BaseSecurityExtractor]]] = {
    "GCP": {
        "iam": GCPIAMExtractor,
        "network_security": GCPNetworkSecurityExtractor,
        "data_protection": GCPDataProtectionExtractor,
        "logging_monitoring": GCPLoggingMonitoringExtractor,
        "compute_security": GCPComputeSecurityExtractor,
        "compliance_governance": GCPComplianceGovernanceExtractor,
        "ai_security": GCPAISecurityExtractor,
        "application_security": GCPApplicationSecurityExtractor,
        "foundation_landing_zone": GCPFoundationLandingZoneExtractor,
        "incident_response_dr": GCPIncidentResponseDRExtractor,
    },
    "AWS": {
        "iam": AWSIAMExtractor,
        "network_security": AWSNetworkSecurityExtractor,
        "data_protection": AWSDataProtectionExtractor,
        "logging_monitoring": AWSLoggingMonitoringExtractor,
        "compute_security": AWSComputeSecurityExtractor,
        "compliance_governance": AWSComplianceGovernanceExtractor,
        "ai_security": AWSAISecurityExtractor,
        "application_security": AWSApplicationSecurityExtractor,
        "foundation_landing_zone": AWSFoundationLandingZoneExtractor,
        "incident_response_dr": AWSIncidentResponseDRExtractor,
    },
    "AZURE": {
        "iam": AzureIAMExtractor,
        "network_security": AzureNetworkSecurityExtractor,
        "data_protection": AzureDataProtectionExtractor,
        "logging_monitoring": AzureLoggingMonitoringExtractor,
        "compute_security": AzureComputeSecurityExtractor,
        "compliance_governance": AzureComplianceGovernanceExtractor,
        "ai_security": AzureAISecurityExtractor,
        "application_security": AzureApplicationSecurityExtractor,
        "foundation_landing_zone": AzureFoundationLandingZoneExtractor,
        "incident_response_dr": AzureIncidentResponseDRExtractor,
    },

    "VMWARE": {
        "iam": VMwareIAMExtractor,
        "network_security": VMwareNetworkSecurityExtractor,
        "data_protection": VMwareDataProtectionExtractor,
        "logging_monitoring": VMwareLoggingMonitoringExtractor,
        "compute_security": VMwareComputeSecurityExtractor,
        "compliance_governance": VMwareComplianceGovernanceExtractor,
        "ai_security": VMwareAISecurityExtractor,
        "application_security": VMwareApplicationSecurityExtractor,
        "foundation_landing_zone": VMwareFoundationLandingZoneExtractor,
        "incident_response_dr": VMwareIncidentResponseDRExtractor
    },
    "OCI": {
        "iam": OCIIAMExtractor,
        "network_security": OCINetworkSecurityExtractor,
        "data_protection": OCIDataProtectionExtractor,
        "logging_monitoring": OCILoggingMonitoringExtractor,
        "compute_security": OCIComputeSecurityExtractor,
        "compliance_governance": OCIComplianceGovernanceExtractor,
        "ai_security": OCIAISecurityExtractor,
        "application_security": OCIApplicationSecurityExtractor,
        "foundation_landing_zone": OCIFoundationLandingZoneExtractor,
        "incident_response_dr": OCIIncidentResponseDRExtractor,
    },
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Cloud Security Analysis - Multi-Cloud Security Configuration Extractor & Doc Generator"
    )
    parser.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="Launch Interactive Terminal Wizard with authentication menus and tower selection."
    )
    parser.add_argument(
        "--cloud",
        "-c",
        nargs="+",
        choices=["GCP", "AWS", "AZURE", "OCI", "VMWARE", "ALL"],
        default=["ALL"],
        help="Target cloud provider(s) to extract security requirements from (default: ALL)."
    )
    parser.add_argument(
        "--domain",
        "-d",
        nargs="+",
        choices=[
            "iam",
            "network_security",
            "data_protection",
            "logging_monitoring",
            "compute_security",
            "compliance_governance",
            "ai_security",
            "application_security",
            "foundation_landing_zone",
            "incident_response_dr",
            "all"
        ],
        default=["all"],
        help="Target security domain(s) / tower(s) to extract (default: all)."
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        default=Path("reports"),
        help="Base directory to save extracted reports (default: reports/)."
    )
    parser.add_argument(
        "--org",
        "-O",
        type=str,
        default="Org",
        help="Organization / Tenancy identifier for folder and report naming."
    )
    parser.add_argument(
        "--project",
        "-P",
        type=str,
        default="Project",
        help="Project / Subscription identifier for folder and report naming."
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        default=True,
        help="Use mock/sample extraction mode (default: True for offline documentation generation)."
    )
    parser.add_argument(
        "--live",
        dest="mock",
        action="store_false",
        help="Attempt live extraction using cloud SDK/CLI credentials."
    )
    parser.add_argument(
        "--formats",
        "-f",
        nargs="+",
        choices=["json", "yaml", "md"],
        default=["json", "yaml", "md"],
        help="Output file formats for each extracted domain."
    )
    return parser.parse_args()


def run_extraction_pipeline(
    target_clouds: List[str],
    target_domains: List[str],
    use_mock: bool,
    base_output_dir: Path,
    org_name: str,
    project_name: str,
    formats: List[str],
    logger: logging.Logger
):
    # Format folder name as <CLOUD>_<ORG>_<PROJECT>
    cloud_str = "_".join(sorted(target_clouds)) if len(target_clouds) < 4 else "MULTI_CLOUD"
    folder_name = f"{cloud_str}_{org_name}_{project_name}".replace(" ", "_")
    final_output_dir = base_output_dir / folder_name
    final_output_dir.mkdir(parents=True, exist_ok=True)

    total_extracted = 0

    for cloud in target_clouds:
        cloud_domains = EXTRACTOR_REGISTRY.get(cloud, {})
        for domain in target_domains:
            extractor_cls = cloud_domains.get(domain)
            if not extractor_cls:
                logger.warning(f"No extractor found for Cloud={cloud}, Domain={domain}. Skipping.")
                continue

            extractor = extractor_cls(use_mock=use_mock)
            try:
                files = extractor.export(output_dir=final_output_dir, formats=formats)
                logger.info(f"[{cloud}/{domain}] Exported files: {list(files.values())}")
                total_extracted += 1
            except Exception as e:
                logger.error(f"Failed extraction for [{cloud}/{domain}]: {e}", exc_info=True)

    # Build Master Security Documentation Book with Cloud, Org, and Project title
    logger.info("Building Master Executive Security Migration Documentation...")
    builder = ReportBuilder(output_dir=final_output_dir, org_name=org_name, project_name=project_name)
    master_doc_filename = f"{folder_name}_SECURITY_DOCUMENTATION.md"
    master_doc_path = final_output_dir / master_doc_filename
    builder.build_master_documentation(master_doc_path, cloud_label=cloud_str)

    logger.info("=" * 70)
    logger.info(f"SUCCESS! Extracted {total_extracted} domain/tower modules across {len(target_clouds)} clouds.")
    logger.info(f"Report Folder      : {final_output_dir.resolve()}")
    logger.info(f"Master Security Doc: {master_doc_path.resolve()}")
    logger.info("=" * 70)
    return master_doc_path


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)]
    )
    logger = logging.getLogger("CloudSecurityMigration")

    args = parse_args()
    auth_ctx: Optional[MemoryAuthContext] = None

    try:
        # Launch interactive mode if -i flag is set OR if called with zero CLI arguments
        if args.interactive or len(sys.argv) == 1:
            target_clouds, target_domains, use_mock, auth_ctx, org_name, project_name, base_dir = run_interactive_wizard()
            formats = ["json", "yaml", "md"]
        else:
            target_clouds = list(EXTRACTOR_REGISTRY.keys()) if "ALL" in [c.upper() for c in args.cloud] else [c.upper() for c in args.cloud]
            target_domains = list(next(iter(EXTRACTOR_REGISTRY.values())).keys()) if "all" in [d.lower() for d in args.domain] else [d.lower() for d in args.domain]
            use_mock = args.mock
            base_dir = args.output_dir
            org_name = args.org
            project_name = args.project
            formats = args.formats

        logger.info(f"Starting Cloud Security Extraction for Clouds: {target_clouds} | Towers/Domains: {target_domains}")
        logger.info(f"Mode: {'MOCK (Offline/Sample)' if use_mock else 'LIVE (API/CLI)'}")
        logger.info(f"Base Destination: {base_dir.resolve()}")

        run_extraction_pipeline(
            target_clouds=target_clouds,
            target_domains=target_domains,
            use_mock=use_mock,
            base_output_dir=base_dir,
            org_name=org_name,
            project_name=project_name,
            formats=formats,
            logger=logger
        )

    finally:
        # Security Guarantee: Always wipe in-memory authentication credentials before exit
        if auth_ctx:
            logger.info("Wiping temporary in-memory credentials from RAM...")
            auth_ctx.clear_secrets()
            logger.info("All in-memory credentials securely cleared.")


if __name__ == "__main__":
    main()

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
