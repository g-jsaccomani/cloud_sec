"""
Report Builder for Cloud Security Analysis & Architecture Requirements.
Consolidates extracted findings across all Cloud Providers (GCP, AWS, Azure, OCI, VMware)
and Security Domains into a unified, executive Markdown Security Documentation Book.

Supports dynamic naming of report folders and documents using Cloud Provider,
Organization, and Project identifiers.
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional


class ReportBuilder:
    """
    Reads extracted domain JSON reports and synthesizes a master
    Security Migration Documentation Markdown report.
    """

    def __init__(self, output_dir: Path, org_name: str = "Org", project_name: str = "Project"):
        self.output_dir = output_dir
        self.org_name = org_name.replace(" ", "_")
        self.project_name = project_name.replace(" ", "_")

    def build_master_documentation(self, report_path: Path, cloud_label: str = "MULTI_CLOUD") -> Path:
        """
        Scans output_dir for all JSON extraction reports and compiles
        the complete documentation book with Cloud, Org, and Project in the title.
        """
        json_files = sorted(self.output_dir.glob("*.json"))
        
        all_items: List[Dict[str, Any]] = []
        by_cloud: Dict[str, List[Dict[str, Any]]] = {}

        for f in json_files:
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                    items = data.get("items", [])
                    cloud = data.get("cloud_provider", "UNKNOWN")
                    if cloud not in by_cloud:
                        by_cloud[cloud] = []
                    by_cloud[cloud].extend(items)
                    all_items.extend(items)
            except Exception as e:
                continue

        lines = [
            f"# [{cloud_label} | Org: {self.org_name} | Project: {self.project_name}] Cloud Security Analysis Architecture & Requirements Documentation",
            "",
            f"> **Executive Summary:** This document compiles the comprehensive security posture, baselines, and architectural requirements for **{cloud_label}** in organization **`{self.org_name}`** and project/scope **`{self.project_name}`**.",
            "",
            f"- **Cloud Provider(s):** `{cloud_label}`",
            f"- **Organization / Tenancy:** `{self.org_name}`",
            f"- **Project / Subscription / Scope:** `{self.project_name}`",
            f"- **Total Security Requirements & Controls Evaluated:** `{len(all_items)}`",
            ""
        ]

        # Calculate statistics
        status_counts = {}
        severity_counts = {}
        for item in all_items:
            status = item.get("status", "UNKNOWN")
            sev = item.get("severity", "INFO")
            status_counts[status] = status_counts.get(status, 0) + 1
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        lines.extend([
            "## 1. Compliance & Security Posture Overview",
            "",
            "### Control Status Breakdown",
            "| Status | Total Controls |",
            "|---|---|"
        ])
        for st, count in sorted(status_counts.items()):
            lines.append(f"| **{st}** | `{count}` |")

        lines.extend([
            "",
            "### Severity Breakdown",
            "| Severity | Total Controls |",
            "|---|---|"
        ])
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in severity_counts:
                lines.append(f"| **{sev}** | `{severity_counts[sev]}` |")

        lines.extend([
            "",
            "## 2. Security Requirements & Configuration Items by Cloud Provider",
            ""
        ])

        for idx, cloud in enumerate(sorted(by_cloud.keys())):
            items = by_cloud[cloud]
            lines.extend([
                f"### 2.{idx+1} {cloud} — Security Requirements (`{len(items)}` controls)",
                "",
                "| ID | Control Name | Tower / Domain | Severity | Current Value | Recommended Value | Status |",
                "|---|---|---|---|---|---|---|"
            ])
            for item in items:
                curr = str(item.get("current_value", "")).replace("\n", " ")
                rec = str(item.get("recommended_value", "")).replace("\n", " ")
                lines.append(
                    f"| `{item.get('id', '')}` | **{item.get('control_name', '')}** | {item.get('category', '')} | {item.get('severity', '')} | `{curr}` | `{rec}` | **{item.get('status', '')}** |"
                )
            lines.append("")

        lines.extend([
            "---",
            "## 3. Migration Action Plan & Remediation Guide",
            "",
            "1. **Critical / High Non-Compliant Items (`NON_COMPLIANT`)**: Must be remediated prior to production workload cutover.",
            "2. **Manual Review Items (`MANUAL_REVIEW`)**: Require architectural validation by the Enterprise Security Architecture team against organizational data classification policies.",
            "3. **Compliant Items (`COMPLIANT`)**: Require ongoing monitoring via Cloud Security Posture Management (CSPM) and Infrastructure as Code (IaC) linting.",
            "",
            "---",
            "*Document generated by Cloud Security Analysis Framework • Lead Security Architecture & Engineering by **J. Saccomani** (`g-jsaccomani` / `jsaccomani@google.com`)*",
            ""
        ])

        report_path.parent.mkdir(parents=True, exist_ok=True)
        with open(report_path, "w", encoding="utf-8") as out_f:
            out_f.write("\n".join(lines))

        return report_path


# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
