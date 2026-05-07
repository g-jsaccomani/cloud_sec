"""
Base Extractor for Cloud Security Analysis & Architecture Requirements.
Provides standardized logging, structured JSON/YAML export, and automatic
Markdown documentation table generation for any Cloud Security Domain.
"""

import json
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Any, Optional

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


@dataclass
class SecurityRequirementItem:
    """Represents an extracted security setting / requirement item."""
    id: str
    category: str
    control_name: str
    description: str
    current_value: Any
    recommended_value: Any
    status: str  # e.g., 'COMPLIANT', 'NON_COMPLIANT', 'MANUAL_REVIEW', 'NOT_FOUND'
    severity: str  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
    evidence_source: str  # e.g., 'GCP Cloud IAM API', 'AWS CloudTrail', etc.
    remediation_notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BaseSecurityExtractor(ABC):
    """
    Abstract Base Class for all Cloud Security Domain Extractors.
    Each cloud (GCP, AWS, Azure, OCI) and domain implements this class.
    """

    def __init__(self, cloud_provider: str, domain_name: str, use_mock: bool = False):
        self.cloud_provider = cloud_provider.upper()
        self.domain_name = domain_name.lower()
        self.use_mock = use_mock
        self.logger = logging.getLogger(f"{self.cloud_provider}.{self.domain_name}")

    @abstractmethod
    def extract_live(self) -> List[SecurityRequirementItem]:
        """Extract configurations using live cloud APIs / SDKs."""
        pass

    @abstractmethod
    def extract_mock(self) -> List[SecurityRequirementItem]:
        """Return representative sample/mock configurations for offline documentation."""
        pass

    def run(self) -> List[SecurityRequirementItem]:
        """
        Execute the extraction. If use_mock is True or if live credentials fail,
        falls back gracefully to mock/sample data so documentation can always be built.
        """
        self.logger.info(f"[{self.cloud_provider}] Starting extraction for domain: {self.domain_name}")
        if self.use_mock:
            self.logger.info("Using mock mode for extraction.")
            return self.extract_mock()
        try:
            items = self.extract_live()
            self.logger.info(f"Successfully extracted {len(items)} items via live SDK/API.")
            return items
        except Exception as e:
            self.logger.warning(
                f"Live extraction failed for {self.cloud_provider}/{self.domain_name} ({e}). "
                "Falling back to mock/sample data."
            )
            return self.extract_mock()

    def generate_markdown(self, items: List[SecurityRequirementItem]) -> str:
        """
        Generates a professionally formatted Markdown document for this domain,
        ready to be included in architectural and migration security docs.
        """
        lines = [
            f"# {self.cloud_provider} - {self.domain_name.replace('_', ' ').title()} Security Profile",
            "",
            f"**Cloud Provider:** {self.cloud_provider}  ",
            f"**Security Domain:** {self.domain_name}  ",
            f"**Total Requirements Extracted:** {len(items)}  ",
            "",
            "## Summary of Extracted Controls",
            "",
            "| ID | Control Name | Category | Severity | Current Value | Recommended | Status |",
            "|---|---|---|---|---|---|---|"
        ]

        for item in items:
            curr = str(item.current_value).replace("\n", " ")
            rec = str(item.recommended_value).replace("\n", " ")
            lines.append(
                f"| `{item.id}` | **{item.control_name}** | {item.category} | {item.severity} | `{curr}` | `{rec}` | **{item.status}** |"
            )

        lines.extend([
            "",
            "## Detailed Findings & Remediation Guidelines",
            ""
        ])

        for item in items:
            lines.extend([
                f"### `{item.id}`: {item.control_name}",
                f"- **Category:** {item.category}",
                f"- **Severity:** {item.severity}",
                f"- **Evidence Source:** `{item.evidence_source}`",
                f"- **Status:** {item.status}",
                f"- **Description:** {item.description}",
                f"- **Current Setting:** `{item.current_value}`",
                f"- **Security Recommendation:** `{item.recommended_value}`",
                f"- **Remediation & Migration Notes:** {item.remediation_notes or 'N/A'}",
                ""
            ])

        return "\n".join(lines)

    def export(self, output_dir: Path, formats: Optional[List[str]] = None) -> Dict[str, str]:
        """
        Export extracted data to the requested output directory in JSON, YAML, and/or Markdown.
        Returns a dictionary of generated file paths.
        """
        if formats is None:
            formats = ["json", "md", "yaml"]

        output_dir.mkdir(parents=True, exist_ok=True)
        items = self.run()
        items_dict = [i.to_dict() for i in items]

        base_filename = f"{self.cloud_provider.lower()}_{self.domain_name}"
        generated_files = {}

        if "json" in formats:
            json_path = output_dir / f"{base_filename}.json"
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump({
                    "cloud_provider": self.cloud_provider,
                    "domain": self.domain_name,
                    "count": len(items),
                    "items": items_dict
                }, f, indent=2)
            generated_files["json"] = str(json_path)

        if "yaml" in formats and HAS_YAML:
            yaml_path = output_dir / f"{base_filename}.yaml"
            with open(yaml_path, "w", encoding="utf-8") as f:
                yaml.dump({
                    "cloud_provider": self.cloud_provider,
                    "domain": self.domain_name,
                    "count": len(items),
                    "items": items_dict
                }, f, default_flow_style=False)
            generated_files["yaml"] = str(yaml_path)

        if "md" in formats or "markdown" in formats:
            md_path = output_dir / f"{base_filename}.md"
            md_content = self.generate_markdown(items)
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(md_content)
            generated_files["md"] = str(md_path)

        return generated_files

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
