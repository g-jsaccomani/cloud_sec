"""
Common modules for Cloud Security Analysis & Architecture extraction.
"""
from .base_extractor import BaseSecurityExtractor, SecurityRequirementItem
from .report_builder import ReportBuilder
from .interactive_menu import run_interactive_wizard, MemoryAuthContext

__all__ = [
    "BaseSecurityExtractor",
    "SecurityRequirementItem",
    "ReportBuilder",
    "run_interactive_wizard",
    "MemoryAuthContext"
]

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analysis Architecture & Requirements Framework
# ==============================================================================
