"""
Software Composition Analysis (SCA) Agent

Intelligent dependency scanning, vulnerability detection, license compliance,
and SBOM generation using AI-powered component analysis and threat intelligence
integration with real-time CVE monitoring.
"""

from .sca_agent import (
    SCAAgent, VulnerabilityReport, Component, ComponentAnalysis, Vulnerability, License,
    VulnerabilitySeverity, LicenseRisk, ComponentType, ScanStatus
)
from .api import app

__all__ = [
    'SCAAgent', 'VulnerabilityReport', 'Component', 'ComponentAnalysis', 'Vulnerability', 'License',
    'VulnerabilitySeverity', 'LicenseRisk', 'ComponentType', 'ScanStatus', 'app'
]