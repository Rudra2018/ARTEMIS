"""
Advanced Analysis Module for AI Security Testing

This module contains advanced AI-driven analysis components including:
- AISecurityAnalyzer: Transformer-driven pattern recognition and anomaly detection
- Behavioral anomaly detection for runtime analysis
- Confidence scoring and auto-remediation systems
"""

from .ai_security_analyzer import AISecurityAnalyzer, SecurityAnalysisResult, AnalysisConfig
from .behavioral_anomaly_detector import BehavioralAnomalyDetector
from .confidence_scorer import ConfidenceScorer
from .auto_remediation import AutoRemediationEngine

__all__ = [
    'AISecurityAnalyzer',
    'SecurityAnalysisResult',
    'AnalysisConfig',
    'BehavioralAnomalyDetector',
    'ConfidenceScorer',
    'AutoRemediationEngine'
]