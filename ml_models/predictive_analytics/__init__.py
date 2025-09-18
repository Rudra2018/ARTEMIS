"""
Predictive Analytics Module for AI Security Testing

This module provides advanced predictive analytics capabilities including:
- Threat prediction using LSTM/GRU neural networks
- Threat intelligence correlation and analysis
- Behavioral anomaly detection with temporal patterns
- Context-aware risk scoring and assessment
- Real-time threat landscape modeling
"""

from .threat_predictor import ThreatPredictor, ThreatPrediction, PredictionModel
from .temporal_analyzer import TemporalThreatAnalyzer, TimeSeriesModel
from .risk_scorer import ContextAwareRiskScorer, RiskAssessment
from .threat_intelligence import ThreatIntelligenceCorrelator, ThreatIndicator
from .behavioral_detector import BehavioralAnomalyDetector, AnomalyPattern

__all__ = [
    'ThreatPredictor',
    'ThreatPrediction',
    'PredictionModel',
    'TemporalThreatAnalyzer',
    'TimeSeriesModel',
    'ContextAwareRiskScorer',
    'RiskAssessment',
    'ThreatIntelligenceCorrelator',
    'ThreatIndicator',
    'BehavioralAnomalyDetector',
    'AnomalyPattern'
]