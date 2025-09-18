"""
Enhanced Security Agent Orchestration System

This module provides intelligent coordination and orchestration of specialized security agents:
- EnhancedSecurityAgentOrchestrator: Main coordination system
- Specialized agents: AIFuzzingAgent, ThreatModelingAgent, ComplianceAgent, SCAAgent
- Smart orchestration with AI-driven planning and task distribution
- Cross-agent data aggregation and correlation
- Parallel task execution with risk synthesis
- Dynamic agent scaling and resource management
"""

from .enhanced_orchestrator import EnhancedSecurityAgentOrchestrator, OrchestrationStrategy
from .ai_fuzzing_agent import AIFuzzingAgent, FuzzingStrategy, FuzzingResult
from .threat_modeling_agent import ThreatModelingAgent, ThreatModel, AttackPath
from .compliance_agent import ComplianceAgent, ComplianceFramework, ComplianceResult
from .sca_agent import SCAAgent, ComponentAnalysis, VulnerabilityReport
from .agent_coordinator import AgentCoordinator, TaskDistribution, ResultAggregator

__all__ = [
    'EnhancedSecurityAgentOrchestrator',
    'OrchestrationStrategy',
    'AIFuzzingAgent',
    'FuzzingStrategy',
    'FuzzingResult',
    'ThreatModelingAgent',
    'ThreatModel',
    'AttackPath',
    'ComplianceAgent',
    'ComplianceFramework',
    'ComplianceResult',
    'SCAAgent',
    'ComponentAnalysis',
    'VulnerabilityReport',
    'AgentCoordinator',
    'TaskDistribution',
    'ResultAggregator'
]