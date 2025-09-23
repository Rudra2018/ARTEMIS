"""
Advanced Pipeline Orchestrator for Modular AI Security Testing
=============================================================

This module implements an advanced pipeline orchestration system that coordinates
multiple specialized AI agents with machine learning optimization and adaptive workflows.
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor
import numpy as np

from .agent_orchestrator import AgentOrchestrator, PipelineManager, AgentTask, AgentResult
from .learning_engine import AdaptiveLearningEngine
from .agents.llm_security_agent import LLMSecurityAgent
from .agents.infrastructure_agent import InfrastructureAgent
from .agents.vulnerability_agent import VulnerabilityAgent

logger = logging.getLogger(__name__)

@dataclass
class PipelineConfig:
    """Configuration for security testing pipeline"""
    pipeline_id: str
    name: str
    description: str
    target: str
    stages: List[Dict[str, Any]]
    parameters: Dict[str, Any]
    priority: int = 1
    timeout: int = 3600  # 1 hour default
    retry_count: int = 2
    adaptive_learning: bool = True
    continuous_monitoring: bool = False

@dataclass
class PipelineResult:
    """Complete pipeline execution result"""
    pipeline_id: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime]
    execution_time: float
    total_findings: int
    risk_score: float
    agent_results: List[Dict[str, Any]]
    learning_insights: Dict[str, Any]
    recommendations: List[str]
    metadata: Dict[str, Any]

class AdvancedPipelineOrchestrator:
    """
    Advanced orchestrator that manages complex security testing pipelines
    with AI agents, machine learning optimization, and adaptive workflows
    """

    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)

        # Initialize core components
        self.agent_orchestrator = AgentOrchestrator(config_path)
        self.pipeline_manager = PipelineManager(self.agent_orchestrator)
        self.learning_engine = AdaptiveLearningEngine(
            models_path=self.config['models_path'],
            learning_data_path=self.config['learning_data_path']
        )

        # Pipeline management
        self.active_pipelines: Dict[str, PipelineConfig] = {}
        self.pipeline_history: List[PipelineResult] = []
        self.pipeline_templates: Dict[str, Dict[str, Any]] = {}

        # Performance metrics
        self.performance_metrics = {
            'total_pipelines_executed': 0,
            'successful_pipelines': 0,
            'average_execution_time': 0.0,
            'total_findings': 0,
            'average_risk_score': 0.0
        }

        # Initialize agents
        self._initialize_agents()

        # Load pipeline templates
        self._load_pipeline_templates()

        # Setup monitoring and alerting
        self.monitoring_enabled = self.config.get('monitoring_enabled', True)
        self.alert_callbacks: List[Callable] = []

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load pipeline orchestrator configuration"""
        default_config = {
            'max_concurrent_pipelines': 5,
            'default_timeout': 3600,
            'retry_attempts': 2,
            'learning_enabled': True,
            'monitoring_enabled': True,
            'models_path': 'ml_models/agent_models',
            'learning_data_path': 'ai_tester_core/learning_data',
            'pipeline_templates_path': 'configs/pipeline_templates',
            'auto_optimization': True,
            'adaptive_parameters': True
        }

        if config_path and Path(config_path).exists():
            try:
                with open(config_path, 'r') as f:
                    loaded_config = json.load(f)
                default_config.update(loaded_config)
            except Exception as e:
                logger.warning(f"Failed to load config from {config_path}: {e}")

        return default_config

    def _initialize_agents(self):
        """Initialize specialized AI agents"""
        # Register LLM Security Agent
        llm_agent = LLMSecurityAgent()
        self.agent_orchestrator.register_agent(llm_agent)

        # Register Infrastructure Agent
        infra_agent = InfrastructureAgent()
        self.agent_orchestrator.register_agent(infra_agent)

        # Register Vulnerability Agent
        vuln_agent = VulnerabilityAgent()
        self.agent_orchestrator.register_agent(vuln_agent)

        logger.info("Initialized specialized AI agents")

    def _load_pipeline_templates(self):
        """Load predefined pipeline templates"""
        self.pipeline_templates = {
            'comprehensive_ai_security_scan': {
                'name': 'Comprehensive AI Security Scan',
                'description': 'Full AI-powered security assessment with all agents',
                'stages': [
                    {
                        'name': 'infrastructure_reconnaissance',
                        'agent_type': 'infrastructure_agent',
                        'parameters': {
                            'deep_scan': True,
                            'include_ssl': True,
                            'include_dns': True,
                            'port_scan': True
                        },
                        'priority': 1,
                        'dependencies': [],
                        'timeout': 600
                    },
                    {
                        'name': 'llm_security_assessment',
                        'agent_type': 'llm_security_agent',
                        'parameters': {
                            'test_type': 'comprehensive',
                            'include_jailbreaking': True,
                            'include_injection': True,
                            'deep_analysis': True
                        },
                        'priority': 2,
                        'dependencies': ['infrastructure_reconnaissance'],
                        'timeout': 900
                    },
                    {
                        'name': 'vulnerability_analysis',
                        'agent_type': 'vulnerability_agent',
                        'parameters': {
                            'scan_type': 'comprehensive',
                            'risk_threshold': 'low'
                        },
                        'priority': 3,
                        'dependencies': ['infrastructure_reconnaissance', 'llm_security_assessment'],
                        'timeout': 1200
                    }
                ],
                'parameters': {
                    'generate_report': True,
                    'include_recommendations': True,
                    'export_formats': ['json', 'pdf']
                }
            },
            'rapid_ai_security_check': {
                'name': 'Rapid AI Security Check',
                'description': 'Quick AI security assessment for immediate feedback',
                'stages': [
                    {
                        'name': 'basic_infrastructure_check',
                        'agent_type': 'infrastructure_agent',
                        'parameters': {
                            'deep_scan': False,
                            'include_ssl': True,
                            'include_dns': False,
                            'port_scan': False
                        },
                        'priority': 1,
                        'dependencies': [],
                        'timeout': 120
                    },
                    {
                        'name': 'basic_llm_security_test',
                        'agent_type': 'llm_security_agent',
                        'parameters': {
                            'test_type': 'basic',
                            'include_jailbreaking': True,
                            'include_injection': True,
                            'deep_analysis': False
                        },
                        'priority': 2,
                        'dependencies': ['basic_infrastructure_check'],
                        'timeout': 300
                    }
                ],
                'parameters': {
                    'generate_report': True,
                    'include_recommendations': False,
                    'export_formats': ['json']
                }
            },
            'continuous_monitoring_pipeline': {
                'name': 'Continuous Security Monitoring',
                'description': 'Ongoing security monitoring with adaptive learning',
                'stages': [
                    {
                        'name': 'monitoring_infrastructure',
                        'agent_type': 'infrastructure_agent',
                        'parameters': {
                            'deep_scan': False,
                            'include_ssl': True,
                            'include_dns': True,
                            'port_scan': False
                        },
                        'priority': 1,
                        'dependencies': [],
                        'timeout': 180
                    },
                    {
                        'name': 'monitoring_llm_security',
                        'agent_type': 'llm_security_agent',
                        'parameters': {
                            'test_type': 'monitoring',
                            'include_jailbreaking': False,
                            'include_injection': True,
                            'deep_analysis': False
                        },
                        'priority': 2,
                        'dependencies': ['monitoring_infrastructure'],
                        'timeout': 240
                    }
                ],
                'parameters': {
                    'continuous': True,
                    'interval': 3600,  # 1 hour
                    'alert_on_changes': True
                }
            }
        }

        logger.info(f"Loaded {len(self.pipeline_templates)} pipeline templates")

    async def execute_pipeline(self, pipeline_config: PipelineConfig) -> PipelineResult:
        """Execute a complete security testing pipeline"""
        start_time = time.time()
        pipeline_id = pipeline_config.pipeline_id

        logger.info(f"Starting pipeline execution: {pipeline_id}")

        # Initialize pipeline result
        pipeline_result = PipelineResult(
            pipeline_id=pipeline_id,
            status='running',
            started_at=datetime.now(),
            completed_at=None,
            execution_time=0.0,
            total_findings=0,
            risk_score=0.0,
            agent_results=[],
            learning_insights={},
            recommendations=[],
            metadata={}
        )

        try:
            # Add to active pipelines
            self.active_pipelines[pipeline_id] = pipeline_config

            # Optimize pipeline parameters using ML if enabled
            if self.config['adaptive_parameters']:
                optimized_config = await self._optimize_pipeline_parameters(pipeline_config)
                pipeline_config = optimized_config

            # Execute pipeline stages
            pipeline_execution_result = await self.agent_orchestrator.execute_pipeline({
                'pipeline_id': pipeline_id,
                'target': pipeline_config.target,
                'stages': pipeline_config.stages
            })

            # Process results
            pipeline_result.agent_results = pipeline_execution_result.get('tasks', [])
            pipeline_result.status = pipeline_execution_result.get('overall_status', 'completed')

            # Aggregate findings and calculate metrics
            all_findings = []
            for agent_result in pipeline_result.agent_results:
                findings = agent_result.get('findings', [])
                all_findings.extend(findings)

            pipeline_result.total_findings = len(all_findings)
            pipeline_result.risk_score = self._calculate_pipeline_risk_score(all_findings)

            # Generate learning insights
            if self.config['learning_enabled']:
                pipeline_result.learning_insights = await self._generate_learning_insights(
                    pipeline_config, pipeline_result
                )

            # Generate recommendations
            pipeline_result.recommendations = await self._generate_recommendations(
                pipeline_config, all_findings
            )

            # Update performance metrics
            self._update_performance_metrics(pipeline_result)

            # Learn from execution
            if self.config['learning_enabled']:
                await self.learning_engine.process_pipeline_results(pipeline_execution_result)

            logger.info(f"Pipeline {pipeline_id} completed successfully")

        except Exception as e:
            pipeline_result.status = 'failed'
            pipeline_result.metadata['error'] = str(e)
            logger.error(f"Pipeline {pipeline_id} failed: {e}")

        finally:
            # Finalize pipeline result
            pipeline_result.completed_at = datetime.now()
            pipeline_result.execution_time = time.time() - start_time

            # Remove from active pipelines
            if pipeline_id in self.active_pipelines:
                del self.active_pipelines[pipeline_id]

            # Add to history
            self.pipeline_history.append(pipeline_result)

            # Trigger alerts if configured
            if self.monitoring_enabled:
                await self._trigger_pipeline_alerts(pipeline_result)

        return pipeline_result

    async def execute_template_pipeline(self, template_name: str, target: str, **kwargs) -> PipelineResult:
        """Execute a predefined pipeline template"""
        if template_name not in self.pipeline_templates:
            raise ValueError(f"Unknown pipeline template: {template_name}")

        template = self.pipeline_templates[template_name].copy()

        # Create pipeline configuration
        pipeline_config = PipelineConfig(
            pipeline_id=f"{template_name}_{int(time.time())}",
            name=template['name'],
            description=template['description'],
            target=target,
            stages=template['stages'],
            parameters=template.get('parameters', {}),
            **kwargs
        )

        return await self.execute_pipeline(pipeline_config)

    async def create_adaptive_pipeline(self, target: str, objectives: List[str]) -> PipelineConfig:
        """Create an adaptive pipeline based on target and objectives using ML"""
        pipeline_id = f"adaptive_{int(time.time())}"

        # Analyze target characteristics
        target_analysis = await self._analyze_target_characteristics(target)

        # Use ML to recommend optimal pipeline configuration
        recommended_stages = await self._recommend_pipeline_stages(target_analysis, objectives)

        # Optimize parameters using learning engine
        optimized_parameters = await self._optimize_stage_parameters(recommended_stages, target_analysis)

        # Create adaptive pipeline configuration
        pipeline_config = PipelineConfig(
            pipeline_id=pipeline_id,
            name=f"Adaptive Pipeline for {target}",
            description="ML-optimized pipeline based on target analysis and objectives",
            target=target,
            stages=recommended_stages,
            parameters=optimized_parameters,
            adaptive_learning=True
        )

        logger.info(f"Created adaptive pipeline {pipeline_id} with {len(recommended_stages)} stages")

        return pipeline_config

    async def start_continuous_monitoring(self, target: str, interval: int = 3600) -> str:
        """Start continuous security monitoring for a target"""
        monitoring_id = f"monitor_{target.replace('://', '_').replace('/', '_')}_{int(time.time())}"

        # Create continuous monitoring configuration
        monitoring_config = PipelineConfig(
            pipeline_id=monitoring_id,
            name=f"Continuous Monitoring for {target}",
            description="Ongoing security monitoring with adaptive learning",
            target=target,
            stages=self.pipeline_templates['continuous_monitoring_pipeline']['stages'],
            parameters={
                'continuous': True,
                'interval': interval,
                'alert_on_changes': True
            },
            continuous_monitoring=True
        )

        # Start monitoring task
        asyncio.create_task(self._continuous_monitoring_loop(monitoring_config))

        logger.info(f"Started continuous monitoring {monitoring_id} for {target}")
        return monitoring_id

    async def _continuous_monitoring_loop(self, config: PipelineConfig):
        """Continuous monitoring loop"""
        while config.continuous_monitoring:
            try:
                result = await self.execute_pipeline(config)

                # Check for significant changes or new threats
                if await self._detect_security_changes(result):
                    await self._trigger_security_alerts(result)

                # Wait for next interval
                await asyncio.sleep(config.parameters.get('interval', 3600))

            except Exception as e:
                logger.error(f"Continuous monitoring error: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes before retry

    async def _optimize_pipeline_parameters(self, config: PipelineConfig) -> PipelineConfig:
        """Optimize pipeline parameters using machine learning"""
        try:
            optimized_config = config

            # Use learning engine to optimize each stage
            for stage in optimized_config.stages:
                if 'parameters' in stage:
                    optimized_params = self.learning_engine.optimize_task_parameters(
                        stage['parameters'],
                        stage['agent_type']
                    )
                    stage['parameters'] = optimized_params

            logger.info(f"Optimized pipeline parameters for {config.pipeline_id}")
            return optimized_config

        except Exception as e:
            logger.warning(f"Failed to optimize pipeline parameters: {e}")
            return config

    async def _analyze_target_characteristics(self, target: str) -> Dict[str, Any]:
        """Analyze target characteristics for adaptive pipeline creation"""
        characteristics = {
            'target_type': 'web_service',
            'technology_stack': [],
            'security_posture': 'unknown',
            'complexity': 'medium',
            'threat_level': 'medium'
        }

        try:
            # Quick reconnaissance to understand target
            recon_task = AgentTask(
                task_id=f"recon_{int(time.time())}",
                agent_type='infrastructure_agent',
                target=target,
                parameters={'deep_scan': False, 'quick_analysis': True}
            )

            # Execute reconnaissance
            recon_result = await self.agent_orchestrator._execute_single_task(recon_task)

            if recon_result.success:
                data = recon_result.data
                characteristics.update({
                    'technology_stack': data.get('technology_detection', {}).get('fingerprints', {}),
                    'security_posture': self._assess_security_posture(data),
                    'complexity': self._assess_target_complexity(data)
                })

        except Exception as e:
            logger.warning(f"Failed to analyze target characteristics: {e}")

        return characteristics

    async def _recommend_pipeline_stages(self, target_analysis: Dict[str, Any], objectives: List[str]) -> List[Dict[str, Any]]:
        """Recommend optimal pipeline stages based on target analysis and objectives"""
        recommended_stages = []

        # Always start with infrastructure reconnaissance
        recommended_stages.append({
            'name': 'infrastructure_reconnaissance',
            'agent_type': 'infrastructure_agent',
            'parameters': {
                'deep_scan': 'comprehensive' in objectives,
                'include_ssl': True,
                'include_dns': True
            },
            'priority': 1,
            'dependencies': []
        })

        # Add LLM security testing if target appears to be AI-powered
        if self._is_ai_target(target_analysis):
            recommended_stages.append({
                'name': 'llm_security_assessment',
                'agent_type': 'llm_security_agent',
                'parameters': {
                    'test_type': 'comprehensive' if 'comprehensive' in objectives else 'basic',
                    'include_jailbreaking': True,
                    'include_injection': True,
                    'deep_analysis': 'deep_analysis' in objectives
                },
                'priority': 2,
                'dependencies': ['infrastructure_reconnaissance']
            })

        # Add vulnerability assessment
        recommended_stages.append({
            'name': 'vulnerability_analysis',
            'agent_type': 'vulnerability_agent',
            'parameters': {
                'scan_type': 'comprehensive' if 'comprehensive' in objectives else 'basic',
                'risk_threshold': 'low' if 'detailed' in objectives else 'medium'
            },
            'priority': 3,
            'dependencies': [stage['name'] for stage in recommended_stages]
        })

        return recommended_stages

    async def _optimize_stage_parameters(self, stages: List[Dict[str, Any]], target_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize stage parameters using ML insights"""
        optimized_parameters = {}

        # Adjust timeouts based on target complexity
        complexity = target_analysis.get('complexity', 'medium')
        timeout_multiplier = {'low': 0.5, 'medium': 1.0, 'high': 1.5}.get(complexity, 1.0)

        # Adjust scan intensity based on security posture
        security_posture = target_analysis.get('security_posture', 'unknown')
        intensity_boost = {'weak': 1.5, 'medium': 1.0, 'strong': 0.7}.get(security_posture, 1.0)

        optimized_parameters.update({
            'timeout_multiplier': timeout_multiplier,
            'intensity_boost': intensity_boost,
            'adaptive_thresholds': True
        })

        return optimized_parameters

    async def _generate_learning_insights(self, config: PipelineConfig, result: PipelineResult) -> Dict[str, Any]:
        """Generate learning insights from pipeline execution"""
        insights = {
            'performance_analysis': {},
            'effectiveness_scores': {},
            'optimization_suggestions': [],
            'pattern_recognition': {}
        }

        try:
            # Analyze agent performance
            for agent_result in result.agent_results:
                agent_type = agent_result.get('agent_type', 'unknown')
                insights['performance_analysis'][agent_type] = {
                    'execution_time': agent_result.get('execution_time', 0),
                    'findings_count': len(agent_result.get('findings', [])),
                    'confidence_score': agent_result.get('confidence_score', 0),
                    'success': agent_result.get('success', False)
                }

            # Calculate effectiveness scores
            if result.total_findings > 0:
                insights['effectiveness_scores']['finding_rate'] = result.total_findings / result.execution_time
                insights['effectiveness_scores']['risk_detection'] = result.risk_score / 100

            # Generate optimization suggestions
            if result.execution_time > config.timeout * 0.8:
                insights['optimization_suggestions'].append('Consider increasing timeout or optimizing agent parameters')

            if result.total_findings == 0:
                insights['optimization_suggestions'].append('No findings detected - consider adjusting sensitivity thresholds')

            # Pattern recognition from learning engine
            learning_stats = self.learning_engine.get_learning_statistics()
            insights['pattern_recognition'] = learning_stats.get('vulnerability_patterns_count', {})

        except Exception as e:
            logger.warning(f"Failed to generate learning insights: {e}")

        return insights

    async def _generate_recommendations(self, config: PipelineConfig, findings: List[Dict[str, Any]]) -> List[str]:
        """Generate actionable recommendations based on pipeline results"""
        recommendations = []

        # Security recommendations based on findings
        critical_findings = [f for f in findings if f.get('severity') == 'critical']
        high_findings = [f for f in findings if f.get('severity') == 'high']

        if critical_findings:
            recommendations.append(f"URGENT: Address {len(critical_findings)} critical security vulnerabilities immediately")

        if high_findings:
            recommendations.append(f"HIGH PRIORITY: Remediate {len(high_findings)} high-severity vulnerabilities")

        # Pipeline optimization recommendations
        if not findings:
            recommendations.append("Consider increasing scan depth or adjusting detection thresholds")

        # Learning-based recommendations
        learning_stats = self.learning_engine.get_learning_statistics()
        if learning_stats.get('model_accuracy', 0) < 0.7:
            recommendations.append("Consider providing feedback to improve ML model accuracy")

        return recommendations

    def _calculate_pipeline_risk_score(self, findings: List[Dict[str, Any]]) -> float:
        """Calculate overall risk score for pipeline results"""
        if not findings:
            return 0.0

        severity_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1, 'info': 0}
        total_score = sum(severity_weights.get(f.get('severity', 'low'), 1) for f in findings)

        # Normalize to 0-100 scale
        max_possible_score = len(findings) * 10
        risk_score = (total_score / max_possible_score) * 100 if max_possible_score > 0 else 0

        return round(risk_score, 2)

    def _assess_security_posture(self, recon_data: Dict[str, Any]) -> str:
        """Assess target security posture from reconnaissance data"""
        security_score = 0

        # Check for security headers
        headers = recon_data.get('header_analysis', {})
        if headers.get('security_score', 0) > 70:
            security_score += 30

        # Check for HTTPS
        if recon_data.get('basic_info', {}).get('uses_https', False):
            security_score += 20

        # Check for security products
        tech_detection = recon_data.get('technology_detection', {})
        if tech_detection.get('security_products'):
            security_score += 25

        # Check SSL configuration
        ssl_analysis = recon_data.get('ssl_analysis', {})
        if ssl_analysis.get('score', 0) > 70:
            security_score += 25

        if security_score >= 70:
            return 'strong'
        elif security_score >= 40:
            return 'medium'
        else:
            return 'weak'

    def _assess_target_complexity(self, recon_data: Dict[str, Any]) -> str:
        """Assess target complexity from reconnaissance data"""
        complexity_indicators = 0

        # Multiple technologies detected
        tech_detection = recon_data.get('technology_detection', {})
        if len(tech_detection.get('fingerprints', {})) > 3:
            complexity_indicators += 1

        # Multiple open ports
        service_enum = recon_data.get('service_enumeration', {})
        if len(service_enum.get('open_ports', [])) > 2:
            complexity_indicators += 1

        # Complex DNS setup
        dns_analysis = recon_data.get('dns_analysis', {})
        if len(dns_analysis.get('security_records', {})) > 1:
            complexity_indicators += 1

        if complexity_indicators >= 2:
            return 'high'
        elif complexity_indicators == 1:
            return 'medium'
        else:
            return 'low'

    def _is_ai_target(self, target_analysis: Dict[str, Any]) -> bool:
        """Determine if target appears to be AI-powered"""
        tech_stack = target_analysis.get('technology_stack', {})

        # Look for AI/ML indicators in technology fingerprints
        ai_indicators = ['openai', 'anthropic', 'huggingface', 'tensorflow', 'pytorch', 'ml', 'ai', 'gpt', 'claude']

        for indicator in ai_indicators:
            for tech_value in tech_stack.values():
                if isinstance(tech_value, str) and indicator.lower() in tech_value.lower():
                    return True

        return False

    def _update_performance_metrics(self, result: PipelineResult):
        """Update overall performance metrics"""
        self.performance_metrics['total_pipelines_executed'] += 1

        if result.status == 'completed':
            self.performance_metrics['successful_pipelines'] += 1

        # Update running averages
        total_executions = self.performance_metrics['total_pipelines_executed']

        current_avg_time = self.performance_metrics['average_execution_time']
        self.performance_metrics['average_execution_time'] = \
            ((current_avg_time * (total_executions - 1)) + result.execution_time) / total_executions

        self.performance_metrics['total_findings'] += result.total_findings

        current_avg_risk = self.performance_metrics['average_risk_score']
        self.performance_metrics['average_risk_score'] = \
            ((current_avg_risk * (total_executions - 1)) + result.risk_score) / total_executions

    async def _detect_security_changes(self, current_result: PipelineResult) -> bool:
        """Detect significant security changes from previous scans"""
        # Find previous results for the same target
        target = None
        for pipeline in self.pipeline_history[-10:]:  # Check last 10 pipelines
            if pipeline.pipeline_id.startswith('monitor_'):
                # Extract target from monitoring pipeline
                if current_result.risk_score > pipeline.risk_score * 1.2:  # 20% increase
                    return True
                if current_result.total_findings > pipeline.total_findings * 1.5:  # 50% more findings
                    return True

        return False

    async def _trigger_pipeline_alerts(self, result: PipelineResult):
        """Trigger alerts based on pipeline results"""
        alerts = []

        # High risk score alert
        if result.risk_score > 70:
            alerts.append(f"HIGH RISK: Pipeline {result.pipeline_id} detected high risk score: {result.risk_score}")

        # Critical findings alert
        critical_count = sum(1 for agent_result in result.agent_results
                           for finding in agent_result.get('findings', [])
                           if finding.get('severity') == 'critical')

        if critical_count > 0:
            alerts.append(f"CRITICAL VULNERABILITIES: {critical_count} critical vulnerabilities found")

        # Pipeline failure alert
        if result.status == 'failed':
            alerts.append(f"PIPELINE FAILURE: Pipeline {result.pipeline_id} failed to complete")

        # Send alerts through registered callbacks
        for alert in alerts:
            for callback in self.alert_callbacks:
                try:
                    await callback(alert, result)
                except Exception as e:
                    logger.error(f"Alert callback failed: {e}")

    async def _trigger_security_alerts(self, result: PipelineResult):
        """Trigger security-specific alerts"""
        security_alerts = []

        # New vulnerability types detected
        current_vuln_types = set()
        for agent_result in result.agent_results:
            for finding in agent_result.get('findings', []):
                current_vuln_types.add(finding.get('type', 'unknown'))

        # Compare with historical data to detect new vulnerability types
        if len(current_vuln_types) > 0:
            security_alerts.append(f"SECURITY UPDATE: Detected {len(current_vuln_types)} vulnerability types")

        # Send security alerts
        for alert in security_alerts:
            logger.warning(alert)
            for callback in self.alert_callbacks:
                try:
                    await callback(alert, result)
                except Exception as e:
                    logger.error(f"Security alert callback failed: {e}")

    def register_alert_callback(self, callback: Callable):
        """Register alert callback function"""
        self.alert_callbacks.append(callback)
        logger.info("Registered new alert callback")

    def get_pipeline_status(self, pipeline_id: str) -> Dict[str, Any]:
        """Get status of a specific pipeline"""
        if pipeline_id in self.active_pipelines:
            return {
                'status': 'running',
                'config': asdict(self.active_pipelines[pipeline_id])
            }

        # Check pipeline history
        for result in reversed(self.pipeline_history):
            if result.pipeline_id == pipeline_id:
                return {
                    'status': result.status,
                    'result': asdict(result)
                }

        return {'status': 'not_found'}

    def get_orchestrator_metrics(self) -> Dict[str, Any]:
        """Get comprehensive orchestrator metrics"""
        return {
            'performance_metrics': self.performance_metrics,
            'active_pipelines': len(self.active_pipelines),
            'pipeline_history_count': len(self.pipeline_history),
            'available_templates': list(self.pipeline_templates.keys()),
            'agent_status': self.agent_orchestrator.get_orchestrator_status(),
            'learning_statistics': self.learning_engine.get_learning_statistics()
        }

    async def shutdown(self):
        """Gracefully shutdown the orchestrator"""
        logger.info("Shutting down Advanced Pipeline Orchestrator...")

        # Stop continuous monitoring
        for pipeline_config in self.active_pipelines.values():
            if hasattr(pipeline_config, 'continuous_monitoring'):
                pipeline_config.continuous_monitoring = False

        # Shutdown agent orchestrator
        await self.agent_orchestrator.shutdown()

        # Save learning models
        await self.learning_engine.save_models()

        logger.info("Advanced Pipeline Orchestrator shutdown complete")