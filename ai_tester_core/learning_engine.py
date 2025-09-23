"""
Adaptive Learning Engine for AI Security Testing
===============================================

This module implements machine learning capabilities for continuous improvement
of security testing agents based on historical data and results.
"""

import asyncio
import json
import logging
import pickle
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import numpy as np
from dataclasses import dataclass, asdict
from collections import defaultdict, deque

# Configure logging
logger = logging.getLogger(__name__)

@dataclass
class LearningDataPoint:
    """Represents a single learning data point"""
    timestamp: datetime
    agent_type: str
    task_parameters: Dict[str, Any]
    execution_time: float
    success: bool
    confidence_score: float
    findings_count: int
    vulnerability_severity: str
    target_characteristics: Dict[str, Any]
    effectiveness_score: float

@dataclass
class AgentPerformanceMetrics:
    """Performance metrics for an agent"""
    success_rate: float
    average_execution_time: float
    average_confidence: float
    effectiveness_score: float
    vulnerability_detection_rate: float
    false_positive_rate: float
    improvement_trend: float

class AdaptiveLearningEngine:
    """
    Machine Learning engine that learns from security testing results
    to improve agent performance and selection
    """

    def __init__(self, models_path: str, learning_data_path: str):
        self.models_path = Path(models_path)
        self.learning_data_path = Path(learning_data_path)
        self.models_path.mkdir(parents=True, exist_ok=True)
        self.learning_data_path.mkdir(parents=True, exist_ok=True)

        # Initialize data structures
        self.learning_data: List[LearningDataPoint] = []
        self.agent_performance_history: Dict[str, List[AgentPerformanceMetrics]] = defaultdict(list)
        self.vulnerability_patterns: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.attack_effectiveness: Dict[str, Dict[str, float]] = defaultdict(dict)

        # ML Models (using simple models for demonstration, can be upgraded to deep learning)
        self.agent_selection_model = None
        self.parameter_optimization_model = None
        self.vulnerability_prediction_model = None

        # Load existing data and models
        self._load_learning_data()
        self._load_models()

        # Performance tracking
        self.performance_window = deque(maxlen=1000)  # Keep last 1000 executions
        self.learning_metrics = {
            'total_executions': 0,
            'successful_predictions': 0,
            'model_accuracy': 0.0,
            'improvement_rate': 0.0
        }

    def _load_learning_data(self):
        """Load historical learning data"""
        try:
            data_file = self.learning_data_path / 'learning_data.json'
            if data_file.exists():
                with open(data_file, 'r') as f:
                    data = json.load(f)

                self.learning_data = [
                    LearningDataPoint(
                        timestamp=datetime.fromisoformat(item['timestamp']),
                        **{k: v for k, v in item.items() if k != 'timestamp'}
                    ) for item in data.get('learning_data', [])
                ]

                self.vulnerability_patterns = data.get('vulnerability_patterns', {})
                self.attack_effectiveness = data.get('attack_effectiveness', {})

                logger.info(f"Loaded {len(self.learning_data)} learning data points")
        except Exception as e:
            logger.warning(f"Failed to load learning data: {e}")

    def _load_models(self):
        """Load trained ML models"""
        try:
            models = ['agent_selection', 'parameter_optimization', 'vulnerability_prediction']
            for model_name in models:
                model_file = self.models_path / f'{model_name}_model.pkl'
                if model_file.exists():
                    with open(model_file, 'rb') as f:
                        model = pickle.load(f)
                        setattr(self, f'{model_name}_model', model)
                    logger.info(f"Loaded {model_name} model")
        except Exception as e:
            logger.warning(f"Failed to load models: {e}")

    async def process_pipeline_results(self, pipeline_results: Dict[str, Any]):
        """Process and learn from pipeline execution results"""
        try:
            # Extract learning data points from pipeline results
            for task_result in pipeline_results.get('tasks', []):
                learning_point = self._create_learning_data_point(task_result, pipeline_results)
                if learning_point:
                    self.learning_data.append(learning_point)
                    self.performance_window.append(learning_point)

            # Update vulnerability patterns
            self._update_vulnerability_patterns(pipeline_results)

            # Update attack effectiveness
            self._update_attack_effectiveness(pipeline_results)

            # Retrain models if enough new data
            if len(self.performance_window) >= 50:  # Retrain every 50 executions
                await self._retrain_models()

            # Update performance metrics
            self._update_performance_metrics()

            logger.info(f"Processed learning data from pipeline {pipeline_results.get('pipeline_id')}")

        except Exception as e:
            logger.error(f"Failed to process pipeline results: {e}")

    def _create_learning_data_point(self, task_result: Dict[str, Any], pipeline_context: Dict[str, Any]) -> Optional[LearningDataPoint]:
        """Create a learning data point from task results"""
        try:
            # Extract target characteristics
            target_characteristics = self._extract_target_characteristics(
                pipeline_context.get('target', ''),
                task_result.get('data', {})
            )

            # Calculate effectiveness score
            effectiveness_score = self._calculate_effectiveness_score(task_result)

            # Determine vulnerability severity
            vulnerability_severity = self._determine_vulnerability_severity(task_result.get('findings', []))

            return LearningDataPoint(
                timestamp=datetime.fromisoformat(task_result['completed_at']),
                agent_type=task_result['agent_type'],
                task_parameters=task_result.get('metadata', {}),
                execution_time=task_result['execution_time'],
                success=task_result['success'],
                confidence_score=task_result['confidence_score'],
                findings_count=len(task_result.get('findings', [])),
                vulnerability_severity=vulnerability_severity,
                target_characteristics=target_characteristics,
                effectiveness_score=effectiveness_score
            )
        except Exception as e:
            logger.warning(f"Failed to create learning data point: {e}")
            return None

    def _extract_target_characteristics(self, target: str, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract characteristics of the target for learning"""
        characteristics = {
            'target_type': 'web_service' if target.startswith('http') else 'unknown',
            'has_authentication': False,
            'response_time_avg': 0.0,
            'error_rate': 0.0,
            'security_headers_present': False,
            'technology_stack': []
        }

        # Analyze task data for characteristics
        if 'infrastructure' in task_data:
            infra_data = task_data['infrastructure']
            characteristics['has_authentication'] = infra_data.get('authentication_detected', False)
            characteristics['security_headers_present'] = len(infra_data.get('security_headers', {})) > 0
            characteristics['technology_stack'] = infra_data.get('detected_technologies', [])

        return characteristics

    def _calculate_effectiveness_score(self, task_result: Dict[str, Any]) -> float:
        """Calculate effectiveness score for a task execution"""
        if not task_result['success']:
            return 0.0

        score = 0.0
        findings = task_result.get('findings', [])

        # Base score from confidence
        score += task_result['confidence_score'] * 0.3

        # Score from findings quality
        if findings:
            severity_weights = {'critical': 1.0, 'high': 0.8, 'medium': 0.6, 'low': 0.4}
            finding_scores = [
                severity_weights.get(finding.get('severity', 'low').lower(), 0.2)
                for finding in findings
            ]
            score += (sum(finding_scores) / len(findings)) * 0.4

        # Score from execution efficiency
        execution_time = task_result['execution_time']
        if execution_time > 0:
            # Penalize very slow executions, reward fast ones
            efficiency_score = max(0, 1 - (execution_time / 300))  # 5 minutes baseline
            score += efficiency_score * 0.3

        return min(score, 1.0)  # Cap at 1.0

    def _determine_vulnerability_severity(self, findings: List[Dict[str, Any]]) -> str:
        """Determine overall vulnerability severity from findings"""
        if not findings:
            return 'none'

        severities = [finding.get('severity', 'low').lower() for finding in findings]

        if 'critical' in severities:
            return 'critical'
        elif 'high' in severities:
            return 'high'
        elif 'medium' in severities:
            return 'medium'
        elif 'low' in severities:
            return 'low'
        else:
            return 'info'

    def _update_vulnerability_patterns(self, pipeline_results: Dict[str, Any]):
        """Update vulnerability patterns based on results"""
        target = pipeline_results.get('target', '')

        for task_result in pipeline_results.get('tasks', []):
            findings = task_result.get('findings', [])

            for finding in findings:
                pattern = {
                    'vulnerability_type': finding.get('type', 'unknown'),
                    'target_characteristics': self._extract_target_characteristics(target, task_result.get('data', {})),
                    'detection_method': task_result.get('agent_type', ''),
                    'confidence': task_result.get('confidence_score', 0.0),
                    'timestamp': datetime.now().isoformat()
                }

                vuln_type = finding.get('type', 'unknown')
                self.vulnerability_patterns[vuln_type].append(pattern)

    def _update_attack_effectiveness(self, pipeline_results: Dict[str, Any]):
        """Update attack effectiveness metrics"""
        for task_result in pipeline_results.get('tasks', []):
            agent_type = task_result.get('agent_type', '')

            # Extract attack methods used
            attack_methods = task_result.get('data', {}).get('attack_methods', [])

            for method in attack_methods:
                if method not in self.attack_effectiveness[agent_type]:
                    self.attack_effectiveness[agent_type][method] = 0.0

                # Update effectiveness based on success and findings
                effectiveness = self._calculate_effectiveness_score(task_result)
                current_eff = self.attack_effectiveness[agent_type][method]

                # Exponential moving average
                self.attack_effectiveness[agent_type][method] = (current_eff * 0.7) + (effectiveness * 0.3)

    async def _retrain_models(self):
        """Retrain ML models with new data"""
        try:
            logger.info("Retraining models with new data...")

            # Prepare training data
            training_data = self._prepare_training_data()

            if len(training_data) < 10:  # Need minimum data
                logger.warning("Insufficient data for model retraining")
                return

            # Train agent selection model
            await self._train_agent_selection_model(training_data)

            # Train parameter optimization model
            await self._train_parameter_optimization_model(training_data)

            # Train vulnerability prediction model
            await self._train_vulnerability_prediction_model(training_data)

            # Save models
            await self.save_models()

            logger.info("Model retraining completed")

        except Exception as e:
            logger.error(f"Model retraining failed: {e}")

    def _prepare_training_data(self) -> List[Dict[str, Any]]:
        """Prepare training data from learning data points"""
        training_data = []

        for point in self.learning_data[-1000:]:  # Use last 1000 points
            training_data.append({
                'features': {
                    'agent_type': point.agent_type,
                    'execution_time': point.execution_time,
                    'target_characteristics': point.target_characteristics,
                    'task_parameters': point.task_parameters
                },
                'targets': {
                    'success': point.success,
                    'effectiveness_score': point.effectiveness_score,
                    'confidence_score': point.confidence_score,
                    'vulnerability_severity': point.vulnerability_severity
                }
            })

        return training_data

    async def _train_agent_selection_model(self, training_data: List[Dict[str, Any]]):
        """Train model for selecting best agent for tasks"""
        # Simple implementation using historical performance
        agent_performance = defaultdict(list)

        for data in training_data:
            agent_type = data['features']['agent_type']
            effectiveness = data['targets']['effectiveness_score']
            agent_performance[agent_type].append(effectiveness)

        # Calculate average performance for each agent type
        self.agent_selection_model = {
            agent_type: np.mean(scores) if scores else 0.0
            for agent_type, scores in agent_performance.items()
        }

    async def _train_parameter_optimization_model(self, training_data: List[Dict[str, Any]]):
        """Train model for optimizing task parameters"""
        # Simple parameter effectiveness tracking
        param_effectiveness = defaultdict(list)

        for data in training_data:
            params = data['features']['task_parameters']
            effectiveness = data['targets']['effectiveness_score']

            for param_name, param_value in params.items():
                if isinstance(param_value, (bool, str)):
                    key = f"{param_name}:{param_value}"
                    param_effectiveness[key].append(effectiveness)

        # Calculate effectiveness for each parameter combination
        self.parameter_optimization_model = {
            param_combo: np.mean(scores) if scores else 0.0
            for param_combo, scores in param_effectiveness.items()
        }

    async def _train_vulnerability_prediction_model(self, training_data: List[Dict[str, Any]]):
        """Train model for predicting vulnerability likelihood"""
        # Simple vulnerability prediction based on target characteristics
        vuln_likelihood = defaultdict(list)

        for data in training_data:
            target_chars = data['features']['target_characteristics']
            has_vulns = data['targets']['vulnerability_severity'] not in ['none', 'info']

            # Create feature combinations
            for char_name, char_value in target_chars.items():
                if isinstance(char_value, (bool, str)):
                    key = f"{char_name}:{char_value}"
                    vuln_likelihood[key].append(1.0 if has_vulns else 0.0)

        self.vulnerability_prediction_model = {
            feature: np.mean(scores) if scores else 0.0
            for feature, scores in vuln_likelihood.items()
        }

    def select_best_agent(self, available_agents: List, task) -> Optional:
        """Select the best agent for a task using ML model"""
        if not self.agent_selection_model or not available_agents:
            return available_agents[0] if available_agents else None

        # Score each agent
        agent_scores = {}
        for agent in available_agents:
            # Get base score from model
            base_score = self.agent_selection_model.get(task.agent_type, 0.5)

            # Adjust based on recent performance
            recent_performance = self._get_recent_performance(agent.agent_id)
            adjusted_score = base_score * (1 + recent_performance)

            agent_scores[agent.agent_id] = adjusted_score

        # Select agent with highest score
        best_agent_id = max(agent_scores, key=agent_scores.get)
        return next(agent for agent in available_agents if agent.agent_id == best_agent_id)

    def optimize_task_parameters(self, base_parameters: Dict[str, Any], task_type: str) -> Dict[str, Any]:
        """Optimize task parameters using ML model"""
        if not self.parameter_optimization_model:
            return base_parameters

        optimized_params = base_parameters.copy()

        # Find most effective parameter combinations
        for param_combo, effectiveness in self.parameter_optimization_model.items():
            if effectiveness > 0.7:  # High effectiveness threshold
                param_name, param_value = param_combo.split(':', 1)

                # Convert string back to appropriate type
                if param_value.lower() in ['true', 'false']:
                    optimized_params[param_name] = param_value.lower() == 'true'
                else:
                    optimized_params[param_name] = param_value

        return optimized_params

    def predict_vulnerability_likelihood(self, target_characteristics: Dict[str, Any]) -> float:
        """Predict likelihood of finding vulnerabilities"""
        if not self.vulnerability_prediction_model:
            return 0.5  # Default probability

        likelihood_scores = []

        for char_name, char_value in target_characteristics.items():
            if isinstance(char_value, (bool, str)):
                key = f"{char_name}:{char_value}"
                if key in self.vulnerability_prediction_model:
                    likelihood_scores.append(self.vulnerability_prediction_model[key])

        if not likelihood_scores:
            return 0.5

        return np.mean(likelihood_scores)

    def _get_recent_performance(self, agent_id: str) -> float:
        """Get recent performance trend for an agent"""
        # Look at performance in last 24 hours
        cutoff_time = datetime.now() - timedelta(hours=24)
        recent_points = [
            point for point in self.learning_data
            if point.timestamp >= cutoff_time and agent_id in point.agent_type
        ]

        if not recent_points:
            return 0.0

        # Calculate trend (positive = improving, negative = declining)
        if len(recent_points) < 2:
            return 0.0

        recent_effectiveness = [point.effectiveness_score for point in recent_points[-10:]]
        if len(recent_effectiveness) < 2:
            return 0.0

        # Simple linear trend
        x = list(range(len(recent_effectiveness)))
        trend = np.corrcoef(x, recent_effectiveness)[0, 1] if len(recent_effectiveness) > 1 else 0.0

        return trend if not np.isnan(trend) else 0.0

    def _update_performance_metrics(self):
        """Update overall learning engine performance metrics"""
        self.learning_metrics['total_executions'] = len(self.learning_data)

        # Calculate model accuracy (simplified)
        if len(self.performance_window) > 10:
            recent_predictions = list(self.performance_window)[-100:]
            successful_predictions = sum(1 for point in recent_predictions if point.success)
            self.learning_metrics['successful_predictions'] = successful_predictions
            self.learning_metrics['model_accuracy'] = successful_predictions / len(recent_predictions)

        # Calculate improvement rate
        if len(self.learning_data) > 100:
            old_avg = np.mean([point.effectiveness_score for point in self.learning_data[-200:-100]])
            new_avg = np.mean([point.effectiveness_score for point in self.learning_data[-100:]])
            self.learning_metrics['improvement_rate'] = (new_avg - old_avg) / old_avg if old_avg > 0 else 0.0

    async def save_models(self):
        """Save trained models and learning data"""
        try:
            # Save learning data
            data_to_save = {
                'learning_data': [
                    {
                        'timestamp': point.timestamp.isoformat(),
                        **{k: v for k, v in asdict(point).items() if k != 'timestamp'}
                    } for point in self.learning_data
                ],
                'vulnerability_patterns': dict(self.vulnerability_patterns),
                'attack_effectiveness': dict(self.attack_effectiveness)
            }

            with open(self.learning_data_path / 'learning_data.json', 'w') as f:
                json.dump(data_to_save, f, indent=2)

            # Save models
            models = {
                'agent_selection_model': self.agent_selection_model,
                'parameter_optimization_model': self.parameter_optimization_model,
                'vulnerability_prediction_model': self.vulnerability_prediction_model
            }

            for model_name, model in models.items():
                if model:
                    with open(self.models_path / f'{model_name}.pkl', 'wb') as f:
                        pickle.dump(model, f)

            logger.info("Models and learning data saved successfully")

        except Exception as e:
            logger.error(f"Failed to save models: {e}")

    def get_learning_statistics(self) -> Dict[str, Any]:
        """Get comprehensive learning statistics"""
        return {
            'total_learning_points': len(self.learning_data),
            'recent_performance_window': len(self.performance_window),
            'model_accuracy': self.learning_metrics['model_accuracy'],
            'improvement_rate': self.learning_metrics['improvement_rate'],
            'agent_performance': {
                agent_type: {
                    'avg_effectiveness': np.mean([p.effectiveness_score for p in self.learning_data if p.agent_type == agent_type]) if any(p.agent_type == agent_type for p in self.learning_data) else 0.0,
                    'success_rate': np.mean([1.0 if p.success else 0.0 for p in self.learning_data if p.agent_type == agent_type]) if any(p.agent_type == agent_type for p in self.learning_data) else 0.0
                }
                for agent_type in set(point.agent_type for point in self.learning_data)
            },
            'vulnerability_patterns_count': {
                vuln_type: len(patterns) for vuln_type, patterns in self.vulnerability_patterns.items()
            },
            'top_effective_attacks': {
                agent_type: sorted(attacks.items(), key=lambda x: x[1], reverse=True)[:5]
                for agent_type, attacks in self.attack_effectiveness.items()
            }
        }