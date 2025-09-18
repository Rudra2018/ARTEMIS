"""
Continuous Learning System for AI Security Testing

This module implements an advanced continuous learning framework that:
- Provides online learning with real-time feedback loops
- Enables adaptive model retraining based on new threat intelligence
- Implements strategy tuning via metric evaluation and optimization
- Supports active learning for optimal data collection
- Features reinforcement learning for strategy optimization
"""

from .continuous_learner import ContinuousLearner, LearningStrategy, FeedbackLoop
from .adaptive_retrainer import AdaptiveRetrainer, RetrainingTrigger, ModelManager
from .strategy_optimizer import StrategyOptimizer, OptimizationMetric, PerformanceTracker
from .active_learner import ActiveLearner, QueryStrategy, UncertaintyMeasure
from .reinforcement_learner import ReinforcementLearner, RewardFunction, PolicyNetwork

__all__ = [
    'ContinuousLearner',
    'LearningStrategy',
    'FeedbackLoop',
    'AdaptiveRetrainer',
    'RetrainingTrigger',
    'ModelManager',
    'StrategyOptimizer',
    'OptimizationMetric',
    'PerformanceTracker',
    'ActiveLearner',
    'QueryStrategy',
    'UncertaintyMeasure',
    'ReinforcementLearner',
    'RewardFunction',
    'PolicyNetwork'
]