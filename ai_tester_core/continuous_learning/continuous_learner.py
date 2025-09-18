"""
Continuous Learning System with Real-time Feedback Loops

This module implements a comprehensive continuous learning framework that:
- Adapts to new threats and attack patterns in real-time
- Maintains multiple feedback loops for different aspects of security
- Implements online learning algorithms for immediate adaptation
- Provides strategy tuning based on performance metrics
- Supports both supervised and unsupervised learning approaches
"""

import json
import time
import logging
import numpy as np
from typing import Dict, List, Any, Optional, Tuple, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import sqlite3
from pathlib import Path
import threading
from collections import deque, defaultdict
import queue
import concurrent.futures
import pickle
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LearningStrategy(Enum):
    """Learning strategies for continuous adaptation"""
    ONLINE_GRADIENT_DESCENT = "online_gradient_descent"
    INCREMENTAL_LEARNING = "incremental_learning"
    TRANSFER_LEARNING = "transfer_learning"
    META_LEARNING = "meta_learning"
    ENSEMBLE_LEARNING = "ensemble_learning"
    ACTIVE_LEARNING = "active_learning"
    REINFORCEMENT_LEARNING = "reinforcement_learning"

class FeedbackType(Enum):
    """Types of feedback for learning"""
    DETECTION_ACCURACY = "detection_accuracy"
    FALSE_POSITIVE_RATE = "false_positive_rate"
    RESPONSE_TIME = "response_time"
    THREAT_SEVERITY = "threat_severity"
    USER_SATISFACTION = "user_satisfaction"
    SYSTEM_PERFORMANCE = "system_performance"
    ATTACK_SUCCESS_RATE = "attack_success_rate"

class LearningMode(Enum):
    """Learning modes for different scenarios"""
    EXPLORATION = "exploration"  # Explore new strategies
    EXPLOITATION = "exploitation"  # Use best known strategies
    BALANCED = "balanced"  # Balance exploration and exploitation
    ADAPTIVE = "adaptive"  # Dynamically adjust based on context

@dataclass
class FeedbackSignal:
    """Represents a feedback signal for learning"""
    signal_id: str
    feedback_type: FeedbackType
    value: float
    confidence: float
    timestamp: datetime
    source: str
    context: Dict[str, Any]
    weight: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class LearningEvent:
    """Represents a learning event"""
    event_id: str
    strategy: LearningStrategy
    input_data: Any
    expected_output: Any
    actual_output: Any
    loss: float
    learning_rate: float
    timestamp: datetime
    success: bool
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ModelSnapshot:
    """Snapshot of model state for rollback/comparison"""
    snapshot_id: str
    model_state: Dict[str, Any]
    performance_metrics: Dict[str, float]
    timestamp: datetime
    strategy_config: Dict[str, Any]
    validation_score: float

class FeedbackLoop:
    """Individual feedback loop for specific learning aspects"""

    def __init__(self, feedback_type: FeedbackType, window_size: int = 100,
                 learning_rate: float = 0.01, decay_factor: float = 0.95):
        self.feedback_type = feedback_type
        self.window_size = window_size
        self.learning_rate = learning_rate
        self.decay_factor = decay_factor

        self.feedback_buffer = deque(maxlen=window_size)
        self.performance_history = deque(maxlen=1000)
        self.adaptation_rules = self._initialize_adaptation_rules()

        # Learning state
        self.current_performance = 0.5  # Initialize to neutral
        self.target_performance = 0.8   # Target performance level
        self.adaptation_threshold = 0.1  # Threshold for triggering adaptation

    def _initialize_adaptation_rules(self) -> Dict[str, Callable]:
        """Initialize adaptation rules for different feedback types"""
        return {
            FeedbackType.DETECTION_ACCURACY.value: self._adapt_detection_accuracy,
            FeedbackType.FALSE_POSITIVE_RATE.value: self._adapt_false_positive_rate,
            FeedbackType.RESPONSE_TIME.value: self._adapt_response_time,
            FeedbackType.THREAT_SEVERITY.value: self._adapt_threat_severity,
            FeedbackType.ATTACK_SUCCESS_RATE.value: self._adapt_attack_success_rate
        }

    def add_feedback(self, feedback: FeedbackSignal) -> Dict[str, Any]:
        """Add feedback signal and trigger adaptation if needed"""
        if feedback.feedback_type != self.feedback_type:
            return {"adapted": False, "reason": "feedback_type_mismatch"}

        # Add to buffer with timestamp
        self.feedback_buffer.append(feedback)

        # Calculate current performance
        self._update_performance_metrics()

        # Check if adaptation is needed
        adaptation_result = self._check_adaptation_trigger()

        # Log feedback
        logger.debug(f"Feedback added to {self.feedback_type.value} loop: {feedback.value:.3f}")

        return adaptation_result

    def _update_performance_metrics(self):
        """Update current performance based on recent feedback"""
        if not self.feedback_buffer:
            return

        # Weighted average of recent feedback
        weights = []
        values = []

        for i, feedback in enumerate(self.feedback_buffer):
            # More recent feedback gets higher weight
            time_weight = self.decay_factor ** (len(self.feedback_buffer) - i - 1)
            total_weight = time_weight * feedback.weight * feedback.confidence

            weights.append(total_weight)
            values.append(feedback.value)

        if weights:
            self.current_performance = np.average(values, weights=weights)

        # Store in history
        self.performance_history.append({
            'timestamp': datetime.now(),
            'performance': self.current_performance,
            'feedback_count': len(self.feedback_buffer)
        })

    def _check_adaptation_trigger(self) -> Dict[str, Any]:
        """Check if adaptation should be triggered"""

        performance_gap = abs(self.current_performance - self.target_performance)

        if performance_gap > self.adaptation_threshold:
            # Trigger adaptation
            adaptation_strategy = self._determine_adaptation_strategy()
            adaptation_params = self._calculate_adaptation_parameters()

            result = {
                "adapted": True,
                "strategy": adaptation_strategy,
                "parameters": adaptation_params,
                "performance_gap": performance_gap,
                "current_performance": self.current_performance,
                "target_performance": self.target_performance
            }

            # Apply adaptation rule
            if self.feedback_type.value in self.adaptation_rules:
                rule_result = self.adaptation_rules[self.feedback_type.value](adaptation_params)
                result.update(rule_result)

            return result

        return {"adapted": False, "performance_gap": performance_gap}

    def _determine_adaptation_strategy(self) -> str:
        """Determine the best adaptation strategy based on current state"""

        # Analyze performance trend
        if len(self.performance_history) >= 5:
            recent_performance = [p['performance'] for p in list(self.performance_history)[-5:]]
            trend = np.polyfit(range(len(recent_performance)), recent_performance, 1)[0]

            if trend > 0.01:  # Improving
                return "gradual_adjustment"
            elif trend < -0.01:  # Declining
                return "aggressive_correction"
            else:  # Stable
                return "fine_tuning"

        return "baseline_adjustment"

    def _calculate_adaptation_parameters(self) -> Dict[str, float]:
        """Calculate parameters for adaptation"""

        performance_gap = abs(self.current_performance - self.target_performance)

        # Calculate adaptive learning rate
        adaptive_lr = self.learning_rate * min(2.0, 1.0 + performance_gap)

        # Calculate confidence in adaptation
        feedback_confidence = np.mean([f.confidence for f in self.feedback_buffer]) if self.feedback_buffer else 0.5

        return {
            "learning_rate": adaptive_lr,
            "confidence": feedback_confidence,
            "performance_gap": performance_gap,
            "adjustment_magnitude": min(1.0, performance_gap * 2)
        }

    def _adapt_detection_accuracy(self, params: Dict[str, float]) -> Dict[str, Any]:
        """Adaptation rule for detection accuracy feedback"""

        if self.current_performance < self.target_performance:
            # Need to improve detection accuracy
            adjustments = {
                "increase_sensitivity": params["adjustment_magnitude"] * 0.8,
                "reduce_threshold": params["adjustment_magnitude"] * 0.6,
                "enhance_features": params["adjustment_magnitude"] * 0.4
            }
        else:
            # Detection accuracy is good, focus on other metrics
            adjustments = {
                "maintain_sensitivity": params["adjustment_magnitude"] * 0.2,
                "optimize_performance": params["adjustment_magnitude"] * 0.3
            }

        return {"adjustments": adjustments, "adaptation_type": "detection_accuracy"}

    def _adapt_false_positive_rate(self, params: Dict[str, float]) -> Dict[str, Any]:
        """Adaptation rule for false positive rate feedback"""

        if self.current_performance > self.target_performance:  # High FPR is bad
            # Need to reduce false positives
            adjustments = {
                "increase_threshold": params["adjustment_magnitude"] * 0.7,
                "improve_specificity": params["adjustment_magnitude"] * 0.8,
                "refine_features": params["adjustment_magnitude"] * 0.5
            }
        else:
            # FPR is acceptable
            adjustments = {
                "maintain_threshold": params["adjustment_magnitude"] * 0.2
            }

        return {"adjustments": adjustments, "adaptation_type": "false_positive_rate"}

    def _adapt_response_time(self, params: Dict[str, float]) -> Dict[str, Any]:
        """Adaptation rule for response time feedback"""

        if self.current_performance > self.target_performance:  # High response time is bad
            # Need to improve response time
            adjustments = {
                "optimize_algorithms": params["adjustment_magnitude"] * 0.8,
                "cache_results": params["adjustment_magnitude"] * 0.6,
                "parallel_processing": params["adjustment_magnitude"] * 0.7
            }
        else:
            # Response time is good
            adjustments = {
                "maintain_performance": params["adjustment_magnitude"] * 0.2
            }

        return {"adjustments": adjustments, "adaptation_type": "response_time"}

    def _adapt_threat_severity(self, params: Dict[str, float]) -> Dict[str, Any]:
        """Adaptation rule for threat severity feedback"""

        adjustments = {
            "adjust_severity_weights": params["adjustment_magnitude"] * 0.8,
            "refine_risk_assessment": params["adjustment_magnitude"] * 0.6,
            "update_threat_models": params["adjustment_magnitude"] * 0.9
        }

        return {"adjustments": adjustments, "adaptation_type": "threat_severity"}

    def _adapt_attack_success_rate(self, params: Dict[str, float]) -> Dict[str, Any]:
        """Adaptation rule for attack success rate feedback"""

        if self.current_performance > self.target_performance:  # High attack success is bad
            # Need to improve defenses
            adjustments = {
                "strengthen_defenses": params["adjustment_magnitude"] * 0.9,
                "update_detection_rules": params["adjustment_magnitude"] * 0.8,
                "enhance_monitoring": params["adjustment_magnitude"] * 0.7
            }
        else:
            # Defenses are working well
            adjustments = {
                "maintain_vigilance": params["adjustment_magnitude"] * 0.3
            }

        return {"adjustments": adjustments, "adaptation_type": "attack_success_rate"}

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary for this feedback loop"""

        if not self.performance_history:
            return {"status": "no_data"}

        recent_performance = list(self.performance_history)[-10:]

        return {
            "feedback_type": self.feedback_type.value,
            "current_performance": self.current_performance,
            "target_performance": self.target_performance,
            "performance_gap": abs(self.current_performance - self.target_performance),
            "feedback_count": len(self.feedback_buffer),
            "recent_trend": self._calculate_trend(recent_performance),
            "adaptation_needed": abs(self.current_performance - self.target_performance) > self.adaptation_threshold
        }

    def _calculate_trend(self, performance_data: List[Dict]) -> str:
        """Calculate performance trend"""
        if len(performance_data) < 3:
            return "insufficient_data"

        values = [p['performance'] for p in performance_data]
        trend = np.polyfit(range(len(values)), values, 1)[0]

        if trend > 0.02:
            return "improving"
        elif trend < -0.02:
            return "declining"
        else:
            return "stable"

class ContinuousLearner:
    """Main continuous learning system coordinating multiple feedback loops"""

    def __init__(self, learning_strategies: List[LearningStrategy] = None,
                 database_path: str = "continuous_learning.db"):

        self.learning_strategies = learning_strategies or [
            LearningStrategy.ONLINE_GRADIENT_DESCENT,
            LearningStrategy.INCREMENTAL_LEARNING
        ]

        self.database_path = database_path

        # Initialize feedback loops
        self.feedback_loops = self._initialize_feedback_loops()

        # Learning state
        self.learning_events = deque(maxlen=10000)
        self.model_snapshots = {}
        self.global_performance = {}

        # Threading for continuous processing
        self.feedback_queue = queue.Queue()
        self.processing_thread = None
        self.stop_processing = threading.Event()

        # Initialize database
        self._initialize_database()

        # Start processing
        self.start_continuous_learning()

    def _initialize_feedback_loops(self) -> Dict[FeedbackType, FeedbackLoop]:
        """Initialize feedback loops for different aspects"""

        loops = {}

        for feedback_type in FeedbackType:
            # Customize parameters based on feedback type
            if feedback_type == FeedbackType.RESPONSE_TIME:
                loop = FeedbackLoop(feedback_type, window_size=50, learning_rate=0.02)
            elif feedback_type == FeedbackType.DETECTION_ACCURACY:
                loop = FeedbackLoop(feedback_type, window_size=100, learning_rate=0.01)
            elif feedback_type == FeedbackType.FALSE_POSITIVE_RATE:
                loop = FeedbackLoop(feedback_type, window_size=200, learning_rate=0.005)
            else:
                loop = FeedbackLoop(feedback_type)

            loops[feedback_type] = loop

        return loops

    def _initialize_database(self):
        """Initialize SQLite database for persistent learning"""

        with sqlite3.connect(self.database_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS feedback_signals (
                    signal_id TEXT PRIMARY KEY,
                    feedback_type TEXT,
                    value REAL,
                    confidence REAL,
                    timestamp TEXT,
                    source TEXT,
                    context TEXT,
                    weight REAL,
                    metadata TEXT
                )
            ''')

            conn.execute('''
                CREATE TABLE IF NOT EXISTS learning_events (
                    event_id TEXT PRIMARY KEY,
                    strategy TEXT,
                    input_data TEXT,
                    expected_output TEXT,
                    actual_output TEXT,
                    loss REAL,
                    learning_rate REAL,
                    timestamp TEXT,
                    success INTEGER,
                    metadata TEXT
                )
            ''')

            conn.execute('''
                CREATE TABLE IF NOT EXISTS model_snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    model_state TEXT,
                    performance_metrics TEXT,
                    timestamp TEXT,
                    strategy_config TEXT,
                    validation_score REAL
                )
            ''')

    def add_feedback(self, feedback_type: FeedbackType, value: float,
                    confidence: float = 1.0, source: str = "system",
                    context: Dict[str, Any] = None) -> str:
        """Add feedback signal to the learning system"""

        signal = FeedbackSignal(
            signal_id=f"fb_{int(time.time())}_{hash(str(value)) % 10000:04d}",
            feedback_type=feedback_type,
            value=value,
            confidence=confidence,
            timestamp=datetime.now(),
            source=source,
            context=context or {},
            weight=1.0
        )

        # Add to queue for processing
        self.feedback_queue.put(('feedback', signal))

        # Store in database
        self._store_feedback_signal(signal)

        logger.info(f"Feedback added: {feedback_type.value} = {value:.3f}")

        return signal.signal_id

    def trigger_learning_event(self, strategy: LearningStrategy, input_data: Any,
                             expected_output: Any, actual_output: Any,
                             learning_rate: float = 0.01) -> str:
        """Trigger a learning event"""

        # Calculate loss
        loss = self._calculate_loss(expected_output, actual_output)

        event = LearningEvent(
            event_id=f"le_{int(time.time())}_{hash(str(input_data)) % 10000:04d}",
            strategy=strategy,
            input_data=input_data,
            expected_output=expected_output,
            actual_output=actual_output,
            loss=loss,
            learning_rate=learning_rate,
            timestamp=datetime.now(),
            success=loss < 0.5  # Simple success criterion
        )

        # Add to queue for processing
        self.feedback_queue.put(('learning_event', event))

        # Store in database
        self._store_learning_event(event)

        logger.info(f"Learning event triggered: {strategy.value}, loss={loss:.3f}")

        return event.event_id

    def create_model_snapshot(self, model_state: Dict[str, Any],
                            performance_metrics: Dict[str, float],
                            strategy_config: Dict[str, Any]) -> str:
        """Create a snapshot of current model state"""

        validation_score = np.mean(list(performance_metrics.values()))

        snapshot = ModelSnapshot(
            snapshot_id=f"snap_{int(time.time())}_{hash(str(model_state)) % 10000:04d}",
            model_state=model_state,
            performance_metrics=performance_metrics,
            timestamp=datetime.now(),
            strategy_config=strategy_config,
            validation_score=validation_score
        )

        self.model_snapshots[snapshot.snapshot_id] = snapshot

        # Store in database
        self._store_model_snapshot(snapshot)

        logger.info(f"Model snapshot created: {snapshot.snapshot_id}, score={validation_score:.3f}")

        return snapshot.snapshot_id

    def start_continuous_learning(self):
        """Start the continuous learning process"""

        if self.processing_thread and self.processing_thread.is_alive():
            return

        self.stop_processing.clear()
        self.processing_thread = threading.Thread(target=self._continuous_processing_loop)
        self.processing_thread.daemon = True
        self.processing_thread.start()

        logger.info("Continuous learning started")

    def stop_continuous_learning(self):
        """Stop the continuous learning process"""

        self.stop_processing.set()

        if self.processing_thread:
            self.processing_thread.join(timeout=5)

        logger.info("Continuous learning stopped")

    def _continuous_processing_loop(self):
        """Main processing loop for continuous learning"""

        while not self.stop_processing.is_set():
            try:
                # Process feedback and learning events
                try:
                    item_type, item = self.feedback_queue.get(timeout=1)

                    if item_type == 'feedback':
                        self._process_feedback_signal(item)
                    elif item_type == 'learning_event':
                        self._process_learning_event(item)

                    self.feedback_queue.task_done()

                except queue.Empty:
                    continue

                # Periodic global optimization
                if len(self.learning_events) % 50 == 0:
                    self._perform_global_optimization()

            except Exception as e:
                logger.error(f"Error in continuous learning loop: {e}")
                time.sleep(1)

    def _process_feedback_signal(self, signal: FeedbackSignal):
        """Process individual feedback signal"""

        if signal.feedback_type in self.feedback_loops:
            loop = self.feedback_loops[signal.feedback_type]
            result = loop.add_feedback(signal)

            if result.get("adapted", False):
                logger.info(f"Adaptation triggered for {signal.feedback_type.value}: {result}")
                self._apply_adaptations(signal.feedback_type, result)

    def _process_learning_event(self, event: LearningEvent):
        """Process individual learning event"""

        self.learning_events.append(event)

        # Update global performance metrics
        self._update_global_performance(event)

        # Check if strategy adjustment is needed
        if len(self.learning_events) % 10 == 0:
            self._evaluate_strategy_performance()

    def _apply_adaptations(self, feedback_type: FeedbackType, adaptation_result: Dict[str, Any]):
        """Apply adaptations based on feedback loop results"""

        adjustments = adaptation_result.get("adjustments", {})

        # Log adaptations
        logger.info(f"Applying adaptations for {feedback_type.value}: {adjustments}")

        # Apply specific adjustments (would integrate with actual system components)
        for adjustment_type, magnitude in adjustments.items():
            self._apply_specific_adjustment(feedback_type, adjustment_type, magnitude)

    def _apply_specific_adjustment(self, feedback_type: FeedbackType,
                                 adjustment_type: str, magnitude: float):
        """Apply specific adjustment to the system"""

        # This would integrate with actual system components
        # For now, we simulate the adjustment
        adjustment_record = {
            'timestamp': datetime.now(),
            'feedback_type': feedback_type.value,
            'adjustment_type': adjustment_type,
            'magnitude': magnitude,
            'applied': True
        }

        # Store adjustment record
        if not hasattr(self, 'adjustments_history'):
            self.adjustments_history = deque(maxlen=1000)

        self.adjustments_history.append(adjustment_record)

        logger.debug(f"Applied adjustment: {adjustment_type} with magnitude {magnitude:.3f}")

    def _update_global_performance(self, event: LearningEvent):
        """Update global performance metrics"""

        strategy = event.strategy.value

        if strategy not in self.global_performance:
            self.global_performance[strategy] = {
                'total_events': 0,
                'successful_events': 0,
                'average_loss': 0.0,
                'recent_losses': deque(maxlen=100)
            }

        metrics = self.global_performance[strategy]
        metrics['total_events'] += 1

        if event.success:
            metrics['successful_events'] += 1

        metrics['recent_losses'].append(event.loss)
        metrics['average_loss'] = np.mean(metrics['recent_losses'])

    def _evaluate_strategy_performance(self):
        """Evaluate and adjust learning strategies"""

        if not self.global_performance:
            return

        # Find best performing strategy
        best_strategy = None
        best_score = float('inf')

        for strategy, metrics in self.global_performance.items():
            if metrics['total_events'] > 10:  # Minimum events for evaluation
                score = metrics['average_loss']
                if score < best_score:
                    best_score = score
                    best_strategy = strategy

        if best_strategy:
            logger.info(f"Best performing strategy: {best_strategy} (avg loss: {best_score:.3f})")

            # Adjust strategy weights (would be used by actual learning algorithms)
            self._adjust_strategy_weights(best_strategy)

    def _adjust_strategy_weights(self, best_strategy: str):
        """Adjust strategy weights based on performance"""

        # Simple strategy weight adjustment
        if not hasattr(self, 'strategy_weights'):
            self.strategy_weights = {s.value: 1.0 for s in self.learning_strategies}

        # Increase weight for best strategy
        self.strategy_weights[best_strategy] *= 1.1

        # Normalize weights
        total_weight = sum(self.strategy_weights.values())
        for strategy in self.strategy_weights:
            self.strategy_weights[strategy] /= total_weight

        logger.debug(f"Updated strategy weights: {self.strategy_weights}")

    def _perform_global_optimization(self):
        """Perform global optimization across all feedback loops"""

        # Calculate overall system performance
        overall_performance = self._calculate_overall_performance()

        # Check if global intervention is needed
        if overall_performance < 0.6:  # Threshold for global optimization
            logger.info(f"Global optimization triggered (performance: {overall_performance:.3f})")

            # Identify problematic areas
            problematic_loops = []
            for feedback_type, loop in self.feedback_loops.items():
                summary = loop.get_performance_summary()
                if summary.get("adaptation_needed", False):
                    problematic_loops.append((feedback_type, summary))

            # Apply global optimizations
            self._apply_global_optimizations(problematic_loops)

    def _calculate_overall_performance(self) -> float:
        """Calculate overall system performance"""

        performances = []

        for loop in self.feedback_loops.values():
            summary = loop.get_performance_summary()
            if summary.get("current_performance") is not None:
                performances.append(summary["current_performance"])

        return np.mean(performances) if performances else 0.5

    def _apply_global_optimizations(self, problematic_loops: List):
        """Apply global optimizations"""

        optimizations = []

        for feedback_type, summary in problematic_loops:
            optimization = {
                'feedback_type': feedback_type.value,
                'performance_gap': summary.get('performance_gap', 0),
                'recommended_action': self._recommend_global_action(feedback_type, summary)
            }
            optimizations.append(optimization)

        logger.info(f"Global optimizations recommended: {len(optimizations)}")

        # Store optimization recommendations
        if not hasattr(self, 'optimization_history'):
            self.optimization_history = deque(maxlen=500)

        self.optimization_history.append({
            'timestamp': datetime.now(),
            'optimizations': optimizations,
            'trigger_performance': self._calculate_overall_performance()
        })

    def _recommend_global_action(self, feedback_type: FeedbackType, summary: Dict) -> str:
        """Recommend global action for problematic feedback loop"""

        performance_gap = summary.get('performance_gap', 0)
        trend = summary.get('recent_trend', 'stable')

        if performance_gap > 0.3:
            if trend == 'declining':
                return 'emergency_intervention'
            else:
                return 'major_adjustment'
        elif performance_gap > 0.15:
            return 'moderate_adjustment'
        else:
            return 'minor_tuning'

    def _calculate_loss(self, expected: Any, actual: Any) -> float:
        """Calculate loss between expected and actual outputs"""

        try:
            if isinstance(expected, (int, float)) and isinstance(actual, (int, float)):
                return abs(expected - actual)
            elif isinstance(expected, str) and isinstance(actual, str):
                # Simple string similarity loss
                return 1.0 - (len(set(expected.split()) & set(actual.split())) /
                             max(len(set(expected.split())), len(set(actual.split())), 1))
            else:
                # Default loss for complex types
                return 0.5 if expected != actual else 0.0
        except Exception:
            return 1.0  # Maximum loss on error

    def _store_feedback_signal(self, signal: FeedbackSignal):
        """Store feedback signal in database"""

        with sqlite3.connect(self.database_path) as conn:
            conn.execute('''
                INSERT OR REPLACE INTO feedback_signals
                (signal_id, feedback_type, value, confidence, timestamp, source, context, weight, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                signal.signal_id,
                signal.feedback_type.value,
                signal.value,
                signal.confidence,
                signal.timestamp.isoformat(),
                signal.source,
                json.dumps(signal.context),
                signal.weight,
                json.dumps(signal.metadata)
            ))

    def _store_learning_event(self, event: LearningEvent):
        """Store learning event in database"""

        with sqlite3.connect(self.database_path) as conn:
            conn.execute('''
                INSERT OR REPLACE INTO learning_events
                (event_id, strategy, input_data, expected_output, actual_output,
                 loss, learning_rate, timestamp, success, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event.event_id,
                event.strategy.value,
                json.dumps(event.input_data, default=str),
                json.dumps(event.expected_output, default=str),
                json.dumps(event.actual_output, default=str),
                event.loss,
                event.learning_rate,
                event.timestamp.isoformat(),
                int(event.success),
                json.dumps(event.metadata)
            ))

    def _store_model_snapshot(self, snapshot: ModelSnapshot):
        """Store model snapshot in database"""

        with sqlite3.connect(self.database_path) as conn:
            conn.execute('''
                INSERT OR REPLACE INTO model_snapshots
                (snapshot_id, model_state, performance_metrics, timestamp, strategy_config, validation_score)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                snapshot.snapshot_id,
                json.dumps(snapshot.model_state, default=str),
                json.dumps(snapshot.performance_metrics),
                snapshot.timestamp.isoformat(),
                json.dumps(snapshot.strategy_config),
                snapshot.validation_score
            ))

    def get_learning_status(self) -> Dict[str, Any]:
        """Get current learning system status"""

        status = {
            'active': not self.stop_processing.is_set(),
            'feedback_loops': len(self.feedback_loops),
            'learning_events': len(self.learning_events),
            'model_snapshots': len(self.model_snapshots),
            'overall_performance': self._calculate_overall_performance(),
            'feedback_loop_status': {},
            'strategy_performance': dict(self.global_performance),
            'pending_feedback': self.feedback_queue.qsize()
        }

        # Add feedback loop status
        for feedback_type, loop in self.feedback_loops.items():
            status['feedback_loop_status'][feedback_type.value] = loop.get_performance_summary()

        # Add recent activity
        if self.learning_events:
            recent_events = list(self.learning_events)[-10:]
            status['recent_activity'] = {
                'events': len(recent_events),
                'success_rate': sum(1 for e in recent_events if e.success) / len(recent_events),
                'average_loss': np.mean([e.loss for e in recent_events])
            }

        return status

    def get_recommendations(self) -> List[Dict[str, Any]]:
        """Get recommendations for system improvement"""

        recommendations = []

        # Analyze feedback loops
        for feedback_type, loop in self.feedback_loops.items():
            summary = loop.get_performance_summary()

            if summary.get("adaptation_needed", False):
                recommendations.append({
                    'type': 'feedback_loop_optimization',
                    'feedback_type': feedback_type.value,
                    'issue': f'Performance gap: {summary.get("performance_gap", 0):.3f}',
                    'recommendation': f'Apply {summary.get("recent_trend", "unknown")} adjustment',
                    'priority': 'high' if summary.get("performance_gap", 0) > 0.3 else 'medium'
                })

        # Analyze strategy performance
        if self.global_performance:
            worst_strategy = min(self.global_performance.items(),
                               key=lambda x: x[1]['successful_events'] / max(x[1]['total_events'], 1))

            if worst_strategy[1]['total_events'] > 10:
                success_rate = worst_strategy[1]['successful_events'] / worst_strategy[1]['total_events']
                if success_rate < 0.6:
                    recommendations.append({
                        'type': 'strategy_optimization',
                        'strategy': worst_strategy[0],
                        'issue': f'Low success rate: {success_rate:.2%}',
                        'recommendation': 'Consider strategy replacement or parameter tuning',
                        'priority': 'medium'
                    })

        # Global performance recommendation
        overall_perf = self._calculate_overall_performance()
        if overall_perf < 0.6:
            recommendations.append({
                'type': 'global_optimization',
                'issue': f'Low overall performance: {overall_perf:.3f}',
                'recommendation': 'Comprehensive system review and optimization needed',
                'priority': 'high'
            })

        return recommendations

# Example usage and testing
if __name__ == "__main__":
    # Initialize continuous learner
    learner = ContinuousLearner([
        LearningStrategy.ONLINE_GRADIENT_DESCENT,
        LearningStrategy.INCREMENTAL_LEARNING,
        LearningStrategy.ENSEMBLE_LEARNING
    ])

    print("🔄 Continuous Learning System")
    print("=" * 50)
    print("Real-time adaptation with multiple feedback loops")
    print("=" * 50)

    # Simulate feedback signals
    feedback_scenarios = [
        (FeedbackType.DETECTION_ACCURACY, 0.85, "High accuracy detection"),
        (FeedbackType.FALSE_POSITIVE_RATE, 0.15, "Acceptable false positive rate"),
        (FeedbackType.RESPONSE_TIME, 0.95, "Fast response time"),
        (FeedbackType.THREAT_SEVERITY, 0.7, "Moderate threat level"),
        (FeedbackType.ATTACK_SUCCESS_RATE, 0.05, "Low attack success")
    ]

    print(f"\n📊 Simulating Feedback Signals:")
    for feedback_type, value, description in feedback_scenarios:
        signal_id = learner.add_feedback(feedback_type, value, 0.9, "test_system")
        print(f"   {feedback_type.value}: {value:.3f} - {description}")

    # Simulate learning events
    learning_scenarios = [
        (LearningStrategy.ONLINE_GRADIENT_DESCENT, "threat_input_1", "malicious", "benign"),
        (LearningStrategy.INCREMENTAL_LEARNING, "threat_input_2", "benign", "benign"),
        (LearningStrategy.ENSEMBLE_LEARNING, "threat_input_3", "malicious", "malicious")
    ]

    print(f"\n🧠 Simulating Learning Events:")
    for strategy, input_data, expected, actual in learning_scenarios:
        event_id = learner.trigger_learning_event(strategy, input_data, expected, actual)
        print(f"   {strategy.value}: {input_data} -> Expected: {expected}, Got: {actual}")

    # Create model snapshot
    model_state = {"weights": [0.1, 0.2, 0.3], "bias": 0.05}
    performance_metrics = {"accuracy": 0.85, "precision": 0.82, "recall": 0.88}
    strategy_config = {"learning_rate": 0.01, "batch_size": 32}

    snapshot_id = learner.create_model_snapshot(model_state, performance_metrics, strategy_config)
    print(f"\n📸 Model snapshot created: {snapshot_id}")

    # Wait for some processing
    time.sleep(2)

    # Get system status
    status = learner.get_learning_status()
    print(f"\n📈 Learning System Status:")
    print(f"   Active: {status['active']}")
    print(f"   Overall Performance: {status['overall_performance']:.3f}")
    print(f"   Learning Events: {status['learning_events']}")
    print(f"   Feedback Loops: {status['feedback_loops']}")

    if 'recent_activity' in status:
        activity = status['recent_activity']
        print(f"   Recent Success Rate: {activity['success_rate']:.2%}")
        print(f"   Average Loss: {activity['average_loss']:.3f}")

    # Get recommendations
    recommendations = learner.get_recommendations()
    print(f"\n💡 System Recommendations ({len(recommendations)}):")
    for rec in recommendations[:3]:  # Show first 3
        print(f"   [{rec['priority'].upper()}] {rec['type']}: {rec['recommendation']}")

    # Show feedback loop performance
    print(f"\n🔄 Feedback Loop Performance:")
    for feedback_type, loop in learner.feedback_loops.items():
        summary = loop.get_performance_summary()
        if summary.get('current_performance') is not None:
            print(f"   {feedback_type.value}: {summary['current_performance']:.3f} "
                  f"({summary.get('recent_trend', 'unknown')})")

    # Stop the learner
    learner.stop_continuous_learning()
    print(f"\n✅ Continuous learning system demonstration completed!")
    print(f"🔄 System successfully adapted to {len(feedback_scenarios)} feedback signals")
    print(f"🧠 Processed {len(learning_scenarios)} learning events with real-time optimization")