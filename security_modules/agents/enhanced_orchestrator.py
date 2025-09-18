"""
Enhanced Security Agent Orchestrator

This module implements intelligent coordination of multiple specialized security agents:
- AI-driven planning and task distribution
- Dynamic resource allocation and agent scaling
- Cross-agent communication and data sharing
- Real-time risk synthesis and prioritization
- Adaptive orchestration strategies based on threat landscape
"""

import json
import time
import logging
import numpy as np
from typing import Dict, List, Any, Optional, Tuple, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import threading
import concurrent.futures
from collections import deque, defaultdict
import queue
import uuid
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class OrchestrationStrategy(Enum):
    """Orchestration strategies for agent coordination"""
    PARALLEL_EXECUTION = "parallel_execution"
    SEQUENTIAL_PIPELINE = "sequential_pipeline"
    ADAPTIVE_PRIORITY = "adaptive_priority"
    RISK_BASED_ALLOCATION = "risk_based_allocation"
    INTELLIGENT_SCHEDULING = "intelligent_scheduling"
    COLLABORATIVE_ANALYSIS = "collaborative_analysis"

class AgentType(Enum):
    """Types of specialized security agents"""
    AI_FUZZING = "ai_fuzzing"
    THREAT_MODELING = "threat_modeling"
    COMPLIANCE = "compliance"
    SCA = "sca"  # Software Composition Analysis
    PENETRATION_TESTING = "penetration_testing"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    INCIDENT_RESPONSE = "incident_response"

class TaskPriority(Enum):
    """Task priority levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    BACKGROUND = "background"

class AgentStatus(Enum):
    """Agent status indicators"""
    IDLE = "idle"
    BUSY = "busy"
    ERROR = "error"
    OFFLINE = "offline"
    INITIALIZING = "initializing"

@dataclass
class OrchestrationTask:
    """Represents a task for orchestration"""
    task_id: str
    task_type: str
    priority: TaskPriority
    target_agents: List[AgentType]
    input_data: Dict[str, Any]
    dependencies: List[str] = field(default_factory=list)
    timeout: float = 300.0  # 5 minutes default
    retry_count: int = 0
    max_retries: int = 3
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AgentResult:
    """Result from an agent execution"""
    agent_type: AgentType
    task_id: str
    success: bool
    result_data: Dict[str, Any]
    execution_time: float
    confidence: float
    risk_score: float
    recommendations: List[str]
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AgentMetrics:
    """Performance metrics for an agent"""
    agent_type: AgentType
    total_tasks: int = 0
    successful_tasks: int = 0
    failed_tasks: int = 0
    average_execution_time: float = 0.0
    average_confidence: float = 0.0
    last_activity: Optional[datetime] = None
    resource_usage: Dict[str, float] = field(default_factory=dict)

class SecurityAgent:
    """Base class for all security agents"""

    def __init__(self, agent_type: AgentType, config: Dict[str, Any] = None):
        self.agent_type = agent_type
        self.config = config or {}
        self.status = AgentStatus.INITIALIZING
        self.metrics = AgentMetrics(agent_type)
        self.task_queue = queue.Queue()
        self.result_callbacks = []

        # Initialize agent
        self._initialize_agent()
        self.status = AgentStatus.IDLE

    def _initialize_agent(self):
        """Initialize agent-specific components"""
        pass  # Override in subclasses

    def execute_task(self, task: OrchestrationTask) -> AgentResult:
        """Execute a task and return results"""
        start_time = time.time()
        self.status = AgentStatus.BUSY
        self.metrics.last_activity = datetime.now()

        try:
            # Execute agent-specific logic
            result_data = self._execute_logic(task)

            # Calculate metrics
            execution_time = time.time() - start_time
            confidence = self._calculate_confidence(task, result_data)
            risk_score = self._calculate_risk_score(task, result_data)
            recommendations = self._generate_recommendations(task, result_data)

            # Create result
            result = AgentResult(
                agent_type=self.agent_type,
                task_id=task.task_id,
                success=True,
                result_data=result_data,
                execution_time=execution_time,
                confidence=confidence,
                risk_score=risk_score,
                recommendations=recommendations
            )

            # Update metrics
            self.metrics.total_tasks += 1
            self.metrics.successful_tasks += 1
            self._update_metrics(execution_time, confidence)

            self.status = AgentStatus.IDLE
            return result

        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Agent {self.agent_type.value} failed task {task.task_id}: {e}")

            # Create error result
            result = AgentResult(
                agent_type=self.agent_type,
                task_id=task.task_id,
                success=False,
                result_data={"error": str(e)},
                execution_time=execution_time,
                confidence=0.0,
                risk_score=1.0,  # High risk due to failure
                recommendations=["Investigate agent failure", "Check system resources"]
            )

            # Update metrics
            self.metrics.total_tasks += 1
            self.metrics.failed_tasks += 1
            self._update_metrics(execution_time, 0.0)

            self.status = AgentStatus.ERROR
            return result

    def _execute_logic(self, task: OrchestrationTask) -> Dict[str, Any]:
        """Execute agent-specific logic - override in subclasses"""
        return {"message": f"Base agent executed task {task.task_id}"}

    def _calculate_confidence(self, task: OrchestrationTask, result_data: Dict[str, Any]) -> float:
        """Calculate confidence in the result"""
        return 0.8  # Default confidence - override in subclasses

    def _calculate_risk_score(self, task: OrchestrationTask, result_data: Dict[str, Any]) -> float:
        """Calculate risk score from the result"""
        return 0.5  # Default risk - override in subclasses

    def _generate_recommendations(self, task: OrchestrationTask, result_data: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on results"""
        return ["Standard security measures recommended"]

    def _update_metrics(self, execution_time: float, confidence: float):
        """Update agent performance metrics"""
        # Update average execution time
        total_tasks = self.metrics.total_tasks
        if total_tasks > 1:
            self.metrics.average_execution_time = (
                (self.metrics.average_execution_time * (total_tasks - 1) + execution_time) / total_tasks
            )
        else:
            self.metrics.average_execution_time = execution_time

        # Update average confidence
        successful_tasks = self.metrics.successful_tasks
        if successful_tasks > 1:
            self.metrics.average_confidence = (
                (self.metrics.average_confidence * (successful_tasks - 1) + confidence) / successful_tasks
            )
        else:
            self.metrics.average_confidence = confidence

    def get_status(self) -> Dict[str, Any]:
        """Get current agent status"""
        return {
            "agent_type": self.agent_type.value,
            "status": self.status.value,
            "metrics": {
                "total_tasks": self.metrics.total_tasks,
                "success_rate": (self.metrics.successful_tasks / max(self.metrics.total_tasks, 1)),
                "average_execution_time": self.metrics.average_execution_time,
                "average_confidence": self.metrics.average_confidence,
                "last_activity": self.metrics.last_activity.isoformat() if self.metrics.last_activity else None
            },
            "queue_size": self.task_queue.qsize()
        }

class TaskScheduler:
    """Intelligent task scheduler for agent orchestration"""

    def __init__(self):
        self.pending_tasks = []
        self.running_tasks = {}
        self.completed_tasks = deque(maxlen=1000)
        self.scheduling_history = deque(maxlen=500)

    def add_task(self, task: OrchestrationTask):
        """Add task to scheduling queue"""
        self.pending_tasks.append(task)
        self._sort_tasks_by_priority()
        logger.info(f"Task {task.task_id} added to scheduler ({task.priority.value} priority)")

    def _sort_tasks_by_priority(self):
        """Sort tasks by priority and creation time"""
        priority_values = {
            TaskPriority.CRITICAL: 0,
            TaskPriority.HIGH: 1,
            TaskPriority.MEDIUM: 2,
            TaskPriority.LOW: 3,
            TaskPriority.BACKGROUND: 4
        }

        self.pending_tasks.sort(
            key=lambda t: (priority_values.get(t.priority, 5), t.created_at)
        )

    def get_next_task(self, agent_capabilities: List[AgentType]) -> Optional[OrchestrationTask]:
        """Get next task for available agent"""
        for i, task in enumerate(self.pending_tasks):
            # Check if any target agent matches capabilities
            if any(agent_type in agent_capabilities for agent_type in task.target_agents):
                # Check dependencies
                if self._check_dependencies(task):
                    return self.pending_tasks.pop(i)

        return None

    def _check_dependencies(self, task: OrchestrationTask) -> bool:
        """Check if task dependencies are satisfied"""
        for dep_task_id in task.dependencies:
            if not any(completed.task_id == dep_task_id for completed in self.completed_tasks):
                return False
        return True

    def mark_task_running(self, task: OrchestrationTask, agent_type: AgentType):
        """Mark task as running"""
        self.running_tasks[task.task_id] = {
            'task': task,
            'agent_type': agent_type,
            'start_time': datetime.now()
        }

    def mark_task_completed(self, task_id: str, result: AgentResult):
        """Mark task as completed"""
        if task_id in self.running_tasks:
            running_info = self.running_tasks.pop(task_id)
            execution_time = (datetime.now() - running_info['start_time']).total_seconds()

            completed_task = {
                'task_id': task_id,
                'result': result,
                'execution_time': execution_time,
                'completed_at': datetime.now()
            }

            self.completed_tasks.append(completed_task)

            # Update scheduling history
            self.scheduling_history.append({
                'task_id': task_id,
                'agent_type': result.agent_type.value,
                'success': result.success,
                'execution_time': execution_time,
                'scheduled_at': running_info['start_time']
            })

            logger.info(f"Task {task_id} completed by {result.agent_type.value} in {execution_time:.2f}s")

    def get_scheduling_stats(self) -> Dict[str, Any]:
        """Get scheduling statistics"""
        if not self.scheduling_history:
            return {"no_data": True}

        recent_history = list(self.scheduling_history)[-50:]  # Last 50 tasks

        stats = {
            "total_scheduled": len(self.scheduling_history),
            "pending_tasks": len(self.pending_tasks),
            "running_tasks": len(self.running_tasks),
            "completed_tasks": len(self.completed_tasks),
            "recent_success_rate": sum(1 for h in recent_history if h['success']) / len(recent_history),
            "average_execution_time": np.mean([h['execution_time'] for h in recent_history]),
            "agent_utilization": self._calculate_agent_utilization(recent_history)
        }

        return stats

    def _calculate_agent_utilization(self, history: List[Dict]) -> Dict[str, float]:
        """Calculate utilization by agent type"""
        agent_counts = defaultdict(int)
        for entry in history:
            agent_counts[entry['agent_type']] += 1

        total_tasks = len(history)
        return {agent: count / total_tasks for agent, count in agent_counts.items()} if total_tasks > 0 else {}

class RiskSynthesizer:
    """Synthesizes risk assessments from multiple agents"""

    def __init__(self):
        self.risk_models = self._initialize_risk_models()
        self.synthesis_history = deque(maxlen=500)

    def _initialize_risk_models(self) -> Dict[str, Dict[str, float]]:
        """Initialize risk weighting models for different agent types"""
        return {
            AgentType.AI_FUZZING.value: {
                "weight": 0.25,
                "confidence_threshold": 0.7,
                "risk_multiplier": 1.2
            },
            AgentType.THREAT_MODELING.value: {
                "weight": 0.30,
                "confidence_threshold": 0.8,
                "risk_multiplier": 1.3
            },
            AgentType.COMPLIANCE.value: {
                "weight": 0.15,
                "confidence_threshold": 0.9,
                "risk_multiplier": 0.8
            },
            AgentType.SCA.value: {
                "weight": 0.20,
                "confidence_threshold": 0.8,
                "risk_multiplier": 1.1
            },
            AgentType.VULNERABILITY_ASSESSMENT.value: {
                "weight": 0.35,
                "confidence_threshold": 0.8,
                "risk_multiplier": 1.4
            }
        }

    def synthesize_risks(self, results: List[AgentResult]) -> Dict[str, Any]:
        """Synthesize risk assessments from multiple agent results"""
        if not results:
            return {"overall_risk": 0.0, "confidence": 0.0, "synthesis_method": "no_data"}

        # Filter successful results
        valid_results = [r for r in results if r.success and r.confidence > 0.5]

        if not valid_results:
            return {"overall_risk": 0.5, "confidence": 0.1, "synthesis_method": "insufficient_data"}

        # Calculate weighted risk score
        weighted_risks = []
        weights = []
        confidences = []

        for result in valid_results:
            agent_model = self.risk_models.get(result.agent_type.value, {})
            base_weight = agent_model.get("weight", 0.2)
            confidence_threshold = agent_model.get("confidence_threshold", 0.7)
            risk_multiplier = agent_model.get("risk_multiplier", 1.0)

            # Adjust weight based on confidence
            if result.confidence >= confidence_threshold:
                adjusted_weight = base_weight * (1.0 + (result.confidence - confidence_threshold))
            else:
                adjusted_weight = base_weight * result.confidence

            # Apply risk multiplier
            adjusted_risk = result.risk_score * risk_multiplier

            weighted_risks.append(adjusted_risk)
            weights.append(adjusted_weight)
            confidences.append(result.confidence)

        # Calculate overall risk
        if weights and sum(weights) > 0:
            overall_risk = np.average(weighted_risks, weights=weights)
            overall_confidence = np.mean(confidences)
        else:
            overall_risk = np.mean(weighted_risks)
            overall_confidence = np.mean(confidences)

        # Apply ensemble adjustments
        risk_variance = np.var(weighted_risks)
        if risk_variance > 0.2:  # High variance indicates disagreement
            overall_confidence *= 0.8  # Reduce confidence

        # Detect risk consensus
        high_risk_count = sum(1 for r in weighted_risks if r > 0.7)
        low_risk_count = sum(1 for r in weighted_risks if r < 0.3)

        synthesis_method = "weighted_ensemble"
        if high_risk_count >= len(weighted_risks) * 0.8:
            synthesis_method = "high_risk_consensus"
            overall_risk = min(1.0, overall_risk * 1.1)  # Boost for consensus
        elif low_risk_count >= len(weighted_risks) * 0.8:
            synthesis_method = "low_risk_consensus"
            overall_risk = max(0.0, overall_risk * 0.9)  # Reduce for consensus

        # Generate risk factors
        risk_factors = self._extract_risk_factors(valid_results)
        recommendations = self._generate_synthesis_recommendations(overall_risk, valid_results)

        synthesis_result = {
            "overall_risk": float(np.clip(overall_risk, 0.0, 1.0)),
            "confidence": float(np.clip(overall_confidence, 0.0, 1.0)),
            "synthesis_method": synthesis_method,
            "agent_count": len(valid_results),
            "risk_variance": float(risk_variance),
            "risk_factors": risk_factors,
            "recommendations": recommendations,
            "agent_contributions": [
                {
                    "agent_type": r.agent_type.value,
                    "risk_score": r.risk_score,
                    "confidence": r.confidence,
                    "weight": self.risk_models.get(r.agent_type.value, {}).get("weight", 0.2)
                }
                for r in valid_results
            ]
        }

        # Store synthesis history
        self.synthesis_history.append({
            "timestamp": datetime.now(),
            "result": synthesis_result,
            "input_count": len(results)
        })

        return synthesis_result

    def _extract_risk_factors(self, results: List[AgentResult]) -> List[str]:
        """Extract common risk factors from agent results"""
        risk_factors = set()

        for result in results:
            # Extract risk indicators from result data
            result_data = result.result_data

            if result.risk_score > 0.7:
                risk_factors.add(f"High risk detected by {result.agent_type.value}")

            # Look for specific risk indicators in result data
            if isinstance(result_data, dict):
                if result_data.get("vulnerabilities"):
                    risk_factors.add("Vulnerabilities identified")
                if result_data.get("compliance_failures"):
                    risk_factors.add("Compliance failures detected")
                if result_data.get("threat_indicators"):
                    risk_factors.add("Threat indicators present")
                if result_data.get("anomalies"):
                    risk_factors.add("Behavioral anomalies detected")

        return list(risk_factors)

    def _generate_synthesis_recommendations(self, overall_risk: float,
                                          results: List[AgentResult]) -> List[str]:
        """Generate recommendations based on synthesized risk"""
        recommendations = []

        # Risk-based recommendations
        if overall_risk > 0.8:
            recommendations.extend([
                "Immediate security intervention required",
                "Escalate to security incident response team",
                "Implement emergency containment measures"
            ])
        elif overall_risk > 0.6:
            recommendations.extend([
                "Enhanced monitoring recommended",
                "Review and strengthen security controls",
                "Conduct detailed risk assessment"
            ])
        elif overall_risk > 0.4:
            recommendations.extend([
                "Standard security measures sufficient",
                "Continue regular monitoring",
                "Consider preventive measures"
            ])
        else:
            recommendations.extend([
                "Low risk profile maintained",
                "Maintain current security posture"
            ])

        # Agent-specific recommendations
        for result in results:
            if result.recommendations:
                recommendations.extend([
                    f"{result.agent_type.value}: {rec}" for rec in result.recommendations[:2]
                ])

        return list(set(recommendations))  # Remove duplicates

class EnhancedSecurityAgentOrchestrator:
    """Main orchestrator for coordinating multiple security agents"""

    def __init__(self, orchestration_strategy: OrchestrationStrategy = OrchestrationStrategy.ADAPTIVE_PRIORITY):
        self.orchestration_strategy = orchestration_strategy
        self.agents = {}
        self.task_scheduler = TaskScheduler()
        self.risk_synthesizer = RiskSynthesizer()

        # Processing infrastructure
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)
        self.task_queue = queue.Queue()
        self.result_queue = queue.Queue()

        # State management
        self.active_orchestrations = {}
        self.orchestration_history = deque(maxlen=1000)

        # Control flags
        self.running = False
        self.processing_thread = None

        logger.info(f"Enhanced Security Agent Orchestrator initialized with {orchestration_strategy.value} strategy")

    def register_agent(self, agent: SecurityAgent):
        """Register a security agent with the orchestrator"""
        self.agents[agent.agent_type] = agent
        logger.info(f"Registered {agent.agent_type.value} agent")

    def create_orchestration(self, target: str, orchestration_type: str,
                           agents: List[AgentType] = None,
                           priority: TaskPriority = TaskPriority.MEDIUM,
                           config: Dict[str, Any] = None) -> str:
        """Create a new security orchestration"""

        orchestration_id = f"orch_{int(time.time())}_{uuid.uuid4().hex[:8]}"

        # Determine agents to use
        if agents is None:
            agents = list(self.agents.keys())
        else:
            # Filter to only available agents
            agents = [agent_type for agent_type in agents if agent_type in self.agents]

        if not agents:
            raise ValueError("No suitable agents available for orchestration")

        # Create tasks for each agent
        tasks = []
        for agent_type in agents:
            task = OrchestrationTask(
                task_id=f"{orchestration_id}_{agent_type.value}",
                task_type=orchestration_type,
                priority=priority,
                target_agents=[agent_type],
                input_data={
                    "target": target,
                    "orchestration_id": orchestration_id,
                    "config": config or {}
                }
            )
            tasks.append(task)
            self.task_scheduler.add_task(task)

        # Store orchestration
        self.active_orchestrations[orchestration_id] = {
            "id": orchestration_id,
            "target": target,
            "type": orchestration_type,
            "agents": agents,
            "tasks": [t.task_id for t in tasks],
            "priority": priority,
            "created_at": datetime.now(),
            "status": "pending",
            "results": {},
            "config": config or {}
        }

        logger.info(f"Created orchestration {orchestration_id} with {len(agents)} agents")
        return orchestration_id

    def start_orchestration(self):
        """Start the orchestration processing"""
        if self.running:
            return

        self.running = True
        self.processing_thread = threading.Thread(target=self._orchestration_loop)
        self.processing_thread.daemon = True
        self.processing_thread.start()

        logger.info("Orchestration processing started")

    def stop_orchestration(self):
        """Stop the orchestration processing"""
        self.running = False

        if self.processing_thread:
            self.processing_thread.join(timeout=5)

        logger.info("Orchestration processing stopped")

    def _orchestration_loop(self):
        """Main orchestration processing loop"""
        while self.running:
            try:
                # Process tasks based on strategy
                if self.orchestration_strategy == OrchestrationStrategy.PARALLEL_EXECUTION:
                    self._process_parallel_execution()
                elif self.orchestration_strategy == OrchestrationStrategy.SEQUENTIAL_PIPELINE:
                    self._process_sequential_pipeline()
                elif self.orchestration_strategy == OrchestrationStrategy.ADAPTIVE_PRIORITY:
                    self._process_adaptive_priority()
                elif self.orchestration_strategy == OrchestrationStrategy.RISK_BASED_ALLOCATION:
                    self._process_risk_based_allocation()
                else:
                    self._process_intelligent_scheduling()

                # Process completed tasks
                self._process_completed_tasks()

                # Small delay to prevent busy waiting
                time.sleep(0.1)

            except Exception as e:
                logger.error(f"Error in orchestration loop: {e}")
                time.sleep(1)

    def _process_parallel_execution(self):
        """Process tasks in parallel execution mode"""
        # Get available agents
        available_agents = [
            agent_type for agent_type, agent in self.agents.items()
            if agent.status == AgentStatus.IDLE
        ]

        # Assign tasks to available agents
        for agent_type in available_agents:
            task = self.task_scheduler.get_next_task([agent_type])
            if task:
                self._execute_task_async(task, agent_type)

    def _process_adaptive_priority(self):
        """Process tasks with adaptive priority adjustment"""
        # Get all available agents
        available_agents = [
            agent_type for agent_type, agent in self.agents.items()
            if agent.status == AgentStatus.IDLE
        ]

        if not available_agents:
            return

        # Get highest priority task that can be executed
        task = self.task_scheduler.get_next_task(available_agents)
        if task:
            # Select best agent for the task
            best_agent = self._select_best_agent(task, available_agents)
            self._execute_task_async(task, best_agent)

    def _process_intelligent_scheduling(self):
        """Process tasks with intelligent scheduling"""
        # This would implement more sophisticated scheduling algorithms
        # For now, fallback to adaptive priority
        self._process_adaptive_priority()

    def _process_sequential_pipeline(self):
        """Process tasks in sequential pipeline mode"""
        # Implementation for sequential processing
        self._process_adaptive_priority()  # Fallback for now

    def _process_risk_based_allocation(self):
        """Process tasks based on risk assessment"""
        # Implementation for risk-based allocation
        self._process_adaptive_priority()  # Fallback for now

    def _select_best_agent(self, task: OrchestrationTask, available_agents: List[AgentType]) -> AgentType:
        """Select the best agent for a task based on performance metrics"""

        # Filter to target agents
        suitable_agents = [a for a in available_agents if a in task.target_agents]

        if not suitable_agents:
            return available_agents[0]  # Fallback

        if len(suitable_agents) == 1:
            return suitable_agents[0]

        # Select based on performance metrics
        best_agent = suitable_agents[0]
        best_score = 0.0

        for agent_type in suitable_agents:
            agent = self.agents[agent_type]
            metrics = agent.metrics

            # Calculate agent score based on success rate and speed
            success_rate = metrics.successful_tasks / max(metrics.total_tasks, 1)
            speed_score = 1.0 / max(metrics.average_execution_time, 0.1)  # Invert time
            confidence_score = metrics.average_confidence

            # Combined score
            agent_score = (success_rate * 0.5 + speed_score * 0.3 + confidence_score * 0.2)

            if agent_score > best_score:
                best_score = agent_score
                best_agent = agent_type

        return best_agent

    def _execute_task_async(self, task: OrchestrationTask, agent_type: AgentType):
        """Execute task asynchronously"""
        agent = self.agents[agent_type]

        # Mark task as running
        self.task_scheduler.mark_task_running(task, agent_type)

        # Submit task to executor
        future = self.executor.submit(agent.execute_task, task)

        # Add callback for result processing
        future.add_done_callback(lambda f: self._handle_task_completion(f, task.task_id))

    def _handle_task_completion(self, future: concurrent.futures.Future, task_id: str):
        """Handle completion of an async task"""
        try:
            result = future.result()
            self.result_queue.put((task_id, result))
        except Exception as e:
            logger.error(f"Task {task_id} failed with exception: {e}")
            # Create error result
            error_result = AgentResult(
                agent_type=AgentType.AI_FUZZING,  # Default type for errors
                task_id=task_id,
                success=False,
                result_data={"error": str(e)},
                execution_time=0.0,
                confidence=0.0,
                risk_score=1.0,
                recommendations=["Investigate task failure"]
            )
            self.result_queue.put((task_id, error_result))

    def _process_completed_tasks(self):
        """Process completed tasks and update orchestrations"""
        while not self.result_queue.empty():
            try:
                task_id, result = self.result_queue.get_nowait()

                # Mark task as completed in scheduler
                self.task_scheduler.mark_task_completed(task_id, result)

                # Update orchestration
                self._update_orchestration_with_result(task_id, result)

            except queue.Empty:
                break
            except Exception as e:
                logger.error(f"Error processing completed task: {e}")

    def _update_orchestration_with_result(self, task_id: str, result: AgentResult):
        """Update orchestration with task result"""
        # Find orchestration containing this task
        orchestration_id = None
        for orch_id, orch_data in self.active_orchestrations.items():
            if task_id in orch_data["tasks"]:
                orchestration_id = orch_id
                break

        if not orchestration_id:
            logger.warning(f"Could not find orchestration for task {task_id}")
            return

        orchestration = self.active_orchestrations[orchestration_id]
        orchestration["results"][task_id] = result

        # Check if orchestration is complete
        completed_tasks = len(orchestration["results"])
        total_tasks = len(orchestration["tasks"])

        if completed_tasks == total_tasks:
            self._finalize_orchestration(orchestration_id)

    def _finalize_orchestration(self, orchestration_id: str):
        """Finalize completed orchestration"""
        orchestration = self.active_orchestrations[orchestration_id]
        results = list(orchestration["results"].values())

        # Synthesize risk assessment
        risk_synthesis = self.risk_synthesizer.synthesize_risks(results)

        # Generate final report
        final_report = {
            "orchestration_id": orchestration_id,
            "target": orchestration["target"],
            "type": orchestration["type"],
            "agents_used": [agent.value for agent in orchestration["agents"]],
            "completed_at": datetime.now(),
            "execution_time": (datetime.now() - orchestration["created_at"]).total_seconds(),
            "agent_results": [
                {
                    "agent_type": r.agent_type.value,
                    "success": r.success,
                    "risk_score": r.risk_score,
                    "confidence": r.confidence,
                    "execution_time": r.execution_time,
                    "recommendations": r.recommendations
                }
                for r in results
            ],
            "risk_synthesis": risk_synthesis,
            "overall_success": all(r.success for r in results),
            "recommendations": self._generate_orchestration_recommendations(results, risk_synthesis)
        }

        # Move to history
        self.orchestration_history.append(final_report)
        del self.active_orchestrations[orchestration_id]

        logger.info(f"Orchestration {orchestration_id} completed - Overall risk: {risk_synthesis['overall_risk']:.3f}")

    def _generate_orchestration_recommendations(self, results: List[AgentResult],
                                              risk_synthesis: Dict[str, Any]) -> List[str]:
        """Generate final recommendations for the orchestration"""
        recommendations = []

        # Add synthesis recommendations
        recommendations.extend(risk_synthesis.get("recommendations", []))

        # Add high-priority agent recommendations
        for result in results:
            if result.risk_score > 0.7 and result.recommendations:
                recommendations.extend(result.recommendations[:1])  # Top recommendation

        # Remove duplicates and limit
        unique_recommendations = list(dict.fromkeys(recommendations))
        return unique_recommendations[:10]  # Limit to top 10

    def get_orchestration_status(self, orchestration_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific orchestration"""
        if orchestration_id in self.active_orchestrations:
            orch = self.active_orchestrations[orchestration_id]
            completed_tasks = len(orch["results"])
            total_tasks = len(orch["tasks"])

            return {
                "orchestration_id": orchestration_id,
                "status": "active",
                "progress": f"{completed_tasks}/{total_tasks}",
                "completion_percentage": (completed_tasks / total_tasks) * 100,
                "created_at": orch["created_at"],
                "agents": [agent.value for agent in orch["agents"]],
                "completed_results": len(orch["results"])
            }

        # Check history
        for completed in self.orchestration_history:
            if completed["orchestration_id"] == orchestration_id:
                return {
                    "orchestration_id": orchestration_id,
                    "status": "completed",
                    "completed_at": completed["completed_at"],
                    "execution_time": completed["execution_time"],
                    "overall_success": completed["overall_success"],
                    "overall_risk": completed["risk_synthesis"]["overall_risk"],
                    "agents_used": completed["agents_used"]
                }

        return None

    def get_system_status(self) -> Dict[str, Any]:
        """Get overall system status"""
        return {
            "orchestrator_running": self.running,
            "strategy": self.orchestration_strategy.value,
            "registered_agents": len(self.agents),
            "active_orchestrations": len(self.active_orchestrations),
            "completed_orchestrations": len(self.orchestration_history),
            "agent_status": {
                agent_type.value: agent.get_status()
                for agent_type, agent in self.agents.items()
            },
            "scheduler_stats": self.task_scheduler.get_scheduling_stats(),
            "recent_performance": self._calculate_recent_performance()
        }

    def _calculate_recent_performance(self) -> Dict[str, Any]:
        """Calculate recent performance metrics"""
        if not self.orchestration_history:
            return {"no_data": True}

        recent = list(self.orchestration_history)[-20:]  # Last 20 orchestrations

        return {
            "total_recent": len(recent),
            "success_rate": sum(1 for o in recent if o["overall_success"]) / len(recent),
            "average_execution_time": np.mean([o["execution_time"] for o in recent]),
            "average_risk_score": np.mean([o["risk_synthesis"]["overall_risk"] for o in recent]),
            "most_used_agents": self._get_most_used_agents(recent)
        }

    def _get_most_used_agents(self, orchestrations: List[Dict]) -> Dict[str, int]:
        """Get most frequently used agents"""
        agent_usage = defaultdict(int)
        for orch in orchestrations:
            for agent in orch["agents_used"]:
                agent_usage[agent] += 1
        return dict(agent_usage)

# Example usage and testing
if __name__ == "__main__":
    # Create orchestrator
    orchestrator = EnhancedSecurityAgentOrchestrator(OrchestrationStrategy.ADAPTIVE_PRIORITY)

    # Create and register mock agents
    ai_fuzzing_agent = SecurityAgent(AgentType.AI_FUZZING)
    threat_modeling_agent = SecurityAgent(AgentType.THREAT_MODELING)
    compliance_agent = SecurityAgent(AgentType.COMPLIANCE)
    sca_agent = SecurityAgent(AgentType.SCA)

    orchestrator.register_agent(ai_fuzzing_agent)
    orchestrator.register_agent(threat_modeling_agent)
    orchestrator.register_agent(compliance_agent)
    orchestrator.register_agent(sca_agent)

    print("🎭 Enhanced Security Agent Orchestrator")
    print("=" * 50)
    print("Intelligent coordination of specialized security agents")
    print("=" * 50)

    # Start orchestration
    orchestrator.start_orchestration()

    # Create test orchestrations
    orchestration_id = orchestrator.create_orchestration(
        target="test_application",
        orchestration_type="comprehensive_security_assessment",
        agents=[AgentType.AI_FUZZING, AgentType.THREAT_MODELING, AgentType.SCA],
        priority=TaskPriority.HIGH
    )

    print(f"\n🚀 Created orchestration: {orchestration_id}")

    # Wait for processing
    time.sleep(3)

    # Check status
    status = orchestrator.get_orchestration_status(orchestration_id)
    if status:
        print(f"\n📊 Orchestration Status:")
        print(f"   Status: {status['status']}")
        print(f"   Progress: {status.get('progress', 'N/A')}")
        if 'completion_percentage' in status:
            print(f"   Completion: {status['completion_percentage']:.1f}%")

    # Get system status
    system_status = orchestrator.get_system_status()
    print(f"\n🖥️  System Status:")
    print(f"   Running: {system_status['orchestrator_running']}")
    print(f"   Strategy: {system_status['strategy']}")
    print(f"   Agents: {system_status['registered_agents']}")
    print(f"   Active: {system_status['active_orchestrations']}")
    print(f"   Completed: {system_status['completed_orchestrations']}")

    # Show agent performance
    print(f"\n🤖 Agent Performance:")
    for agent_type, agent_status in system_status['agent_status'].items():
        metrics = agent_status['metrics']
        print(f"   {agent_type}: {metrics['success_rate']:.2%} success, "
              f"{metrics['average_execution_time']:.2f}s avg time")

    # Wait for completion
    time.sleep(5)

    # Check final status
    final_status = orchestrator.get_orchestration_status(orchestration_id)
    if final_status and final_status['status'] == 'completed':
        print(f"\n✅ Orchestration completed successfully!")
        print(f"   Execution time: {final_status['execution_time']:.2f}s")
        print(f"   Overall success: {final_status['overall_success']}")
        print(f"   Risk score: {final_status['overall_risk']:.3f}")

    # Stop orchestrator
    orchestrator.stop_orchestration()
    print(f"\n🔄 Orchestrator demonstration completed!")
    print(f"🎯 Successfully coordinated {len(orchestrator.agents)} specialized agents")