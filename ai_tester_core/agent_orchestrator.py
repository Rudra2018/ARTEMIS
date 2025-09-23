"""
Agentic AI Orchestrator for Modular Security Testing
====================================================

This module implements the core orchestration system for specialized AI agents
that handle different aspects of security testing with machine learning integration.
"""

import asyncio
import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
import pickle
import numpy as np

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class AgentTask:
    """Represents a task for an agent to execute"""
    task_id: str
    agent_type: str
    target: str
    parameters: Dict[str, Any]
    priority: int = 1
    dependencies: List[str] = None
    created_at: datetime = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.dependencies is None:
            self.dependencies = []

@dataclass
class AgentResult:
    """Represents the result from an agent execution"""
    task_id: str
    agent_type: str
    success: bool
    data: Dict[str, Any]
    execution_time: float
    confidence_score: float
    findings: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    completed_at: datetime = None

    def __post_init__(self):
        if self.completed_at is None:
            self.completed_at = datetime.now()

class BaseAgent(ABC):
    """Base class for all specialized security agents"""

    def __init__(self, agent_id: str, config: Dict[str, Any] = None):
        self.agent_id = agent_id
        self.config = config or {}
        self.execution_history = []
        self.learning_data = []

    @abstractmethod
    async def execute_task(self, task: AgentTask) -> AgentResult:
        """Execute a specific task"""
        pass

    @abstractmethod
    def get_capabilities(self) -> List[str]:
        """Return list of capabilities this agent provides"""
        pass

    def record_execution(self, task: AgentTask, result: AgentResult):
        """Record execution for learning purposes"""
        execution_record = {
            'timestamp': datetime.now().isoformat(),
            'task': asdict(task),
            'result': asdict(result),
            'performance_metrics': {
                'execution_time': result.execution_time,
                'confidence_score': result.confidence_score,
                'success_rate': len([r for r in self.execution_history if r['result']['success']]) / max(len(self.execution_history), 1)
            }
        }
        self.execution_history.append(execution_record)
        self.learning_data.append(execution_record)

class AgentOrchestrator:
    """Main orchestrator for managing and coordinating AI agents"""

    def __init__(self, config_path: Optional[str] = None):
        self.agents: Dict[str, BaseAgent] = {}
        self.task_queue: List[AgentTask] = []
        self.completed_tasks: Dict[str, AgentResult] = {}
        self.active_tasks: Dict[str, AgentTask] = {}
        self.learning_engine = None
        self.knowledge_base = {}

        # Load configuration
        self.config = self._load_config(config_path)

        # Initialize learning engine
        self._initialize_learning_engine()

        # Setup directories
        self._setup_directories()

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load orchestrator configuration"""
        default_config = {
            'max_concurrent_agents': 10,
            'task_timeout': 300,
            'learning_enabled': True,
            'auto_improvement': True,
            'knowledge_base_path': 'ai_tester_core/knowledge_base',
            'learning_data_path': 'ai_tester_core/learning_data',
            'models_path': 'ml_models/agent_models'
        }

        if config_path and Path(config_path).exists():
            try:
                with open(config_path, 'r') as f:
                    loaded_config = json.load(f)
                default_config.update(loaded_config)
            except Exception as e:
                logger.warning(f"Failed to load config from {config_path}: {e}")

        return default_config

    def _setup_directories(self):
        """Setup required directories for the orchestrator"""
        directories = [
            self.config['knowledge_base_path'],
            self.config['learning_data_path'],
            self.config['models_path']
        ]

        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)

    def _initialize_learning_engine(self):
        """Initialize the machine learning engine for continuous improvement"""
        from .learning_engine import AdaptiveLearningEngine
        self.learning_engine = AdaptiveLearningEngine(
            models_path=self.config['models_path'],
            learning_data_path=self.config['learning_data_path']
        )

    def register_agent(self, agent: BaseAgent):
        """Register a new agent with the orchestrator"""
        self.agents[agent.agent_id] = agent
        logger.info(f"Registered agent: {agent.agent_id} with capabilities: {agent.get_capabilities()}")

    def unregister_agent(self, agent_id: str):
        """Unregister an agent"""
        if agent_id in self.agents:
            del self.agents[agent_id]
            logger.info(f"Unregistered agent: {agent_id}")

    async def submit_task(self, task: AgentTask) -> str:
        """Submit a task to the orchestrator"""
        # Validate task
        if not self._validate_task(task):
            raise ValueError(f"Invalid task: {task.task_id}")

        # Check dependencies
        if not self._check_dependencies(task):
            logger.info(f"Task {task.task_id} waiting for dependencies: {task.dependencies}")

        # Add to queue
        self.task_queue.append(task)
        logger.info(f"Task {task.task_id} submitted for agent type: {task.agent_type}")

        return task.task_id

    async def execute_pipeline(self, pipeline_config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a complete security testing pipeline"""
        pipeline_id = pipeline_config.get('pipeline_id', f"pipeline_{int(time.time())}")
        logger.info(f"Starting pipeline execution: {pipeline_id}")

        pipeline_results = {
            'pipeline_id': pipeline_id,
            'started_at': datetime.now().isoformat(),
            'tasks': [],
            'overall_status': 'running'
        }

        try:
            # Create tasks from pipeline configuration
            tasks = self._create_pipeline_tasks(pipeline_config)

            # Submit all tasks
            task_ids = []
            for task in tasks:
                task_id = await self.submit_task(task)
                task_ids.append(task_id)

            # Execute tasks with dependency management
            await self._execute_task_queue()

            # Collect results
            for task_id in task_ids:
                if task_id in self.completed_tasks:
                    pipeline_results['tasks'].append(asdict(self.completed_tasks[task_id]))

            pipeline_results['overall_status'] = 'completed'
            pipeline_results['completed_at'] = datetime.now().isoformat()

            # Learn from pipeline execution
            if self.config['learning_enabled']:
                await self._learn_from_pipeline(pipeline_results)

        except Exception as e:
            pipeline_results['overall_status'] = 'failed'
            pipeline_results['error'] = str(e)
            logger.error(f"Pipeline {pipeline_id} failed: {e}")

        return pipeline_results

    async def _execute_task_queue(self):
        """Execute tasks in the queue with proper dependency management"""
        while self.task_queue or self.active_tasks:
            # Find tasks ready to execute (no pending dependencies)
            ready_tasks = [
                task for task in self.task_queue
                if self._check_dependencies(task)
            ]

            if not ready_tasks and self.active_tasks:
                # Wait for active tasks to complete
                await asyncio.sleep(0.1)
                continue

            # Limit concurrent executions
            available_slots = self.config['max_concurrent_agents'] - len(self.active_tasks)
            tasks_to_execute = ready_tasks[:available_slots]

            # Execute tasks concurrently
            if tasks_to_execute:
                await asyncio.gather(*[
                    self._execute_single_task(task) for task in tasks_to_execute
                ])

            # Remove completed tasks from queue
            for task in tasks_to_execute:
                if task in self.task_queue:
                    self.task_queue.remove(task)

    async def _execute_single_task(self, task: AgentTask):
        """Execute a single task"""
        # Find appropriate agent
        agent = self._find_agent_for_task(task)
        if not agent:
            logger.error(f"No suitable agent found for task {task.task_id}")
            return

        # Mark as active
        self.active_tasks[task.task_id] = task

        try:
            # Execute task with timeout
            start_time = time.time()
            result = await asyncio.wait_for(
                agent.execute_task(task),
                timeout=self.config['task_timeout']
            )

            # Record execution
            agent.record_execution(task, result)
            self.completed_tasks[task.task_id] = result

            logger.info(f"Task {task.task_id} completed successfully in {result.execution_time:.2f}s")

        except asyncio.TimeoutError:
            logger.error(f"Task {task.task_id} timed out")
            result = AgentResult(
                task_id=task.task_id,
                agent_type=task.agent_type,
                success=False,
                data={'error': 'Task timeout'},
                execution_time=self.config['task_timeout'],
                confidence_score=0.0,
                findings=[],
                metadata={'timeout': True}
            )
            self.completed_tasks[task.task_id] = result

        except Exception as e:
            logger.error(f"Task {task.task_id} failed: {e}")
            result = AgentResult(
                task_id=task.task_id,
                agent_type=task.agent_type,
                success=False,
                data={'error': str(e)},
                execution_time=time.time() - start_time,
                confidence_score=0.0,
                findings=[],
                metadata={'exception': str(e)}
            )
            self.completed_tasks[task.task_id] = result

        finally:
            # Remove from active tasks
            if task.task_id in self.active_tasks:
                del self.active_tasks[task.task_id]

    def _find_agent_for_task(self, task: AgentTask) -> Optional[BaseAgent]:
        """Find the most suitable agent for a task"""
        suitable_agents = [
            agent for agent in self.agents.values()
            if task.agent_type in agent.get_capabilities()
        ]

        if not suitable_agents:
            return None

        # Use learning engine to select best agent if available
        if self.learning_engine and len(suitable_agents) > 1:
            return self.learning_engine.select_best_agent(suitable_agents, task)

        # Return first suitable agent
        return suitable_agents[0]

    def _validate_task(self, task: AgentTask) -> bool:
        """Validate task before submission"""
        if not task.task_id or not task.agent_type:
            return False

        # Check if any agent can handle this task type
        capable_agents = [
            agent for agent in self.agents.values()
            if task.agent_type in agent.get_capabilities()
        ]

        return len(capable_agents) > 0

    def _check_dependencies(self, task: AgentTask) -> bool:
        """Check if task dependencies are satisfied"""
        for dep_id in task.dependencies:
            if dep_id not in self.completed_tasks:
                return False
            if not self.completed_tasks[dep_id].success:
                return False
        return True

    def _create_pipeline_tasks(self, pipeline_config: Dict[str, Any]) -> List[AgentTask]:
        """Create tasks from pipeline configuration"""
        tasks = []

        for i, stage in enumerate(pipeline_config.get('stages', [])):
            task = AgentTask(
                task_id=f"{pipeline_config.get('pipeline_id', 'pipeline')}_{stage['name']}_{i}",
                agent_type=stage['agent_type'],
                target=pipeline_config.get('target', ''),
                parameters=stage.get('parameters', {}),
                priority=stage.get('priority', 1),
                dependencies=stage.get('dependencies', [])
            )
            tasks.append(task)

        return tasks

    async def _learn_from_pipeline(self, pipeline_results: Dict[str, Any]):
        """Learn from pipeline execution results"""
        if self.learning_engine:
            await self.learning_engine.process_pipeline_results(pipeline_results)

    def get_orchestrator_status(self) -> Dict[str, Any]:
        """Get current status of the orchestrator"""
        return {
            'active_agents': len(self.agents),
            'queued_tasks': len(self.task_queue),
            'active_tasks': len(self.active_tasks),
            'completed_tasks': len(self.completed_tasks),
            'agent_capabilities': {
                agent_id: agent.get_capabilities()
                for agent_id, agent in self.agents.items()
            }
        }

    async def shutdown(self):
        """Gracefully shutdown the orchestrator"""
        logger.info("Shutting down orchestrator...")

        # Wait for active tasks to complete
        while self.active_tasks:
            await asyncio.sleep(0.1)

        # Save learning data
        if self.learning_engine:
            await self.learning_engine.save_models()

        logger.info("Orchestrator shutdown complete")


class PipelineManager:
    """Manages predefined and custom security testing pipelines"""

    def __init__(self, orchestrator: AgentOrchestrator):
        self.orchestrator = orchestrator
        self.predefined_pipelines = self._load_predefined_pipelines()

    def _load_predefined_pipelines(self) -> Dict[str, Dict[str, Any]]:
        """Load predefined pipeline configurations"""
        return {
            'comprehensive_security_scan': {
                'name': 'Comprehensive Security Scan',
                'description': 'Full security assessment with all agent types',
                'stages': [
                    {
                        'name': 'infrastructure_recon',
                        'agent_type': 'infrastructure_agent',
                        'parameters': {'deep_scan': True},
                        'priority': 1,
                        'dependencies': []
                    },
                    {
                        'name': 'llm_security_test',
                        'agent_type': 'llm_security_agent',
                        'parameters': {'include_jailbreaking': True},
                        'priority': 2,
                        'dependencies': ['infrastructure_recon']
                    },
                    {
                        'name': 'protocol_analysis',
                        'agent_type': 'protocol_agent',
                        'parameters': {'protocol_type': 'mcp'},
                        'priority': 2,
                        'dependencies': ['infrastructure_recon']
                    },
                    {
                        'name': 'vulnerability_assessment',
                        'agent_type': 'vulnerability_agent',
                        'parameters': {'scan_type': 'comprehensive'},
                        'priority': 3,
                        'dependencies': ['llm_security_test', 'protocol_analysis']
                    },
                    {
                        'name': 'reporting',
                        'agent_type': 'reporting_agent',
                        'parameters': {'format': 'comprehensive'},
                        'priority': 4,
                        'dependencies': ['vulnerability_assessment']
                    }
                ]
            },
            'quick_security_check': {
                'name': 'Quick Security Check',
                'description': 'Fast security assessment for rapid feedback',
                'stages': [
                    {
                        'name': 'basic_recon',
                        'agent_type': 'infrastructure_agent',
                        'parameters': {'deep_scan': False},
                        'priority': 1,
                        'dependencies': []
                    },
                    {
                        'name': 'basic_llm_test',
                        'agent_type': 'llm_security_agent',
                        'parameters': {'include_jailbreaking': False},
                        'priority': 2,
                        'dependencies': ['basic_recon']
                    },
                    {
                        'name': 'quick_report',
                        'agent_type': 'reporting_agent',
                        'parameters': {'format': 'summary'},
                        'priority': 3,
                        'dependencies': ['basic_llm_test']
                    }
                ]
            }
        }

    async def execute_predefined_pipeline(self, pipeline_name: str, target: str, **kwargs) -> Dict[str, Any]:
        """Execute a predefined pipeline"""
        if pipeline_name not in self.predefined_pipelines:
            raise ValueError(f"Unknown pipeline: {pipeline_name}")

        pipeline_config = self.predefined_pipelines[pipeline_name].copy()
        pipeline_config['target'] = target
        pipeline_config['pipeline_id'] = f"{pipeline_name}_{int(time.time())}"
        pipeline_config.update(kwargs)

        return await self.orchestrator.execute_pipeline(pipeline_config)

    def create_custom_pipeline(self, pipeline_config: Dict[str, Any]) -> str:
        """Create and register a custom pipeline"""
        pipeline_name = pipeline_config.get('name', f"custom_pipeline_{int(time.time())}")
        self.predefined_pipelines[pipeline_name] = pipeline_config
        return pipeline_name

    def list_available_pipelines(self) -> Dict[str, str]:
        """List all available pipelines"""
        return {
            name: config.get('description', 'No description available')
            for name, config in self.predefined_pipelines.items()
        }