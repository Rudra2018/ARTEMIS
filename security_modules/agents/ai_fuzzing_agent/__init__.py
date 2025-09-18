"""
AI Fuzzing Agent

Intelligent input mutation and fuzzing for LLM interfaces using semantic fuzzing,
payload mutation, and coverage metrics. Supports various fuzzing strategies
including transformer-based semantic mutations.
"""

from .fuzzing_agent import AIFuzzingAgent, FuzzingStrategy, FuzzingResult
from .api import app

__all__ = ['AIFuzzingAgent', 'FuzzingStrategy', 'FuzzingResult', 'app']