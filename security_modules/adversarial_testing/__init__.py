"""
Adversarial Testing Framework for LLM Security

This module implements comprehensive adversarial testing capabilities including:
- Arcanum Prompt Injection Taxonomy integration
- CL4R1T4S LLM adversarial techniques
- Multi-layered attack vector generation
- Structured payload generation and testing
- Advanced evasion and obfuscation techniques

Attribution:
This methodology/content is based on the Arcanum Prompt Injection Taxonomy
by Jason Haddix (Arcanum Information Security) and techniques from the
CL4R1T4S project.
"""

from .arcanum_taxonomy import ArcanumTaxonomy, AttackIntent, AttackTechnique, AttackEvasion
from .claritas_techniques import ClaritasTechniques, JailbreakTechnique, PromptInjectionPayload
from .adversarial_framework import AdversarialTestingFramework, AttackSuite, TestResult
from .payload_generator import PayloadGenerator, PayloadTemplate, GenerationStrategy
from .evasion_engine import EvasionEngine, ObfuscationMethod, BypassTechnique

__all__ = [
    'AdversarialTestingFramework',
    'ArcanumTaxonomy',
    'ClaritasTechniques',
    'PayloadGenerator',
    'EvasionEngine',
    'AttackSuite',
    'AttackIntent',
    'AttackTechnique',
    'AttackEvasion',
    'JailbreakTechnique',
    'PromptInjectionPayload',
    'TestResult',
    'PayloadTemplate',
    'GenerationStrategy',
    'ObfuscationMethod',
    'BypassTechnique'
]