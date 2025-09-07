"""Security detection module skeletons.

This module defines placeholder classes for various security
modules described in the core architecture plan. Each detector inherits
from :class:`BaseDetector` and implements a ``detect`` method that accepts
an input string and returns a structured result. The real implementations
can plug into LLM providers and advanced analysis engines.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class DetectionResult:
    """Result returned by detector ``detect`` methods."""

    ok: bool
    details: Dict[str, Any]


class BaseDetector:
    """Base class for all vulnerability detectors."""

    name: str = "base"

    def detect(self, text: str) -> DetectionResult:  # pragma: no cover - placeholder
        """Analyze ``text`` and return a :class:`DetectionResult`.

        Sub‑classes should implement this method with real logic.
        """

        raise NotImplementedError


class PromptInjectionDetector(BaseDetector):
    """Detect prompt injection attempts using pattern and semantic checks."""

    name = "prompt_injection"

    def detect(self, text: str) -> DetectionResult:  # pragma: no cover - placeholder
        return DetectionResult(ok=True, details={"reason": "not implemented"})


class JailbreakAnalyzer(BaseDetector):
    """Analyze text for jailbreak patterns and evasive behaviour."""

    name = "jailbreak_analyzer"

    def detect(self, text: str) -> DetectionResult:  # pragma: no cover - placeholder
        return DetectionResult(ok=True, details={"reason": "not implemented"})


class DataLeakageScanner(BaseDetector):
    """Identify potential leakage of PII or sensitive data."""

    name = "data_leakage_scanner"

    def detect(self, text: str) -> DetectionResult:  # pragma: no cover - placeholder
        return DetectionResult(ok=True, details={"reason": "not implemented"})


class OutputValidationChecker(BaseDetector):
    """Validate model output for XSS, injections and malicious content."""

    name = "output_validation_checker"

    def detect(self, text: str) -> DetectionResult:  # pragma: no cover - placeholder
        return DetectionResult(ok=True, details={"reason": "not implemented"})


class ModelTheftDetector(BaseDetector):
    """Detect signs of model extraction or unauthorized access."""

    name = "model_theft_detector"

    def detect(self, text: str) -> DetectionResult:  # pragma: no cover - placeholder
        return DetectionResult(ok=True, details={"reason": "not implemented"})


class TrainingDataPoisoningAnalyzer(BaseDetector):
    """Analyze text for indicators of training data poisoning."""

    name = "training_data_poisoning_analyzer"

    def detect(self, text: str) -> DetectionResult:  # pragma: no cover - placeholder
        return DetectionResult(ok=True, details={"reason": "not implemented"})
