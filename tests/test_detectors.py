import pytest

from ai_tester_core.security.detectors import (
    BaseDetector,
    DetectionResult,
    PromptInjectionDetector,
    JailbreakAnalyzer,
    DataLeakageScanner,
    OutputValidationChecker,
    ModelTheftDetector,
    TrainingDataPoisoningAnalyzer,
)


def test_base_detector_not_implemented():
    detector = BaseDetector()
    with pytest.raises(NotImplementedError):
        detector.detect("test")


def check_detector(detector):
    result = detector.detect("hello")
    assert isinstance(result, DetectionResult)
    assert result.ok is True
    assert "reason" in result.details


def test_prompt_injection_detector():
    check_detector(PromptInjectionDetector())


def test_jailbreak_analyzer():
    check_detector(JailbreakAnalyzer())


def test_data_leakage_scanner():
    check_detector(DataLeakageScanner())


def test_output_validation_checker():
    check_detector(OutputValidationChecker())


def test_model_theft_detector():
    check_detector(ModelTheftDetector())


def test_training_data_poisoning_analyzer():
    check_detector(TrainingDataPoisoningAnalyzer())
