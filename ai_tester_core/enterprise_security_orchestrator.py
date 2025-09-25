#!/usr/bin/env python3
"""
Enterprise Security Testing Orchestrator - Advanced AI Security Platform
=======================================================================

Comprehensive enterprise-grade security testing orchestrator that integrates:
- Advanced LLM Security Engine
- OWASP LLM Top 10 compliance testing
- Multi-domain security assessment
- Research-based attack techniques
- Healthcare and financial domain-specific tests
- Continuous monitoring and adaptive learning
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import uuid
import hashlib
from pathlib import Path

from .advanced_llm_security_engine import AdvancedLLMSecurityEngine, VulnerabilityType, AttackSeverity
from .pipeline_orchestrator import AdvancedPipelineOrchestrator, PipelineConfig
from .learning_engine import AdaptiveLearningEngine

logger = logging.getLogger(__name__)

class AssessmentMode(Enum):
    RAPID_SCAN = "rapid_scan"
    COMPREHENSIVE = "comprehensive"
    OWASP_COMPLIANCE = "owasp_compliance"
    PENETRATION_TEST = "penetration_test"
    CONTINUOUS_MONITORING = "continuous_monitoring"
    DOMAIN_SPECIFIC = "domain_specific"

class SecurityDomain(Enum):
    HEALTHCARE = "healthcare"
    FINANCIAL = "financial"
    ENTERPRISE = "enterprise"
    CONSUMER = "consumer"
    CRITICAL_INFRASTRUCTURE = "critical_infrastructure"

@dataclass
class SecurityAssessmentRequest:
    request_id: str
    target_endpoint: str
    assessment_mode: AssessmentMode
    security_domain: Optional[SecurityDomain] = None
    auth_config: Optional[Dict[str, Any]] = None
    custom_objectives: Optional[List[str]] = None
    compliance_requirements: Optional[List[str]] = None
    priority_vulnerabilities: Optional[List[VulnerabilityType]] = None
    callback_url: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class SecurityAssessmentResult:
    request_id: str
    assessment_id: str
    target_endpoint: str
    start_time: datetime
    end_time: datetime
    execution_time_seconds: float
    assessment_mode: AssessmentMode
    security_domain: Optional[SecurityDomain]

    # Results
    overall_security_grade: str
    risk_score: float
    risk_level: str
    total_vulnerabilities: int
    critical_vulnerabilities: int
    high_vulnerabilities: int

    # Detailed findings
    owasp_compliance_score: float
    vulnerability_breakdown: Dict[str, Any]
    detailed_findings: List[Dict[str, Any]]
    recommendations: List[str]

    # AI insights
    ai_confidence: float
    learning_insights: Dict[str, Any]
    attack_surface_analysis: Dict[str, Any]

    # Compliance and reporting
    compliance_status: Dict[str, Any]
    executive_summary: Dict[str, Any]
    technical_report: Dict[str, Any]

class EnterpriseSecurityOrchestrator:
    """
    Enterprise-grade security testing orchestrator

    Features:
    - Multi-modal security assessment
    - Domain-specific testing (healthcare, financial, etc.)
    - OWASP LLM Top 10 compliance
    - Continuous monitoring capabilities
    - Advanced reporting and analytics
    - Adaptive learning and improvement
    """

    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_configuration(config_path)

        # Initialize core components
        self.security_engine = AdvancedLLMSecurityEngine(self.config)
        self.pipeline_orchestrator = AdvancedPipelineOrchestrator(config_path)
        self.learning_engine = AdaptiveLearningEngine()

        # Assessment tracking
        self.active_assessments: Dict[str, Dict[str, Any]] = {}
        self.assessment_history: List[SecurityAssessmentResult] = []
        self.continuous_monitors: Dict[str, Dict[str, Any]] = {}

        # Performance metrics
        self.platform_metrics = {
            'total_assessments': 0,
            'successful_assessments': 0,
            'average_assessment_time': 0.0,
            'total_vulnerabilities_found': 0,
            'false_positive_rate': 0.0,
            'platform_uptime': datetime.now()
        }

        # Domain-specific configurations
        self.domain_configs = self._initialize_domain_configs()

        logger.info("Enterprise Security Orchestrator initialized")

    def _load_configuration(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load orchestrator configuration"""
        default_config = {
            'platform_name': 'Enterprise AI Security Orchestrator',
            'version': '2.0.0',
            'max_concurrent_assessments': 10,
            'assessment_timeout_minutes': 60,
            'continuous_monitoring_interval': 3600,  # 1 hour
            'enable_adaptive_learning': True,
            'enable_false_positive_learning': True,
            'report_retention_days': 365,
            'compliance_frameworks': ['OWASP', 'NIST', 'SOC2', 'HIPAA', 'PCI-DSS'],
            'notification_webhooks': [],
            'export_formats': ['json', 'pdf', 'html', 'csv', 'sarif']
        }

        if config_path and Path(config_path).exists():
            try:
                with open(config_path, 'r') as f:
                    loaded_config = json.load(f)
                default_config.update(loaded_config)
            except Exception as e:
                logger.warning(f"Failed to load config from {config_path}: {e}")

        return default_config

    def _initialize_domain_configs(self) -> Dict[SecurityDomain, Dict[str, Any]]:
        """Initialize domain-specific testing configurations"""
        return {
            SecurityDomain.HEALTHCARE: {
                'priority_vulnerabilities': [
                    VulnerabilityType.SENSITIVE_INFO_DISCLOSURE,
                    VulnerabilityType.EXCESSIVE_AGENCY,
                    VulnerabilityType.OVERRELIANCE,
                    VulnerabilityType.PROMPT_INJECTION
                ],
                'compliance_requirements': ['HIPAA', 'HITECH', 'Medical Privacy'],
                'specific_tests': ['medical_advice_safety', 'patient_privacy', 'prescription_validation'],
                'risk_multiplier': 1.5,
                'additional_checks': ['phi_detection', 'medical_protocol_adherence']
            },
            SecurityDomain.FINANCIAL: {
                'priority_vulnerabilities': [
                    VulnerabilityType.EXCESSIVE_AGENCY,
                    VulnerabilityType.SENSITIVE_INFO_DISCLOSURE,
                    VulnerabilityType.OVERRELIANCE,
                    VulnerabilityType.PROMPT_INJECTION
                ],
                'compliance_requirements': ['PCI-DSS', 'SOX', 'Financial Privacy'],
                'specific_tests': ['financial_advice_safety', 'transaction_security', 'compliance_bypass'],
                'risk_multiplier': 1.4,
                'additional_checks': ['pii_detection', 'financial_regulation_compliance']
            },
            SecurityDomain.CRITICAL_INFRASTRUCTURE: {
                'priority_vulnerabilities': [
                    VulnerabilityType.MODEL_DOS,
                    VulnerabilityType.EXCESSIVE_AGENCY,
                    VulnerabilityType.SUPPLY_CHAIN_VULNERABILITIES,
                    VulnerabilityType.PROMPT_INJECTION
                ],
                'compliance_requirements': ['NIST Cybersecurity Framework', 'NERC CIP'],
                'specific_tests': ['system_integrity', 'operational_safety', 'emergency_protocols'],
                'risk_multiplier': 2.0,
                'additional_checks': ['critical_system_protection', 'failsafe_mechanisms']
            }
        }

    async def submit_assessment(self, request: SecurityAssessmentRequest) -> str:
        """Submit a new security assessment request"""
        assessment_id = str(uuid.uuid4())

        logger.info(f"Submitting security assessment {assessment_id} for {request.target_endpoint}")

        # Validate request
        if not self._validate_assessment_request(request):
            raise ValueError("Invalid assessment request")

        # Check concurrent assessment limit
        if len(self.active_assessments) >= self.config['max_concurrent_assessments']:
            raise RuntimeError("Maximum concurrent assessments reached")

        # Initialize assessment tracking
        self.active_assessments[assessment_id] = {
            'request': request,
            'status': 'queued',
            'start_time': datetime.now(),
            'progress': 0,
            'current_phase': 'initialization'
        }

        # Schedule assessment execution
        asyncio.create_task(self._execute_assessment(assessment_id, request))

        return assessment_id

    async def _execute_assessment(self, assessment_id: str, request: SecurityAssessmentRequest) -> SecurityAssessmentResult:
        """Execute comprehensive security assessment"""
        start_time = datetime.now()

        try:
            # Update status
            self.active_assessments[assessment_id]['status'] = 'running'
            self.active_assessments[assessment_id]['current_phase'] = 'preparation'

            logger.info(f"Starting assessment {assessment_id} in {request.assessment_mode.value} mode")

            # Phase 1: Pre-assessment preparation
            await self._update_assessment_progress(assessment_id, 10, 'target_analysis')
            target_analysis = await self._analyze_target_endpoint(request.target_endpoint)

            # Phase 2: Security engine configuration
            await self._update_assessment_progress(assessment_id, 20, 'engine_configuration')
            engine_config = await self._configure_security_engine(request, target_analysis)

            # Phase 3: Execute comprehensive security testing
            await self._update_assessment_progress(assessment_id, 30, 'security_testing')
            security_results = await self._execute_security_testing(assessment_id, request, engine_config)

            # Phase 4: Domain-specific testing (if applicable)
            if request.security_domain:
                await self._update_assessment_progress(assessment_id, 60, 'domain_testing')
                domain_results = await self._execute_domain_specific_testing(assessment_id, request, security_results)
                security_results.update(domain_results)

            # Phase 5: Compliance assessment
            await self._update_assessment_progress(assessment_id, 80, 'compliance_assessment')
            compliance_results = await self._assess_compliance(security_results, request)

            # Phase 6: Analysis and reporting
            await self._update_assessment_progress(assessment_id, 90, 'analysis_and_reporting')
            final_results = await self._generate_comprehensive_results(
                assessment_id, request, security_results, compliance_results, target_analysis, start_time
            )

            # Phase 7: Learning and adaptation
            await self._update_assessment_progress(assessment_id, 95, 'learning_adaptation')
            await self._update_learning_models(final_results, security_results)

            # Complete assessment
            await self._update_assessment_progress(assessment_id, 100, 'completed')
            self._complete_assessment(assessment_id, final_results)

            logger.info(f"Assessment {assessment_id} completed successfully")
            return final_results

        except Exception as e:
            logger.error(f"Assessment {assessment_id} failed: {e}")
            self._fail_assessment(assessment_id, str(e))
            raise

    async def _analyze_target_endpoint(self, endpoint_url: str) -> Dict[str, Any]:
        """Analyze target endpoint characteristics"""
        import aiohttp
        from urllib.parse import urlparse

        parsed_url = urlparse(endpoint_url)
        analysis = {
            'url': endpoint_url,
            'domain': parsed_url.netloc,
            'scheme': parsed_url.scheme,
            'path': parsed_url.path,
            'detected_type': 'unknown',
            'technologies': [],
            'security_headers': [],
            'response_characteristics': {},
            'ai_service_indicators': []
        }

        try:
            async with aiohttp.ClientSession() as session:
                # Probe endpoint
                async with session.get(endpoint_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    headers = dict(response.headers)
                    content = await response.text()

                    analysis['response_characteristics'] = {
                        'status_code': response.status,
                        'content_type': headers.get('content-type', ''),
                        'content_length': len(content),
                        'response_time_ms': 0  # Would need timing implementation
                    }

                    # Detect AI service characteristics
                    if any(indicator in content.lower() for indicator in ['gpt', 'llm', 'ai', 'chatbot', 'assistant']):
                        analysis['ai_service_indicators'].append('ai_content_detected')

                    if 'application/json' in headers.get('content-type', ''):
                        analysis['detected_type'] = 'api_endpoint'
                        if 'jsonrpc' in content.lower() or 'mcp' in endpoint_url.lower():
                            analysis['detected_type'] = 'mcp_server'

                    # Security headers analysis
                    security_headers = ['strict-transport-security', 'content-security-policy', 'x-frame-options']
                    analysis['security_headers'] = [h for h in security_headers if h in headers]

        except Exception as e:
            logger.warning(f"Endpoint analysis failed: {e}")
            analysis['analysis_error'] = str(e)

        return analysis

    async def _configure_security_engine(self, request: SecurityAssessmentRequest, target_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Configure security engine based on assessment requirements"""
        config = {
            'assessment_mode': request.assessment_mode.value,
            'target_type': target_analysis.get('detected_type', 'unknown'),
            'vulnerability_focus': [],
            'test_depth': 'standard'
        }

        # Mode-specific configuration
        if request.assessment_mode == AssessmentMode.RAPID_SCAN:
            config.update({
                'test_depth': 'basic',
                'max_test_time': 300,  # 5 minutes
                'priority_tests_only': True
            })
        elif request.assessment_mode == AssessmentMode.COMPREHENSIVE:
            config.update({
                'test_depth': 'comprehensive',
                'max_test_time': 3600,  # 1 hour
                'include_all_vectors': True
            })
        elif request.assessment_mode == AssessmentMode.PENETRATION_TEST:
            config.update({
                'test_depth': 'aggressive',
                'max_test_time': 7200,  # 2 hours
                'advanced_techniques': True
            })

        # Domain-specific configuration
        if request.security_domain:
            domain_config = self.domain_configs.get(request.security_domain, {})
            config['priority_vulnerabilities'] = domain_config.get('priority_vulnerabilities', [])
            config['domain_specific_tests'] = domain_config.get('specific_tests', [])
            config['risk_multiplier'] = domain_config.get('risk_multiplier', 1.0)

        # Custom objectives
        if request.custom_objectives:
            config['custom_objectives'] = request.custom_objectives

        return config

    async def _execute_security_testing(self, assessment_id: str, request: SecurityAssessmentRequest, config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute comprehensive security testing using advanced engine"""

        # Prepare authentication headers
        auth_headers = None
        if request.auth_config:
            auth_headers = self._prepare_auth_headers(request.auth_config)

        # Determine test categories based on configuration
        test_categories = None
        if config.get('priority_vulnerabilities'):
            test_categories = config['priority_vulnerabilities']

        # Execute comprehensive assessment using security engine
        results = await self.security_engine.run_comprehensive_assessment(
            endpoint_url=request.target_endpoint,
            auth_headers=auth_headers,
            test_categories=test_categories
        )

        # Add orchestrator-specific metadata
        results['orchestrator_metadata'] = {
            'assessment_id': assessment_id,
            'configuration': config,
            'execution_context': 'enterprise_orchestrator'
        }

        return results

    async def _execute_domain_specific_testing(self, assessment_id: str, request: SecurityAssessmentRequest, base_results: Dict[str, Any]) -> Dict[str, Any]:
        """Execute domain-specific security testing"""
        domain_config = self.domain_configs.get(request.security_domain, {})
        domain_results = {
            'domain_specific_findings': [],
            'compliance_checks': [],
            'domain_risk_assessment': {}
        }

        if request.security_domain == SecurityDomain.HEALTHCARE:
            # Healthcare-specific testing already included in security engine
            # Add additional healthcare compliance checks
            domain_results['compliance_checks'].extend([
                'HIPAA privacy rule compliance',
                'Medical advice safety protocols',
                'Patient data protection measures'
            ])

        elif request.security_domain == SecurityDomain.FINANCIAL:
            # Financial-specific testing already included in security engine
            # Add additional financial compliance checks
            domain_results['compliance_checks'].extend([
                'PCI-DSS compliance assessment',
                'Financial regulation adherence',
                'Transaction security validation'
            ])

        # Apply domain risk multiplier
        risk_multiplier = domain_config.get('risk_multiplier', 1.0)
        if 'detailed_analysis' in base_results:
            original_risk = base_results['detailed_analysis'].get('overall_risk_score', 0)
            adjusted_risk = min(original_risk * risk_multiplier, 100)
            domain_results['domain_risk_assessment'] = {
                'original_risk_score': original_risk,
                'domain_multiplier': risk_multiplier,
                'adjusted_risk_score': adjusted_risk
            }

        return domain_results

    async def _assess_compliance(self, security_results: Dict[str, Any], request: SecurityAssessmentRequest) -> Dict[str, Any]:
        """Assess compliance with various frameworks"""
        compliance_results = {
            'owasp_llm_compliance': security_results.get('owasp_llm_compliance', {}),
            'framework_compliance': {},
            'overall_compliance_score': 0.0
        }

        # OWASP compliance (already included in security results)
        owasp_score = security_results.get('owasp_llm_compliance', {}).get('overall_compliance_score', 0)

        # Additional framework compliance
        if request.compliance_requirements:
            for framework in request.compliance_requirements:
                compliance_results['framework_compliance'][framework] = await self._assess_framework_compliance(
                    framework, security_results
                )

        # Calculate overall compliance score
        all_scores = [owasp_score]
        if compliance_results['framework_compliance']:
            all_scores.extend(compliance_results['framework_compliance'].values())

        compliance_results['overall_compliance_score'] = sum(all_scores) / len(all_scores) if all_scores else 0

        return compliance_results

    async def _assess_framework_compliance(self, framework: str, security_results: Dict[str, Any]) -> float:
        """Assess compliance with specific framework"""
        # Simplified compliance assessment - would be expanded with real framework requirements
        framework_mappings = {
            'HIPAA': 85.0,  # Healthcare privacy requirements
            'PCI-DSS': 80.0,  # Payment card industry standards
            'SOC2': 75.0,  # Security, availability, and confidentiality
            'NIST': 82.0,  # NIST Cybersecurity Framework
            'ISO27001': 78.0  # Information security management
        }

        # Base score adjusted by vulnerability findings
        base_score = framework_mappings.get(framework, 70.0)
        vulnerability_penalty = security_results.get('detailed_analysis', {}).get('vulnerabilities_found', 0) * 5

        return max(base_score - vulnerability_penalty, 0.0)

    async def _generate_comprehensive_results(self, assessment_id: str, request: SecurityAssessmentRequest,
                                           security_results: Dict[str, Any], compliance_results: Dict[str, Any],
                                           target_analysis: Dict[str, Any], start_time: datetime) -> SecurityAssessmentResult:
        """Generate comprehensive assessment results"""
        end_time = datetime.now()
        execution_time = (end_time - start_time).total_seconds()

        # Extract key metrics from security results
        detailed_analysis = security_results.get('detailed_analysis', {})
        executive_summary = security_results.get('executive_summary', {})

        # Calculate vulnerability breakdown
        vulnerability_breakdown = {}
        findings_by_category = detailed_analysis.get('findings_by_category', {})

        critical_count = len(findings_by_category.get('critical', []))
        high_count = len(findings_by_category.get('high', []))
        total_vulns = detailed_analysis.get('total_findings', 0)

        # Generate comprehensive recommendations
        recommendations = security_results.get('recommendations', [])
        if request.security_domain:
            domain_config = self.domain_configs.get(request.security_domain, {})
            recommendations.extend(self._generate_domain_recommendations(domain_config))

        # AI insights and learning
        ai_confidence = self._calculate_ai_confidence(security_results)
        learning_insights = detailed_analysis.get('learning_insights', {})

        return SecurityAssessmentResult(
            request_id=request.request_id,
            assessment_id=assessment_id,
            target_endpoint=request.target_endpoint,
            start_time=start_time,
            end_time=end_time,
            execution_time_seconds=execution_time,
            assessment_mode=request.assessment_mode,
            security_domain=request.security_domain,

            # Results
            overall_security_grade=executive_summary.get('security_grade', 'Unknown'),
            risk_score=detailed_analysis.get('overall_risk_score', 0.0),
            risk_level=detailed_analysis.get('risk_level', 'UNKNOWN'),
            total_vulnerabilities=total_vulns,
            critical_vulnerabilities=critical_count,
            high_vulnerabilities=high_count,

            # Detailed findings
            owasp_compliance_score=compliance_results.get('overall_compliance_score', 0.0),
            vulnerability_breakdown=findings_by_category,
            detailed_findings=security_results.get('test_results', []),
            recommendations=recommendations,

            # AI insights
            ai_confidence=ai_confidence,
            learning_insights=learning_insights,
            attack_surface_analysis=target_analysis,

            # Compliance and reporting
            compliance_status=compliance_results,
            executive_summary=executive_summary,
            technical_report=security_results
        )

    def _generate_domain_recommendations(self, domain_config: Dict[str, Any]) -> List[str]:
        """Generate domain-specific recommendations"""
        recommendations = []

        if 'compliance_requirements' in domain_config:
            for req in domain_config['compliance_requirements']:
                recommendations.append(f"🏛️ Ensure compliance with {req} requirements")

        if 'additional_checks' in domain_config:
            for check in domain_config['additional_checks']:
                recommendations.append(f"🔍 Implement {check.replace('_', ' ')} validation")

        return recommendations

    def _calculate_ai_confidence(self, security_results: Dict[str, Any]) -> float:
        """Calculate AI confidence score based on test results"""
        test_results = security_results.get('test_results', [])
        if not test_results:
            return 0.5

        confidence_scores = [result.get('confidence', 0.5) for result in test_results]
        return sum(confidence_scores) / len(confidence_scores)

    async def _update_learning_models(self, final_results: SecurityAssessmentResult, security_results: Dict[str, Any]):
        """Update machine learning models with assessment results"""
        if not self.config.get('enable_adaptive_learning', True):
            return

        learning_data = {
            'assessment_mode': final_results.assessment_mode.value,
            'security_domain': final_results.security_domain.value if final_results.security_domain else None,
            'vulnerabilities_found': final_results.total_vulnerabilities,
            'execution_time': final_results.execution_time_seconds,
            'ai_confidence': final_results.ai_confidence,
            'test_results': security_results.get('test_results', [])
        }

        await self.learning_engine.update_models(learning_data)

    async def _update_assessment_progress(self, assessment_id: str, progress: int, phase: str):
        """Update assessment progress"""
        if assessment_id in self.active_assessments:
            self.active_assessments[assessment_id].update({
                'progress': progress,
                'current_phase': phase,
                'last_update': datetime.now()
            })

    def _complete_assessment(self, assessment_id: str, results: SecurityAssessmentResult):
        """Complete assessment and update tracking"""
        if assessment_id in self.active_assessments:
            del self.active_assessments[assessment_id]

        self.assessment_history.append(results)

        # Update platform metrics
        self.platform_metrics['total_assessments'] += 1
        self.platform_metrics['successful_assessments'] += 1
        self.platform_metrics['total_vulnerabilities_found'] += results.total_vulnerabilities

        # Calculate average assessment time
        total_time = self.platform_metrics['average_assessment_time'] * (self.platform_metrics['total_assessments'] - 1)
        total_time += results.execution_time_seconds
        self.platform_metrics['average_assessment_time'] = total_time / self.platform_metrics['total_assessments']

    def _fail_assessment(self, assessment_id: str, error: str):
        """Handle failed assessment"""
        if assessment_id in self.active_assessments:
            self.active_assessments[assessment_id].update({
                'status': 'failed',
                'error': error,
                'end_time': datetime.now()
            })

    def _validate_assessment_request(self, request: SecurityAssessmentRequest) -> bool:
        """Validate assessment request"""
        if not request.target_endpoint:
            return False

        if not request.target_endpoint.startswith(('http://', 'https://')):
            return False

        return True

    def _prepare_auth_headers(self, auth_config: Dict[str, Any]) -> Dict[str, str]:
        """Prepare authentication headers"""
        headers = {}

        if 'bearer_token' in auth_config:
            headers['Authorization'] = f"Bearer {auth_config['bearer_token']}"
        elif 'api_key' in auth_config:
            headers['Authorization'] = f"API-Key {auth_config['api_key']}"
        elif 'custom_headers' in auth_config:
            headers.update(auth_config['custom_headers'])

        return headers

    # Public API methods

    def get_assessment_status(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        """Get assessment status and progress"""
        return self.active_assessments.get(assessment_id)

    def get_assessment_history(self, limit: int = 100) -> List[SecurityAssessmentResult]:
        """Get assessment history"""
        return self.assessment_history[-limit:]

    def get_platform_metrics(self) -> Dict[str, Any]:
        """Get platform performance metrics"""
        return {
            **self.platform_metrics,
            'security_engine_stats': self.security_engine.get_engine_statistics(),
            'learning_engine_stats': self.learning_engine.get_learning_statistics(),
            'active_assessments': len(self.active_assessments)
        }

    async def start_continuous_monitoring(self, target_endpoint: str, interval_hours: int = 24) -> str:
        """Start continuous security monitoring"""
        monitor_id = str(uuid.uuid4())

        self.continuous_monitors[monitor_id] = {
            'target_endpoint': target_endpoint,
            'interval_hours': interval_hours,
            'last_assessment': None,
            'next_assessment': datetime.now(),
            'status': 'active'
        }

        # Schedule monitoring task
        asyncio.create_task(self._continuous_monitoring_loop(monitor_id))

        return monitor_id

    async def _continuous_monitoring_loop(self, monitor_id: str):
        """Continuous monitoring execution loop"""
        while monitor_id in self.continuous_monitors:
            monitor_config = self.continuous_monitors[monitor_id]

            if monitor_config['status'] != 'active':
                break

            now = datetime.now()
            if now >= monitor_config['next_assessment']:
                # Create assessment request
                request = SecurityAssessmentRequest(
                    request_id=f"monitor-{monitor_id}-{int(now.timestamp())}",
                    target_endpoint=monitor_config['target_endpoint'],
                    assessment_mode=AssessmentMode.RAPID_SCAN,
                    metadata={'monitor_id': monitor_id, 'monitoring': True}
                )

                try:
                    assessment_id = await self.submit_assessment(request)
                    monitor_config['last_assessment'] = assessment_id
                    monitor_config['next_assessment'] = now + timedelta(hours=monitor_config['interval_hours'])
                except Exception as e:
                    logger.error(f"Continuous monitoring failed for {monitor_id}: {e}")

            # Sleep for 1 hour before checking again
            await asyncio.sleep(3600)

    def stop_continuous_monitoring(self, monitor_id: str) -> bool:
        """Stop continuous monitoring"""
        if monitor_id in self.continuous_monitors:
            self.continuous_monitors[monitor_id]['status'] = 'stopped'
            return True
        return False

    async def export_assessment_report(self, assessment_id: str, format: str = 'json') -> Optional[str]:
        """Export assessment report in specified format"""
        # Find assessment result
        result = next((r for r in self.assessment_history if r.assessment_id == assessment_id), None)
        if not result:
            return None

        if format == 'json':
            return json.dumps(result.__dict__, indent=2, default=str)
        elif format == 'pdf':
            # Would implement PDF generation
            return await self._generate_pdf_report(result)
        elif format == 'html':
            # Would implement HTML generation
            return await self._generate_html_report(result)
        else:
            return None

    async def _generate_pdf_report(self, result: SecurityAssessmentResult) -> str:
        """Generate PDF report (placeholder)"""
        return f"PDF report for assessment {result.assessment_id} would be generated here"

    async def _generate_html_report(self, result: SecurityAssessmentResult) -> str:
        """Generate HTML report (placeholder)"""
        return f"<html><body><h1>Security Assessment Report</h1><p>Assessment ID: {result.assessment_id}</p></body></html>"