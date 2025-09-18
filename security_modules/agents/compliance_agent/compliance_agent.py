"""
AI Compliance Checking Agent

Intelligent regulatory compliance assessment for GDPR, PCI-DSS, HIPAA,
SOX, and ISO 27001/27002 using AI-powered policy analysis, automated
control mapping, and real-time compliance monitoring.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    GDPR = "gdpr"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    SOX = "sox"
    ISO_27001 = "iso_27001"
    ISO_27002 = "iso_27002"
    SOC2 = "soc2"
    NIST_CSF = "nist_csf"

class ComplianceStatus(Enum):
    """Compliance assessment status"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_APPLICABLE = "not_applicable"
    REQUIRES_REVIEW = "requires_review"

class RiskLevel(Enum):
    """Risk levels for compliance gaps"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

class ControlCategory(Enum):
    """Categories of security controls"""
    ACCESS_CONTROL = "access_control"
    DATA_PROTECTION = "data_protection"
    ENCRYPTION = "encryption"
    INCIDENT_RESPONSE = "incident_response"
    MONITORING = "monitoring"
    GOVERNANCE = "governance"
    RISK_MANAGEMENT = "risk_management"
    VENDOR_MANAGEMENT = "vendor_management"
    BUSINESS_CONTINUITY = "business_continuity"
    PHYSICAL_SECURITY = "physical_security"

@dataclass
class ComplianceRequirement:
    """Individual compliance requirement"""
    id: str
    framework: ComplianceFramework
    title: str
    description: str
    category: ControlCategory
    mandatory: bool
    section: str
    subsection: Optional[str] = None
    control_objectives: List[str] = field(default_factory=list)
    implementation_guidance: str = ""
    testing_procedures: List[str] = field(default_factory=list)
    evidence_required: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

@dataclass
class ControlImplementation:
    """Implementation details for a security control"""
    requirement_id: str
    implemented: bool
    implementation_details: str
    evidence: List[str] = field(default_factory=list)
    responsible_party: str = ""
    implementation_date: Optional[datetime] = None
    last_reviewed: Optional[datetime] = None
    review_frequency: str = "annual"
    automated: bool = False
    effectiveness_rating: int = 0  # 1-5 scale

@dataclass
class ComplianceGap:
    """Identified compliance gap"""
    id: str
    requirement_id: str
    framework: ComplianceFramework
    gap_description: str
    risk_level: RiskLevel
    impact_description: str
    remediation_recommendations: List[str]
    effort_estimate: str
    target_resolution_date: Optional[datetime] = None
    assigned_to: str = ""
    status: str = "open"

@dataclass
class ComplianceResult:
    """Result of compliance assessment"""
    id: str
    framework: ComplianceFramework
    organization: str
    assessment_date: datetime
    overall_status: ComplianceStatus
    compliance_score: float  # 0.0-1.0
    requirements_assessed: int
    requirements_compliant: int
    requirements_gaps: int
    gaps: List[ComplianceGap]
    recommendations: List[str]
    next_review_date: datetime
    assessor: str = ""
    scope: str = ""
    limitations: List[str] = field(default_factory=list)

class ComplianceAgent:
    """
    AI-powered compliance checking agent with multi-framework support
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.session_id = str(uuid.uuid4())
        self.frameworks = self._initialize_frameworks()
        self.ai_patterns = self._initialize_ai_patterns()

        logger.info(f"ComplianceAgent initialized with session {self.session_id}")

    def _initialize_frameworks(self) -> Dict[ComplianceFramework, Dict[str, Any]]:
        """Initialize compliance framework definitions"""
        return {
            ComplianceFramework.GDPR: {
                "name": "General Data Protection Regulation",
                "version": "2018",
                "applicability": "EU data processing",
                "key_principles": [
                    "lawfulness", "fairness", "transparency", "purpose_limitation",
                    "data_minimization", "accuracy", "storage_limitation",
                    "integrity_confidentiality", "accountability"
                ],
                "requirements": self._get_gdpr_requirements()
            },
            ComplianceFramework.PCI_DSS: {
                "name": "Payment Card Industry Data Security Standard",
                "version": "4.0",
                "applicability": "Payment card data processing",
                "key_principles": [
                    "secure_network", "protect_cardholder_data", "vulnerability_management",
                    "access_control", "monitoring", "information_security_policy"
                ],
                "requirements": self._get_pci_dss_requirements()
            },
            ComplianceFramework.HIPAA: {
                "name": "Health Insurance Portability and Accountability Act",
                "version": "2013 Final Rule",
                "applicability": "Healthcare PHI processing",
                "key_principles": [
                    "administrative_safeguards", "physical_safeguards",
                    "technical_safeguards", "breach_notification"
                ],
                "requirements": self._get_hipaa_requirements()
            },
            ComplianceFramework.ISO_27001: {
                "name": "Information Security Management Systems",
                "version": "2022",
                "applicability": "Information security management",
                "key_principles": [
                    "risk_based_approach", "continual_improvement",
                    "leadership_commitment", "process_approach"
                ],
                "requirements": self._get_iso27001_requirements()
            },
            ComplianceFramework.SOC2: {
                "name": "Service Organization Control 2",
                "version": "2017",
                "applicability": "Service organizations",
                "key_principles": [
                    "security", "availability", "processing_integrity",
                    "confidentiality", "privacy"
                ],
                "requirements": self._get_soc2_requirements()
            }
        }

    def _get_gdpr_requirements(self) -> List[ComplianceRequirement]:
        """Get GDPR compliance requirements"""
        return [
            ComplianceRequirement(
                id="GDPR-6",
                framework=ComplianceFramework.GDPR,
                title="Lawfulness of processing",
                description="Processing shall be lawful only if and to the extent that at least one legal basis applies",
                category=ControlCategory.GOVERNANCE,
                mandatory=True,
                section="Article 6",
                control_objectives=["legal_basis_identification", "documentation", "ongoing_assessment"],
                implementation_guidance="Identify and document legal basis for all processing activities",
                evidence_required=["processing_records", "legal_basis_documentation", "privacy_notices"]
            ),
            ComplianceRequirement(
                id="GDPR-25",
                framework=ComplianceFramework.GDPR,
                title="Data protection by design and by default",
                description="The controller shall implement appropriate technical and organisational measures",
                category=ControlCategory.DATA_PROTECTION,
                mandatory=True,
                section="Article 25",
                control_objectives=["privacy_by_design", "privacy_by_default", "technical_measures"],
                implementation_guidance="Integrate data protection into system design and default settings",
                evidence_required=["design_documentation", "privacy_impact_assessments", "system_configurations"]
            ),
            ComplianceRequirement(
                id="GDPR-32",
                framework=ComplianceFramework.GDPR,
                title="Security of processing",
                description="The controller and processor shall implement appropriate technical and organisational measures",
                category=ControlCategory.ENCRYPTION,
                mandatory=True,
                section="Article 32",
                control_objectives=["pseudonymisation", "encryption", "ongoing_security", "regular_testing"],
                implementation_guidance="Implement state-of-the-art security measures for personal data",
                evidence_required=["security_policies", "encryption_evidence", "security_testing_reports"]
            ),
            ComplianceRequirement(
                id="GDPR-33",
                framework=ComplianceFramework.GDPR,
                title="Notification of personal data breach to supervisory authority",
                description="In case of personal data breach, notify supervisory authority within 72 hours",
                category=ControlCategory.INCIDENT_RESPONSE,
                mandatory=True,
                section="Article 33",
                control_objectives=["breach_detection", "72_hour_notification", "documentation"],
                implementation_guidance="Establish breach detection and notification procedures",
                evidence_required=["incident_response_plan", "breach_logs", "notification_records"]
            ),
            ComplianceRequirement(
                id="GDPR-35",
                framework=ComplianceFramework.GDPR,
                title="Data protection impact assessment",
                description="Where processing is likely to result in high risk, carry out DPIA",
                category=ControlCategory.RISK_MANAGEMENT,
                mandatory=True,
                section="Article 35",
                control_objectives=["risk_assessment", "high_risk_identification", "mitigation_measures"],
                implementation_guidance="Conduct DPIA for high-risk processing activities",
                evidence_required=["dpia_reports", "risk_assessments", "mitigation_plans"]
            )
        ]

    def _get_pci_dss_requirements(self) -> List[ComplianceRequirement]:
        """Get PCI DSS compliance requirements"""
        return [
            ComplianceRequirement(
                id="PCI-1",
                framework=ComplianceFramework.PCI_DSS,
                title="Install and maintain network security controls",
                description="Install and maintain network security controls to protect the cardholder data environment",
                category=ControlCategory.ACCESS_CONTROL,
                mandatory=True,
                section="Requirement 1",
                control_objectives=["firewall_configuration", "network_segmentation", "traffic_control"],
                implementation_guidance="Implement and maintain firewall configurations to protect cardholder data",
                evidence_required=["firewall_rules", "network_diagrams", "configuration_standards"]
            ),
            ComplianceRequirement(
                id="PCI-3",
                framework=ComplianceFramework.PCI_DSS,
                title="Protect stored cardholder data",
                description="Protect stored cardholder data through appropriate technical controls",
                category=ControlCategory.ENCRYPTION,
                mandatory=True,
                section="Requirement 3",
                control_objectives=["data_encryption", "key_management", "secure_storage"],
                implementation_guidance="Encrypt cardholder data and implement proper key management",
                evidence_required=["encryption_policies", "key_management_procedures", "storage_configurations"]
            ),
            ComplianceRequirement(
                id="PCI-8",
                framework=ComplianceFramework.PCI_DSS,
                title="Identify users and authenticate access to system components",
                description="Identify users and authenticate access to system components",
                category=ControlCategory.ACCESS_CONTROL,
                mandatory=True,
                section="Requirement 8",
                control_objectives=["user_identification", "authentication", "access_management"],
                implementation_guidance="Implement strong authentication and access controls",
                evidence_required=["user_access_policies", "authentication_logs", "access_reviews"]
            ),
            ComplianceRequirement(
                id="PCI-10",
                framework=ComplianceFramework.PCI_DSS,
                title="Log and monitor all access to network resources and cardholder data",
                description="Log and monitor all access to network resources and cardholder data",
                category=ControlCategory.MONITORING,
                mandatory=True,
                section="Requirement 10",
                control_objectives=["comprehensive_logging", "log_monitoring", "audit_trails"],
                implementation_guidance="Implement comprehensive logging and monitoring capabilities",
                evidence_required=["logging_policies", "log_reviews", "monitoring_reports"]
            ),
            ComplianceRequirement(
                id="PCI-11",
                framework=ComplianceFramework.PCI_DSS,
                title="Test security of systems and networks regularly",
                description="Test security of systems and networks regularly",
                category=ControlCategory.MONITORING,
                mandatory=True,
                section="Requirement 11",
                control_objectives=["vulnerability_scanning", "penetration_testing", "wireless_monitoring"],
                implementation_guidance="Conduct regular security testing and vulnerability assessments",
                evidence_required=["scan_reports", "penetration_test_reports", "remediation_evidence"]
            )
        ]

    def _get_hipaa_requirements(self) -> List[ComplianceRequirement]:
        """Get HIPAA compliance requirements"""
        return [
            ComplianceRequirement(
                id="HIPAA-164.308",
                framework=ComplianceFramework.HIPAA,
                title="Administrative Safeguards",
                description="Implement administrative safeguards to protect PHI",
                category=ControlCategory.GOVERNANCE,
                mandatory=True,
                section="45 CFR 164.308",
                control_objectives=["security_officer", "workforce_training", "access_procedures"],
                implementation_guidance="Establish administrative procedures for PHI protection",
                evidence_required=["policies_procedures", "training_records", "access_controls"]
            ),
            ComplianceRequirement(
                id="HIPAA-164.312",
                framework=ComplianceFramework.HIPAA,
                title="Technical Safeguards",
                description="Implement technical safeguards to protect PHI",
                category=ControlCategory.ENCRYPTION,
                mandatory=True,
                section="45 CFR 164.312",
                control_objectives=["access_control", "audit_controls", "integrity", "transmission_security"],
                implementation_guidance="Implement technical controls for PHI protection",
                evidence_required=["technical_documentation", "audit_logs", "encryption_evidence"]
            )
        ]

    def _get_iso27001_requirements(self) -> List[ComplianceRequirement]:
        """Get ISO 27001 compliance requirements"""
        return [
            ComplianceRequirement(
                id="ISO-A.9.1",
                framework=ComplianceFramework.ISO_27001,
                title="Access control policy",
                description="An access control policy shall be established and reviewed",
                category=ControlCategory.ACCESS_CONTROL,
                mandatory=True,
                section="A.9.1",
                control_objectives=["access_policy", "regular_review", "management_approval"],
                implementation_guidance="Establish, document, and maintain access control policy",
                evidence_required=["access_control_policy", "review_records", "approval_documentation"]
            ),
            ComplianceRequirement(
                id="ISO-A.10.1",
                framework=ComplianceFramework.ISO_27001,
                title="Cryptographic controls",
                description="A policy on the use of cryptographic controls shall be developed",
                category=ControlCategory.ENCRYPTION,
                mandatory=True,
                section="A.10.1",
                control_objectives=["crypto_policy", "key_management", "implementation_guidance"],
                implementation_guidance="Develop and implement cryptographic controls policy",
                evidence_required=["cryptographic_policy", "key_management_procedures", "implementation_evidence"]
            )
        ]

    def _get_soc2_requirements(self) -> List[ComplianceRequirement]:
        """Get SOC 2 compliance requirements"""
        return [
            ComplianceRequirement(
                id="SOC2-CC6.1",
                framework=ComplianceFramework.SOC2,
                title="Logical and Physical Access Controls",
                description="The entity implements logical and physical access security software",
                category=ControlCategory.ACCESS_CONTROL,
                mandatory=True,
                section="CC6.1",
                control_objectives=["logical_access", "physical_access", "authentication"],
                implementation_guidance="Implement comprehensive access controls",
                evidence_required=["access_control_documentation", "authentication_systems", "physical_security"]
            ),
            ComplianceRequirement(
                id="SOC2-CC6.7",
                framework=ComplianceFramework.SOC2,
                title="Data Transmission",
                description="The entity restricts the transmission of data to authorized users",
                category=ControlCategory.ENCRYPTION,
                mandatory=True,
                section="CC6.7",
                control_objectives=["transmission_security", "encryption", "authorized_access"],
                implementation_guidance="Secure data transmission channels",
                evidence_required=["transmission_policies", "encryption_evidence", "access_logs"]
            )
        ]

    def _initialize_ai_patterns(self) -> Dict[str, Any]:
        """Initialize AI pattern recognition for compliance assessment"""
        return {
            "data_classification_patterns": {
                "pii": r"(?i)\b(ssn|social.?security|passport|driver.?license|tax.?id)\b",
                "phi": r"(?i)\b(medical|health|patient|diagnosis|treatment|medication)\b",
                "pci": r"(?i)\b(credit.?card|payment|cardholder|pan|cvv|cvn)\b",
                "financial": r"(?i)\b(account.?number|routing|iban|swift|financial)\b"
            },
            "security_control_patterns": {
                "encryption": r"(?i)\b(encrypt|aes|rsa|tls|ssl|cryptograph)\b",
                "authentication": r"(?i)\b(auth|login|password|mfa|2fa|biometric)\b",
                "logging": r"(?i)\b(log|audit|monitor|track|record)\b",
                "access_control": r"(?i)\b(access|permission|role|rbac|authorization)\b"
            },
            "compliance_indicators": {
                "gdpr_keywords": ["consent", "lawful basis", "data subject", "controller", "processor"],
                "pci_keywords": ["cardholder", "payment", "secure", "network", "firewall"],
                "hipaa_keywords": ["phi", "covered entity", "business associate", "safeguards"],
                "sox_keywords": ["financial reporting", "internal controls", "audit", "disclosure"]
            },
            "risk_indicators": {
                "high_risk": ["unencrypted", "no authentication", "public access", "admin privileges"],
                "medium_risk": ["weak encryption", "basic authentication", "limited monitoring"],
                "low_risk": ["encrypted", "strong authentication", "comprehensive monitoring"]
            }
        }

    async def assess_compliance(self, framework: ComplianceFramework,
                              system_configuration: Dict[str, Any],
                              evidence: Dict[str, Any]) -> ComplianceResult:
        """
        Perform comprehensive compliance assessment
        """
        logger.info(f"Starting compliance assessment for {framework.value}")

        # Get framework requirements
        framework_info = self.frameworks[framework]
        requirements = framework_info["requirements"]

        # Assess each requirement
        gaps = []
        compliant_count = 0
        assessed_count = len(requirements)

        for requirement in requirements:
            assessment = await self._assess_requirement(
                requirement, system_configuration, evidence
            )

            if assessment["status"] == ComplianceStatus.COMPLIANT:
                compliant_count += 1
            elif assessment["status"] == ComplianceStatus.NON_COMPLIANT:
                gap = ComplianceGap(
                    id=str(uuid.uuid4()),
                    requirement_id=requirement.id,
                    framework=framework,
                    gap_description=assessment["gap_description"],
                    risk_level=assessment["risk_level"],
                    impact_description=assessment["impact"],
                    remediation_recommendations=assessment["recommendations"],
                    effort_estimate=assessment["effort_estimate"]
                )
                gaps.append(gap)

        # Calculate compliance score
        compliance_score = compliant_count / assessed_count if assessed_count > 0 else 0.0

        # Determine overall status
        overall_status = self._determine_overall_status(compliance_score, gaps)

        # Generate recommendations
        recommendations = await self._generate_compliance_recommendations(framework, gaps)

        # Create result
        result = ComplianceResult(
            id=str(uuid.uuid4()),
            framework=framework,
            organization=system_configuration.get("organization", "Unknown"),
            assessment_date=datetime.now(),
            overall_status=overall_status,
            compliance_score=compliance_score,
            requirements_assessed=assessed_count,
            requirements_compliant=compliant_count,
            requirements_gaps=len(gaps),
            gaps=gaps,
            recommendations=recommendations,
            next_review_date=datetime.now() + timedelta(days=365),
            assessor=f"AI Compliance Agent {self.session_id}",
            scope=system_configuration.get("scope", "Full system assessment")
        )

        logger.info(f"Compliance assessment completed. Score: {compliance_score:.2%}, Gaps: {len(gaps)}")
        return result

    async def _assess_requirement(self, requirement: ComplianceRequirement,
                                system_config: Dict[str, Any],
                                evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Assess individual compliance requirement"""

        # AI-powered analysis of requirement compliance
        compliance_score = 0.0
        findings = []
        recommendations = []

        # Check for relevant evidence
        relevant_evidence = self._find_relevant_evidence(requirement, evidence)

        # Analyze system configuration
        config_analysis = self._analyze_configuration(requirement, system_config)

        # Pattern matching for specific requirements
        pattern_analysis = self._pattern_match_requirement(requirement, system_config, evidence)

        # Combine analysis results
        if relevant_evidence:
            compliance_score += 0.4

        if config_analysis["compliant"]:
            compliance_score += 0.4

        if pattern_analysis["matches"]:
            compliance_score += 0.2

        # Determine status
        if compliance_score >= 0.8:
            status = ComplianceStatus.COMPLIANT
            risk_level = RiskLevel.LOW
        elif compliance_score >= 0.5:
            status = ComplianceStatus.PARTIALLY_COMPLIANT
            risk_level = RiskLevel.MEDIUM
        else:
            status = ComplianceStatus.NON_COMPLIANT
            risk_level = self._assess_risk_level(requirement, compliance_score)

        # Generate gap description and recommendations
        gap_description = self._generate_gap_description(requirement, compliance_score, findings)
        recommendations = self._generate_requirement_recommendations(requirement, config_analysis, pattern_analysis)

        return {
            "status": status,
            "score": compliance_score,
            "gap_description": gap_description,
            "risk_level": risk_level,
            "impact": self._assess_impact(requirement, risk_level),
            "recommendations": recommendations,
            "effort_estimate": self._estimate_effort(requirement, compliance_score)
        }

    def _find_relevant_evidence(self, requirement: ComplianceRequirement,
                              evidence: Dict[str, Any]) -> List[str]:
        """Find evidence relevant to specific requirement"""
        relevant = []

        for evidence_type in requirement.evidence_required:
            if evidence_type in evidence:
                relevant.append(evidence_type)

        # AI pattern matching for additional evidence
        for key, value in evidence.items():
            if isinstance(value, str):
                # Check for keywords related to requirement category
                category_keywords = self._get_category_keywords(requirement.category)
                if any(keyword.lower() in value.lower() for keyword in category_keywords):
                    relevant.append(key)

        return relevant

    def _analyze_configuration(self, requirement: ComplianceRequirement,
                             config: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze system configuration for compliance"""
        analysis = {"compliant": False, "findings": [], "gaps": []}

        # Framework-specific configuration analysis
        if requirement.framework == ComplianceFramework.PCI_DSS:
            analysis = self._analyze_pci_config(requirement, config)
        elif requirement.framework == ComplianceFramework.GDPR:
            analysis = self._analyze_gdpr_config(requirement, config)
        elif requirement.framework == ComplianceFramework.HIPAA:
            analysis = self._analyze_hipaa_config(requirement, config)
        elif requirement.framework == ComplianceFramework.ISO_27001:
            analysis = self._analyze_iso_config(requirement, config)

        return analysis

    def _analyze_pci_config(self, requirement: ComplianceRequirement,
                          config: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze PCI DSS specific configuration"""
        analysis = {"compliant": False, "findings": [], "gaps": []}

        if requirement.id == "PCI-1":  # Network security controls
            if config.get("firewall", {}).get("enabled", False):
                analysis["findings"].append("Firewall is enabled")
                analysis["compliant"] = True
            else:
                analysis["gaps"].append("Firewall not properly configured")

        elif requirement.id == "PCI-3":  # Protect cardholder data
            encryption = config.get("encryption", {})
            if encryption.get("at_rest", False) and encryption.get("in_transit", False):
                analysis["findings"].append("Data encryption implemented")
                analysis["compliant"] = True
            else:
                analysis["gaps"].append("Cardholder data encryption incomplete")

        elif requirement.id == "PCI-8":  # Authentication
            auth = config.get("authentication", {})
            if auth.get("mfa_enabled", False) and auth.get("strong_passwords", False):
                analysis["findings"].append("Strong authentication implemented")
                analysis["compliant"] = True
            else:
                analysis["gaps"].append("Authentication controls insufficient")

        return analysis

    def _analyze_gdpr_config(self, requirement: ComplianceRequirement,
                           config: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze GDPR specific configuration"""
        analysis = {"compliant": False, "findings": [], "gaps": []}

        if requirement.id == "GDPR-25":  # Privacy by design
            privacy_features = config.get("privacy_features", {})
            if privacy_features.get("data_minimization", False) and privacy_features.get("purpose_limitation", False):
                analysis["findings"].append("Privacy by design implemented")
                analysis["compliant"] = True
            else:
                analysis["gaps"].append("Privacy by design not fully implemented")

        elif requirement.id == "GDPR-32":  # Security of processing
            security = config.get("security", {})
            if security.get("encryption", False) and security.get("access_controls", False):
                analysis["findings"].append("Technical security measures implemented")
                analysis["compliant"] = True
            else:
                analysis["gaps"].append("Security measures insufficient")

        return analysis

    def _analyze_hipaa_config(self, requirement: ComplianceRequirement,
                            config: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze HIPAA specific configuration"""
        analysis = {"compliant": False, "findings": [], "gaps": []}

        if requirement.id == "HIPAA-164.312":  # Technical safeguards
            safeguards = config.get("technical_safeguards", {})
            if safeguards.get("access_control", False) and safeguards.get("audit_controls", False):
                analysis["findings"].append("Technical safeguards implemented")
                analysis["compliant"] = True
            else:
                analysis["gaps"].append("Technical safeguards incomplete")

        return analysis

    def _analyze_iso_config(self, requirement: ComplianceRequirement,
                          config: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze ISO 27001 specific configuration"""
        analysis = {"compliant": False, "findings": [], "gaps": []}

        if requirement.id == "ISO-A.9.1":  # Access control policy
            policies = config.get("policies", {})
            if policies.get("access_control", False):
                analysis["findings"].append("Access control policy exists")
                analysis["compliant"] = True
            else:
                analysis["gaps"].append("Access control policy missing")

        elif requirement.id == "ISO-A.10.1":  # Cryptographic controls
            crypto = config.get("cryptographic_controls", {})
            if crypto.get("policy_exists", False) and crypto.get("key_management", False):
                analysis["findings"].append("Cryptographic controls implemented")
                analysis["compliant"] = True
            else:
                analysis["gaps"].append("Cryptographic controls insufficient")

        return analysis

    def _pattern_match_requirement(self, requirement: ComplianceRequirement,
                                 config: Dict[str, Any], evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Use AI pattern matching for requirement assessment"""
        analysis = {"matches": False, "patterns_found": [], "patterns_missing": []}

        # Get relevant patterns for requirement category
        category_patterns = self._get_category_patterns(requirement.category)

        # Search for patterns in configuration and evidence
        all_text = json.dumps(config) + " " + json.dumps(evidence)

        for pattern_name, pattern in category_patterns.items():
            if re.search(pattern, all_text, re.IGNORECASE):
                analysis["patterns_found"].append(pattern_name)
                analysis["matches"] = True
            else:
                analysis["patterns_missing"].append(pattern_name)

        return analysis

    def _get_category_patterns(self, category: ControlCategory) -> Dict[str, str]:
        """Get regex patterns for specific control category"""
        pattern_map = {
            ControlCategory.ENCRYPTION: self.ai_patterns["security_control_patterns"]["encryption"],
            ControlCategory.ACCESS_CONTROL: self.ai_patterns["security_control_patterns"]["access_control"],
            ControlCategory.MONITORING: self.ai_patterns["security_control_patterns"]["logging"],
            ControlCategory.DATA_PROTECTION: self.ai_patterns["data_classification_patterns"]["pii"]
        }

        return {category.value: pattern_map.get(category, r"\b\w+\b")}

    def _get_category_keywords(self, category: ControlCategory) -> List[str]:
        """Get keywords for specific control category"""
        keyword_map = {
            ControlCategory.ENCRYPTION: ["encrypt", "cryptography", "cipher", "key"],
            ControlCategory.ACCESS_CONTROL: ["access", "permission", "role", "authentication"],
            ControlCategory.MONITORING: ["log", "audit", "monitor", "track"],
            ControlCategory.DATA_PROTECTION: ["privacy", "personal data", "sensitive", "confidential"]
        }

        return keyword_map.get(category, [])

    def _assess_risk_level(self, requirement: ComplianceRequirement, score: float) -> RiskLevel:
        """Assess risk level based on requirement and compliance score"""
        if requirement.mandatory and score < 0.3:
            return RiskLevel.CRITICAL
        elif requirement.mandatory and score < 0.6:
            return RiskLevel.HIGH
        elif score < 0.4:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def _assess_impact(self, requirement: ComplianceRequirement, risk_level: RiskLevel) -> str:
        """Assess impact of non-compliance"""
        impact_map = {
            RiskLevel.CRITICAL: f"Critical compliance gap in {requirement.title} could result in regulatory penalties, legal action, and significant reputational damage",
            RiskLevel.HIGH: f"High-risk non-compliance with {requirement.title} may lead to regulatory scrutiny and potential fines",
            RiskLevel.MEDIUM: f"Medium-risk gap in {requirement.title} requires attention to maintain compliance posture",
            RiskLevel.LOW: f"Low-risk issue with {requirement.title} should be addressed during next review cycle"
        }

        return impact_map.get(risk_level, "Impact assessment required")

    def _generate_gap_description(self, requirement: ComplianceRequirement,
                                score: float, findings: List[str]) -> str:
        """Generate description of compliance gap"""
        if score >= 0.8:
            return f"Requirement {requirement.id} appears to be adequately addressed"

        gap_level = "Partial" if score >= 0.5 else "Significant"
        return f"{gap_level} compliance gap identified for {requirement.title}. " \
               f"Current implementation score: {score:.1%}. " \
               f"Additional controls and evidence required to meet {requirement.framework.value} requirements."

    def _generate_requirement_recommendations(self, requirement: ComplianceRequirement,
                                            config_analysis: Dict[str, Any],
                                            pattern_analysis: Dict[str, Any]) -> List[str]:
        """Generate specific recommendations for requirement"""
        recommendations = []

        # Add gap-specific recommendations
        for gap in config_analysis.get("gaps", []):
            recommendations.append(f"Address configuration gap: {gap}")

        # Add pattern-based recommendations
        for missing_pattern in pattern_analysis.get("patterns_missing", []):
            recommendations.append(f"Implement {missing_pattern.replace('_', ' ')} controls")

        # Add framework-specific recommendations
        if requirement.framework == ComplianceFramework.GDPR:
            recommendations.extend(self._get_gdpr_recommendations(requirement))
        elif requirement.framework == ComplianceFramework.PCI_DSS:
            recommendations.extend(self._get_pci_recommendations(requirement))

        # Add implementation guidance
        if requirement.implementation_guidance:
            recommendations.append(f"Follow implementation guidance: {requirement.implementation_guidance}")

        return recommendations

    def _get_gdpr_recommendations(self, requirement: ComplianceRequirement) -> List[str]:
        """Get GDPR-specific recommendations"""
        recommendations = []

        if requirement.id == "GDPR-6":
            recommendations.extend([
                "Document legal basis for all processing activities",
                "Implement consent management system if relying on consent",
                "Regular review of legal basis validity"
            ])
        elif requirement.id == "GDPR-25":
            recommendations.extend([
                "Implement privacy by design principles in system architecture",
                "Configure privacy-friendly default settings",
                "Conduct privacy impact assessments for new systems"
            ])
        elif requirement.id == "GDPR-32":
            recommendations.extend([
                "Implement end-to-end encryption for personal data",
                "Deploy advanced access controls and monitoring",
                "Regular security testing and vulnerability assessments"
            ])

        return recommendations

    def _get_pci_recommendations(self, requirement: ComplianceRequirement) -> List[str]:
        """Get PCI DSS-specific recommendations"""
        recommendations = []

        if requirement.id == "PCI-1":
            recommendations.extend([
                "Configure firewall rules to restrict cardholder data environment access",
                "Implement network segmentation",
                "Regular firewall rule reviews"
            ])
        elif requirement.id == "PCI-3":
            recommendations.extend([
                "Implement strong encryption for stored cardholder data",
                "Deploy proper key management system",
                "Minimize cardholder data storage"
            ])
        elif requirement.id == "PCI-8":
            recommendations.extend([
                "Implement multi-factor authentication",
                "Enforce strong password policies",
                "Regular access reviews and de-provisioning"
            ])

        return recommendations

    def _estimate_effort(self, requirement: ComplianceRequirement, score: float) -> str:
        """Estimate implementation effort"""
        if score >= 0.8:
            return "Low - Minor adjustments needed"
        elif score >= 0.5:
            return "Medium - Moderate implementation effort required"
        elif score >= 0.3:
            return "High - Significant implementation project needed"
        else:
            return "Very High - Major system changes and process implementation required"

    def _determine_overall_status(self, score: float, gaps: List[ComplianceGap]) -> ComplianceStatus:
        """Determine overall compliance status"""
        critical_gaps = sum(1 for gap in gaps if gap.risk_level == RiskLevel.CRITICAL)
        high_gaps = sum(1 for gap in gaps if gap.risk_level == RiskLevel.HIGH)

        if critical_gaps > 0:
            return ComplianceStatus.NON_COMPLIANT
        elif high_gaps > 0 or score < 0.7:
            return ComplianceStatus.PARTIALLY_COMPLIANT
        elif score >= 0.9:
            return ComplianceStatus.COMPLIANT
        else:
            return ComplianceStatus.REQUIRES_REVIEW

    async def _generate_compliance_recommendations(self, framework: ComplianceFramework,
                                                 gaps: List[ComplianceGap]) -> List[str]:
        """Generate high-level compliance recommendations"""
        recommendations = []

        # Prioritize by risk level
        critical_gaps = [g for g in gaps if g.risk_level == RiskLevel.CRITICAL]
        high_gaps = [g for g in gaps if g.risk_level == RiskLevel.HIGH]

        if critical_gaps:
            recommendations.append(f"URGENT: Address {len(critical_gaps)} critical compliance gaps immediately")

        if high_gaps:
            recommendations.append(f"HIGH PRIORITY: Remediate {len(high_gaps)} high-risk compliance issues")

        # Framework-specific recommendations
        framework_recommendations = {
            ComplianceFramework.GDPR: [
                "Conduct comprehensive data mapping and classification",
                "Implement privacy by design across all systems",
                "Establish robust data subject rights procedures"
            ],
            ComplianceFramework.PCI_DSS: [
                "Implement comprehensive cardholder data protection",
                "Deploy continuous compliance monitoring",
                "Conduct regular penetration testing"
            ],
            ComplianceFramework.HIPAA: [
                "Strengthen PHI safeguards across all systems",
                "Implement comprehensive workforce training",
                "Establish robust incident response procedures"
            ]
        }

        recommendations.extend(framework_recommendations.get(framework, []))

        # Add remediation timeline recommendation
        if gaps:
            recommendations.append("Develop remediation roadmap with clear timelines and ownership")
            recommendations.append("Implement continuous compliance monitoring and reporting")

        return recommendations

    async def generate_compliance_report(self, results: List[ComplianceResult]) -> Dict[str, Any]:
        """Generate comprehensive compliance report"""
        logger.info("Generating comprehensive compliance report")

        # Aggregate results across frameworks
        total_requirements = sum(r.requirements_assessed for r in results)
        total_compliant = sum(r.requirements_compliant for r in results)
        total_gaps = sum(r.requirements_gaps for r in results)

        overall_score = total_compliant / total_requirements if total_requirements > 0 else 0.0

        # Risk analysis
        all_gaps = []
        for result in results:
            all_gaps.extend(result.gaps)

        risk_distribution = defaultdict(int)
        for gap in all_gaps:
            risk_distribution[gap.risk_level.value] += 1

        # Framework comparison
        framework_scores = {}
        for result in results:
            framework_scores[result.framework.value] = {
                "score": result.compliance_score,
                "status": result.overall_status.value,
                "gaps": result.requirements_gaps
            }

        # Top recommendations
        all_recommendations = []
        for result in results:
            all_recommendations.extend(result.recommendations)

        # Priority actions
        critical_gaps = [g for g in all_gaps if g.risk_level == RiskLevel.CRITICAL]
        high_gaps = [g for g in all_gaps if g.risk_level == RiskLevel.HIGH]

        report = {
            "executive_summary": {
                "overall_compliance_score": overall_score,
                "total_frameworks_assessed": len(results),
                "total_requirements_assessed": total_requirements,
                "total_gaps_identified": total_gaps,
                "critical_gaps": len(critical_gaps),
                "high_risk_gaps": len(high_gaps)
            },
            "framework_results": framework_scores,
            "risk_analysis": {
                "risk_distribution": dict(risk_distribution),
                "top_risk_areas": self._identify_top_risk_areas(all_gaps),
                "remediation_priority": self._prioritize_remediation(all_gaps)
            },
            "detailed_results": [
                {
                    "framework": result.framework.value,
                    "assessment_date": result.assessment_date.isoformat(),
                    "compliance_score": result.compliance_score,
                    "status": result.overall_status.value,
                    "gaps": [
                        {
                            "requirement_id": gap.requirement_id,
                            "description": gap.gap_description,
                            "risk_level": gap.risk_level.value,
                            "impact": gap.impact_description,
                            "recommendations": gap.remediation_recommendations
                        }
                        for gap in result.gaps
                    ]
                }
                for result in results
            ],
            "recommendations": {
                "immediate_actions": [gap.remediation_recommendations[0] for gap in critical_gaps if gap.remediation_recommendations],
                "short_term": [gap.remediation_recommendations[0] for gap in high_gaps if gap.remediation_recommendations],
                "strategic": all_recommendations[:10]  # Top 10 strategic recommendations
            },
            "next_steps": [
                "Address critical compliance gaps within 30 days",
                "Develop comprehensive remediation plan",
                "Implement continuous compliance monitoring",
                "Schedule regular compliance assessments",
                "Establish compliance governance structure"
            ]
        }

        logger.info("Compliance report generated successfully")
        return report

    def _identify_top_risk_areas(self, gaps: List[ComplianceGap]) -> List[Dict[str, Any]]:
        """Identify top risk areas from compliance gaps"""
        # Group gaps by requirement category
        category_risks = defaultdict(list)
        for gap in gaps:
            # This would need to be enhanced with actual requirement categorization
            category_risks["general"].append(gap)

        # Calculate risk scores by category
        risk_areas = []
        for category, category_gaps in category_risks.items():
            total_risk = sum(self._gap_risk_score(gap) for gap in category_gaps)
            risk_areas.append({
                "category": category,
                "total_risk_score": total_risk,
                "gap_count": len(category_gaps),
                "average_risk": total_risk / len(category_gaps) if category_gaps else 0
            })

        return sorted(risk_areas, key=lambda x: x["total_risk_score"], reverse=True)

    def _gap_risk_score(self, gap: ComplianceGap) -> float:
        """Calculate numerical risk score for gap"""
        risk_scores = {
            RiskLevel.CRITICAL: 10.0,
            RiskLevel.HIGH: 7.0,
            RiskLevel.MEDIUM: 4.0,
            RiskLevel.LOW: 2.0,
            RiskLevel.INFORMATIONAL: 1.0
        }
        return risk_scores.get(gap.risk_level, 0.0)

    def _prioritize_remediation(self, gaps: List[ComplianceGap]) -> List[Dict[str, Any]]:
        """Prioritize remediation efforts"""
        # Sort gaps by risk level and impact
        sorted_gaps = sorted(gaps, key=lambda g: (
            self._gap_risk_score(g),
            len(g.remediation_recommendations)
        ), reverse=True)

        return [
            {
                "priority": idx + 1,
                "requirement_id": gap.requirement_id,
                "framework": gap.framework.value,
                "risk_level": gap.risk_level.value,
                "description": gap.gap_description,
                "effort_estimate": gap.effort_estimate
            }
            for idx, gap in enumerate(sorted_gaps[:20])  # Top 20 priorities
        ]

    def get_compliance_summary(self, result: ComplianceResult) -> Dict[str, Any]:
        """Get summary of compliance result"""
        return {
            "result_id": result.id,
            "framework": result.framework.value,
            "organization": result.organization,
            "assessment_date": result.assessment_date.isoformat(),
            "overall_status": result.overall_status.value,
            "compliance_score": result.compliance_score,
            "requirements_summary": {
                "total": result.requirements_assessed,
                "compliant": result.requirements_compliant,
                "gaps": result.requirements_gaps,
                "compliance_percentage": (result.requirements_compliant / result.requirements_assessed * 100) if result.requirements_assessed > 0 else 0
            },
            "risk_summary": {
                "critical_gaps": sum(1 for gap in result.gaps if gap.risk_level == RiskLevel.CRITICAL),
                "high_gaps": sum(1 for gap in result.gaps if gap.risk_level == RiskLevel.HIGH),
                "medium_gaps": sum(1 for gap in result.gaps if gap.risk_level == RiskLevel.MEDIUM),
                "low_gaps": sum(1 for gap in result.gaps if gap.risk_level == RiskLevel.LOW)
            },
            "top_recommendations": result.recommendations[:5],
            "next_review_date": result.next_review_date.isoformat()
        }