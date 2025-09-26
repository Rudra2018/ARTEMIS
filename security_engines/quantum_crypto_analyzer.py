#!/usr/bin/env python3
"""
🏹 ARTEMIS QUANTUMSENTINEL-NEXUS v5.0
Quantum-Resistant Cryptography Analysis Engine
Post-Quantum Cryptography Security Assessment and Quantum Attack Simulation
"""

import json
import logging
import hashlib
import random
import time
import math
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import uuid
from datetime import datetime
import base64

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class QuantumThreatLevel(Enum):
    IMMEDIATE = "immediate"      # Quantum computers can break this today
    NEAR_TERM = "near_term"     # Vulnerable within 5-10 years
    LONG_TERM = "long_term"     # May be vulnerable in 15+ years
    QUANTUM_SAFE = "quantum_safe" # Believed to be quantum-resistant

class CryptoAlgorithmType(Enum):
    SYMMETRIC = "symmetric"
    ASYMMETRIC = "asymmetric"
    HASH = "hash_function"
    SIGNATURE = "digital_signature"
    KEY_EXCHANGE = "key_exchange"

@dataclass
class CryptoVulnerability:
    """Represents a cryptographic vulnerability"""
    vuln_id: str
    algorithm_name: str
    algorithm_type: CryptoAlgorithmType
    threat_level: QuantumThreatLevel
    key_size: int
    quantum_attack_vector: str
    time_to_break_classical: str
    time_to_break_quantum: str
    recommended_replacement: str
    migration_complexity: str
    business_impact: str

@dataclass
class QuantumAttackSimulation:
    """Results from quantum attack simulation"""
    attack_id: str
    target_algorithm: str
    attack_method: str
    success_probability: float
    quantum_resources_required: Dict[str, int]
    estimated_time_hours: float
    key_recovery_successful: bool
    attack_evidence: List[str]

class QuantumCryptoAnalyzer:
    """Quantum-Resistant Cryptography Analysis Engine"""

    def __init__(self):
        self.session_id = str(uuid.uuid4())[:8]
        self.vulnerability_database = self._initialize_crypto_vulnerabilities()
        self.quantum_attack_suite = self._initialize_quantum_attacks()
        self.post_quantum_recommendations = self._load_pqc_standards()

    def _initialize_crypto_vulnerabilities(self) -> Dict[str, CryptoVulnerability]:
        """Initialize cryptographic vulnerability database"""

        vulnerabilities = [
            # RSA Vulnerabilities
            CryptoVulnerability(
                vuln_id="QC-RSA-1024",
                algorithm_name="RSA-1024",
                algorithm_type=CryptoAlgorithmType.ASYMMETRIC,
                threat_level=QuantumThreatLevel.IMMEDIATE,
                key_size=1024,
                quantum_attack_vector="Shor's Algorithm",
                time_to_break_classical="2^80 operations (~1 million years)",
                time_to_break_quantum="~8 hours on NISQ device",
                recommended_replacement="Kyber-1024 (Post-Quantum KEM)",
                migration_complexity="high",
                business_impact="critical"
            ),
            CryptoVulnerability(
                vuln_id="QC-RSA-2048",
                algorithm_name="RSA-2048",
                algorithm_type=CryptoAlgorithmType.ASYMMETRIC,
                threat_level=QuantumThreatLevel.NEAR_TERM,
                key_size=2048,
                quantum_attack_vector="Shor's Algorithm",
                time_to_break_classical="2^112 operations",
                time_to_break_quantum="~24 hours on fault-tolerant QC",
                recommended_replacement="Kyber-1024 or Dilithium-3",
                migration_complexity="high",
                business_impact="critical"
            ),
            CryptoVulnerability(
                vuln_id="QC-RSA-4096",
                algorithm_name="RSA-4096",
                algorithm_type=CryptoAlgorithmType.ASYMMETRIC,
                threat_level=QuantumThreatLevel.LONG_TERM,
                key_size=4096,
                quantum_attack_vector="Shor's Algorithm",
                time_to_break_classical="2^140 operations",
                time_to_break_quantum="~1 week on fault-tolerant QC",
                recommended_replacement="Kyber-1024 or Dilithium-5",
                migration_complexity="medium",
                business_impact="high"
            ),

            # ECDSA Vulnerabilities
            CryptoVulnerability(
                vuln_id="QC-ECDSA-P256",
                algorithm_name="ECDSA-P256",
                algorithm_type=CryptoAlgorithmType.SIGNATURE,
                threat_level=QuantumThreatLevel.IMMEDIATE,
                key_size=256,
                quantum_attack_vector="Shor's Algorithm (Elliptic Curve)",
                time_to_break_classical="2^128 operations",
                time_to_break_quantum="~2 hours on NISQ device",
                recommended_replacement="Dilithium-2",
                migration_complexity="medium",
                business_impact="critical"
            ),
            CryptoVulnerability(
                vuln_id="QC-ECDSA-P384",
                algorithm_name="ECDSA-P384",
                algorithm_type=CryptoAlgorithmType.SIGNATURE,
                threat_level=QuantumThreatLevel.NEAR_TERM,
                key_size=384,
                quantum_attack_vector="Shor's Algorithm (Elliptic Curve)",
                time_to_break_classical="2^192 operations",
                time_to_break_quantum="~6 hours on fault-tolerant QC",
                recommended_replacement="Dilithium-3",
                migration_complexity="medium",
                business_impact="critical"
            ),

            # DH/ECDH Vulnerabilities
            CryptoVulnerability(
                vuln_id="QC-DH-2048",
                algorithm_name="Diffie-Hellman-2048",
                algorithm_type=CryptoAlgorithmType.KEY_EXCHANGE,
                threat_level=QuantumThreatLevel.NEAR_TERM,
                key_size=2048,
                quantum_attack_vector="Shor's Algorithm",
                time_to_break_classical="2^112 operations",
                time_to_break_quantum="~24 hours on fault-tolerant QC",
                recommended_replacement="Kyber-1024",
                migration_complexity="high",
                business_impact="critical"
            ),
            CryptoVulnerability(
                vuln_id="QC-ECDH-P256",
                algorithm_name="ECDH-P256",
                algorithm_type=CryptoAlgorithmType.KEY_EXCHANGE,
                threat_level=QuantumThreatLevel.IMMEDIATE,
                key_size=256,
                quantum_attack_vector="Shor's Algorithm (Elliptic Curve)",
                time_to_break_classical="2^128 operations",
                time_to_break_quantum="~2 hours on NISQ device",
                recommended_replacement="Kyber-768",
                migration_complexity="medium",
                business_impact="critical"
            ),

            # Symmetric Algorithm Analysis
            CryptoVulnerability(
                vuln_id="QC-AES-128",
                algorithm_name="AES-128",
                algorithm_type=CryptoAlgorithmType.SYMMETRIC,
                threat_level=QuantumThreatLevel.LONG_TERM,
                key_size=128,
                quantum_attack_vector="Grover's Algorithm",
                time_to_break_classical="2^128 operations",
                time_to_break_quantum="2^64 operations (~equivalent to AES-64)",
                recommended_replacement="AES-256",
                migration_complexity="low",
                business_impact="medium"
            ),
            CryptoVulnerability(
                vuln_id="QC-AES-256",
                algorithm_name="AES-256",
                algorithm_type=CryptoAlgorithmType.SYMMETRIC,
                threat_level=QuantumThreatLevel.QUANTUM_SAFE,
                key_size=256,
                quantum_attack_vector="Grover's Algorithm",
                time_to_break_classical="2^256 operations",
                time_to_break_quantum="2^128 operations (~equivalent to AES-128)",
                recommended_replacement="No replacement needed",
                migration_complexity="none",
                business_impact="low"
            ),

            # Hash Function Analysis
            CryptoVulnerability(
                vuln_id="QC-SHA-256",
                algorithm_name="SHA-256",
                algorithm_type=CryptoAlgorithmType.HASH,
                threat_level=QuantumThreatLevel.LONG_TERM,
                key_size=256,
                quantum_attack_vector="Grover's Algorithm",
                time_to_break_classical="2^256 preimage, 2^128 collision",
                time_to_break_quantum="2^128 preimage, 2^64 collision",
                recommended_replacement="SHA-3-512 or SHA-512",
                migration_complexity="low",
                business_impact="medium"
            ),
            CryptoVulnerability(
                vuln_id="QC-SHA-512",
                algorithm_name="SHA-512",
                algorithm_type=CryptoAlgorithmType.HASH,
                threat_level=QuantumThreatLevel.QUANTUM_SAFE,
                key_size=512,
                quantum_attack_vector="Grover's Algorithm",
                time_to_break_classical="2^512 preimage, 2^256 collision",
                time_to_break_quantum="2^256 preimage, 2^128 collision",
                recommended_replacement="No replacement needed",
                migration_complexity="none",
                business_impact="low"
            )
        ]

        return {vuln.vuln_id: vuln for vuln in vulnerabilities}

    def _initialize_quantum_attacks(self) -> Dict[str, Dict[str, Any]]:
        """Initialize quantum attack simulation suite"""
        return {
            "shors_algorithm": {
                "name": "Shor's Factorization Algorithm",
                "targets": ["RSA", "ECDSA", "DH", "ECDH"],
                "quantum_speedup": "exponential",
                "qubits_required_formula": "2n + 3",  # n = key size in bits
                "gate_complexity": "O(n^3)",
                "success_probability": 0.999,
                "fault_tolerance_required": True,
                "current_implementations": [
                    "IBM demonstrated factoring 15 using Shor's algorithm",
                    "Google/UCSB factored 143 using variational quantum eigensolver",
                    "Various implementations up to ~20-30 bit numbers"
                ]
            },
            "grovers_algorithm": {
                "name": "Grover's Search Algorithm",
                "targets": ["AES", "SHA", "symmetric_ciphers", "hash_functions"],
                "quantum_speedup": "quadratic",
                "qubits_required_formula": "n",  # n = key size in bits
                "gate_complexity": "O(sqrt(2^n))",
                "success_probability": 0.75,
                "fault_tolerance_required": False,
                "current_implementations": [
                    "IBM implemented 3-qubit Grover's search",
                    "Google demonstrated 12-qubit Grover with 99.5% fidelity",
                    "Various academic demonstrations up to ~20 qubits"
                ]
            },
            "quantum_period_finding": {
                "name": "Quantum Period Finding",
                "targets": ["discrete_log_protocols", "elliptic_curve_crypto"],
                "quantum_speedup": "exponential",
                "qubits_required_formula": "4n",  # Conservative estimate
                "gate_complexity": "O(n^3)",
                "success_probability": 0.95,
                "fault_tolerance_required": True,
                "current_implementations": [
                    "Period finding demonstrated for small moduli",
                    "Quantum Fourier Transform implementations",
                    "Proof-of-concept attacks on toy problems"
                ]
            },
            "variational_quantum_attacks": {
                "name": "Variational Quantum Eigensolvers (VQE)",
                "targets": ["optimization_based_crypto", "lattice_problems"],
                "quantum_speedup": "problem_dependent",
                "qubits_required_formula": "problem_size",
                "gate_complexity": "O(poly(n))",
                "success_probability": 0.6,
                "fault_tolerance_required": False,
                "current_implementations": [
                    "NISQ-era algorithms for small crypto problems",
                    "Quantum approximate optimization algorithm (QAOA)",
                    "Hybrid classical-quantum attacks"
                ]
            }
        }

    def _load_pqc_standards(self) -> Dict[str, Dict[str, Any]]:
        """Load post-quantum cryptography standards and recommendations"""
        return {
            "nist_pqc_finalists": {
                "key_encapsulation": {
                    "kyber": {
                        "variants": ["Kyber-512", "Kyber-768", "Kyber-1024"],
                        "security_level": [1, 3, 5],  # NIST security levels
                        "base_problem": "Module Learning With Errors (M-LWE)",
                        "standardization_status": "NIST Standard (FIPS 203)",
                        "recommended_for": ["TLS", "secure_messaging", "key_exchange"]
                    }
                },
                "digital_signatures": {
                    "dilithium": {
                        "variants": ["Dilithium-2", "Dilithium-3", "Dilithium-5"],
                        "security_level": [2, 3, 5],
                        "base_problem": "Module Learning With Errors (M-LWE)",
                        "standardization_status": "NIST Standard (FIPS 204)",
                        "recommended_for": ["code_signing", "certificates", "authentication"]
                    },
                    "sphincs_plus": {
                        "variants": ["SPHINCS+-128f", "SPHINCS+-192f", "SPHINCS+-256f"],
                        "security_level": [1, 3, 5],
                        "base_problem": "Hash-based signatures",
                        "standardization_status": "NIST Standard (FIPS 205)",
                        "recommended_for": ["long_term_signatures", "firmware_signing"]
                    }
                }
            },
            "migration_guidelines": {
                "hybrid_approach": {
                    "description": "Use both classical and post-quantum algorithms during transition",
                    "benefits": ["backward_compatibility", "defense_in_depth", "gradual_migration"],
                    "drawbacks": ["increased_overhead", "complexity", "larger_signatures"]
                },
                "crypto_agility": {
                    "description": "Design systems to easily swap cryptographic algorithms",
                    "requirements": ["algorithm_identifiers", "version_negotiation", "parameter_flexibility"],
                    "benefits": ["future_proofing", "rapid_response", "standardization_ready"]
                }
            }
        }

    def analyze_quantum_vulnerabilities(self, target_system: str, crypto_inventory: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze quantum cryptographic vulnerabilities in target system"""
        logger.info(f"🔮 Analyzing quantum cryptographic vulnerabilities: {target_system}")

        start_time = time.time()

        # Phase 1: Cryptographic Asset Discovery
        discovered_crypto = self._discover_crypto_assets(crypto_inventory)

        # Phase 2: Vulnerability Assessment
        vulnerability_assessment = self._assess_crypto_vulnerabilities(discovered_crypto)

        # Phase 3: Quantum Attack Simulation
        attack_simulations = self._simulate_quantum_attacks(discovered_crypto)

        # Phase 4: Risk Prioritization
        risk_analysis = self._prioritize_quantum_risks(vulnerability_assessment, attack_simulations)

        # Phase 5: Migration Roadmap
        migration_plan = self._generate_migration_roadmap(vulnerability_assessment)

        analysis_time = time.time() - start_time

        return {
            "quantum_crypto_analysis": {
                "session_id": self.session_id,
                "target_system": target_system,
                "analysis_timestamp": datetime.now().isoformat(),
                "analysis_duration_seconds": round(analysis_time, 2),
                "quantum_analyzer_version": "QUANTUMSENTINEL-5.0-CRYPTO"
            },
            "cryptographic_inventory": discovered_crypto,
            "vulnerability_assessment": vulnerability_assessment,
            "quantum_attack_simulations": attack_simulations,
            "risk_analysis": risk_analysis,
            "migration_roadmap": migration_plan,
            "compliance_status": self._assess_pqc_compliance(discovered_crypto),
            "recommendations": self._generate_quantum_crypto_recommendations(risk_analysis)
        }

    def _discover_crypto_assets(self, inventory: Dict[str, Any]) -> Dict[str, Any]:
        """Discover cryptographic assets in the system"""

        # Simulate cryptographic asset discovery
        discovered_assets = {
            "tls_certificates": [
                {"algorithm": "RSA-2048", "usage": "server_authentication", "expiry": "2025-12-31"},
                {"algorithm": "ECDSA-P256", "usage": "client_certificates", "expiry": "2024-06-15"}
            ],
            "api_signatures": [
                {"algorithm": "ECDSA-P256", "usage": "jwt_signing", "frequency": "high"},
                {"algorithm": "RSA-2048", "usage": "api_authentication", "frequency": "medium"}
            ],
            "data_encryption": [
                {"algorithm": "AES-256-GCM", "usage": "database_encryption", "data_sensitivity": "high"},
                {"algorithm": "AES-128-CBC", "usage": "file_encryption", "data_sensitivity": "medium"}
            ],
            "key_exchange": [
                {"algorithm": "ECDH-P256", "usage": "tls_handshake", "frequency": "very_high"},
                {"algorithm": "DH-2048", "usage": "vpn_tunnels", "frequency": "low"}
            ],
            "hash_functions": [
                {"algorithm": "SHA-256", "usage": "data_integrity", "frequency": "very_high"},
                {"algorithm": "SHA-1", "usage": "legacy_checksums", "frequency": "low"}
            ]
        }

        # Add metadata
        discovered_assets["discovery_metadata"] = {
            "total_crypto_assets": sum(len(assets) for assets in discovered_assets.values() if isinstance(assets, list)),
            "asset_categories": len([k for k, v in discovered_assets.items() if isinstance(v, list)]),
            "high_frequency_usage": len([
                asset for assets in discovered_assets.values()
                if isinstance(assets, list)
                for asset in assets
                if asset.get("frequency") in ["high", "very_high"]
            ]),
            "discovery_completeness": "estimated_85_percent"
        }

        return discovered_assets

    def _assess_crypto_vulnerabilities(self, discovered_crypto: Dict[str, Any]) -> Dict[str, Any]:
        """Assess vulnerabilities in discovered cryptographic assets"""

        vulnerability_results = {
            "critical_vulnerabilities": [],
            "high_risk_vulnerabilities": [],
            "medium_risk_vulnerabilities": [],
            "low_risk_vulnerabilities": [],
            "quantum_safe_algorithms": []
        }

        # Analyze each category of cryptographic assets
        for category, assets in discovered_crypto.items():
            if not isinstance(assets, list):
                continue

            for asset in assets:
                algorithm = asset.get("algorithm", "unknown")
                vuln_assessment = self._assess_single_algorithm(algorithm, asset)

                if vuln_assessment:
                    risk_level = self._determine_risk_level(vuln_assessment)
                    vuln_assessment["asset_context"] = asset
                    vuln_assessment["category"] = category

                    vulnerability_results[f"{risk_level}_vulnerabilities"].append(vuln_assessment)

        # Calculate summary statistics
        total_vulns = sum(len(vulns) for key, vulns in vulnerability_results.items() if key.endswith("_vulnerabilities"))

        vulnerability_results["summary"] = {
            "total_vulnerabilities_found": total_vulns,
            "critical_count": len(vulnerability_results["critical_vulnerabilities"]),
            "high_risk_count": len(vulnerability_results["high_risk_vulnerabilities"]),
            "medium_risk_count": len(vulnerability_results["medium_risk_vulnerabilities"]),
            "low_risk_count": len(vulnerability_results["low_risk_vulnerabilities"]),
            "quantum_safe_count": len(vulnerability_results["quantum_safe_algorithms"]),
            "overall_quantum_readiness": self._calculate_quantum_readiness(vulnerability_results)
        }

        return vulnerability_results

    def _assess_single_algorithm(self, algorithm: str, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Assess vulnerability of a single cryptographic algorithm"""

        # Find matching vulnerability in database
        matching_vulns = [
            vuln for vuln_id, vuln in self.vulnerability_database.items()
            if algorithm.lower() in vuln.algorithm_name.lower()
        ]

        if not matching_vulns:
            return None

        # Use the closest match
        vuln = matching_vulns[0]

        assessment = {
            "vulnerability_id": vuln.vuln_id,
            "algorithm": vuln.algorithm_name,
            "algorithm_type": vuln.algorithm_type.value,
            "threat_level": vuln.threat_level.value,
            "quantum_attack_vector": vuln.quantum_attack_vector,
            "time_to_break": {
                "classical": vuln.time_to_break_classical,
                "quantum": vuln.time_to_break_quantum
            },
            "recommended_replacement": vuln.recommended_replacement,
            "migration_complexity": vuln.migration_complexity,
            "business_impact": vuln.business_impact,
            "usage_frequency": context.get("frequency", "unknown"),
            "data_sensitivity": context.get("data_sensitivity", "unknown")
        }

        return assessment

    def _determine_risk_level(self, vulnerability: Dict[str, Any]) -> str:
        """Determine risk level based on threat level and context"""
        threat_level = vulnerability.get("threat_level", "long_term")
        business_impact = vulnerability.get("business_impact", "low")
        frequency = vulnerability.get("usage_frequency", "low")

        # Risk calculation matrix
        if threat_level == "immediate":
            return "critical"
        elif threat_level == "near_term" and business_impact in ["critical", "high"]:
            return "critical"
        elif threat_level == "near_term" or (threat_level == "long_term" and business_impact == "critical"):
            return "high_risk"
        elif threat_level == "long_term" and business_impact in ["high", "medium"]:
            return "medium_risk"
        elif threat_level == "quantum_safe":
            return "quantum_safe_algorithms"
        else:
            return "low_risk"

    def _simulate_quantum_attacks(self, discovered_crypto: Dict[str, Any]) -> List[QuantumAttackSimulation]:
        """Simulate quantum attacks against discovered cryptographic assets"""

        simulations = []
        attack_counter = 1

        for category, assets in discovered_crypto.items():
            if not isinstance(assets, list):
                continue

            for asset in assets:
                algorithm = asset.get("algorithm", "unknown")

                # Determine applicable quantum attacks
                applicable_attacks = self._get_applicable_attacks(algorithm)

                for attack_name in applicable_attacks:
                    simulation = self._run_attack_simulation(
                        attack_counter, algorithm, attack_name, asset
                    )
                    simulations.append(simulation)
                    attack_counter += 1

        return simulations

    def _get_applicable_attacks(self, algorithm: str) -> List[str]:
        """Get applicable quantum attacks for an algorithm"""
        algorithm_lower = algorithm.lower()

        applicable = []

        # Check each attack type
        for attack_name, attack_info in self.quantum_attack_suite.items():
            targets = attack_info["targets"]

            for target in targets:
                if target.lower() in algorithm_lower or algorithm_lower.startswith(target.lower()):
                    applicable.append(attack_name)
                    break

        return applicable

    def _run_attack_simulation(self, attack_id: int, algorithm: str, attack_name: str, context: Dict[str, Any]) -> QuantumAttackSimulation:
        """Run a single quantum attack simulation"""

        attack_info = self.quantum_attack_suite[attack_name]

        # Extract key size for quantum resource estimation
        key_size = self._extract_key_size(algorithm)

        # Calculate quantum resources required
        quantum_resources = self._calculate_quantum_resources(attack_name, key_size)

        # Estimate success probability based on current quantum computing capabilities
        success_prob = self._estimate_success_probability(attack_name, key_size)

        # Estimate time to complete attack
        estimated_time = self._estimate_attack_time(attack_name, key_size, quantum_resources)

        # Determine if key recovery would be successful
        key_recovery = success_prob > 0.8 and quantum_resources["logical_qubits"] < 10000  # Practical threshold

        # Generate attack evidence
        evidence = self._generate_attack_evidence(attack_name, algorithm, success_prob)

        return QuantumAttackSimulation(
            attack_id=f"QA-{attack_id:04d}",
            target_algorithm=algorithm,
            attack_method=attack_info["name"],
            success_probability=success_prob,
            quantum_resources_required=quantum_resources,
            estimated_time_hours=estimated_time,
            key_recovery_successful=key_recovery,
            attack_evidence=evidence
        )

    def _extract_key_size(self, algorithm: str) -> int:
        """Extract key size from algorithm name"""
        import re

        # Try to find numbers in algorithm name
        numbers = re.findall(r'\d+', algorithm)

        if numbers:
            return int(numbers[-1])  # Use the last number found

        # Default key sizes for common algorithms
        defaults = {
            "rsa": 2048,
            "ecdsa": 256,
            "ecdh": 256,
            "dh": 2048,
            "aes": 256,
            "sha": 256
        }

        for alg, default_size in defaults.items():
            if alg in algorithm.lower():
                return default_size

        return 256  # Default fallback

    def _calculate_quantum_resources(self, attack_name: str, key_size: int) -> Dict[str, int]:
        """Calculate quantum computing resources required for attack"""

        if attack_name == "shors_algorithm":
            # Shor's algorithm resource requirements
            logical_qubits = 2 * key_size + 3
            physical_qubits = logical_qubits * 1000  # Assuming ~1000:1 error correction overhead
            gate_operations = key_size ** 3

        elif attack_name == "grovers_algorithm":
            # Grover's algorithm resource requirements
            logical_qubits = key_size
            physical_qubits = logical_qubits * 100  # Lower error correction needs
            gate_operations = int(math.sqrt(2 ** key_size))

        elif attack_name == "quantum_period_finding":
            # Period finding resource requirements
            logical_qubits = 4 * key_size
            physical_qubits = logical_qubits * 1000
            gate_operations = key_size ** 3

        else:  # variational_quantum_attacks
            # VQE/QAOA resource requirements
            logical_qubits = min(key_size, 100)  # Limited by current NISQ capabilities
            physical_qubits = logical_qubits * 10  # Much lower overhead
            gate_operations = key_size ** 2

        return {
            "logical_qubits": logical_qubits,
            "physical_qubits": physical_qubits,
            "gate_operations": gate_operations,
            "error_correction_overhead": physical_qubits // logical_qubits if logical_qubits > 0 else 1
        }

    def _estimate_success_probability(self, attack_name: str, key_size: int) -> float:
        """Estimate attack success probability based on current capabilities"""

        base_prob = self.quantum_attack_suite[attack_name]["success_probability"]

        # Adjust based on key size and current quantum computing limitations
        if attack_name in ["shors_algorithm", "quantum_period_finding"]:
            # Exponential scaling attacks - very limited by current QC capabilities
            if key_size <= 15:  # Demonstrated range
                return base_prob * 0.9
            elif key_size <= 100:  # Near-term possibility
                return base_prob * 0.3
            elif key_size <= 2048:  # Fault-tolerant QC required
                return base_prob * 0.1
            else:  # Far future
                return base_prob * 0.01

        elif attack_name == "grovers_algorithm":
            # Quadratic speedup - more achievable on NISQ devices
            if key_size <= 64:  # Current NISQ range
                return base_prob * 0.7
            elif key_size <= 256:  # Near-term fault-tolerant QC
                return base_prob * 0.4
            else:  # Future fault-tolerant QC
                return base_prob * 0.2

        else:  # variational_quantum_attacks
            # NISQ-era algorithms
            if key_size <= 50:
                return base_prob * 0.8
            elif key_size <= 200:
                return base_prob * 0.4
            else:
                return base_prob * 0.1

    def _estimate_attack_time(self, attack_name: str, key_size: int, resources: Dict[str, int]) -> float:
        """Estimate time required to complete attack"""

        # Base time estimates in hours
        base_times = {
            "shors_algorithm": key_size * 0.1,  # Scales with key size
            "grovers_algorithm": math.sqrt(2 ** min(key_size, 32)) / 1000000,  # Grover iterations
            "quantum_period_finding": key_size * 0.2,
            "variational_quantum_attacks": key_size * 0.05  # NISQ algorithms are faster but less certain
        }

        base_time = base_times.get(attack_name, 24.0)

        # Scale by quantum resource availability (simulated)
        resource_scaling = min(resources["logical_qubits"] / 1000, 10.0)  # More qubits = potentially faster

        return max(0.1, base_time / (1 + resource_scaling * 0.1))

    def _generate_attack_evidence(self, attack_name: str, algorithm: str, success_prob: float) -> List[str]:
        """Generate evidence for quantum attack simulation"""

        evidence_templates = {
            "shors_algorithm": [
                f"Shor's algorithm applicable to {algorithm} due to integer factorization dependency",
                f"Estimated success probability: {success_prob:.2%}",
                f"Quantum period finding subroutine can extract private key components",
                "Attack requires fault-tolerant quantum computer for practical key sizes"
            ],
            "grovers_algorithm": [
                f"Grover's search provides quadratic speedup against {algorithm}",
                f"Effective key strength reduced by half: {algorithm} → equivalent classical strength",
                f"Success probability: {success_prob:.2%}",
                "Attack feasible on NISQ devices for smaller key sizes"
            ],
            "quantum_period_finding": [
                f"Quantum period finding attacks discrete logarithm basis of {algorithm}",
                f"Period extraction reveals private key material",
                f"Estimated success rate: {success_prob:.2%}",
                "Requires quantum Fourier transform implementation"
            ],
            "variational_quantum_attacks": [
                f"Variational quantum algorithms can optimize against {algorithm}",
                f"NISQ-era attack with {success_prob:.2%} success rate",
                "Hybrid classical-quantum approach reduces quantum resource requirements",
                "Attack effectiveness depends on problem structure and noise levels"
            ]
        }

        return evidence_templates.get(attack_name, [f"Generic quantum attack against {algorithm}"])

    def _prioritize_quantum_risks(self, vulnerability_assessment: Dict[str, Any], attack_simulations: List[QuantumAttackSimulation]) -> Dict[str, Any]:
        """Prioritize quantum cryptographic risks"""

        # Calculate overall risk scores
        risk_scores = []

        for vuln_category in ["critical_vulnerabilities", "high_risk_vulnerabilities", "medium_risk_vulnerabilities"]:
            for vuln in vulnerability_assessment.get(vuln_category, []):

                # Find corresponding attack simulations
                relevant_attacks = [
                    sim for sim in attack_simulations
                    if sim.target_algorithm.lower() in vuln["algorithm"].lower()
                ]

                # Calculate composite risk score
                threat_level_score = {
                    "immediate": 10, "near_term": 7, "long_term": 4, "quantum_safe": 1
                }.get(vuln.get("threat_level", "long_term"), 4)

                business_impact_score = {
                    "critical": 10, "high": 7, "medium": 4, "low": 1
                }.get(vuln.get("business_impact", "low"), 1)

                usage_frequency_score = {
                    "very_high": 5, "high": 4, "medium": 3, "low": 2, "unknown": 2
                }.get(vuln.get("usage_frequency", "unknown"), 2)

                # Factor in attack simulation results
                max_attack_success = max([sim.success_probability for sim in relevant_attacks], default=0.0)
                attack_feasibility_score = max_attack_success * 10

                composite_risk = (
                    threat_level_score * 0.4 +
                    business_impact_score * 0.3 +
                    usage_frequency_score * 0.2 +
                    attack_feasibility_score * 0.1
                )

                risk_scores.append({
                    "algorithm": vuln["algorithm"],
                    "category": vuln.get("category", "unknown"),
                    "composite_risk_score": round(composite_risk, 2),
                    "threat_level": vuln.get("threat_level", "unknown"),
                    "business_impact": vuln.get("business_impact", "unknown"),
                    "attack_feasibility": round(max_attack_success, 3),
                    "migration_priority": self._determine_migration_priority(composite_risk)
                })

        # Sort by risk score
        risk_scores.sort(key=lambda x: x["composite_risk_score"], reverse=True)

        return {
            "prioritized_risks": risk_scores[:20],  # Top 20 risks
            "risk_distribution": {
                "immediate_action_required": len([r for r in risk_scores if r["composite_risk_score"] >= 8.0]),
                "high_priority": len([r for r in risk_scores if 6.0 <= r["composite_risk_score"] < 8.0]),
                "medium_priority": len([r for r in risk_scores if 4.0 <= r["composite_risk_score"] < 6.0]),
                "low_priority": len([r for r in risk_scores if r["composite_risk_score"] < 4.0])
            },
            "overall_quantum_risk_level": self._calculate_overall_risk_level(risk_scores)
        }

    def _determine_migration_priority(self, risk_score: float) -> str:
        """Determine migration priority based on risk score"""
        if risk_score >= 8.0:
            return "immediate"
        elif risk_score >= 6.0:
            return "within_6_months"
        elif risk_score >= 4.0:
            return "within_2_years"
        else:
            return "long_term_planning"

    def _calculate_overall_risk_level(self, risk_scores: List[Dict[str, Any]]) -> str:
        """Calculate overall quantum risk level"""
        if not risk_scores:
            return "low"

        avg_risk = sum(r["composite_risk_score"] for r in risk_scores) / len(risk_scores)
        high_risk_count = len([r for r in risk_scores if r["composite_risk_score"] >= 7.0])

        if avg_risk >= 7.0 or high_risk_count >= 5:
            return "critical"
        elif avg_risk >= 5.0 or high_risk_count >= 2:
            return "high"
        elif avg_risk >= 3.0:
            return "medium"
        else:
            return "low"

    def _generate_migration_roadmap(self, vulnerability_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Generate post-quantum cryptography migration roadmap"""

        pqc_standards = self.post_quantum_recommendations["nist_pqc_finalists"]

        migration_phases = {
            "phase_1_immediate": {
                "timeline": "0-6 months",
                "description": "Address critical quantum vulnerabilities",
                "actions": [],
                "algorithms_to_replace": [],
                "estimated_effort": "high"
            },
            "phase_2_near_term": {
                "timeline": "6-18 months",
                "description": "Replace high-risk algorithms with hybrid approach",
                "actions": [],
                "algorithms_to_replace": [],
                "estimated_effort": "very_high"
            },
            "phase_3_long_term": {
                "timeline": "18+ months",
                "description": "Complete transition to post-quantum cryptography",
                "actions": [],
                "algorithms_to_replace": [],
                "estimated_effort": "medium"
            }
        }

        # Categorize algorithms by migration phase
        for vuln_category, phase_key in [
            ("critical_vulnerabilities", "phase_1_immediate"),
            ("high_risk_vulnerabilities", "phase_2_near_term"),
            ("medium_risk_vulnerabilities", "phase_3_long_term")
        ]:
            for vuln in vulnerability_assessment.get(vuln_category, []):
                algorithm = vuln["algorithm"]
                replacement = vuln.get("recommended_replacement", "TBD")

                migration_phases[phase_key]["algorithms_to_replace"].append({
                    "current": algorithm,
                    "replacement": replacement,
                    "migration_complexity": vuln.get("migration_complexity", "unknown"),
                    "category": vuln.get("category", "unknown")
                })

        # Generate specific actions for each phase
        migration_phases["phase_1_immediate"]["actions"] = [
            "Conduct detailed cryptographic inventory",
            "Prioritize critical business systems",
            "Begin hybrid cryptography implementation",
            "Update security policies and standards"
        ]

        migration_phases["phase_2_near_term"]["actions"] = [
            "Deploy post-quantum algorithms for new systems",
            "Implement crypto-agility frameworks",
            "Begin systematic replacement of vulnerable algorithms",
            "Staff training on post-quantum cryptography"
        ]

        migration_phases["phase_3_long_term"]["actions"] = [
            "Complete migration to post-quantum standards",
            "Decommission legacy cryptographic systems",
            "Continuous monitoring and compliance validation",
            "Regular post-quantum security assessments"
        ]

        return {
            "migration_phases": migration_phases,
            "recommended_pqc_algorithms": {
                "key_encapsulation": pqc_standards["key_encapsulation"]["kyber"],
                "digital_signatures": pqc_standards["digital_signatures"]["dilithium"],
                "backup_signatures": pqc_standards["digital_signatures"]["sphincs_plus"]
            },
            "migration_principles": [
                "Crypto-agility: Design systems to easily swap algorithms",
                "Hybrid approach: Use both classical and post-quantum during transition",
                "Risk-based prioritization: Address highest risk systems first",
                "Standards compliance: Follow NIST and industry standards",
                "Continuous assessment: Regular evaluation of quantum threat landscape"
            ]
        }

    def _calculate_quantum_readiness(self, vulnerability_results: Dict[str, Any]) -> float:
        """Calculate overall quantum readiness score"""
        total_assets = sum(len(vulns) for key, vulns in vulnerability_results.items() if key.endswith("_vulnerabilities"))

        if total_assets == 0:
            return 100.0

        quantum_safe_count = len(vulnerability_results.get("quantum_safe_algorithms", []))
        critical_count = len(vulnerability_results.get("critical_vulnerabilities", []))
        high_risk_count = len(vulnerability_results.get("high_risk_vulnerabilities", []))

        # Scoring: quantum-safe algorithms add to score, vulnerabilities reduce it
        readiness_score = (quantum_safe_count / total_assets) * 100
        readiness_score -= (critical_count / total_assets) * 60  # Critical vulns heavily impact score
        readiness_score -= (high_risk_count / total_assets) * 30  # High-risk vulns moderately impact

        return max(0.0, min(100.0, round(readiness_score, 1)))

    def _assess_pqc_compliance(self, discovered_crypto: Dict[str, Any]) -> Dict[str, Any]:
        """Assess post-quantum cryptography compliance status"""

        compliance_status = {
            "nist_pqc_compliance": "non_compliant",
            "standards_alignment": [],
            "compliant_algorithms": [],
            "non_compliant_algorithms": [],
            "compliance_score": 0.0
        }

        # NIST-approved post-quantum algorithms
        nist_approved = [
            "kyber-512", "kyber-768", "kyber-1024",
            "dilithium-2", "dilithium-3", "dilithium-5",
            "sphincs+-128f", "sphincs+-192f", "sphincs+-256f"
        ]

        total_algorithms = 0
        compliant_count = 0

        for category, assets in discovered_crypto.items():
            if not isinstance(assets, list):
                continue

            for asset in assets:
                algorithm = asset.get("algorithm", "").lower()
                total_algorithms += 1

                is_compliant = any(nist_alg in algorithm for nist_alg in nist_approved)

                if is_compliant:
                    compliant_count += 1
                    compliance_status["compliant_algorithms"].append({
                        "algorithm": asset.get("algorithm"),
                        "category": category,
                        "usage": asset.get("usage", "unknown")
                    })
                else:
                    compliance_status["non_compliant_algorithms"].append({
                        "algorithm": asset.get("algorithm"),
                        "category": category,
                        "quantum_vulnerability": self._get_quantum_threat_level(algorithm)
                    })

        if total_algorithms > 0:
            compliance_status["compliance_score"] = round((compliant_count / total_algorithms) * 100, 1)

        # Determine overall compliance status
        if compliance_status["compliance_score"] >= 95:
            compliance_status["nist_pqc_compliance"] = "fully_compliant"
        elif compliance_status["compliance_score"] >= 75:
            compliance_status["nist_pqc_compliance"] = "mostly_compliant"
        elif compliance_status["compliance_score"] >= 25:
            compliance_status["nist_pqc_compliance"] = "partially_compliant"
        else:
            compliance_status["nist_pqc_compliance"] = "non_compliant"

        return compliance_status

    def _get_quantum_threat_level(self, algorithm: str) -> str:
        """Get quantum threat level for algorithm"""
        for vuln in self.vulnerability_database.values():
            if algorithm.lower() in vuln.algorithm_name.lower():
                return vuln.threat_level.value
        return "unknown"

    def _generate_quantum_crypto_recommendations(self, risk_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate quantum cryptography recommendations"""

        recommendations = []

        overall_risk = risk_analysis.get("overall_quantum_risk_level", "medium")

        if overall_risk in ["critical", "high"]:
            recommendations.extend([
                {
                    "priority": "critical",
                    "category": "immediate_action",
                    "recommendation": "Begin immediate migration planning for critical systems",
                    "rationale": f"Overall quantum risk level is {overall_risk}",
                    "timeline": "within_30_days"
                },
                {
                    "priority": "critical",
                    "category": "crypto_inventory",
                    "recommendation": "Complete comprehensive cryptographic asset inventory",
                    "rationale": "Cannot protect what you cannot identify",
                    "timeline": "within_60_days"
                }
            ])

        # Always include these foundational recommendations
        recommendations.extend([
            {
                "priority": "high",
                "category": "crypto_agility",
                "recommendation": "Implement crypto-agility in all new systems",
                "rationale": "Enable rapid algorithm replacement when quantum threat materializes",
                "timeline": "within_6_months"
            },
            {
                "priority": "high",
                "category": "hybrid_approach",
                "recommendation": "Deploy hybrid classical-quantum cryptography",
                "rationale": "Provides security during transition period",
                "timeline": "within_12_months"
            },
            {
                "priority": "medium",
                "category": "staff_training",
                "recommendation": "Train technical staff on post-quantum cryptography",
                "rationale": "Knowledge gap is significant barrier to adoption",
                "timeline": "ongoing"
            },
            {
                "priority": "medium",
                "category": "monitoring",
                "recommendation": "Establish quantum threat intelligence monitoring",
                "rationale": "Stay informed about quantum computing advances and threats",
                "timeline": "within_3_months"
            }
        ])

        return recommendations

def main():
    """Demo quantum crypto analyzer"""
    analyzer = QuantumCryptoAnalyzer()

    # Sample crypto inventory
    crypto_inventory = {
        "discovered_systems": ["web_app", "api_gateway", "database"],
        "scan_depth": "comprehensive"
    }

    results = analyzer.analyze_quantum_vulnerabilities("Healthcare LLM System", crypto_inventory)

    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()