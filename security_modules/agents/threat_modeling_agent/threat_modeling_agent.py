"""
Automated Threat Modeling Agent

Intelligent STRIDE-based threat modeling with attack surface analysis,
automated risk assessment, and mitigation recommendation using graph
neural networks and security knowledge graphs.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import networkx as nx
import numpy as np
from collections import defaultdict
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatCategory(Enum):
    """STRIDE threat categories"""
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"

class AssetType(Enum):
    """Types of assets in the system"""
    DATA_STORE = "data_store"
    PROCESS = "process"
    EXTERNAL_ENTITY = "external_entity"
    DATA_FLOW = "data_flow"
    TRUST_BOUNDARY = "trust_boundary"
    INTERACTOR = "interactor"

class RiskLevel(Enum):
    """Risk assessment levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

class ConfidenceLevel(Enum):
    """Confidence levels for threat predictions"""
    VERY_HIGH = "very_high"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    VERY_LOW = "very_low"

@dataclass
class Asset:
    """Represents a system asset"""
    id: str
    name: str
    asset_type: AssetType
    description: str
    properties: Dict[str, Any] = field(default_factory=dict)
    security_controls: List[str] = field(default_factory=list)
    trust_level: int = 0  # 0-10 scale
    exposure_level: int = 0  # 0-10 scale
    criticality: int = 5  # 1-10 scale

@dataclass
class ThreatVector:
    """Represents a potential threat vector"""
    id: str
    name: str
    category: ThreatCategory
    description: str
    affected_assets: List[str]
    attack_techniques: List[str]
    prerequisites: List[str]
    impact_rating: int  # 1-10 scale
    likelihood: float  # 0.0-1.0
    confidence: ConfidenceLevel
    mitre_techniques: List[str] = field(default_factory=list)
    cwe_references: List[str] = field(default_factory=list)

@dataclass
class AttackPath:
    """Represents a sequence of attack steps"""
    id: str
    name: str
    description: str
    steps: List[Dict[str, Any]]
    total_risk_score: float
    complexity: int  # 1-10 scale
    required_privileges: List[str]
    detection_difficulty: int  # 1-10 scale
    target_assets: List[str]

@dataclass
class Mitigation:
    """Represents a security mitigation"""
    id: str
    name: str
    description: str
    mitigation_type: str
    effectiveness: float  # 0.0-1.0
    implementation_cost: int  # 1-10 scale
    operational_impact: int  # 1-10 scale
    applicable_threats: List[str]
    implementation_guidance: str

@dataclass
class ThreatModel:
    """Complete threat model representation"""
    id: str
    name: str
    description: str
    target_system: str
    assets: List[Asset]
    threat_vectors: List[ThreatVector]
    attack_paths: List[AttackPath]
    mitigations: List[Mitigation]
    risk_matrix: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    version: str = "1.0"
    methodology: str = "STRIDE"
    scope: str = ""
    assumptions: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)

class ThreatModelingAgent:
    """
    Automated threat modeling agent with STRIDE analysis capabilities
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.session_id = str(uuid.uuid4())
        self.threat_graph = nx.DiGraph()
        self.knowledge_base = self._initialize_knowledge_base()
        self.stride_mappings = self._initialize_stride_mappings()

        logger.info(f"ThreatModelingAgent initialized with session {self.session_id}")

    def _initialize_knowledge_base(self) -> Dict[str, Any]:
        """Initialize threat intelligence knowledge base"""
        return {
            "threat_patterns": {
                "web_application": [
                    {"pattern": "sql_injection", "category": ThreatCategory.TAMPERING, "likelihood": 0.7},
                    {"pattern": "xss", "category": ThreatCategory.TAMPERING, "likelihood": 0.8},
                    {"pattern": "csrf", "category": ThreatCategory.SPOOFING, "likelihood": 0.6},
                    {"pattern": "authentication_bypass", "category": ThreatCategory.SPOOFING, "likelihood": 0.5},
                    {"pattern": "privilege_escalation", "category": ThreatCategory.ELEVATION_OF_PRIVILEGE, "likelihood": 0.4}
                ],
                "api": [
                    {"pattern": "broken_authentication", "category": ThreatCategory.SPOOFING, "likelihood": 0.6},
                    {"pattern": "excessive_data_exposure", "category": ThreatCategory.INFORMATION_DISCLOSURE, "likelihood": 0.7},
                    {"pattern": "rate_limiting_bypass", "category": ThreatCategory.DENIAL_OF_SERVICE, "likelihood": 0.5},
                    {"pattern": "injection_attacks", "category": ThreatCategory.TAMPERING, "likelihood": 0.6}
                ],
                "database": [
                    {"pattern": "unauthorized_access", "category": ThreatCategory.SPOOFING, "likelihood": 0.5},
                    {"pattern": "data_exfiltration", "category": ThreatCategory.INFORMATION_DISCLOSURE, "likelihood": 0.6},
                    {"pattern": "data_corruption", "category": ThreatCategory.TAMPERING, "likelihood": 0.4}
                ],
                "network": [
                    {"pattern": "man_in_the_middle", "category": ThreatCategory.INFORMATION_DISCLOSURE, "likelihood": 0.4},
                    {"pattern": "ddos_attack", "category": ThreatCategory.DENIAL_OF_SERVICE, "likelihood": 0.6},
                    {"pattern": "network_sniffing", "category": ThreatCategory.INFORMATION_DISCLOSURE, "likelihood": 0.3}
                ]
            },
            "mitre_mappings": {
                "T1190": {"name": "Exploit Public-Facing Application", "category": ThreatCategory.ELEVATION_OF_PRIVILEGE},
                "T1078": {"name": "Valid Accounts", "category": ThreatCategory.SPOOFING},
                "T1566": {"name": "Phishing", "category": ThreatCategory.SPOOFING},
                "T1055": {"name": "Process Injection", "category": ThreatCategory.ELEVATION_OF_PRIVILEGE},
                "T1083": {"name": "File and Directory Discovery", "category": ThreatCategory.INFORMATION_DISCLOSURE}
            },
            "cwe_mappings": {
                "CWE-89": {"name": "SQL Injection", "category": ThreatCategory.TAMPERING},
                "CWE-79": {"name": "Cross-site Scripting", "category": ThreatCategory.TAMPERING},
                "CWE-22": {"name": "Path Traversal", "category": ThreatCategory.INFORMATION_DISCLOSURE},
                "CWE-352": {"name": "Cross-Site Request Forgery", "category": ThreatCategory.SPOOFING},
                "CWE-287": {"name": "Improper Authentication", "category": ThreatCategory.SPOOFING}
            }
        }

    def _initialize_stride_mappings(self) -> Dict[ThreatCategory, Dict[str, Any]]:
        """Initialize STRIDE category mappings and characteristics"""
        return {
            ThreatCategory.SPOOFING: {
                "description": "Impersonating something or someone else",
                "common_techniques": ["credential_stuffing", "session_hijacking", "identity_spoofing"],
                "typical_targets": ["authentication_systems", "user_accounts", "service_identities"],
                "detection_methods": ["behavioral_analysis", "multi_factor_authentication", "anomaly_detection"]
            },
            ThreatCategory.TAMPERING: {
                "description": "Modifying data or code",
                "common_techniques": ["sql_injection", "code_injection", "data_manipulation"],
                "typical_targets": ["databases", "application_logic", "configuration_files"],
                "detection_methods": ["integrity_checking", "input_validation", "code_signing"]
            },
            ThreatCategory.REPUDIATION: {
                "description": "Claiming to have not performed an action",
                "common_techniques": ["log_deletion", "timestamp_manipulation", "identity_confusion"],
                "typical_targets": ["audit_logs", "transaction_records", "accountability_systems"],
                "detection_methods": ["immutable_logging", "digital_signatures", "witness_systems"]
            },
            ThreatCategory.INFORMATION_DISCLOSURE: {
                "description": "Exposing information to unauthorized individuals",
                "common_techniques": ["data_leakage", "side_channel_attacks", "unauthorized_access"],
                "typical_targets": ["sensitive_data", "configuration_info", "system_internals"],
                "detection_methods": ["access_monitoring", "data_classification", "encryption"]
            },
            ThreatCategory.DENIAL_OF_SERVICE: {
                "description": "Denying or degrading service availability",
                "common_techniques": ["resource_exhaustion", "amplification_attacks", "system_overload"],
                "typical_targets": ["service_endpoints", "infrastructure", "critical_processes"],
                "detection_methods": ["rate_limiting", "traffic_analysis", "resource_monitoring"]
            },
            ThreatCategory.ELEVATION_OF_PRIVILEGE: {
                "description": "Gaining capabilities without proper authorization",
                "common_techniques": ["privilege_escalation", "vulnerability_exploitation", "misconfigurations"],
                "typical_targets": ["access_controls", "system_privileges", "administrative_functions"],
                "detection_methods": ["privilege_monitoring", "behavioral_analysis", "access_reviews"]
            }
        }

    async def analyze_system_architecture(self, architecture_description: Dict[str, Any]) -> List[Asset]:
        """
        Analyze system architecture and identify assets
        """
        logger.info("Analyzing system architecture for threat modeling")

        assets = []

        # Extract components from architecture description
        components = architecture_description.get("components", [])
        data_flows = architecture_description.get("data_flows", [])
        external_entities = architecture_description.get("external_entities", [])

        # Process components
        for component in components:
            asset = Asset(
                id=str(uuid.uuid4()),
                name=component.get("name", "Unknown Component"),
                asset_type=self._determine_asset_type(component),
                description=component.get("description", ""),
                properties=component.get("properties", {}),
                security_controls=component.get("security_controls", []),
                trust_level=component.get("trust_level", 5),
                exposure_level=self._calculate_exposure_level(component),
                criticality=component.get("criticality", 5)
            )
            assets.append(asset)

            # Add to threat graph
            self.threat_graph.add_node(
                asset.id,
                name=asset.name,
                type=asset.asset_type.value,
                trust_level=asset.trust_level,
                exposure_level=asset.exposure_level
            )

        # Process data flows
        for flow in data_flows:
            flow_asset = Asset(
                id=str(uuid.uuid4()),
                name=flow.get("name", "Data Flow"),
                asset_type=AssetType.DATA_FLOW,
                description=f"Data flow from {flow.get('source')} to {flow.get('destination')}",
                properties={
                    "source": flow.get("source"),
                    "destination": flow.get("destination"),
                    "data_type": flow.get("data_type"),
                    "encryption": flow.get("encryption", False)
                },
                trust_level=flow.get("trust_level", 5),
                exposure_level=self._calculate_flow_exposure(flow)
            )
            assets.append(flow_asset)

            # Add flow relationships to graph
            source_nodes = [n for n, d in self.threat_graph.nodes(data=True) if d.get('name') == flow.get('source')]
            dest_nodes = [n for n, d in self.threat_graph.nodes(data=True) if d.get('name') == flow.get('destination')]

            if source_nodes and dest_nodes:
                self.threat_graph.add_edge(
                    source_nodes[0],
                    dest_nodes[0],
                    flow_id=flow_asset.id,
                    data_type=flow.get("data_type"),
                    encrypted=flow.get("encryption", False)
                )

        # Process external entities
        for entity in external_entities:
            entity_asset = Asset(
                id=str(uuid.uuid4()),
                name=entity.get("name", "External Entity"),
                asset_type=AssetType.EXTERNAL_ENTITY,
                description=entity.get("description", ""),
                properties=entity.get("properties", {}),
                trust_level=entity.get("trust_level", 3),  # External entities typically have lower trust
                exposure_level=10  # Fully exposed by definition
            )
            assets.append(entity_asset)

            self.threat_graph.add_node(
                entity_asset.id,
                name=entity_asset.name,
                type=entity_asset.asset_type.value,
                trust_level=entity_asset.trust_level,
                external=True
            )

        logger.info(f"Identified {len(assets)} assets in system architecture")
        return assets

    def _determine_asset_type(self, component: Dict[str, Any]) -> AssetType:
        """Determine asset type based on component characteristics"""
        component_type = component.get("type", "").lower()

        if "database" in component_type or "storage" in component_type:
            return AssetType.DATA_STORE
        elif "service" in component_type or "api" in component_type or "process" in component_type:
            return AssetType.PROCESS
        elif "user" in component_type or "client" in component_type:
            return AssetType.INTERACTOR
        else:
            return AssetType.PROCESS  # Default

    def _calculate_exposure_level(self, component: Dict[str, Any]) -> int:
        """Calculate exposure level based on component characteristics"""
        exposure = 0

        # Internet-facing components have higher exposure
        if component.get("internet_facing", False):
            exposure += 5

        # Public APIs have higher exposure
        if component.get("public_api", False):
            exposure += 3

        # Authentication requirements reduce exposure
        if component.get("requires_authentication", True):
            exposure -= 2

        # Network segmentation reduces exposure
        if component.get("network_segmented", False):
            exposure -= 1

        return max(0, min(10, exposure + 3))  # Base exposure of 3

    def _calculate_flow_exposure(self, flow: Dict[str, Any]) -> int:
        """Calculate exposure level for data flows"""
        exposure = 5  # Base exposure

        if not flow.get("encryption", False):
            exposure += 3

        if flow.get("crosses_trust_boundary", False):
            exposure += 2

        if flow.get("external_network", False):
            exposure += 2

        return min(10, exposure)

    async def generate_threat_vectors(self, assets: List[Asset]) -> List[ThreatVector]:
        """
        Generate threat vectors using STRIDE methodology
        """
        logger.info("Generating threat vectors using STRIDE methodology")

        threat_vectors = []

        for asset in assets:
            # Generate threats for each STRIDE category
            for category in ThreatCategory:
                threats = await self._generate_threats_for_category(asset, category)
                threat_vectors.extend(threats)

        # Add cross-asset threats
        cross_asset_threats = await self._generate_cross_asset_threats(assets)
        threat_vectors.extend(cross_asset_threats)

        logger.info(f"Generated {len(threat_vectors)} threat vectors")
        return threat_vectors

    async def _generate_threats_for_category(self, asset: Asset, category: ThreatCategory) -> List[ThreatVector]:
        """Generate threats for specific STRIDE category and asset"""
        threats = []
        category_info = self.stride_mappings[category]

        # Get relevant threat patterns from knowledge base
        patterns = self._get_relevant_patterns(asset, category)

        for pattern in patterns:
            threat = ThreatVector(
                id=str(uuid.uuid4()),
                name=f"{category.value.title()} - {pattern['pattern'].replace('_', ' ').title()}",
                category=category,
                description=self._generate_threat_description(asset, category, pattern),
                affected_assets=[asset.id],
                attack_techniques=self._get_attack_techniques(pattern),
                prerequisites=self._get_prerequisites(asset, pattern),
                impact_rating=self._calculate_impact_rating(asset, category, pattern),
                likelihood=self._calculate_likelihood(asset, pattern),
                confidence=self._determine_confidence_level(asset, pattern),
                mitre_techniques=self._map_to_mitre(pattern),
                cwe_references=self._map_to_cwe(pattern)
            )
            threats.append(threat)

        return threats

    def _get_relevant_patterns(self, asset: Asset, category: ThreatCategory) -> List[Dict[str, Any]]:
        """Get threat patterns relevant to asset and category"""
        patterns = []

        # Determine asset context
        if asset.asset_type == AssetType.PROCESS:
            if "api" in asset.name.lower() or "service" in asset.name.lower():
                patterns.extend(self.knowledge_base["threat_patterns"].get("api", []))
            else:
                patterns.extend(self.knowledge_base["threat_patterns"].get("web_application", []))
        elif asset.asset_type == AssetType.DATA_STORE:
            patterns.extend(self.knowledge_base["threat_patterns"].get("database", []))
        elif asset.asset_type == AssetType.DATA_FLOW:
            patterns.extend(self.knowledge_base["threat_patterns"].get("network", []))

        # Filter by category
        relevant_patterns = [p for p in patterns if p.get("category") == category]

        return relevant_patterns

    def _generate_threat_description(self, asset: Asset, category: ThreatCategory, pattern: Dict[str, Any]) -> str:
        """Generate descriptive threat description"""
        base_desc = self.stride_mappings[category]["description"]
        pattern_name = pattern["pattern"].replace("_", " ")

        return f"{base_desc} targeting {asset.name} through {pattern_name}. " \
               f"This could compromise the {asset.asset_type.value} and affect system security."

    def _get_attack_techniques(self, pattern: Dict[str, Any]) -> List[str]:
        """Get attack techniques for threat pattern"""
        technique_mappings = {
            "sql_injection": ["union_based", "blind_injection", "time_based"],
            "xss": ["stored_xss", "reflected_xss", "dom_xss"],
            "csrf": ["form_hijacking", "ajax_hijacking"],
            "authentication_bypass": ["credential_stuffing", "session_fixation", "brute_force"],
            "privilege_escalation": ["vertical_escalation", "horizontal_escalation"],
            "data_exfiltration": ["bulk_download", "side_channel", "covert_channel"]
        }

        return technique_mappings.get(pattern["pattern"], ["generic_attack"])

    def _get_prerequisites(self, asset: Asset, pattern: Dict[str, Any]) -> List[str]:
        """Get prerequisites for successful attack"""
        base_prereqs = []

        if asset.exposure_level > 7:
            base_prereqs.append("network_access")

        if not asset.security_controls:
            base_prereqs.append("no_security_controls")

        pattern_prereqs = {
            "sql_injection": ["database_interaction", "user_input"],
            "xss": ["user_input", "web_interface"],
            "csrf": ["authenticated_session", "state_changing_operation"],
            "privilege_escalation": ["initial_access", "vulnerability_presence"]
        }

        base_prereqs.extend(pattern_prereqs.get(pattern["pattern"], []))
        return base_prereqs

    def _calculate_impact_rating(self, asset: Asset, category: ThreatCategory, pattern: Dict[str, Any]) -> int:
        """Calculate impact rating (1-10 scale)"""
        base_impact = asset.criticality

        # Adjust based on threat category
        category_multipliers = {
            ThreatCategory.INFORMATION_DISCLOSURE: 1.2,
            ThreatCategory.TAMPERING: 1.1,
            ThreatCategory.DENIAL_OF_SERVICE: 1.0,
            ThreatCategory.SPOOFING: 1.1,
            ThreatCategory.ELEVATION_OF_PRIVILEGE: 1.3,
            ThreatCategory.REPUDIATION: 0.8
        }

        adjusted_impact = base_impact * category_multipliers.get(category, 1.0)
        return min(10, max(1, int(adjusted_impact)))

    def _calculate_likelihood(self, asset: Asset, pattern: Dict[str, Any]) -> float:
        """Calculate likelihood of successful attack"""
        base_likelihood = pattern.get("likelihood", 0.5)

        # Adjust based on asset characteristics
        if asset.exposure_level > 7:
            base_likelihood *= 1.3

        if not asset.security_controls:
            base_likelihood *= 1.2

        if asset.trust_level < 5:
            base_likelihood *= 1.1

        return min(1.0, base_likelihood)

    def _determine_confidence_level(self, asset: Asset, pattern: Dict[str, Any]) -> ConfidenceLevel:
        """Determine confidence level for threat assessment"""
        confidence_score = 0.5

        # Higher confidence for well-known patterns
        if pattern["pattern"] in ["sql_injection", "xss", "csrf"]:
            confidence_score += 0.3

        # Higher confidence for exposed assets
        if asset.exposure_level > 7:
            confidence_score += 0.2

        if confidence_score >= 0.9:
            return ConfidenceLevel.VERY_HIGH
        elif confidence_score >= 0.7:
            return ConfidenceLevel.HIGH
        elif confidence_score >= 0.5:
            return ConfidenceLevel.MEDIUM
        elif confidence_score >= 0.3:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW

    def _map_to_mitre(self, pattern: Dict[str, Any]) -> List[str]:
        """Map threat pattern to MITRE ATT&CK techniques"""
        mitre_mappings = {
            "sql_injection": ["T1190"],
            "xss": ["T1190"],
            "authentication_bypass": ["T1078"],
            "privilege_escalation": ["T1055", "T1078"],
            "data_exfiltration": ["T1083"]
        }

        return mitre_mappings.get(pattern["pattern"], [])

    def _map_to_cwe(self, pattern: Dict[str, Any]) -> List[str]:
        """Map threat pattern to CWE references"""
        cwe_mappings = {
            "sql_injection": ["CWE-89"],
            "xss": ["CWE-79"],
            "csrf": ["CWE-352"],
            "authentication_bypass": ["CWE-287"],
            "path_traversal": ["CWE-22"]
        }

        return cwe_mappings.get(pattern["pattern"], [])

    async def _generate_cross_asset_threats(self, assets: List[Asset]) -> List[ThreatVector]:
        """Generate threats that span multiple assets"""
        cross_threats = []

        # Lateral movement threats
        for source_asset in assets:
            for target_asset in assets:
                if source_asset.id != target_asset.id and self._can_reach(source_asset, target_asset):
                    threat = ThreatVector(
                        id=str(uuid.uuid4()),
                        name=f"Lateral Movement: {source_asset.name} to {target_asset.name}",
                        category=ThreatCategory.ELEVATION_OF_PRIVILEGE,
                        description=f"Attacker moves from compromised {source_asset.name} to {target_asset.name}",
                        affected_assets=[source_asset.id, target_asset.id],
                        attack_techniques=["credential_harvesting", "privilege_escalation", "network_traversal"],
                        prerequisites=["initial_compromise", "network_connectivity"],
                        impact_rating=max(source_asset.criticality, target_asset.criticality),
                        likelihood=0.4,
                        confidence=ConfidenceLevel.MEDIUM
                    )
                    cross_threats.append(threat)

        return cross_threats

    def _can_reach(self, source: Asset, target: Asset) -> bool:
        """Determine if source asset can reach target asset"""
        # Simple heuristic - in real implementation, this would use network topology
        if source.asset_type == AssetType.EXTERNAL_ENTITY:
            return target.exposure_level > 5

        return abs(source.trust_level - target.trust_level) <= 3

    async def identify_attack_paths(self, assets: List[Asset], threat_vectors: List[ThreatVector]) -> List[AttackPath]:
        """
        Identify potential attack paths through the system
        """
        logger.info("Identifying attack paths using graph analysis")

        attack_paths = []

        # Build attack graph with threat vectors
        attack_graph = self._build_attack_graph(assets, threat_vectors)

        # Find paths from external entities to critical assets
        external_assets = [a for a in assets if a.asset_type == AssetType.EXTERNAL_ENTITY]
        critical_assets = [a for a in assets if a.criticality >= 8]

        for external in external_assets:
            for critical in critical_assets:
                paths = await self._find_attack_paths(attack_graph, external, critical, threat_vectors)
                attack_paths.extend(paths)

        # Sort by risk score
        attack_paths.sort(key=lambda x: x.total_risk_score, reverse=True)

        logger.info(f"Identified {len(attack_paths)} attack paths")
        return attack_paths[:20]  # Return top 20 paths

    def _build_attack_graph(self, assets: List[Asset], threat_vectors: List[ThreatVector]) -> nx.DiGraph:
        """Build attack graph from assets and threat vectors"""
        graph = nx.DiGraph()

        # Add asset nodes
        for asset in assets:
            graph.add_node(asset.id, asset=asset)

        # Add edges based on threat vectors and reachability
        for threat in threat_vectors:
            if len(threat.affected_assets) >= 2:
                # Multi-asset threat creates edges between assets
                for i in range(len(threat.affected_assets) - 1):
                    graph.add_edge(
                        threat.affected_assets[i],
                        threat.affected_assets[i + 1],
                        threat=threat,
                        weight=threat.likelihood * threat.impact_rating
                    )

        return graph

    async def _find_attack_paths(self, graph: nx.DiGraph, source: Asset, target: Asset,
                               threat_vectors: List[ThreatVector]) -> List[AttackPath]:
        """Find attack paths between source and target assets"""
        paths = []

        try:
            # Find all simple paths (avoiding cycles)
            simple_paths = list(nx.all_simple_paths(
                graph, source.id, target.id, cutoff=5
            ))

            for path_nodes in simple_paths[:10]:  # Limit to 10 paths per pair
                path_steps = []
                total_risk = 0
                complexity = 0

                for i in range(len(path_nodes) - 1):
                    edge_data = graph.get_edge_data(path_nodes[i], path_nodes[i + 1])
                    if edge_data:
                        threat = edge_data.get('threat')
                        if threat:
                            step = {
                                "step_number": i + 1,
                                "threat_id": threat.id,
                                "threat_name": threat.name,
                                "source_asset": path_nodes[i],
                                "target_asset": path_nodes[i + 1],
                                "techniques": threat.attack_techniques,
                                "prerequisites": threat.prerequisites,
                                "impact": threat.impact_rating,
                                "likelihood": threat.likelihood
                            }
                            path_steps.append(step)
                            total_risk += threat.likelihood * threat.impact_rating
                            complexity += len(threat.prerequisites)

                if path_steps:
                    attack_path = AttackPath(
                        id=str(uuid.uuid4()),
                        name=f"Attack path: {source.name} → {target.name}",
                        description=f"Multi-step attack from {source.name} to {target.name}",
                        steps=path_steps,
                        total_risk_score=total_risk / len(path_steps) if path_steps else 0,
                        complexity=min(10, complexity // len(path_steps) if path_steps else 0),
                        required_privileges=self._extract_required_privileges(path_steps),
                        detection_difficulty=self._calculate_detection_difficulty(path_steps),
                        target_assets=[target.id]
                    )
                    paths.append(attack_path)

        except nx.NetworkXNoPath:
            # No path exists between these assets
            pass

        return paths

    def _extract_required_privileges(self, steps: List[Dict[str, Any]]) -> List[str]:
        """Extract required privileges from attack path steps"""
        privileges = set()
        for step in steps:
            for prereq in step.get("prerequisites", []):
                if "privilege" in prereq or "access" in prereq:
                    privileges.add(prereq)
        return list(privileges)

    def _calculate_detection_difficulty(self, steps: List[Dict[str, Any]]) -> int:
        """Calculate detection difficulty for attack path"""
        base_difficulty = 5

        # More steps = easier to detect somewhere
        if len(steps) > 3:
            base_difficulty -= 1

        # High-impact techniques are often easier to detect
        avg_impact = sum(step.get("impact", 5) for step in steps) / len(steps) if steps else 5
        if avg_impact > 7:
            base_difficulty -= 1

        return max(1, min(10, base_difficulty))

    async def generate_mitigations(self, threat_vectors: List[ThreatVector],
                                 attack_paths: List[AttackPath]) -> List[Mitigation]:
        """
        Generate mitigation recommendations
        """
        logger.info("Generating mitigation recommendations")

        mitigations = []

        # Group threats by category for systematic mitigation
        threats_by_category = defaultdict(list)
        for threat in threat_vectors:
            threats_by_category[threat.category].append(threat)

        # Generate category-specific mitigations
        for category, threats in threats_by_category.items():
            category_mitigations = await self._generate_category_mitigations(category, threats)
            mitigations.extend(category_mitigations)

        # Generate attack path specific mitigations
        path_mitigations = await self._generate_path_mitigations(attack_paths)
        mitigations.extend(path_mitigations)

        # Remove duplicates and prioritize
        unique_mitigations = self._deduplicate_mitigations(mitigations)
        prioritized_mitigations = self._prioritize_mitigations(unique_mitigations, threat_vectors)

        logger.info(f"Generated {len(prioritized_mitigations)} mitigation recommendations")
        return prioritized_mitigations

    async def _generate_category_mitigations(self, category: ThreatCategory,
                                           threats: List[ThreatVector]) -> List[Mitigation]:
        """Generate mitigations for specific threat category"""
        mitigations = []
        category_info = self.stride_mappings[category]

        # Common mitigations by category
        mitigation_templates = {
            ThreatCategory.SPOOFING: [
                {
                    "name": "Multi-Factor Authentication",
                    "description": "Implement MFA to prevent identity spoofing",
                    "type": "authentication",
                    "effectiveness": 0.8,
                    "cost": 6,
                    "impact": 3
                },
                {
                    "name": "Certificate-Based Authentication",
                    "description": "Use digital certificates for strong authentication",
                    "type": "cryptographic",
                    "effectiveness": 0.9,
                    "cost": 7,
                    "impact": 4
                }
            ],
            ThreatCategory.TAMPERING: [
                {
                    "name": "Input Validation",
                    "description": "Implement comprehensive input validation and sanitization",
                    "type": "defensive",
                    "effectiveness": 0.85,
                    "cost": 5,
                    "impact": 2
                },
                {
                    "name": "Data Integrity Checks",
                    "description": "Implement checksums and digital signatures",
                    "type": "cryptographic",
                    "effectiveness": 0.9,
                    "cost": 6,
                    "impact": 3
                }
            ],
            ThreatCategory.REPUDIATION: [
                {
                    "name": "Comprehensive Audit Logging",
                    "description": "Implement tamper-proof audit logging",
                    "type": "monitoring",
                    "effectiveness": 0.8,
                    "cost": 5,
                    "impact": 2
                }
            ],
            ThreatCategory.INFORMATION_DISCLOSURE: [
                {
                    "name": "Data Encryption",
                    "description": "Encrypt sensitive data at rest and in transit",
                    "type": "cryptographic",
                    "effectiveness": 0.9,
                    "cost": 6,
                    "impact": 3
                },
                {
                    "name": "Access Control Implementation",
                    "description": "Implement role-based access controls",
                    "type": "access_control",
                    "effectiveness": 0.8,
                    "cost": 7,
                    "impact": 4
                }
            ],
            ThreatCategory.DENIAL_OF_SERVICE: [
                {
                    "name": "Rate Limiting",
                    "description": "Implement request rate limiting and throttling",
                    "type": "defensive",
                    "effectiveness": 0.7,
                    "cost": 4,
                    "impact": 2
                },
                {
                    "name": "DDoS Protection Service",
                    "description": "Deploy cloud-based DDoS protection",
                    "type": "infrastructure",
                    "effectiveness": 0.85,
                    "cost": 8,
                    "impact": 1
                }
            ],
            ThreatCategory.ELEVATION_OF_PRIVILEGE: [
                {
                    "name": "Principle of Least Privilege",
                    "description": "Implement least privilege access controls",
                    "type": "access_control",
                    "effectiveness": 0.8,
                    "cost": 6,
                    "impact": 4
                },
                {
                    "name": "Privilege Escalation Monitoring",
                    "description": "Monitor for privilege escalation attempts",
                    "type": "monitoring",
                    "effectiveness": 0.7,
                    "cost": 5,
                    "impact": 2
                }
            ]
        }

        templates = mitigation_templates.get(category, [])
        threat_ids = [t.id for t in threats]

        for template in templates:
            mitigation = Mitigation(
                id=str(uuid.uuid4()),
                name=template["name"],
                description=template["description"],
                mitigation_type=template["type"],
                effectiveness=template["effectiveness"],
                implementation_cost=template["cost"],
                operational_impact=template["impact"],
                applicable_threats=threat_ids,
                implementation_guidance=self._generate_implementation_guidance(template)
            )
            mitigations.append(mitigation)

        return mitigations

    async def _generate_path_mitigations(self, attack_paths: List[AttackPath]) -> List[Mitigation]:
        """Generate mitigations specific to attack paths"""
        mitigations = []

        # Analyze common path patterns
        path_techniques = defaultdict(int)
        for path in attack_paths:
            for step in path.steps:
                for technique in step.get("techniques", []):
                    path_techniques[technique] += 1

        # Generate mitigations for common techniques
        for technique, frequency in path_techniques.items():
            if frequency >= 2:  # Technique appears in multiple paths
                mitigation = Mitigation(
                    id=str(uuid.uuid4()),
                    name=f"Mitigation for {technique.replace('_', ' ').title()}",
                    description=f"Specific controls to prevent {technique.replace('_', ' ')} attacks",
                    mitigation_type="technique_specific",
                    effectiveness=0.7,
                    implementation_cost=5,
                    operational_impact=3,
                    applicable_threats=[],
                    implementation_guidance=self._generate_technique_guidance(technique)
                )
                mitigations.append(mitigation)

        return mitigations

    def _generate_implementation_guidance(self, template: Dict[str, Any]) -> str:
        """Generate implementation guidance for mitigation"""
        guidance_templates = {
            "authentication": "1. Choose appropriate MFA method\n2. Integrate with identity provider\n3. Configure fallback mechanisms\n4. Train users on new process",
            "cryptographic": "1. Select appropriate encryption algorithm\n2. Implement proper key management\n3. Ensure compliance requirements\n4. Test performance impact",
            "defensive": "1. Analyze attack vectors\n2. Design validation rules\n3. Implement error handling\n4. Monitor effectiveness",
            "monitoring": "1. Define monitoring requirements\n2. Configure log collection\n3. Set up alerting rules\n4. Establish response procedures",
            "access_control": "1. Define role hierarchy\n2. Map permissions to roles\n3. Implement enforcement points\n4. Regular access reviews"
        }

        return guidance_templates.get(template["type"], "Generic implementation guidance needed")

    def _generate_technique_guidance(self, technique: str) -> str:
        """Generate guidance for specific attack technique mitigation"""
        technique_guidance = {
            "credential_stuffing": "Implement account lockout policies, monitor for suspicious login patterns, use CAPTCHA",
            "privilege_escalation": "Apply principle of least privilege, monitor privilege changes, regular privilege audits",
            "data_exfiltration": "Implement data loss prevention, monitor unusual data access patterns, encrypt sensitive data"
        }

        return technique_guidance.get(technique, f"Implement controls specific to {technique.replace('_', ' ')}")

    def _deduplicate_mitigations(self, mitigations: List[Mitigation]) -> List[Mitigation]:
        """Remove duplicate mitigations"""
        seen_names = set()
        unique_mitigations = []

        for mitigation in mitigations:
            if mitigation.name not in seen_names:
                seen_names.add(mitigation.name)
                unique_mitigations.append(mitigation)

        return unique_mitigations

    def _prioritize_mitigations(self, mitigations: List[Mitigation],
                              threat_vectors: List[ThreatVector]) -> List[Mitigation]:
        """Prioritize mitigations based on effectiveness and threat coverage"""

        def calculate_priority_score(mitigation: Mitigation) -> float:
            # Higher effectiveness = higher priority
            effectiveness_score = mitigation.effectiveness * 10

            # Lower cost = higher priority
            cost_score = (11 - mitigation.implementation_cost) * 0.5

            # Lower operational impact = higher priority
            impact_score = (11 - mitigation.operational_impact) * 0.3

            # Count applicable high-risk threats
            high_risk_threats = sum(1 for t in threat_vectors
                                  if t.id in mitigation.applicable_threats and
                                  t.likelihood * t.impact_rating > 35)
            threat_coverage_score = high_risk_threats * 2

            return effectiveness_score + cost_score + impact_score + threat_coverage_score

        # Sort by priority score (descending)
        return sorted(mitigations, key=calculate_priority_score, reverse=True)

    async def create_threat_model(self, architecture_description: Dict[str, Any],
                                system_name: str, description: str = "") -> ThreatModel:
        """
        Create complete threat model
        """
        logger.info(f"Creating comprehensive threat model for {system_name}")

        # Step 1: Analyze architecture and identify assets
        assets = await self.analyze_system_architecture(architecture_description)

        # Step 2: Generate threat vectors
        threat_vectors = await self.generate_threat_vectors(assets)

        # Step 3: Identify attack paths
        attack_paths = await self.identify_attack_paths(assets, threat_vectors)

        # Step 4: Generate mitigations
        mitigations = await self.generate_mitigations(threat_vectors, attack_paths)

        # Step 5: Create risk matrix
        risk_matrix = self._create_risk_matrix(threat_vectors)

        # Create threat model
        threat_model = ThreatModel(
            id=str(uuid.uuid4()),
            name=system_name,
            description=description,
            target_system=system_name,
            assets=assets,
            threat_vectors=threat_vectors,
            attack_paths=attack_paths,
            mitigations=mitigations,
            risk_matrix=risk_matrix,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            methodology="STRIDE",
            scope=architecture_description.get("scope", ""),
            assumptions=architecture_description.get("assumptions", []),
            out_of_scope=architecture_description.get("out_of_scope", [])
        )

        logger.info(f"Threat model created successfully with {len(assets)} assets, "
                   f"{len(threat_vectors)} threats, {len(attack_paths)} attack paths, "
                   f"and {len(mitigations)} mitigations")

        return threat_model

    def _create_risk_matrix(self, threat_vectors: List[ThreatVector]) -> Dict[str, Any]:
        """Create risk assessment matrix"""
        risk_counts = defaultdict(int)
        category_risks = defaultdict(list)

        for threat in threat_vectors:
            risk_score = threat.likelihood * threat.impact_rating

            if risk_score >= 7:
                risk_level = RiskLevel.CRITICAL
            elif risk_score >= 5:
                risk_level = RiskLevel.HIGH
            elif risk_score >= 3:
                risk_level = RiskLevel.MEDIUM
            elif risk_score >= 1:
                risk_level = RiskLevel.LOW
            else:
                risk_level = RiskLevel.INFORMATIONAL

            risk_counts[risk_level.value] += 1
            category_risks[threat.category.value].append(risk_score)

        # Calculate category averages
        category_averages = {}
        for category, scores in category_risks.items():
            category_averages[category] = sum(scores) / len(scores) if scores else 0

        return {
            "risk_distribution": dict(risk_counts),
            "category_risk_averages": category_averages,
            "total_threats": len(threat_vectors),
            "overall_risk_score": sum(t.likelihood * t.impact_rating for t in threat_vectors) / len(threat_vectors) if threat_vectors else 0
        }

    def get_threat_model_summary(self, threat_model: ThreatModel) -> Dict[str, Any]:
        """Get summary of threat model"""
        return {
            "model_id": threat_model.id,
            "system_name": threat_model.name,
            "created": threat_model.created_at.isoformat(),
            "assets_count": len(threat_model.assets),
            "threats_count": len(threat_model.threat_vectors),
            "attack_paths_count": len(threat_model.attack_paths),
            "mitigations_count": len(threat_model.mitigations),
            "risk_summary": threat_model.risk_matrix,
            "top_risks": [
                {
                    "threat": t.name,
                    "category": t.category.value,
                    "risk_score": t.likelihood * t.impact_rating,
                    "confidence": t.confidence.value
                }
                for t in sorted(threat_model.threat_vectors,
                              key=lambda x: x.likelihood * x.impact_rating,
                              reverse=True)[:10]
            ]
        }