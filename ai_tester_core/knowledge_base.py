"""
Security Knowledge Base - Centralized Knowledge Management for AI Security Testing
=================================================================================

This module implements a comprehensive knowledge base that stores, organizes, and
retrieves security knowledge, vulnerability patterns, and learning insights.
"""

import json
import logging
import pickle
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
import hashlib

logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityPattern:
    """Represents a vulnerability pattern in the knowledge base"""
    pattern_id: str
    vulnerability_type: str
    pattern_data: Dict[str, Any]
    effectiveness_score: float
    discovery_count: int
    false_positive_rate: float
    last_seen: datetime
    created_at: datetime
    updated_at: datetime

@dataclass
class ThreatIntelligence:
    """Represents threat intelligence data"""
    intel_id: str
    threat_type: str
    indicators: List[str]
    severity: str
    source: str
    confidence: float
    created_at: datetime
    expires_at: Optional[datetime]

@dataclass
class AttackTechnique:
    """Represents an attack technique"""
    technique_id: str
    name: str
    description: str
    category: str
    success_rate: float
    payloads: List[str]
    countermeasures: List[str]
    mitre_id: Optional[str]
    created_at: datetime
    updated_at: datetime

class SecurityKnowledgeBase:
    """
    Comprehensive security knowledge base that learns and evolves
    from security assessments and external intelligence
    """

    def __init__(self, db_path: str = "ai_tester_core/knowledge_base/security_kb.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize database
        self._initialize_database()

        # In-memory caches for performance
        self.vulnerability_cache: Dict[str, VulnerabilityPattern] = {}
        self.threat_intel_cache: Dict[str, ThreatIntelligence] = {}
        self.attack_technique_cache: Dict[str, AttackTechnique] = {}

        # Statistics and metrics
        self.kb_stats = {
            'vulnerability_patterns': 0,
            'threat_intelligence_items': 0,
            'attack_techniques': 0,
            'last_updated': datetime.now(),
            'total_queries': 0,
            'cache_hits': 0
        }

        # Load initial data
        self._load_initial_data()
        self._update_statistics()

    def _initialize_database(self):
        """Initialize SQLite database with required tables"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Vulnerability patterns table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerability_patterns (
                    pattern_id TEXT PRIMARY KEY,
                    vulnerability_type TEXT NOT NULL,
                    pattern_data TEXT NOT NULL,
                    effectiveness_score REAL DEFAULT 0.0,
                    discovery_count INTEGER DEFAULT 0,
                    false_positive_rate REAL DEFAULT 0.0,
                    last_seen TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            ''')

            # Threat intelligence table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_intelligence (
                    intel_id TEXT PRIMARY KEY,
                    threat_type TEXT NOT NULL,
                    indicators TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source TEXT NOT NULL,
                    confidence REAL DEFAULT 0.0,
                    created_at TEXT NOT NULL,
                    expires_at TEXT
                )
            ''')

            # Attack techniques table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS attack_techniques (
                    technique_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    category TEXT NOT NULL,
                    success_rate REAL DEFAULT 0.0,
                    payloads TEXT NOT NULL,
                    countermeasures TEXT NOT NULL,
                    mitre_id TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            ''')

            # Assessment history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS assessment_history (
                    assessment_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    assessment_type TEXT NOT NULL,
                    findings_count INTEGER DEFAULT 0,
                    risk_score REAL DEFAULT 0.0,
                    execution_time REAL DEFAULT 0.0,
                    success BOOLEAN DEFAULT 1,
                    created_at TEXT NOT NULL
                )
            ''')

            # Knowledge base metrics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS kb_metrics (
                    metric_date TEXT PRIMARY KEY,
                    vulnerability_patterns_count INTEGER DEFAULT 0,
                    threat_intel_count INTEGER DEFAULT 0,
                    attack_techniques_count INTEGER DEFAULT 0,
                    assessments_count INTEGER DEFAULT 0,
                    avg_effectiveness REAL DEFAULT 0.0
                )
            ''')

            conn.commit()

        logger.info("Knowledge base database initialized")

    def _load_initial_data(self):
        """Load initial security knowledge data"""
        try:
            # Load vulnerability patterns
            self._load_vulnerability_patterns()

            # Load threat intelligence
            self._load_threat_intelligence()

            # Load attack techniques
            self._load_attack_techniques()

            logger.info("Initial knowledge base data loaded")

        except Exception as e:
            logger.error(f"Failed to load initial data: {e}")

    def _load_vulnerability_patterns(self):
        """Load vulnerability patterns from database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM vulnerability_patterns')

            for row in cursor.fetchall():
                pattern = VulnerabilityPattern(
                    pattern_id=row[0],
                    vulnerability_type=row[1],
                    pattern_data=json.loads(row[2]),
                    effectiveness_score=row[3],
                    discovery_count=row[4],
                    false_positive_rate=row[5],
                    last_seen=datetime.fromisoformat(row[6]) if row[6] else None,
                    created_at=datetime.fromisoformat(row[7]),
                    updated_at=datetime.fromisoformat(row[8])
                )
                self.vulnerability_cache[pattern.pattern_id] = pattern

    def _load_threat_intelligence(self):
        """Load threat intelligence from database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM threat_intelligence')

            for row in cursor.fetchall():
                intel = ThreatIntelligence(
                    intel_id=row[0],
                    threat_type=row[1],
                    indicators=json.loads(row[2]),
                    severity=row[3],
                    source=row[4],
                    confidence=row[5],
                    created_at=datetime.fromisoformat(row[6]),
                    expires_at=datetime.fromisoformat(row[7]) if row[7] else None
                )
                self.threat_intel_cache[intel.intel_id] = intel

    def _load_attack_techniques(self):
        """Load attack techniques from database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM attack_techniques')

            for row in cursor.fetchall():
                technique = AttackTechnique(
                    technique_id=row[0],
                    name=row[1],
                    description=row[2],
                    category=row[3],
                    success_rate=row[4],
                    payloads=json.loads(row[5]),
                    countermeasures=json.loads(row[6]),
                    mitre_id=row[7],
                    created_at=datetime.fromisoformat(row[8]),
                    updated_at=datetime.fromisoformat(row[9])
                )
                self.attack_technique_cache[technique.technique_id] = technique

    async def update_from_assessment(self, assessment_result) -> Dict[str, Any]:
        """Update knowledge base from assessment results"""
        updates = {
            'new_patterns': 0,
            'updated_patterns': 0,
            'new_techniques': 0,
            'updated_effectiveness': 0
        }

        try:
            # Record assessment in history
            await self._record_assessment(assessment_result)

            # Extract and update vulnerability patterns
            for agent_result in assessment_result.agent_results:
                findings = agent_result.get('findings', [])

                for finding in findings:
                    # Update vulnerability patterns
                    pattern_updated = await self._update_vulnerability_pattern(finding, agent_result)
                    if pattern_updated['new']:
                        updates['new_patterns'] += 1
                    else:
                        updates['updated_patterns'] += 1

                    # Update attack technique effectiveness
                    if 'payload' in finding:
                        technique_updated = await self._update_attack_technique_effectiveness(finding)
                        if technique_updated:
                            updates['updated_effectiveness'] += 1

            # Update knowledge base statistics
            self._update_statistics()

            logger.info(f"Knowledge base updated: {updates}")
            return updates

        except Exception as e:
            logger.error(f"Failed to update knowledge base: {e}")
            return updates

    async def _record_assessment(self, assessment_result):
        """Record assessment in history"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute('''
                INSERT OR REPLACE INTO assessment_history
                (assessment_id, target, assessment_type, findings_count, risk_score, execution_time, success, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                assessment_result.pipeline_id,
                getattr(assessment_result, 'target', 'unknown'),
                'security_assessment',
                assessment_result.total_findings,
                assessment_result.risk_score,
                assessment_result.execution_time,
                assessment_result.status == 'completed',
                assessment_result.started_at.isoformat()
            ))

            conn.commit()

    async def _update_vulnerability_pattern(self, finding: Dict[str, Any], agent_result: Dict[str, Any]) -> Dict[str, Any]:
        """Update or create vulnerability pattern"""
        # Generate pattern ID from finding characteristics
        pattern_data = {
            'type': finding.get('type', 'unknown'),
            'severity': finding.get('severity', 'low'),
            'payload': finding.get('payload', ''),
            'indicators': self._extract_indicators(finding)
        }

        pattern_id = self._generate_pattern_id(pattern_data)

        # Check if pattern exists
        if pattern_id in self.vulnerability_cache:
            # Update existing pattern
            pattern = self.vulnerability_cache[pattern_id]
            pattern.discovery_count += 1
            pattern.last_seen = datetime.now()
            pattern.updated_at = datetime.now()

            # Update effectiveness based on agent confidence
            agent_confidence = agent_result.get('confidence_score', 0.5)
            pattern.effectiveness_score = (pattern.effectiveness_score * 0.8) + (agent_confidence * 0.2)

            await self._save_vulnerability_pattern(pattern)
            return {'new': False, 'pattern_id': pattern_id}

        else:
            # Create new pattern
            pattern = VulnerabilityPattern(
                pattern_id=pattern_id,
                vulnerability_type=finding.get('type', 'unknown'),
                pattern_data=pattern_data,
                effectiveness_score=agent_result.get('confidence_score', 0.5),
                discovery_count=1,
                false_positive_rate=0.0,
                last_seen=datetime.now(),
                created_at=datetime.now(),
                updated_at=datetime.now()
            )

            self.vulnerability_cache[pattern_id] = pattern
            await self._save_vulnerability_pattern(pattern)
            return {'new': True, 'pattern_id': pattern_id}

    async def _update_attack_technique_effectiveness(self, finding: Dict[str, Any]) -> bool:
        """Update attack technique effectiveness"""
        payload = finding.get('payload', '')
        if not payload:
            return False

        # Find matching attack technique
        technique_id = self._find_attack_technique_by_payload(payload)
        if not technique_id:
            return False

        # Update success rate
        technique = self.attack_technique_cache[technique_id]
        current_success_rate = technique.success_rate

        # Assume successful if finding was discovered
        new_success_rate = (current_success_rate * 0.9) + (1.0 * 0.1)
        technique.success_rate = new_success_rate
        technique.updated_at = datetime.now()

        await self._save_attack_technique(technique)
        return True

    def query_vulnerability_patterns(self, vuln_type: str = None, min_effectiveness: float = 0.0) -> List[VulnerabilityPattern]:
        """Query vulnerability patterns"""
        self.kb_stats['total_queries'] += 1

        patterns = list(self.vulnerability_cache.values())

        # Filter by vulnerability type
        if vuln_type:
            patterns = [p for p in patterns if p.vulnerability_type == vuln_type]

        # Filter by minimum effectiveness
        patterns = [p for p in patterns if p.effectiveness_score >= min_effectiveness]

        # Sort by effectiveness
        patterns.sort(key=lambda p: p.effectiveness_score, reverse=True)

        self.kb_stats['cache_hits'] += 1
        return patterns

    def get_attack_techniques(self, category: str = None, min_success_rate: float = 0.0) -> List[AttackTechnique]:
        """Get attack techniques"""
        self.kb_stats['total_queries'] += 1

        techniques = list(self.attack_technique_cache.values())

        # Filter by category
        if category:
            techniques = [t for t in techniques if t.category == category]

        # Filter by minimum success rate
        techniques = [t for t in techniques if t.success_rate >= min_success_rate]

        # Sort by success rate
        techniques.sort(key=lambda t: t.success_rate, reverse=True)

        return techniques

    def get_threat_intelligence(self, threat_type: str = None, min_confidence: float = 0.0) -> List[ThreatIntelligence]:
        """Get threat intelligence"""
        self.kb_stats['total_queries'] += 1

        # Filter expired intelligence
        current_time = datetime.now()
        intel_items = [
            intel for intel in self.threat_intel_cache.values()
            if intel.expires_at is None or intel.expires_at > current_time
        ]

        # Filter by threat type
        if threat_type:
            intel_items = [i for i in intel_items if i.threat_type == threat_type]

        # Filter by minimum confidence
        intel_items = [i for i in intel_items if i.confidence >= min_confidence]

        # Sort by confidence
        intel_items.sort(key=lambda i: i.confidence, reverse=True)

        return intel_items

    def recommend_payloads(self, vulnerability_type: str, target_characteristics: Dict[str, Any] = None) -> List[str]:
        """Recommend most effective payloads for a vulnerability type"""
        patterns = self.query_vulnerability_patterns(vulnerability_type, min_effectiveness=0.3)

        # Extract payloads and rank by effectiveness
        payload_effectiveness = {}
        for pattern in patterns:
            payload = pattern.pattern_data.get('payload', '')
            if payload:
                effectiveness = pattern.effectiveness_score * (1 - pattern.false_positive_rate)
                payload_effectiveness[payload] = max(payload_effectiveness.get(payload, 0), effectiveness)

        # Sort by effectiveness
        recommended_payloads = sorted(payload_effectiveness.items(), key=lambda x: x[1], reverse=True)

        return [payload for payload, _ in recommended_payloads[:10]]  # Top 10

    def analyze_vulnerability_trends(self, days: int = 30) -> Dict[str, Any]:
        """Analyze vulnerability trends over specified time period"""
        cutoff_date = datetime.now() - timedelta(days=days)

        recent_patterns = [
            p for p in self.vulnerability_cache.values()
            if p.last_seen and p.last_seen >= cutoff_date
        ]

        # Analyze trends
        vuln_type_counts = Counter(p.vulnerability_type for p in recent_patterns)
        severity_counts = Counter(p.pattern_data.get('severity', 'unknown') for p in recent_patterns)

        avg_effectiveness = sum(p.effectiveness_score for p in recent_patterns) / len(recent_patterns) if recent_patterns else 0

        return {
            'time_period_days': days,
            'total_patterns': len(recent_patterns),
            'vulnerability_type_distribution': dict(vuln_type_counts),
            'severity_distribution': dict(severity_counts),
            'average_effectiveness': avg_effectiveness,
            'most_common_types': vuln_type_counts.most_common(5),
            'trend_analysis': self._calculate_trend_analysis(recent_patterns)
        }

    def get_knowledge_recommendations(self, assessment_context: Dict[str, Any]) -> Dict[str, Any]:
        """Get knowledge-based recommendations for an assessment"""
        target_type = assessment_context.get('target_type', 'web_service')
        objectives = assessment_context.get('objectives', [])

        recommendations = {
            'recommended_techniques': [],
            'high_value_patterns': [],
            'threat_intelligence': [],
            'custom_payloads': []
        }

        # Recommend techniques based on target type
        techniques = self.get_attack_techniques(category=target_type, min_success_rate=0.4)
        recommendations['recommended_techniques'] = [
            {
                'technique_id': t.technique_id,
                'name': t.name,
                'success_rate': t.success_rate,
                'payloads': t.payloads[:3]  # Top 3 payloads
            } for t in techniques[:5]
        ]

        # High-value vulnerability patterns
        patterns = self.query_vulnerability_patterns(min_effectiveness=0.6)
        recommendations['high_value_patterns'] = [
            {
                'pattern_id': p.pattern_id,
                'type': p.vulnerability_type,
                'effectiveness': p.effectiveness_score,
                'discovery_count': p.discovery_count
            } for p in patterns[:5]
        ]

        # Relevant threat intelligence
        threat_intel = self.get_threat_intelligence(min_confidence=0.7)
        recommendations['threat_intelligence'] = [
            {
                'intel_id': i.intel_id,
                'threat_type': i.threat_type,
                'severity': i.severity,
                'indicators': i.indicators[:3]  # Top 3 indicators
            } for i in threat_intel[:3]
        ]

        return recommendations

    async def add_threat_intelligence(self, threat_type: str, indicators: List[str],
                                    severity: str, source: str, confidence: float,
                                    expires_in_days: int = None) -> str:
        """Add new threat intelligence"""
        intel_id = f"intel_{int(time.time())}_{hash(str(indicators))}"

        expires_at = None
        if expires_in_days:
            expires_at = datetime.now() + timedelta(days=expires_in_days)

        intel = ThreatIntelligence(
            intel_id=intel_id,
            threat_type=threat_type,
            indicators=indicators,
            severity=severity,
            source=source,
            confidence=confidence,
            created_at=datetime.now(),
            expires_at=expires_at
        )

        self.threat_intel_cache[intel_id] = intel
        await self._save_threat_intelligence(intel)

        return intel_id

    async def add_attack_technique(self, name: str, description: str, category: str,
                                 payloads: List[str], countermeasures: List[str],
                                 mitre_id: str = None) -> str:
        """Add new attack technique"""
        technique_id = f"tech_{int(time.time())}_{hash(name)}"

        technique = AttackTechnique(
            technique_id=technique_id,
            name=name,
            description=description,
            category=category,
            success_rate=0.5,  # Start with neutral success rate
            payloads=payloads,
            countermeasures=countermeasures,
            mitre_id=mitre_id,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )

        self.attack_technique_cache[technique_id] = technique
        await self._save_attack_technique(technique)

        return technique_id

    async def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive knowledge base statistics"""
        return {
            'knowledge_base_stats': self.kb_stats,
            'vulnerability_patterns': len(self.vulnerability_cache),
            'threat_intelligence': len(self.threat_intel_cache),
            'attack_techniques': len(self.attack_technique_cache),
            'effectiveness_metrics': await self._calculate_effectiveness_metrics(),
            'recent_updates': await self._get_recent_updates_summary()
        }

    async def get_recent_updates(self, days: int = 7) -> Dict[str, Any]:
        """Get recent knowledge base updates"""
        cutoff_date = datetime.now() - timedelta(days=days)

        recent_patterns = [
            p for p in self.vulnerability_cache.values()
            if p.updated_at >= cutoff_date
        ]

        recent_techniques = [
            t for t in self.attack_technique_cache.values()
            if t.updated_at >= cutoff_date
        ]

        recent_intel = [
            i for i in self.threat_intel_cache.values()
            if i.created_at >= cutoff_date
        ]

        return {
            'time_period_days': days,
            'updated_patterns': len(recent_patterns),
            'updated_techniques': len(recent_techniques),
            'new_intelligence': len(recent_intel),
            'pattern_details': [
                {
                    'pattern_id': p.pattern_id,
                    'type': p.vulnerability_type,
                    'effectiveness': p.effectiveness_score
                } for p in recent_patterns
            ],
            'technique_details': [
                {
                    'technique_id': t.technique_id,
                    'name': t.name,
                    'success_rate': t.success_rate
                } for t in recent_techniques
            ]
        }

    # Helper methods

    def _extract_indicators(self, finding: Dict[str, Any]) -> List[str]:
        """Extract indicators from a finding"""
        indicators = []

        # Extract patterns from payload
        payload = finding.get('payload', '')
        if payload:
            indicators.append(payload[:50])  # First 50 chars as indicator

        # Extract patterns from response
        response = finding.get('response', '')
        if response:
            # Look for common vulnerability indicators
            common_indicators = ['error', 'exception', 'sql', 'script', 'alert']
            for indicator in common_indicators:
                if indicator.lower() in response.lower():
                    indicators.append(indicator)

        return indicators

    def _generate_pattern_id(self, pattern_data: Dict[str, Any]) -> str:
        """Generate unique pattern ID from pattern data"""
        pattern_str = json.dumps(pattern_data, sort_keys=True)
        return hashlib.md5(pattern_str.encode()).hexdigest()[:16]

    def _find_attack_technique_by_payload(self, payload: str) -> Optional[str]:
        """Find attack technique that matches a payload"""
        for technique_id, technique in self.attack_technique_cache.items():
            if payload in technique.payloads:
                return technique_id
        return None

    def _calculate_trend_analysis(self, patterns: List[VulnerabilityPattern]) -> Dict[str, Any]:
        """Calculate trend analysis for patterns"""
        if not patterns:
            return {}

        # Group by week
        weekly_counts = defaultdict(int)
        for pattern in patterns:
            if pattern.last_seen:
                week_key = pattern.last_seen.strftime('%Y-W%U')
                weekly_counts[week_key] += 1

        # Calculate trend direction
        weeks = sorted(weekly_counts.keys())
        if len(weeks) >= 2:
            recent_avg = sum(weekly_counts[w] for w in weeks[-2:]) / 2
            older_avg = sum(weekly_counts[w] for w in weeks[:-2]) / max(len(weeks) - 2, 1)
            trend_direction = 'increasing' if recent_avg > older_avg else 'decreasing'
        else:
            trend_direction = 'stable'

        return {
            'trend_direction': trend_direction,
            'weekly_counts': dict(weekly_counts),
            'peak_week': max(weekly_counts.items(), key=lambda x: x[1])[0] if weekly_counts else None
        }

    async def _calculate_effectiveness_metrics(self) -> Dict[str, Any]:
        """Calculate effectiveness metrics"""
        if not self.vulnerability_cache:
            return {}

        effectiveness_scores = [p.effectiveness_score for p in self.vulnerability_cache.values()]
        false_positive_rates = [p.false_positive_rate for p in self.vulnerability_cache.values()]

        return {
            'average_effectiveness': sum(effectiveness_scores) / len(effectiveness_scores),
            'max_effectiveness': max(effectiveness_scores),
            'min_effectiveness': min(effectiveness_scores),
            'average_false_positive_rate': sum(false_positive_rates) / len(false_positive_rates),
            'high_effectiveness_patterns': len([s for s in effectiveness_scores if s > 0.8]),
            'low_false_positive_patterns': len([r for r in false_positive_rates if r < 0.1])
        }

    async def _get_recent_updates_summary(self) -> Dict[str, Any]:
        """Get summary of recent updates"""
        recent_updates = await self.get_recent_updates(7)
        return {
            'patterns_updated_last_week': recent_updates['updated_patterns'],
            'techniques_updated_last_week': recent_updates['updated_techniques'],
            'new_intelligence_last_week': recent_updates['new_intelligence']
        }

    def _update_statistics(self):
        """Update knowledge base statistics"""
        self.kb_stats.update({
            'vulnerability_patterns': len(self.vulnerability_cache),
            'threat_intelligence_items': len(self.threat_intel_cache),
            'attack_techniques': len(self.attack_technique_cache),
            'last_updated': datetime.now()
        })

    # Database operations

    async def _save_vulnerability_pattern(self, pattern: VulnerabilityPattern):
        """Save vulnerability pattern to database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute('''
                INSERT OR REPLACE INTO vulnerability_patterns
                (pattern_id, vulnerability_type, pattern_data, effectiveness_score, discovery_count,
                 false_positive_rate, last_seen, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                pattern.pattern_id,
                pattern.vulnerability_type,
                json.dumps(pattern.pattern_data),
                pattern.effectiveness_score,
                pattern.discovery_count,
                pattern.false_positive_rate,
                pattern.last_seen.isoformat() if pattern.last_seen else None,
                pattern.created_at.isoformat(),
                pattern.updated_at.isoformat()
            ))

            conn.commit()

    async def _save_threat_intelligence(self, intel: ThreatIntelligence):
        """Save threat intelligence to database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute('''
                INSERT OR REPLACE INTO threat_intelligence
                (intel_id, threat_type, indicators, severity, source, confidence, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                intel.intel_id,
                intel.threat_type,
                json.dumps(intel.indicators),
                intel.severity,
                intel.source,
                intel.confidence,
                intel.created_at.isoformat(),
                intel.expires_at.isoformat() if intel.expires_at else None
            ))

            conn.commit()

    async def _save_attack_technique(self, technique: AttackTechnique):
        """Save attack technique to database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute('''
                INSERT OR REPLACE INTO attack_techniques
                (technique_id, name, description, category, success_rate, payloads, countermeasures, mitre_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                technique.technique_id,
                technique.name,
                technique.description,
                technique.category,
                technique.success_rate,
                json.dumps(technique.payloads),
                json.dumps(technique.countermeasures),
                technique.mitre_id,
                technique.created_at.isoformat(),
                technique.updated_at.isoformat()
            ))

            conn.commit()