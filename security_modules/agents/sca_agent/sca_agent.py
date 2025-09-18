"""
Software Composition Analysis (SCA) Agent

Intelligent dependency scanning, vulnerability detection, license compliance,
and SBOM generation using AI-powered component analysis and threat intelligence
integration with real-time CVE monitoring.
"""

import asyncio
import json
import logging
import uuid
import hashlib
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import semver
import aiohttp

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VulnerabilitySeverity(Enum):
    """CVE severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

class LicenseRisk(Enum):
    """License risk categories"""
    HIGH_RISK = "high_risk"
    MEDIUM_RISK = "medium_risk"
    LOW_RISK = "low_risk"
    APPROVED = "approved"
    UNKNOWN = "unknown"

class ComponentType(Enum):
    """Types of software components"""
    LIBRARY = "library"
    FRAMEWORK = "framework"
    RUNTIME = "runtime"
    TOOL = "tool"
    PLUGIN = "plugin"
    CONTAINER = "container"
    OPERATING_SYSTEM = "operating_system"

class ScanStatus(Enum):
    """Scan execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class Vulnerability:
    """Software vulnerability information"""
    cve_id: str
    title: str
    description: str
    severity: VulnerabilitySeverity
    cvss_score: float
    cvss_vector: str
    published_date: datetime
    last_modified: datetime
    affected_versions: List[str]
    fixed_versions: List[str]
    references: List[str]
    cwe_ids: List[str] = field(default_factory=list)
    exploit_available: bool = False
    exploitability_score: float = 0.0
    impact_score: float = 0.0

@dataclass
class License:
    """Software license information"""
    name: str
    spdx_id: str
    risk_level: LicenseRisk
    commercial_use: bool
    modification_allowed: bool
    distribution_allowed: bool
    patent_grant: bool
    copyleft: bool
    attribution_required: bool
    full_text: str = ""
    restrictions: List[str] = field(default_factory=list)
    obligations: List[str] = field(default_factory=list)

@dataclass
class Component:
    """Software component information"""
    name: str
    version: str
    component_type: ComponentType
    package_manager: str
    namespace: Optional[str] = None
    description: str = ""
    homepage: str = ""
    repository: str = ""
    license: Optional[License] = None
    dependencies: List[str] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    checksums: Dict[str, str] = field(default_factory=dict)
    download_url: str = ""
    file_paths: List[str] = field(default_factory=list)
    size_bytes: int = 0
    last_modified: Optional[datetime] = None
    is_direct_dependency: bool = True
    depth_level: int = 0

@dataclass
class ComponentAnalysis:
    """Analysis results for a component"""
    component: Component
    risk_score: float
    vulnerability_count: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    license_risk: LicenseRisk
    outdated: bool
    latest_version: str = ""
    version_lag: int = 0  # Versions behind latest
    remediation_available: bool = False
    recommended_version: str = ""
    security_advisories: List[str] = field(default_factory=list)
    usage_analysis: Dict[str, Any] = field(default_factory=dict)

@dataclass
class VulnerabilityReport:
    """Comprehensive vulnerability assessment report"""
    scan_id: str
    target_path: str
    scan_date: datetime
    total_components: int
    vulnerable_components: int
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    components: List[ComponentAnalysis]
    risk_summary: Dict[str, Any]
    remediation_recommendations: List[str]
    sbom: Dict[str, Any]
    execution_time: float
    scan_status: ScanStatus
    error_messages: List[str] = field(default_factory=list)

class SCAAgent:
    """
    Software Composition Analysis agent with intelligent vulnerability detection
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.session_id = str(uuid.uuid4())
        self.vulnerability_db = self._initialize_vulnerability_db()
        self.license_db = self._initialize_license_db()
        self.package_managers = self._initialize_package_managers()
        self.ai_analysis = self._initialize_ai_analysis()

        logger.info(f"SCAAgent initialized with session {self.session_id}")

    def _initialize_vulnerability_db(self) -> Dict[str, Any]:
        """Initialize vulnerability database with known CVEs"""
        return {
            "cve_cache": {},
            "severity_thresholds": {
                "critical": 9.0,
                "high": 7.0,
                "medium": 4.0,
                "low": 0.1
            },
            "known_vulnerabilities": {
                # Sample vulnerabilities for demonstration
                "lodash": [
                    {
                        "cve_id": "CVE-2021-23337",
                        "title": "Command Injection in lodash",
                        "severity": VulnerabilitySeverity.HIGH,
                        "cvss_score": 7.2,
                        "affected_versions": ["<4.17.21"],
                        "fixed_versions": ["4.17.21"]
                    }
                ],
                "express": [
                    {
                        "cve_id": "CVE-2022-24999",
                        "title": "qs vulnerable to Prototype Pollution",
                        "severity": VulnerabilitySeverity.HIGH,
                        "cvss_score": 7.5,
                        "affected_versions": ["<4.18.2"],
                        "fixed_versions": ["4.18.2"]
                    }
                ],
                "django": [
                    {
                        "cve_id": "CVE-2023-24580",
                        "title": "Potential DoS via file uploads",
                        "severity": VulnerabilitySeverity.MEDIUM,
                        "cvss_score": 6.5,
                        "affected_versions": ["<4.1.7"],
                        "fixed_versions": ["4.1.7", "4.0.10"]
                    }
                ]
            }
        }

    def _initialize_license_db(self) -> Dict[str, License]:
        """Initialize license database"""
        return {
            "MIT": License(
                name="MIT License",
                spdx_id="MIT",
                risk_level=LicenseRisk.APPROVED,
                commercial_use=True,
                modification_allowed=True,
                distribution_allowed=True,
                patent_grant=False,
                copyleft=False,
                attribution_required=True
            ),
            "Apache-2.0": License(
                name="Apache License 2.0",
                spdx_id="Apache-2.0",
                risk_level=LicenseRisk.APPROVED,
                commercial_use=True,
                modification_allowed=True,
                distribution_allowed=True,
                patent_grant=True,
                copyleft=False,
                attribution_required=True
            ),
            "GPL-3.0": License(
                name="GNU General Public License v3.0",
                spdx_id="GPL-3.0",
                risk_level=LicenseRisk.HIGH_RISK,
                commercial_use=True,
                modification_allowed=True,
                distribution_allowed=True,
                patent_grant=True,
                copyleft=True,
                attribution_required=True,
                restrictions=["Must disclose source code", "Must include license"]
            ),
            "BSD-3-Clause": License(
                name="BSD 3-Clause License",
                spdx_id="BSD-3-Clause",
                risk_level=LicenseRisk.APPROVED,
                commercial_use=True,
                modification_allowed=True,
                distribution_allowed=True,
                patent_grant=False,
                copyleft=False,
                attribution_required=True
            ),
            "LGPL-2.1": License(
                name="GNU Lesser General Public License v2.1",
                spdx_id="LGPL-2.1",
                risk_level=LicenseRisk.MEDIUM_RISK,
                commercial_use=True,
                modification_allowed=True,
                distribution_allowed=True,
                patent_grant=False,
                copyleft=True,
                attribution_required=True,
                restrictions=["Dynamic linking allowed", "Must provide source for LGPL components"]
            )
        }

    def _initialize_package_managers(self) -> Dict[str, Dict[str, Any]]:
        """Initialize package manager configurations"""
        return {
            "npm": {
                "manifest_files": ["package.json", "package-lock.json", "yarn.lock"],
                "lock_files": ["package-lock.json", "yarn.lock"],
                "dependency_patterns": {
                    "dependencies": r'"([^"]+)":\s*"([^"]+)"',
                    "devDependencies": r'"([^"]+)":\s*"([^"]+)"'
                },
                "registry_url": "https://registry.npmjs.org",
                "api_url": "https://api.npmjs.org"
            },
            "pip": {
                "manifest_files": ["requirements.txt", "Pipfile", "pyproject.toml", "setup.py"],
                "lock_files": ["Pipfile.lock", "poetry.lock"],
                "dependency_patterns": {
                    "requirements": r'^([^=<>!]+)[=<>!]*([^\s#]*)',
                    "pipfile": r'"([^"]+)":\s*"([^"]+)"'
                },
                "registry_url": "https://pypi.org",
                "api_url": "https://pypi.org/pypi"
            },
            "maven": {
                "manifest_files": ["pom.xml"],
                "lock_files": [],
                "dependency_patterns": {
                    "maven": r'<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>'
                },
                "registry_url": "https://repo1.maven.org/maven2",
                "api_url": "https://search.maven.org/solrsearch/select"
            },
            "gradle": {
                "manifest_files": ["build.gradle", "build.gradle.kts"],
                "lock_files": ["gradle.lockfile"],
                "dependency_patterns": {
                    "gradle": r"implementation\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]"
                },
                "registry_url": "https://repo1.maven.org/maven2",
                "api_url": "https://search.maven.org/solrsearch/select"
            },
            "composer": {
                "manifest_files": ["composer.json"],
                "lock_files": ["composer.lock"],
                "dependency_patterns": {
                    "composer": r'"([^"]+)":\s*"([^"]+)"'
                },
                "registry_url": "https://packagist.org",
                "api_url": "https://packagist.org/packages"
            },
            "go": {
                "manifest_files": ["go.mod", "go.sum"],
                "lock_files": ["go.sum"],
                "dependency_patterns": {
                    "go_mod": r'^([^\s]+)\s+v([^\s]+)'
                },
                "registry_url": "https://proxy.golang.org",
                "api_url": "https://proxy.golang.org"
            }
        }

    def _initialize_ai_analysis(self) -> Dict[str, Any]:
        """Initialize AI-powered analysis patterns"""
        return {
            "risk_indicators": {
                "high_risk_patterns": [
                    r"eval\(", r"exec\(", r"system\(", r"shell_exec",
                    r"unserialize", r"pickle\.loads", r"yaml\.load"
                ],
                "crypto_patterns": [
                    r"md5", r"sha1", r"des", r"rc4", r"ssl3"
                ],
                "network_patterns": [
                    r"http://", r"ftp://", r"telnet://", r"ldap://"
                ]
            },
            "quality_indicators": {
                "maintenance_patterns": [
                    r"deprecated", r"legacy", r"abandoned", r"unmaintained"
                ],
                "version_patterns": {
                    "alpha": r"alpha|a\d+",
                    "beta": r"beta|b\d+",
                    "rc": r"rc|release.candidate",
                    "snapshot": r"snapshot|dev"
                }
            },
            "license_risk_factors": {
                "copyleft_licenses": ["GPL", "LGPL", "AGPL", "MPL"],
                "commercial_restrictions": ["CC-BY-NC", "SSPL"],
                "patent_issues": ["CPAL-1.0", "EUPL-1.1"]
            }
        }

    async def scan_project(self, project_path: str, scan_config: Optional[Dict[str, Any]] = None) -> VulnerabilityReport:
        """
        Perform comprehensive SCA scan of project
        """
        logger.info(f"Starting SCA scan of project: {project_path}")
        start_time = datetime.now()

        scan_id = str(uuid.uuid4())
        config = scan_config or {}

        try:
            # Discover package managers and dependencies
            discovered_components = await self._discover_components(project_path, config)

            # Analyze each component
            component_analyses = []
            for component in discovered_components:
                analysis = await self._analyze_component(component)
                component_analyses.append(analysis)

            # Generate vulnerability report
            report = await self._generate_report(
                scan_id, project_path, component_analyses, start_time
            )

            logger.info(f"SCA scan completed. Found {report.total_vulnerabilities} vulnerabilities in {report.total_components} components")
            return report

        except Exception as e:
            logger.error(f"SCA scan failed: {e}")
            execution_time = (datetime.now() - start_time).total_seconds()

            return VulnerabilityReport(
                scan_id=scan_id,
                target_path=project_path,
                scan_date=start_time,
                total_components=0,
                vulnerable_components=0,
                total_vulnerabilities=0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                components=[],
                risk_summary={},
                remediation_recommendations=[],
                sbom={},
                execution_time=execution_time,
                scan_status=ScanStatus.FAILED,
                error_messages=[str(e)]
            )

    async def _discover_components(self, project_path: str, config: Dict[str, Any]) -> List[Component]:
        """Discover software components in project"""
        logger.info("Discovering software components")

        components = []
        included_managers = config.get("package_managers", list(self.package_managers.keys()))

        for manager_name, manager_config in self.package_managers.items():
            if manager_name not in included_managers:
                continue

            manager_components = await self._scan_package_manager(
                project_path, manager_name, manager_config
            )
            components.extend(manager_components)

        # Remove duplicates and resolve dependencies
        unique_components = self._deduplicate_components(components)
        resolved_components = await self._resolve_dependencies(unique_components)

        logger.info(f"Discovered {len(resolved_components)} unique components")
        return resolved_components

    async def _scan_package_manager(self, project_path: str, manager_name: str,
                                  manager_config: Dict[str, Any]) -> List[Component]:
        """Scan specific package manager for components"""
        components = []

        # Look for manifest files
        manifest_files = manager_config["manifest_files"]
        dependency_patterns = manager_config["dependency_patterns"]

        for manifest_file in manifest_files:
            file_path = f"{project_path}/{manifest_file}"
            try:
                # Simulate file reading - in real implementation, would read actual files
                file_content = await self._read_manifest_file(file_path, manager_name)
                if file_content:
                    file_components = await self._parse_manifest(
                        file_content, manager_name, dependency_patterns
                    )
                    components.extend(file_components)
            except Exception as e:
                logger.debug(f"Could not read {file_path}: {e}")

        return components

    async def _read_manifest_file(self, file_path: str, manager_name: str) -> Optional[str]:
        """Read and return manifest file content"""
        # Simulate manifest file content for demonstration
        sample_manifests = {
            "npm": '''
{
  "name": "sample-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.18.1",
    "lodash": "4.17.20",
    "axios": "0.27.2"
  },
  "devDependencies": {
    "jest": "28.1.3",
    "eslint": "8.22.0"
  }
}
            ''',
            "pip": '''
express==4.18.1
lodash==4.17.20
django==4.1.5
requests==2.28.1
numpy==1.23.3
            ''',
            "maven": '''
<dependencies>
    <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-core</artifactId>
        <version>5.3.21</version>
    </dependency>
    <dependency>
        <groupId>junit</groupId>
        <artifactId>junit</artifactId>
        <version>4.13.2</version>
    </dependency>
</dependencies>
            '''
        }

        if "package.json" in file_path and manager_name == "npm":
            return sample_manifests["npm"]
        elif "requirements.txt" in file_path and manager_name == "pip":
            return sample_manifests["pip"]
        elif "pom.xml" in file_path and manager_name == "maven":
            return sample_manifests["maven"]

        return None

    async def _parse_manifest(self, content: str, manager_name: str,
                            patterns: Dict[str, str]) -> List[Component]:
        """Parse manifest file content to extract components"""
        components = []

        if manager_name == "npm":
            components.extend(await self._parse_npm_manifest(content))
        elif manager_name == "pip":
            components.extend(await self._parse_pip_manifest(content))
        elif manager_name == "maven":
            components.extend(await self._parse_maven_manifest(content))

        return components

    async def _parse_npm_manifest(self, content: str) -> List[Component]:
        """Parse NPM package.json file"""
        components = []

        try:
            data = json.loads(content)

            # Parse dependencies
            for dep_type in ["dependencies", "devDependencies"]:
                deps = data.get(dep_type, {})
                for name, version in deps.items():
                    component = Component(
                        name=name,
                        version=self._clean_version(version),
                        component_type=ComponentType.LIBRARY,
                        package_manager="npm",
                        is_direct_dependency=True,
                        depth_level=0
                    )
                    components.append(component)

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse NPM manifest: {e}")

        return components

    async def _parse_pip_manifest(self, content: str) -> List[Component]:
        """Parse Python requirements.txt file"""
        components = []

        for line in content.strip().split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                # Parse requirement line (name==version or name>=version)
                match = re.match(r'^([^=<>!]+)[=<>!]*([^\s#]*)', line)
                if match:
                    name = match.group(1).strip()
                    version = match.group(2).strip() or "latest"

                    component = Component(
                        name=name,
                        version=self._clean_version(version),
                        component_type=ComponentType.LIBRARY,
                        package_manager="pip",
                        is_direct_dependency=True,
                        depth_level=0
                    )
                    components.append(component)

        return components

    async def _parse_maven_manifest(self, content: str) -> List[Component]:
        """Parse Maven pom.xml file"""
        components = []

        # Simple regex parsing for demonstration
        pattern = r'<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>'
        matches = re.findall(pattern, content, re.DOTALL)

        for group_id, artifact_id, version in matches:
            component = Component(
                name=f"{group_id}:{artifact_id}",
                version=self._clean_version(version),
                component_type=ComponentType.LIBRARY,
                package_manager="maven",
                namespace=group_id,
                is_direct_dependency=True,
                depth_level=0
            )
            components.append(component)

        return components

    def _clean_version(self, version: str) -> str:
        """Clean and normalize version string"""
        # Remove common prefixes and special characters
        cleaned = re.sub(r'^[~^>=<]*', '', version)
        cleaned = re.sub(r'\s.*$', '', cleaned)  # Remove everything after space
        return cleaned or "latest"

    def _deduplicate_components(self, components: List[Component]) -> List[Component]:
        """Remove duplicate components"""
        seen = {}
        unique_components = []

        for component in components:
            key = f"{component.name}:{component.version}:{component.package_manager}"
            if key not in seen:
                seen[key] = component
                unique_components.append(component)

        return unique_components

    async def _resolve_dependencies(self, components: List[Component]) -> List[Component]:
        """Resolve transitive dependencies"""
        # For demonstration, add some sample transitive dependencies
        all_components = components.copy()

        for component in components:
            if component.name == "express" and component.package_manager == "npm":
                # Add Express dependencies
                transitive_deps = [
                    Component(
                        name="body-parser",
                        version="1.20.0",
                        component_type=ComponentType.LIBRARY,
                        package_manager="npm",
                        is_direct_dependency=False,
                        depth_level=1
                    ),
                    Component(
                        name="cookie-parser",
                        version="1.4.6",
                        component_type=ComponentType.LIBRARY,
                        package_manager="npm",
                        is_direct_dependency=False,
                        depth_level=1
                    )
                ]
                all_components.extend(transitive_deps)

        return self._deduplicate_components(all_components)

    async def _analyze_component(self, component: Component) -> ComponentAnalysis:
        """Perform comprehensive analysis of component"""
        logger.debug(f"Analyzing component: {component.name}@{component.version}")

        # Get vulnerabilities
        vulnerabilities = await self._get_component_vulnerabilities(component)
        component.vulnerabilities = vulnerabilities

        # Get license information
        license_info = await self._get_component_license(component)
        component.license = license_info

        # Analyze version currency
        version_analysis = await self._analyze_version_currency(component)

        # Calculate risk score
        risk_score = self._calculate_risk_score(component, vulnerabilities, license_info)

        # Generate usage analysis
        usage_analysis = await self._analyze_component_usage(component)

        # Count vulnerabilities by severity
        vuln_counts = self._count_vulnerabilities_by_severity(vulnerabilities)

        analysis = ComponentAnalysis(
            component=component,
            risk_score=risk_score,
            vulnerability_count=len(vulnerabilities),
            critical_vulnerabilities=vuln_counts["critical"],
            high_vulnerabilities=vuln_counts["high"],
            license_risk=license_info.risk_level if license_info else LicenseRisk.UNKNOWN,
            outdated=version_analysis["outdated"],
            latest_version=version_analysis["latest_version"],
            version_lag=version_analysis["version_lag"],
            remediation_available=version_analysis["remediation_available"],
            recommended_version=version_analysis["recommended_version"],
            security_advisories=await self._get_security_advisories(component),
            usage_analysis=usage_analysis
        )

        return analysis

    async def _get_component_vulnerabilities(self, component: Component) -> List[Vulnerability]:
        """Get known vulnerabilities for component"""
        vulnerabilities = []

        # Check local vulnerability database
        component_vulns = self.vulnerability_db["known_vulnerabilities"].get(component.name, [])

        for vuln_data in component_vulns:
            # Check if component version is affected
            if self._is_version_affected(component.version, vuln_data["affected_versions"]):
                vulnerability = Vulnerability(
                    cve_id=vuln_data["cve_id"],
                    title=vuln_data["title"],
                    description=f"Vulnerability in {component.name} version {component.version}",
                    severity=vuln_data["severity"],
                    cvss_score=vuln_data["cvss_score"],
                    cvss_vector=f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    published_date=datetime.now() - timedelta(days=30),
                    last_modified=datetime.now() - timedelta(days=15),
                    affected_versions=vuln_data["affected_versions"],
                    fixed_versions=vuln_data["fixed_versions"],
                    references=[f"https://nvd.nist.gov/vuln/detail/{vuln_data['cve_id']}"]
                )
                vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _is_version_affected(self, version: str, affected_versions: List[str]) -> bool:
        """Check if version is affected by vulnerability"""
        try:
            # Simple version comparison logic
            for affected_range in affected_versions:
                if "<" in affected_range:
                    max_version = affected_range.replace("<", "")
                    if version < max_version:
                        return True
                elif "=" in affected_range:
                    exact_version = affected_range.replace("=", "")
                    if version == exact_version:
                        return True
        except Exception as e:
            logger.debug(f"Version comparison failed: {e}")
            return False

        return False

    async def _get_component_license(self, component: Component) -> Optional[License]:
        """Get license information for component"""
        # Sample license mapping based on component name
        license_mapping = {
            "express": "MIT",
            "lodash": "MIT",
            "axios": "MIT",
            "django": "BSD-3-Clause",
            "requests": "Apache-2.0",
            "numpy": "BSD-3-Clause",
            "spring-core": "Apache-2.0",
            "junit": "EPL-2.0"
        }

        license_id = license_mapping.get(component.name, "MIT")
        return self.license_db.get(license_id)

    async def _analyze_version_currency(self, component: Component) -> Dict[str, Any]:
        """Analyze if component version is current"""
        # Simulate version analysis
        version_mappings = {
            "express": {"latest": "4.18.2", "recommended": "4.18.2"},
            "lodash": {"latest": "4.17.21", "recommended": "4.17.21"},
            "django": {"latest": "4.1.7", "recommended": "4.1.7"},
            "axios": {"latest": "1.3.4", "recommended": "1.3.4"}
        }

        version_info = version_mappings.get(component.name, {
            "latest": component.version,
            "recommended": component.version
        })

        latest_version = version_info["latest"]
        recommended_version = version_info["recommended"]

        outdated = component.version != latest_version
        version_lag = self._calculate_version_lag(component.version, latest_version)
        remediation_available = component.vulnerabilities and recommended_version != component.version

        return {
            "outdated": outdated,
            "latest_version": latest_version,
            "version_lag": version_lag,
            "remediation_available": remediation_available,
            "recommended_version": recommended_version
        }

    def _calculate_version_lag(self, current: str, latest: str) -> int:
        """Calculate how many versions behind current is from latest"""
        try:
            # Simple version lag calculation
            current_parts = [int(x) for x in current.split('.')]
            latest_parts = [int(x) for x in latest.split('.')]

            # Calculate difference in patch version
            if len(current_parts) >= 3 and len(latest_parts) >= 3:
                return latest_parts[2] - current_parts[2]
        except Exception:
            pass

        return 0

    def _calculate_risk_score(self, component: Component, vulnerabilities: List[Vulnerability],
                            license_info: Optional[License]) -> float:
        """Calculate overall risk score for component"""
        risk_score = 0.0

        # Vulnerability risk (0-7 points)
        for vuln in vulnerabilities:
            if vuln.severity == VulnerabilitySeverity.CRITICAL:
                risk_score += 3.0
            elif vuln.severity == VulnerabilitySeverity.HIGH:
                risk_score += 2.0
            elif vuln.severity == VulnerabilitySeverity.MEDIUM:
                risk_score += 1.0
            elif vuln.severity == VulnerabilitySeverity.LOW:
                risk_score += 0.5

        # License risk (0-2 points)
        if license_info:
            if license_info.risk_level == LicenseRisk.HIGH_RISK:
                risk_score += 2.0
            elif license_info.risk_level == LicenseRisk.MEDIUM_RISK:
                risk_score += 1.0

        # Maintenance risk (0-1 point)
        if component.version.endswith("-alpha") or component.version.endswith("-beta"):
            risk_score += 1.0

        return min(10.0, risk_score)

    async def _analyze_component_usage(self, component: Component) -> Dict[str, Any]:
        """Analyze how component is used in the project"""
        return {
            "is_direct_dependency": component.is_direct_dependency,
            "depth_level": component.depth_level,
            "estimated_usage": "high" if component.is_direct_dependency else "medium",
            "critical_path": component.is_direct_dependency,
            "removal_impact": "high" if component.is_direct_dependency else "low"
        }

    def _count_vulnerabilities_by_severity(self, vulnerabilities: List[Vulnerability]) -> Dict[str, int]:
        """Count vulnerabilities by severity level"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for vuln in vulnerabilities:
            counts[vuln.severity.value] += 1

        return counts

    async def _get_security_advisories(self, component: Component) -> List[str]:
        """Get security advisories for component"""
        advisories = []

        if component.vulnerabilities:
            for vuln in component.vulnerabilities:
                advisories.append(f"Security Advisory: {vuln.cve_id} - {vuln.title}")

        return advisories

    async def _generate_report(self, scan_id: str, target_path: str,
                             analyses: List[ComponentAnalysis], start_time: datetime) -> VulnerabilityReport:
        """Generate comprehensive vulnerability report"""
        execution_time = (datetime.now() - start_time).total_seconds()

        # Calculate summary statistics
        total_components = len(analyses)
        vulnerable_components = sum(1 for a in analyses if a.vulnerability_count > 0)
        total_vulnerabilities = sum(a.vulnerability_count for a in analyses)

        # Count vulnerabilities by severity
        critical_count = sum(a.critical_vulnerabilities for a in analyses)
        high_count = sum(a.high_vulnerabilities for a in analyses)
        medium_count = sum(a.vulnerability_count - a.critical_vulnerabilities - a.high_vulnerabilities for a in analyses if a.vulnerability_count > 0)
        low_count = 0  # Simplified for this example

        # Generate risk summary
        risk_summary = await self._generate_risk_summary(analyses)

        # Generate remediation recommendations
        recommendations = await self._generate_remediation_recommendations(analyses)

        # Generate SBOM
        sbom = await self._generate_sbom(analyses)

        report = VulnerabilityReport(
            scan_id=scan_id,
            target_path=target_path,
            scan_date=start_time,
            total_components=total_components,
            vulnerable_components=vulnerable_components,
            total_vulnerabilities=total_vulnerabilities,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            components=analyses,
            risk_summary=risk_summary,
            remediation_recommendations=recommendations,
            sbom=sbom,
            execution_time=execution_time,
            scan_status=ScanStatus.COMPLETED
        )

        return report

    async def _generate_risk_summary(self, analyses: List[ComponentAnalysis]) -> Dict[str, Any]:
        """Generate risk summary from component analyses"""
        if not analyses:
            return {}

        # Calculate risk distribution
        risk_levels = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        license_risks = defaultdict(int)
        total_risk_score = 0.0

        for analysis in analyses:
            total_risk_score += analysis.risk_score

            # Categorize risk level
            if analysis.risk_score >= 8.0:
                risk_levels["critical"] += 1
            elif analysis.risk_score >= 6.0:
                risk_levels["high"] += 1
            elif analysis.risk_score >= 3.0:
                risk_levels["medium"] += 1
            else:
                risk_levels["low"] += 1

            # Count license risks
            license_risks[analysis.license_risk.value] += 1

        average_risk_score = total_risk_score / len(analyses)

        return {
            "average_risk_score": average_risk_score,
            "risk_distribution": risk_levels,
            "license_risk_distribution": dict(license_risks),
            "outdated_components": sum(1 for a in analyses if a.outdated),
            "components_with_remediation": sum(1 for a in analyses if a.remediation_available),
            "total_security_advisories": sum(len(a.security_advisories) for a in analyses)
        }

    async def _generate_remediation_recommendations(self, analyses: List[ComponentAnalysis]) -> List[str]:
        """Generate remediation recommendations"""
        recommendations = []

        # Critical vulnerabilities
        critical_components = [a for a in analyses if a.critical_vulnerabilities > 0]
        if critical_components:
            recommendations.append(f"URGENT: Update {len(critical_components)} components with critical vulnerabilities")

        # High vulnerability components
        high_vuln_components = [a for a in analyses if a.high_vulnerabilities > 0]
        if high_vuln_components:
            recommendations.append(f"HIGH PRIORITY: Address {len(high_vuln_components)} components with high-severity vulnerabilities")

        # Outdated components
        outdated_components = [a for a in analyses if a.outdated]
        if outdated_components:
            recommendations.append(f"Update {len(outdated_components)} outdated components to latest versions")

        # License compliance
        high_risk_licenses = [a for a in analyses if a.license_risk == LicenseRisk.HIGH_RISK]
        if high_risk_licenses:
            recommendations.append(f"Review {len(high_risk_licenses)} components with high-risk licenses")

        # Specific component recommendations
        for analysis in analyses:
            if analysis.remediation_available:
                recommendations.append(f"Update {analysis.component.name} from {analysis.component.version} to {analysis.recommended_version}")

        # General recommendations
        recommendations.extend([
            "Implement automated dependency scanning in CI/CD pipeline",
            "Establish regular dependency review and update schedule",
            "Monitor security advisories for used components",
            "Consider implementing Software Bill of Materials (SBOM) tracking"
        ])

        return recommendations

    async def _generate_sbom(self, analyses: List[ComponentAnalysis]) -> Dict[str, Any]:
        """Generate Software Bill of Materials (SBOM)"""
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "tools": [
                    {
                        "vendor": "AI Security Tester",
                        "name": "SCA Agent",
                        "version": "1.0.0"
                    }
                ]
            },
            "components": []
        }

        for analysis in analyses:
            component = analysis.component
            component_data = {
                "type": "library",
                "bom-ref": f"{component.name}@{component.version}",
                "name": component.name,
                "version": component.version,
                "purl": f"pkg:{component.package_manager}/{component.name}@{component.version}",
                "scope": "required" if component.is_direct_dependency else "optional"
            }

            # Add license information
            if component.license:
                component_data["licenses"] = [
                    {
                        "license": {
                            "id": component.license.spdx_id,
                            "name": component.license.name
                        }
                    }
                ]

            # Add vulnerability information
            if component.vulnerabilities:
                component_data["vulnerabilities"] = [
                    {
                        "id": vuln.cve_id,
                        "source": {
                            "name": "NVD",
                            "url": f"https://nvd.nist.gov/vuln/detail/{vuln.cve_id}"
                        },
                        "ratings": [
                            {
                                "source": {
                                    "name": "NVD"
                                },
                                "score": vuln.cvss_score,
                                "severity": vuln.severity.value.upper(),
                                "method": "CVSSv3"
                            }
                        ]
                    }
                    for vuln in component.vulnerabilities
                ]

            sbom["components"].append(component_data)

        return sbom

    def get_scan_summary(self, report: VulnerabilityReport) -> Dict[str, Any]:
        """Get summary of scan results"""
        return {
            "scan_id": report.scan_id,
            "target_path": report.target_path,
            "scan_date": report.scan_date.isoformat(),
            "execution_time": report.execution_time,
            "status": report.scan_status.value,
            "summary": {
                "total_components": report.total_components,
                "vulnerable_components": report.vulnerable_components,
                "total_vulnerabilities": report.total_vulnerabilities,
                "vulnerability_breakdown": {
                    "critical": report.critical_count,
                    "high": report.high_count,
                    "medium": report.medium_count,
                    "low": report.low_count
                }
            },
            "risk_assessment": report.risk_summary,
            "top_recommendations": report.remediation_recommendations[:5],
            "sbom_available": bool(report.sbom)
        }