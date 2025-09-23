"""
Infrastructure Security Agent - Specialized AI Agent for Infrastructure Assessment
================================================================================

This agent focuses on infrastructure security testing including network reconnaissance,
service enumeration, and infrastructure vulnerability assessment.
"""

import asyncio
import json
import logging
import socket
import ssl
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
import aiohttp
import dns.resolver
from urllib.parse import urlparse

from ..agent_orchestrator import BaseAgent, AgentTask, AgentResult

logger = logging.getLogger(__name__)

class InfrastructureAgent(BaseAgent):
    """Specialized agent for infrastructure security assessment"""

    def __init__(self, agent_id: str = "infrastructure_agent", config: Dict[str, Any] = None):
        super().__init__(agent_id, config)

        # Infrastructure assessment techniques
        self.recon_techniques = self._initialize_recon_techniques()
        self.vulnerability_checks = self._initialize_vulnerability_checks()

        # Learning and adaptation
        self.technique_effectiveness = {}
        self.discovered_services = {}
        self.technology_fingerprints = {}

        # Performance tracking
        self.scan_stats = {
            'total_scans': 0,
            'successful_discoveries': 0,
            'vulnerabilities_found': 0,
            'average_scan_time': 0.0
        }

    def get_capabilities(self) -> List[str]:
        """Return capabilities of this agent"""
        return [
            'infrastructure_agent',
            'network_reconnaissance',
            'service_enumeration',
            'ssl_analysis',
            'dns_analysis',
            'header_analysis',
            'technology_detection',
            'vulnerability_scanning'
        ]

    async def execute_task(self, task: AgentTask) -> AgentResult:
        """Execute infrastructure security assessment task"""
        start_time = time.time()

        try:
            logger.info(f"Infrastructure Agent executing task: {task.task_id}")

            # Parse task parameters
            deep_scan = task.parameters.get('deep_scan', False)
            include_ssl = task.parameters.get('include_ssl', True)
            include_dns = task.parameters.get('include_dns', True)
            port_scan = task.parameters.get('port_scan', False)

            findings = []
            assessment_results = {
                'basic_info': {},
                'ssl_analysis': {},
                'dns_analysis': {},
                'header_analysis': {},
                'technology_detection': {},
                'service_enumeration': {},
                'vulnerability_assessment': {},
                'scan_methods': []
            }

            # Basic target analysis
            basic_info = await self._analyze_target_basic_info(task.target)
            assessment_results['basic_info'] = basic_info
            assessment_results['scan_methods'].append('basic_analysis')

            # SSL/TLS analysis
            if include_ssl and basic_info.get('uses_https', False):
                ssl_results = await self._analyze_ssl_configuration(task.target)
                assessment_results['ssl_analysis'] = ssl_results
                findings.extend(ssl_results.get('findings', []))
                assessment_results['scan_methods'].append('ssl_analysis')

            # DNS analysis
            if include_dns:
                dns_results = await self._analyze_dns_configuration(task.target)
                assessment_results['dns_analysis'] = dns_results
                findings.extend(dns_results.get('findings', []))
                assessment_results['scan_methods'].append('dns_analysis')

            # HTTP header analysis
            header_results = await self._analyze_security_headers(task.target)
            assessment_results['header_analysis'] = header_results
            findings.extend(header_results.get('findings', []))
            assessment_results['scan_methods'].append('header_analysis')

            # Technology detection
            tech_results = await self._detect_technologies(task.target)
            assessment_results['technology_detection'] = tech_results
            findings.extend(tech_results.get('findings', []))
            assessment_results['scan_methods'].append('technology_detection')

            # Service enumeration (if deep scan)
            if deep_scan:
                service_results = await self._enumerate_services(task.target)
                assessment_results['service_enumeration'] = service_results
                findings.extend(service_results.get('findings', []))
                assessment_results['scan_methods'].append('service_enumeration')

            # Vulnerability assessment
            vuln_results = await self._assess_vulnerabilities(task.target, assessment_results)
            assessment_results['vulnerability_assessment'] = vuln_results
            findings.extend(vuln_results.get('findings', []))
            assessment_results['scan_methods'].append('vulnerability_assessment')

            # Calculate confidence score
            confidence_score = self._calculate_confidence_score(assessment_results, findings)

            # Update learning data
            self._update_learning_data(assessment_results, findings)

            execution_time = time.time() - start_time

            return AgentResult(
                task_id=task.task_id,
                agent_type=self.agent_id,
                success=True,
                data=assessment_results,
                execution_time=execution_time,
                confidence_score=confidence_score,
                findings=findings,
                metadata={
                    'deep_scan': deep_scan,
                    'total_checks': len(assessment_results['scan_methods']),
                    'services_discovered': len(assessment_results.get('service_enumeration', {})),
                    'technologies_detected': len(assessment_results.get('technology_detection', {}))
                }
            )

        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Infrastructure Agent task failed: {e}")

            return AgentResult(
                task_id=task.task_id,
                agent_type=self.agent_id,
                success=False,
                data={'error': str(e)},
                execution_time=execution_time,
                confidence_score=0.0,
                findings=[],
                metadata={'error': str(e)}
            )

    async def _analyze_target_basic_info(self, target: str) -> Dict[str, Any]:
        """Analyze basic target information"""
        parsed_url = urlparse(target)

        basic_info = {
            'hostname': parsed_url.hostname,
            'port': parsed_url.port or (443 if parsed_url.scheme == 'https' else 80),
            'scheme': parsed_url.scheme,
            'uses_https': parsed_url.scheme == 'https',
            'path': parsed_url.path,
            'ip_address': None,
            'response_time': 0.0,
            'status_reachable': False
        }

        try:
            # Resolve IP address
            basic_info['ip_address'] = socket.gethostbyname(basic_info['hostname'])

            # Test connectivity
            start_time = time.time()
            async with aiohttp.ClientSession() as session:
                async with session.get(target, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    basic_info['response_time'] = time.time() - start_time
                    basic_info['status_reachable'] = True
                    basic_info['status_code'] = response.status

        except Exception as e:
            basic_info['error'] = str(e)

        return basic_info

    async def _analyze_ssl_configuration(self, target: str) -> Dict[str, Any]:
        """Analyze SSL/TLS configuration"""
        findings = []
        ssl_analysis = {
            'tls_version': None,
            'cipher_suite': None,
            'certificate_info': {},
            'security_issues': [],
            'score': 0
        }

        try:
            parsed_url = urlparse(target)
            hostname = parsed_url.hostname
            port = parsed_url.port or 443

            # SSL context for analysis
            context = ssl.create_default_context()

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get TLS version and cipher
                    ssl_analysis['tls_version'] = ssock.version()
                    ssl_analysis['cipher_suite'] = ssock.cipher()

                    # Get certificate information
                    cert = ssock.getpeercert()
                    ssl_analysis['certificate_info'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'version': cert['version'],
                        'serial_number': str(cert['serialNumber'])
                    }

                    # Security analysis
                    if ssl_analysis['tls_version'] in ['TLSv1.3']:
                        ssl_analysis['score'] += 40
                    elif ssl_analysis['tls_version'] in ['TLSv1.2']:
                        ssl_analysis['score'] += 30
                    elif ssl_analysis['tls_version'] in ['TLSv1.1']:
                        ssl_analysis['score'] += 15
                        ssl_analysis['security_issues'].append('Using outdated TLS 1.1')
                        findings.append({
                            'type': 'ssl_vulnerability',
                            'severity': 'medium',
                            'description': 'Outdated TLS version 1.1 detected',
                            'recommendation': 'Upgrade to TLS 1.2 or 1.3'
                        })
                    else:
                        ssl_analysis['security_issues'].append('Using insecure TLS version')
                        findings.append({
                            'type': 'ssl_vulnerability',
                            'severity': 'high',
                            'description': f'Insecure TLS version detected: {ssl_analysis["tls_version"]}',
                            'recommendation': 'Upgrade to TLS 1.2 or 1.3'
                        })

                    # Cipher analysis
                    if ssl_analysis['cipher_suite']:
                        cipher_name = ssl_analysis['cipher_suite'][0]
                        if 'AES' in cipher_name and 'GCM' in cipher_name:
                            ssl_analysis['score'] += 30
                        elif 'AES' in cipher_name:
                            ssl_analysis['score'] += 20
                        else:
                            ssl_analysis['security_issues'].append('Weak cipher suite')
                            findings.append({
                                'type': 'ssl_vulnerability',
                                'severity': 'medium',
                                'description': f'Weak cipher suite: {cipher_name}',
                                'recommendation': 'Use stronger cipher suites with AES-GCM'
                            })

                    # Certificate validation
                    subject = ssl_analysis['certificate_info']['subject']
                    if 'commonName' not in subject and 'organizationName' not in subject:
                        findings.append({
                            'type': 'ssl_vulnerability',
                            'severity': 'low',
                            'description': 'Certificate missing common name or organization',
                            'recommendation': 'Ensure certificate has proper subject information'
                        })

        except Exception as e:
            ssl_analysis['error'] = str(e)
            findings.append({
                'type': 'ssl_error',
                'severity': 'low',
                'description': f'SSL analysis failed: {str(e)}',
                'recommendation': 'Check SSL/TLS configuration'
            })

        ssl_analysis['findings'] = findings
        return ssl_analysis

    async def _analyze_dns_configuration(self, target: str) -> Dict[str, Any]:
        """Analyze DNS configuration"""
        findings = []
        dns_analysis = {
            'a_records': [],
            'aaaa_records': [],
            'mx_records': [],
            'txt_records': [],
            'cname_records': [],
            'ns_records': [],
            'security_records': {},
            'issues': []
        }

        try:
            parsed_url = urlparse(target)
            hostname = parsed_url.hostname

            # Query different record types
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS']

            for record_type in record_types:
                try:
                    records = dns.resolver.resolve(hostname, record_type)
                    record_list = [str(record) for record in records]
                    dns_analysis[f'{record_type.lower()}_records'] = record_list

                    # Security analysis
                    if record_type == 'TXT':
                        # Check for security-related TXT records
                        for record in record_list:
                            if 'spf' in record.lower():
                                dns_analysis['security_records']['spf'] = record
                            elif 'dmarc' in record.lower():
                                dns_analysis['security_records']['dmarc'] = record
                            elif 'dkim' in record.lower():
                                dns_analysis['security_records']['dkim'] = record

                except dns.resolver.NXDOMAIN:
                    dns_analysis[f'{record_type.lower()}_records'] = []
                except Exception as e:
                    dns_analysis['issues'].append(f"Failed to query {record_type}: {str(e)}")

            # Security findings
            if not dns_analysis['security_records'].get('spf'):
                findings.append({
                    'type': 'dns_security',
                    'severity': 'low',
                    'description': 'No SPF record found',
                    'recommendation': 'Implement SPF record to prevent email spoofing'
                })

            if not dns_analysis['security_records'].get('dmarc'):
                findings.append({
                    'type': 'dns_security',
                    'severity': 'low',
                    'description': 'No DMARC record found',
                    'recommendation': 'Implement DMARC for email authentication'
                })

        except Exception as e:
            dns_analysis['error'] = str(e)

        dns_analysis['findings'] = findings
        return dns_analysis

    async def _analyze_security_headers(self, target: str) -> Dict[str, Any]:
        """Analyze HTTP security headers"""
        findings = []
        header_analysis = {
            'present_headers': {},
            'missing_headers': [],
            'security_score': 0,
            'recommendations': []
        }

        # Security headers to check
        security_headers = {
            'Strict-Transport-Security': {'required': True, 'score': 20},
            'Content-Security-Policy': {'required': True, 'score': 25},
            'X-Frame-Options': {'required': True, 'score': 15},
            'X-Content-Type-Options': {'required': True, 'score': 10},
            'X-XSS-Protection': {'required': False, 'score': 10},
            'Referrer-Policy': {'required': False, 'score': 10},
            'Permissions-Policy': {'required': False, 'score': 10}
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(target, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    response_headers = dict(response.headers)

                    for header_name, header_info in security_headers.items():
                        if header_name in response_headers:
                            header_analysis['present_headers'][header_name] = response_headers[header_name]
                            header_analysis['security_score'] += header_info['score']
                        else:
                            header_analysis['missing_headers'].append(header_name)
                            if header_info['required']:
                                severity = 'high' if header_info['score'] >= 20 else 'medium'
                                findings.append({
                                    'type': 'missing_security_header',
                                    'severity': severity,
                                    'description': f'Missing security header: {header_name}',
                                    'recommendation': f'Implement {header_name} header for enhanced security'
                                })

                    # Analyze specific headers
                    if 'Strict-Transport-Security' in header_analysis['present_headers']:
                        hsts_value = header_analysis['present_headers']['Strict-Transport-Security']
                        if 'max-age=' not in hsts_value:
                            findings.append({
                                'type': 'security_header_misconfiguration',
                                'severity': 'medium',
                                'description': 'HSTS header missing max-age directive',
                                'recommendation': 'Add max-age directive to HSTS header'
                            })

                    if 'Content-Security-Policy' in header_analysis['present_headers']:
                        csp_value = header_analysis['present_headers']['Content-Security-Policy']
                        if "'unsafe-eval'" in csp_value or "'unsafe-inline'" in csp_value:
                            findings.append({
                                'type': 'security_header_misconfiguration',
                                'severity': 'medium',
                                'description': 'CSP contains unsafe directives',
                                'recommendation': 'Remove unsafe-eval and unsafe-inline from CSP'
                            })

        except Exception as e:
            header_analysis['error'] = str(e)

        header_analysis['findings'] = findings
        return header_analysis

    async def _detect_technologies(self, target: str) -> Dict[str, Any]:
        """Detect technologies used by the target"""
        findings = []
        tech_detection = {
            'web_server': None,
            'framework': None,
            'cms': None,
            'programming_language': None,
            'cdn': None,
            'security_products': [],
            'fingerprints': {}
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(target, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    headers = dict(response.headers)
                    content = await response.text()

                    # Server detection
                    if 'Server' in headers:
                        server_header = headers['Server']
                        tech_detection['web_server'] = server_header
                        tech_detection['fingerprints']['server'] = server_header

                        # Check for known vulnerabilities in server versions
                        if 'nginx' in server_header.lower():
                            tech_detection['web_server'] = 'nginx'
                        elif 'apache' in server_header.lower():
                            tech_detection['web_server'] = 'apache'

                    # Powered-By detection
                    if 'X-Powered-By' in headers:
                        powered_by = headers['X-Powered-By']
                        tech_detection['framework'] = powered_by
                        tech_detection['fingerprints']['powered_by'] = powered_by

                    # CDN detection
                    cdn_headers = ['CF-Ray', 'X-Amz-Cf-Id', 'X-Azure-Ref']
                    for cdn_header in cdn_headers:
                        if cdn_header in headers:
                            if 'CF-Ray' in headers:
                                tech_detection['cdn'] = 'Cloudflare'
                            elif 'X-Amz-Cf-Id' in headers:
                                tech_detection['cdn'] = 'AWS CloudFront'
                            elif 'X-Azure-Ref' in headers:
                                tech_detection['cdn'] = 'Azure CDN'

                    # Security product detection
                    security_headers = ['X-WAF-Event-Info', 'X-Sucuri-ID', 'X-Mod-Security-Message']
                    for sec_header in security_headers:
                        if sec_header in headers:
                            tech_detection['security_products'].append(sec_header)

                    # Content analysis for CMS detection
                    content_lower = content.lower()
                    if 'wp-content' in content_lower or 'wordpress' in content_lower:
                        tech_detection['cms'] = 'WordPress'
                    elif 'drupal' in content_lower:
                        tech_detection['cms'] = 'Drupal'
                    elif 'joomla' in content_lower:
                        tech_detection['cms'] = 'Joomla'

                    # Security findings based on technology detection
                    if tech_detection['cms'] == 'WordPress':
                        findings.append({
                            'type': 'technology_detection',
                            'severity': 'info',
                            'description': 'WordPress CMS detected',
                            'recommendation': 'Ensure WordPress and plugins are up to date'
                        })

                    if not tech_detection['security_products']:
                        findings.append({
                            'type': 'technology_detection',
                            'severity': 'low',
                            'description': 'No WAF or security products detected',
                            'recommendation': 'Consider implementing a Web Application Firewall'
                        })

        except Exception as e:
            tech_detection['error'] = str(e)

        tech_detection['findings'] = findings
        return tech_detection

    async def _enumerate_services(self, target: str) -> Dict[str, Any]:
        """Enumerate services on common ports"""
        findings = []
        service_enum = {
            'open_ports': [],
            'services': {},
            'scan_results': {}
        }

        try:
            parsed_url = urlparse(target)
            hostname = parsed_url.hostname

            # Common ports to scan
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]

            for port in common_ports:
                try:
                    # Simple TCP connection test
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((hostname, port))

                    if result == 0:
                        service_enum['open_ports'].append(port)

                        # Try to identify service
                        service_name = self._identify_service(port)
                        service_enum['services'][port] = service_name

                        # Security findings for unexpected open ports
                        if port not in [80, 443]:
                            findings.append({
                                'type': 'open_port',
                                'severity': 'low',
                                'description': f'Unexpected open port detected: {port}',
                                'recommendation': f'Review if port {port} ({service_name}) needs to be exposed'
                            })

                    sock.close()

                except Exception as e:
                    service_enum['scan_results'][port] = f'Error: {str(e)}'

        except Exception as e:
            service_enum['error'] = str(e)

        service_enum['findings'] = findings
        return service_enum

    async def _assess_vulnerabilities(self, target: str, assessment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess vulnerabilities based on gathered information"""
        findings = []
        vuln_assessment = {
            'risk_score': 0,
            'vulnerability_categories': {},
            'recommendations': []
        }

        # Analyze SSL vulnerabilities
        ssl_data = assessment_data.get('ssl_analysis', {})
        if ssl_data.get('security_issues'):
            vuln_assessment['vulnerability_categories']['ssl'] = len(ssl_data['security_issues'])
            vuln_assessment['risk_score'] += len(ssl_data['security_issues']) * 10

        # Analyze header security
        header_data = assessment_data.get('header_analysis', {})
        missing_headers = len(header_data.get('missing_headers', []))
        if missing_headers > 0:
            vuln_assessment['vulnerability_categories']['headers'] = missing_headers
            vuln_assessment['risk_score'] += missing_headers * 5

        # Analyze technology risks
        tech_data = assessment_data.get('technology_detection', {})
        if tech_data.get('cms') and not tech_data.get('security_products'):
            vuln_assessment['risk_score'] += 15
            findings.append({
                'type': 'infrastructure_vulnerability',
                'severity': 'medium',
                'description': 'CMS detected without apparent WAF protection',
                'recommendation': 'Implement Web Application Firewall and keep CMS updated'
            })

        # Overall risk assessment
        if vuln_assessment['risk_score'] > 50:
            vuln_assessment['overall_risk'] = 'high'
        elif vuln_assessment['risk_score'] > 25:
            vuln_assessment['overall_risk'] = 'medium'
        else:
            vuln_assessment['overall_risk'] = 'low'

        vuln_assessment['findings'] = findings
        return vuln_assessment

    def _identify_service(self, port: int) -> str:
        """Identify service by port number"""
        port_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt'
        }
        return port_services.get(port, 'Unknown')

    def _calculate_confidence_score(self, assessment_results: Dict[str, Any], findings: List[Dict[str, Any]]) -> float:
        """Calculate confidence score for the assessment"""
        # Base confidence from number of successful checks
        completed_checks = len([k for k, v in assessment_results.items() if v and not isinstance(v, list) and 'error' not in v])
        total_possible_checks = 7  # Total number of assessment categories

        base_confidence = completed_checks / total_possible_checks

        # Boost confidence if vulnerabilities are found (indicates thorough testing)
        if findings:
            severity_boost = len([f for f in findings if f.get('severity') in ['high', 'critical']]) * 0.1
            base_confidence = min(base_confidence + severity_boost, 1.0)

        return round(base_confidence, 2)

    def _update_learning_data(self, assessment_results: Dict[str, Any], findings: List[Dict[str, Any]]):
        """Update learning data for future improvements"""
        self.scan_stats['total_scans'] += 1
        self.scan_stats['vulnerabilities_found'] += len(findings)

        # Track technique effectiveness
        for method in assessment_results.get('scan_methods', []):
            if method not in self.technique_effectiveness:
                self.technique_effectiveness[method] = {'attempts': 0, 'findings': 0}

            self.technique_effectiveness[method]['attempts'] += 1
            method_findings = [f for f in findings if method in f.get('description', '')]
            self.technique_effectiveness[method]['findings'] += len(method_findings)

    def _initialize_recon_techniques(self) -> Dict[str, Dict[str, Any]]:
        """Initialize reconnaissance techniques"""
        return {
            'passive': {
                'dns_enumeration': True,
                'whois_lookup': True,
                'certificate_transparency': True
            },
            'active': {
                'port_scanning': True,
                'service_enumeration': True,
                'banner_grabbing': True
            }
        }

    def _initialize_vulnerability_checks(self) -> Dict[str, List[str]]:
        """Initialize vulnerability check categories"""
        return {
            'ssl_tls': [
                'outdated_protocols',
                'weak_ciphers',
                'certificate_issues'
            ],
            'http_headers': [
                'missing_security_headers',
                'misconfigured_headers',
                'information_disclosure'
            ],
            'network': [
                'open_ports',
                'unnecessary_services',
                'firewall_bypass'
            ]
        }