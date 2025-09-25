#!/usr/bin/env python3
"""
Generic MVP Security Tester - Modular AI Platform Integration
============================================================

Universal security testing tool for any web application, API, or service
using the advanced modular AI security testing platform.
"""

import asyncio
import argparse
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from ai_tester_core.pipeline_orchestrator import AdvancedPipelineOrchestrator, PipelineConfig
from ai_tester_core.learning_engine import AdaptiveLearningEngine
from ai_tester_core.knowledge_base import SecurityKnowledgeBase

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/generic_mvp_tester.log')
    ]
)

logger = logging.getLogger(__name__)

class GenericMVPSecurityTester:
    """
    Generic MVP Security Tester using Modular AI Platform

    Supports testing of:
    - Web Applications
    - REST APIs
    - GraphQL APIs
    - WebSocket Services
    - MCP Servers
    - Microservices
    - Any HTTP-based service
    """

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or "configs/modular_ai_config.json"
        self.config = self._load_config()

        # Initialize modular AI components
        self.orchestrator = AdvancedPipelineOrchestrator(self.config_path)
        self.learning_engine = self.orchestrator.learning_engine
        self.knowledge_base = SecurityKnowledgeBase()

        # Platform statistics
        self.stats = {
            'tests_executed': 0,
            'vulnerabilities_found': 0,
            'targets_tested': set(),
            'platform_uptime': datetime.now()
        }

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration with MVP-specific defaults"""
        default_config = {
            'platform_name': 'Generic MVP Security Tester',
            'version': '2.0.0',
            'mvp_mode': True,
            'auto_detect_target_type': True,
            'adaptive_testing': True,
            'quick_scan_timeout': 300,
            'comprehensive_scan_timeout': 1800,
            'default_output_format': 'json',
            'enable_ai_recommendations': True
        }

        if Path(self.config_path).exists():
            try:
                with open(self.config_path, 'r') as f:
                    loaded_config = json.load(f)
                default_config.update(loaded_config)
            except Exception as e:
                logger.warning(f"Failed to load config: {e}")

        return default_config

    async def test_target(self,
                         target_url: str,
                         test_mode: str = 'auto',
                         output_file: Optional[str] = None,
                         custom_objectives: List[str] = None) -> Dict[str, Any]:
        """
        Test any target using modular AI platform

        Args:
            target_url: Target URL to test
            test_mode: 'auto', 'quick', 'comprehensive', 'custom'
            output_file: Optional output file path
            custom_objectives: Custom testing objectives

        Returns:
            Assessment results dictionary
        """

        print(f"🛡️  GENERIC MVP SECURITY TESTER v{self.config['version']}")
        print(f"🎯 Target: {target_url}")
        print(f"🔬 Test Mode: {test_mode.upper()}")
        print("=" * 60)

        start_time = time.time()

        try:
            # Phase 1: Target Analysis
            print("\n🔍 PHASE 1: TARGET ANALYSIS")
            print("-" * 40)

            target_info = await self._analyze_target(target_url)
            target_type = target_info.get('detected_type', 'web_application')

            print(f"✅ Target Type: {target_type}")
            print(f"✅ Technology Stack: {', '.join(target_info.get('technologies', ['Unknown']))}")
            print(f"✅ Security Posture: {target_info.get('security_level', 'Unknown')}")

            # Phase 2: Test Strategy Selection
            print("\n🧠 PHASE 2: AI-POWERED TEST STRATEGY")
            print("-" * 40)

            pipeline_config = await self._select_test_strategy(
                target_url, target_info, test_mode, custom_objectives
            )

            print(f"✅ Pipeline: {pipeline_config.name}")
            print(f"✅ Agents: {len(pipeline_config.stages)}")
            print(f"✅ Estimated Duration: {self._estimate_duration(pipeline_config)} minutes")

            # Phase 3: Execute Assessment
            print("\n🚀 PHASE 3: EXECUTING AI SECURITY ASSESSMENT")
            print("-" * 40)

            result = await self.orchestrator.execute_pipeline(pipeline_config)

            # Phase 4: Process Results
            print("\n📊 PHASE 4: PROCESSING RESULTS")
            print("-" * 40)

            processed_results = await self._process_results(result, target_info)

            # Phase 5: Generate Report
            print("\n📄 PHASE 5: GENERATING REPORT")
            print("-" * 40)

            report = await self._generate_mvp_report(processed_results, target_url, target_info)

            if output_file:
                await self._save_report(report, output_file)
                print(f"✅ Report saved: {output_file}")

            # Update statistics
            self._update_stats(result)

            execution_time = time.time() - start_time

            # Summary
            print(f"\n🎉 ASSESSMENT COMPLETE")
            print("=" * 60)
            print(f"⏱️  Duration: {execution_time:.1f} seconds")
            print(f"🎯 Risk Score: {processed_results.get('risk_score', 0)}/100")
            print(f"🔍 Findings: {processed_results.get('total_findings', 0)}")
            print(f"📋 Recommendations: {len(processed_results.get('recommendations', []))}")

            return {
                'status': 'success',
                'target': target_url,
                'target_type': target_type,
                'execution_time': execution_time,
                'result': processed_results,
                'report': report
            }

        except Exception as e:
            logger.error(f"Assessment failed: {e}")
            return {
                'status': 'error',
                'target': target_url,
                'error': str(e),
                'execution_time': time.time() - start_time
            }

    async def _analyze_target(self, target_url: str) -> Dict[str, Any]:
        """Analyze target to determine type and characteristics"""
        try:
            import aiohttp

            parsed_url = urlparse(target_url)
            target_info = {
                'url': target_url,
                'domain': parsed_url.netloc,
                'scheme': parsed_url.scheme,
                'path': parsed_url.path,
                'detected_type': 'web_application',
                'technologies': [],
                'security_level': 'unknown',
                'endpoints': []
            }

            # Quick probe to determine target type
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(target_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        headers = dict(response.headers)
                        content = await response.text()

                        # Detect target type based on response
                        if 'application/json' in headers.get('content-type', ''):
                            if 'jsonrpc' in content.lower() or '/mcp' in target_url:
                                target_info['detected_type'] = 'mcp_server'
                            elif 'graphql' in content.lower() or 'query' in content.lower():
                                target_info['detected_type'] = 'graphql_api'
                            else:
                                target_info['detected_type'] = 'rest_api'
                        elif 'websocket' in headers.get('upgrade', '').lower():
                            target_info['detected_type'] = 'websocket_service'
                        else:
                            target_info['detected_type'] = 'web_application'

                        # Detect technologies
                        if 'server' in headers:
                            target_info['technologies'].append(headers['server'])
                        if 'x-powered-by' in headers:
                            target_info['technologies'].append(headers['x-powered-by'])

                        # Assess basic security
                        security_headers = ['strict-transport-security', 'content-security-policy', 'x-frame-options']
                        present_headers = sum(1 for h in security_headers if h in headers)

                        if present_headers >= 2:
                            target_info['security_level'] = 'good'
                        elif present_headers == 1:
                            target_info['security_level'] = 'medium'
                        else:
                            target_info['security_level'] = 'basic'

                except Exception as e:
                    logger.warning(f"Target analysis failed: {e}")

            return target_info

        except Exception as e:
            logger.error(f"Target analysis error: {e}")
            return {'detected_type': 'unknown', 'technologies': [], 'security_level': 'unknown'}

    async def _select_test_strategy(self, target_url: str, target_info: Dict[str, Any],
                                   test_mode: str, objectives: List[str] = None) -> PipelineConfig:
        """Select optimal test strategy using AI"""

        if test_mode == 'auto':
            # Use AI to determine best strategy
            target_type = target_info.get('detected_type', 'web_application')
            security_level = target_info.get('security_level', 'unknown')

            # Auto-select based on target characteristics
            if target_type == 'mcp_server':
                template = 'comprehensive_ai_security_scan'
            elif security_level == 'good':
                template = 'comprehensive_ai_security_scan'
            else:
                template = 'rapid_ai_security_check'

        elif test_mode == 'quick':
            template = 'rapid_ai_security_check'
        elif test_mode == 'comprehensive':
            template = 'comprehensive_ai_security_scan'
        elif test_mode == 'custom' and objectives:
            # Create adaptive pipeline
            return await self.orchestrator.create_adaptive_pipeline(target_url, objectives)
        else:
            template = 'rapid_ai_security_check'

        # Get template and customize
        base_template = self.orchestrator.pipeline_templates[template]

        pipeline_config = PipelineConfig(
            pipeline_id=f"mvp_{target_info.get('detected_type', 'generic')}_{int(time.time())}",
            name=f"MVP {test_mode.title()} Test - {target_info.get('detected_type', 'Generic').title()}",
            description=f"AI-powered security test for {target_url}",
            target=target_url,
            stages=base_template['stages'].copy(),
            parameters=base_template.get('parameters', {}),
            adaptive_learning=True
        )

        # Customize based on target type
        self._customize_pipeline_for_target(pipeline_config, target_info)

        return pipeline_config

    def _customize_pipeline_for_target(self, pipeline_config: PipelineConfig, target_info: Dict[str, Any]):
        """Customize pipeline based on target characteristics"""
        target_type = target_info.get('detected_type', 'web_application')

        # Adjust parameters based on target type
        for stage in pipeline_config.stages:
            if stage['agent_type'] == 'llm_security_agent':
                if target_type == 'mcp_server':
                    stage['parameters']['test_type'] = 'comprehensive'
                    stage['parameters']['include_jailbreaking'] = True
                    stage['parameters']['deep_analysis'] = True
                elif target_type in ['rest_api', 'graphql_api']:
                    stage['parameters']['test_type'] = 'api_focused'
                    stage['parameters']['include_injection'] = True

            elif stage['agent_type'] == 'infrastructure_agent':
                if target_type == 'web_application':
                    stage['parameters']['deep_scan'] = True
                    stage['parameters']['include_dns'] = True
                else:
                    stage['parameters']['deep_scan'] = False
                    stage['parameters']['include_ssl'] = True

    async def _process_results(self, pipeline_result, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Process pipeline results for MVP reporting"""

        all_findings = []
        agent_summaries = []

        for agent_result in pipeline_result.agent_results:
            findings = agent_result.get('findings', [])
            all_findings.extend(findings)

            agent_summaries.append({
                'agent': agent_result.get('agent_type'),
                'status': 'success' if agent_result.get('success') else 'failed',
                'findings': len(findings),
                'execution_time': agent_result.get('execution_time', 0),
                'confidence': agent_result.get('confidence_score', 0)
            })

        # Calculate risk score
        risk_score = self._calculate_risk_score(all_findings)

        # Categorize findings
        categorized_findings = self._categorize_findings(all_findings)

        # Generate recommendations
        recommendations = await self._generate_ai_recommendations(all_findings, target_info)

        return {
            'pipeline_id': pipeline_result.pipeline_id,
            'total_findings': len(all_findings),
            'risk_score': risk_score,
            'risk_level': self._get_risk_level(risk_score),
            'agent_summaries': agent_summaries,
            'findings_by_category': categorized_findings,
            'detailed_findings': all_findings,
            'recommendations': recommendations,
            'learning_insights': pipeline_result.learning_insights,
            'execution_stats': {
                'total_time': pipeline_result.execution_time,
                'agents_used': len(agent_summaries),
                'success_rate': len([a for a in agent_summaries if a['status'] == 'success']) / len(agent_summaries) if agent_summaries else 0
            }
        }

    def _calculate_risk_score(self, findings: List[Dict[str, Any]]) -> int:
        """Calculate risk score from findings"""
        severity_weights = {'critical': 25, 'high': 15, 'medium': 8, 'low': 3, 'info': 1}

        total_score = 0
        for finding in findings:
            severity = finding.get('severity', 'low')
            total_score += severity_weights.get(severity, 1)

        # Normalize to 0-100 scale
        max_possible = len(findings) * 25 if findings else 1
        normalized_score = min((total_score / max_possible) * 100, 100)

        return int(normalized_score)

    def _get_risk_level(self, risk_score: int) -> str:
        """Convert risk score to risk level"""
        if risk_score >= 80:
            return 'CRITICAL'
        elif risk_score >= 60:
            return 'HIGH'
        elif risk_score >= 40:
            return 'MEDIUM'
        elif risk_score >= 20:
            return 'LOW'
        else:
            return 'MINIMAL'

    def _categorize_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Categorize findings by type and severity"""
        categories = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }

        for finding in findings:
            severity = finding.get('severity', 'low')
            if severity in categories:
                categories[severity].append(finding)

        return categories

    async def _generate_ai_recommendations(self, findings: List[Dict[str, Any]], target_info: Dict[str, Any]) -> List[str]:
        """Generate AI-powered recommendations"""
        recommendations = []

        # Basic recommendations based on findings
        severity_counts = {}
        for finding in findings:
            severity = finding.get('severity', 'low')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        if severity_counts.get('critical', 0) > 0:
            recommendations.append("🚨 URGENT: Address critical vulnerabilities immediately")

        if severity_counts.get('high', 0) > 0:
            recommendations.append("⚠️ HIGH PRIORITY: Remediate high-severity issues")

        if severity_counts.get('medium', 0) > 2:
            recommendations.append("🔧 Review and fix multiple medium-severity issues")

        # Target-specific recommendations
        target_type = target_info.get('detected_type', 'web_application')

        if target_type == 'mcp_server':
            recommendations.append("🤖 Consider MCP-specific security hardening")
        elif target_type in ['rest_api', 'graphql_api']:
            recommendations.append("🔌 Implement API-specific security measures")
        elif target_type == 'web_application':
            recommendations.append("🌐 Follow web application security best practices")

        # General recommendations
        recommendations.extend([
            "🔄 Schedule regular security assessments",
            "📚 Implement security training for development team",
            "🛡️ Consider implementing additional security layers"
        ])

        return recommendations[:8]  # Limit to 8 recommendations

    async def _generate_mvp_report(self, results: Dict[str, Any], target_url: str, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive MVP report"""

        return {
            'report_type': 'Generic MVP Security Assessment',
            'generated_at': datetime.now().isoformat(),
            'target': {
                'url': target_url,
                'type': target_info.get('detected_type', 'unknown'),
                'technologies': target_info.get('technologies', []),
                'security_baseline': target_info.get('security_level', 'unknown')
            },
            'executive_summary': {
                'overall_risk': results['risk_level'],
                'risk_score': results['risk_score'],
                'total_findings': results['total_findings'],
                'key_issues': [f for f in results['detailed_findings'] if f.get('severity') in ['critical', 'high']][:5],
                'security_grade': self._calculate_security_grade(results['risk_score'])
            },
            'detailed_results': results,
            'ai_insights': {
                'learning_improvements': results.get('learning_insights', {}),
                'agent_performance': results['agent_summaries'],
                'recommendation_confidence': 'high' if results['total_findings'] > 0 else 'medium'
            },
            'next_steps': {
                'immediate_actions': [r for r in results['recommendations'] if '🚨' in r or '⚠️' in r],
                'long_term_improvements': [r for r in results['recommendations'] if '🔄' in r or '📚' in r],
                'monitoring_recommendations': [
                    'Enable continuous security monitoring',
                    'Set up automated vulnerability scanning',
                    'Implement security metrics tracking'
                ]
            },
            'compliance_notes': {
                'owasp_coverage': 'Top 10 vulnerabilities assessed',
                'framework_alignment': 'NIST Cybersecurity Framework compatible',
                'industry_standards': 'Follows security industry best practices'
            }
        }

    def _calculate_security_grade(self, risk_score: int) -> str:
        """Calculate security grade from risk score"""
        if risk_score <= 10:
            return 'A+'
        elif risk_score <= 20:
            return 'A'
        elif risk_score <= 35:
            return 'B+'
        elif risk_score <= 50:
            return 'B'
        elif risk_score <= 65:
            return 'C+'
        elif risk_score <= 80:
            return 'C'
        else:
            return 'D'

    async def _save_report(self, report: Dict[str, Any], output_file: str):
        """Save report to file"""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if output_file.endswith('.json'):
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
        elif output_file.endswith('.pdf'):
            await self._generate_pdf_report(report, output_file)
        elif output_file.endswith('.html'):
            await self._generate_html_report(report, output_file)
        else:
            # Default to JSON
            with open(output_file + '.json', 'w') as f:
                json.dump(report, f, indent=2, default=str)

    async def _generate_pdf_report(self, report: Dict[str, Any], output_file: str):
        """Generate PDF report using ReportLab"""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors
            from reportlab.lib.units import inch

            # Create document
            doc = SimpleDocTemplate(output_file, pagesize=A4)
            styles = getSampleStyleSheet()
            story = []

            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=18,
                spaceAfter=30,
                textColor=colors.darkblue
            )

            story.append(Paragraph("🛡️ MVP Security Assessment Report", title_style))
            story.append(Spacer(1, 12))

            # Executive Summary
            exec_summary = report.get('executive_summary', {})
            story.append(Paragraph("Executive Summary", styles['Heading2']))

            summary_data = [
                ['Target', report.get('target', {}).get('url', 'Unknown')],
                ['Target Type', report.get('target', {}).get('type', 'Unknown')],
                ['Overall Risk', exec_summary.get('overall_risk', 'Unknown')],
                ['Security Grade', exec_summary.get('security_grade', 'Unknown')],
                ['Total Findings', str(exec_summary.get('total_findings', 0))],
                ['Risk Score', f"{exec_summary.get('risk_score', 0)}/100"]
            ]

            summary_table = Table(summary_data, colWidths=[2*inch, 3*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))

            story.append(summary_table)
            story.append(Spacer(1, 12))

            # Key Findings
            story.append(Paragraph("Key Findings", styles['Heading2']))

            detailed_results = report.get('detailed_results', {})
            findings_by_category = detailed_results.get('findings_by_category', {})

            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                findings = findings_by_category.get(severity, [])
                if findings:
                    story.append(Paragraph(f"{severity.title()} Severity ({len(findings)} findings)", styles['Heading3']))
                    for finding in findings[:3]:  # Limit to top 3 per severity
                        story.append(Paragraph(f"• {finding.get('description', 'No description')}", styles['Normal']))
                    story.append(Spacer(1, 6))

            # Recommendations
            story.append(Paragraph("Recommendations", styles['Heading2']))
            recommendations = detailed_results.get('recommendations', [])
            for i, rec in enumerate(recommendations[:8], 1):  # Limit to top 8
                story.append(Paragraph(f"{i}. {rec}", styles['Normal']))

            story.append(Spacer(1, 12))

            # AI Insights
            ai_insights = report.get('ai_insights', {})
            if ai_insights:
                story.append(Paragraph("AI Insights", styles['Heading2']))
                learning_improvements = ai_insights.get('learning_improvements', {})
                if learning_improvements:
                    story.append(Paragraph("Machine Learning Optimizations:", styles['Heading3']))
                    story.append(Paragraph(f"• Agent Performance: {ai_insights.get('recommendation_confidence', 'Unknown')} confidence", styles['Normal']))

            # Footer
            story.append(Spacer(1, 24))
            footer_style = ParagraphStyle(
                'Footer',
                parent=styles['Normal'],
                fontSize=8,
                textColor=colors.grey
            )
            story.append(Paragraph(f"Generated by AI Security Testing Platform v2.0 on {report.get('generated_at', 'Unknown')}", footer_style))

            # Build PDF
            doc.build(story)

        except ImportError:
            # Fallback to simple text-based PDF if ReportLab not available
            await self._generate_simple_pdf_report(report, output_file)

    async def _generate_simple_pdf_report(self, report: Dict[str, Any], output_file: str):
        """Generate simple text-based report if ReportLab not available"""
        # For now, save as text file with PDF extension
        content = f"""
🛡️ MVP SECURITY ASSESSMENT REPORT
================================

Target: {report.get('target', {}).get('url', 'Unknown')}
Target Type: {report.get('target', {}).get('type', 'Unknown')}
Generated: {report.get('generated_at', 'Unknown')}

EXECUTIVE SUMMARY
================
Overall Risk: {report.get('executive_summary', {}).get('overall_risk', 'Unknown')}
Security Grade: {report.get('executive_summary', {}).get('security_grade', 'Unknown')}
Total Findings: {report.get('executive_summary', {}).get('total_findings', 0)}
Risk Score: {report.get('executive_summary', {}).get('risk_score', 0)}/100

KEY ISSUES
==========
"""

        detailed_results = report.get('detailed_results', {})
        findings_by_category = detailed_results.get('findings_by_category', {})

        for severity in ['critical', 'high', 'medium', 'low']:
            findings = findings_by_category.get(severity, [])
            if findings:
                content += f"\n{severity.upper()} SEVERITY ({len(findings)} findings):\n"
                for finding in findings[:3]:
                    content += f"• {finding.get('description', 'No description')}\n"

        content += "\nRECOMMENDATIONS\n===============\n"
        recommendations = detailed_results.get('recommendations', [])
        for i, rec in enumerate(recommendations[:8], 1):
            content += f"{i}. {rec}\n"

        content += "\n" + "="*60 + "\n"
        content += "Generated by AI Security Testing Platform v2.0\n"

        with open(output_file, 'w') as f:
            f.write(content)

    async def _generate_html_report(self, report: Dict[str, Any], output_file: str):
        """Generate HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>MVP Security Assessment Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
                .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
                .section { margin: 20px 0; padding: 15px; border-left: 4px solid #667eea; background: #f8f9fa; }
                .finding { border-left: 4px solid #ff6b6b; padding: 10px; margin: 10px 0; background: white; }
                .finding.critical { border-left-color: #d63031; background: #fff5f5; }
                .finding.high { border-left-color: #e17055; background: #fff8f5; }
                .finding.medium { border-left-color: #fdcb6e; background: #fffbf0; }
                .finding.low { border-left-color: #00b894; background: #f0fff4; }
                .risk-score { font-size: 2em; font-weight: bold; text-align: center; padding: 20px; }
                .risk-low { color: #00b894; }
                .risk-medium { color: #fdcb6e; }
                .risk-high { color: #e17055; }
                .risk-critical { color: #d63031; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #667eea; color: white; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ MVP Security Assessment Report</h1>
                <p><strong>Target:</strong> {target_url}</p>
                <p><strong>Target Type:</strong> {target_type}</p>
                <p><strong>Generated:</strong> {generated_at}</p>
            </div>

            <div class="section">
                <h2>📊 Executive Summary</h2>
                <div class="risk-score risk-{risk_class}">
                    Security Grade: {security_grade} | Risk Score: {risk_score}/100
                </div>
                <table>
                    <tr><th>Metric</th><th>Value</th></tr>
                    <tr><td>Overall Risk Level</td><td>{overall_risk}</td></tr>
                    <tr><td>Total Findings</td><td>{total_findings}</td></tr>
                    <tr><td>Target Type</td><td>{target_type}</td></tr>
                </table>
            </div>

            <div class="section">
                <h2>🔍 Security Findings</h2>
                {findings_html}
            </div>

            <div class="section">
                <h2>📋 Recommendations</h2>
                <ol>
                    {recommendations_html}
                </ol>
            </div>

            <div class="section">
                <h2>🧠 AI Insights</h2>
                <p><strong>Recommendation Confidence:</strong> {ai_confidence}</p>
                <p><strong>Machine Learning Status:</strong> Active and learning from results</p>
            </div>

            <div style="margin-top: 40px; padding: 20px; background: #f1f3f4; border-radius: 8px; text-align: center; color: #666;">
                <p>Generated by AI Security Testing Platform v2.0</p>
                <p>🤖 Powered by Modular AI • 🧠 Machine Learning Enhanced • 🛡️ Continuously Improving</p>
            </div>
        </body>
        </html>
        """

        # Extract data for template
        target_info = report.get('target', {})
        exec_summary = report.get('executive_summary', {})
        detailed_results = report.get('detailed_results', {})
        ai_insights = report.get('ai_insights', {})

        risk_score = exec_summary.get('risk_score', 0)
        risk_class = 'low' if risk_score < 30 else 'medium' if risk_score < 60 else 'high' if risk_score < 80 else 'critical'

        # Generate findings HTML
        findings_html = ""
        findings_by_category = detailed_results.get('findings_by_category', {})
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            findings = findings_by_category.get(severity, [])
            if findings:
                findings_html += f'<h3>{severity.title()} Severity ({len(findings)} findings)</h3>'
                for finding in findings:
                    findings_html += f'''
                    <div class="finding {severity}">
                        <strong>{finding.get("type", "Unknown").replace("_", " ").title()}</strong><br>
                        {finding.get("description", "No description available")}
                    </div>
                    '''

        # Generate recommendations HTML
        recommendations_html = ""
        for rec in detailed_results.get('recommendations', []):
            recommendations_html += f"<li>{rec}</li>"

        # Fill template
        html_content = html_template.format(
            target_url=target_info.get('url', 'Unknown'),
            target_type=target_info.get('type', 'Unknown'),
            generated_at=report.get('generated_at', 'Unknown'),
            security_grade=exec_summary.get('security_grade', 'Unknown'),
            risk_score=risk_score,
            risk_class=risk_class,
            overall_risk=exec_summary.get('overall_risk', 'Unknown'),
            total_findings=exec_summary.get('total_findings', 0),
            findings_html=findings_html,
            recommendations_html=recommendations_html,
            ai_confidence=ai_insights.get('recommendation_confidence', 'Unknown')
        )

        with open(output_file, 'w') as f:
            f.write(html_content)

    def _estimate_duration(self, pipeline_config: PipelineConfig) -> float:
        """Estimate pipeline duration in minutes"""
        base_time = 2.0  # Base 2 minutes
        agent_time = len(pipeline_config.stages) * 1.5  # 1.5 minutes per agent
        return base_time + agent_time

    def _update_stats(self, result):
        """Update platform statistics"""
        self.stats['tests_executed'] += 1
        self.stats['vulnerabilities_found'] += result.total_findings

    def get_platform_stats(self) -> Dict[str, Any]:
        """Get platform statistics"""
        return {
            'platform_stats': self.stats,
            'orchestrator_metrics': self.orchestrator.get_orchestrator_metrics(),
            'learning_statistics': self.learning_engine.get_learning_statistics()
        }


async def main():
    """Main entry point for Generic MVP Security Tester"""

    parser = argparse.ArgumentParser(
        description='Generic MVP Security Tester - Universal AI-Powered Security Testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://api.example.com --mode quick
  %(prog)s https://app.example.com --mode comprehensive --output report.json
  %(prog)s https://mcp-server.example.com/mcp --mode auto --objectives comprehensive deep_analysis
  %(prog)s https://graphql.example.com/graphql --mode custom --objectives api_security rate_limiting
        """
    )

    parser.add_argument('target', help='Target URL to test')
    parser.add_argument('--mode', choices=['auto', 'quick', 'comprehensive', 'custom'],
                       default='auto', help='Testing mode (default: auto)')
    parser.add_argument('--objectives', nargs='+', help='Custom testing objectives')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--stats', action='store_true', help='Show platform statistics')
    parser.add_argument('--format', choices=['json', 'html'], default='json',
                       help='Output format')

    args = parser.parse_args()

    # Initialize tester
    tester = GenericMVPSecurityTester(args.config)

    if args.stats:
        # Show platform statistics
        stats = tester.get_platform_stats()
        print(json.dumps(stats, indent=2, default=str))
        return

    # Run security test
    result = await tester.test_target(
        target_url=args.target,
        test_mode=args.mode,
        output_file=args.output,
        custom_objectives=args.objectives
    )

    # Exit with appropriate code
    sys.exit(0 if result['status'] == 'success' else 1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Assessment interrupted by user")
    except Exception as e:
        print(f"\n❌ Assessment failed: {e}")
        sys.exit(1)