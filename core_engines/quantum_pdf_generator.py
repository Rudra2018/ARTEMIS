#!/usr/bin/env python3
"""
🏹 ARTEMIS QUANTUMSENTINEL-NEXUS v5.0
Comprehensive PDF Report Generator
Advanced Multi-Format Report Generation with Executive Intelligence
"""

import json
import logging
import os
import sys
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import subprocess
import tempfile
import base64

# Try to import reportlab for PDF generation
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.colors import HexColor, black, white, red, green, blue, orange
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.platypus import Image as RLImage
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
    from reportlab.graphics.shapes import Drawing, Rect, Circle
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    print("Warning: reportlab not available. PDF generation will use alternative method.")
    REPORTLAB_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class QuantumPDFGenerator:
    """Advanced PDF Report Generator for ARTEMIS QUANTUMSENTINEL-NEXUS v5.0"""

    def __init__(self):
        self.company_colors = {
            'primary': HexColor('#1f2937') if REPORTLAB_AVAILABLE else '#1f2937',
            'secondary': HexColor('#3b82f6') if REPORTLAB_AVAILABLE else '#3b82f6',
            'success': HexColor('#10b981') if REPORTLAB_AVAILABLE else '#10b981',
            'warning': HexColor('#f59e0b') if REPORTLAB_AVAILABLE else '#f59e0b',
            'danger': HexColor('#ef4444') if REPORTLAB_AVAILABLE else '#ef4444',
            'info': HexColor('#06b6d4') if REPORTLAB_AVAILABLE else '#06b6d4'
        }

        if REPORTLAB_AVAILABLE:
            self.styles = self._create_custom_styles()

        self.risk_colors = {
            'critical': self.company_colors['danger'],
            'high': HexColor('#f97316') if REPORTLAB_AVAILABLE else '#f97316',
            'medium': self.company_colors['warning'],
            'low': self.company_colors['success']
        }

    def _create_custom_styles(self):
        """Create custom styles for the report"""

        styles = getSampleStyleSheet()

        # Custom title style
        styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=styles['Title'],
            fontSize=24,
            textColor=self.company_colors['primary'],
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))

        # Custom heading styles
        styles.add(ParagraphStyle(
            name='CustomHeading1',
            parent=styles['Heading1'],
            fontSize=18,
            textColor=self.company_colors['primary'],
            spaceAfter=12,
            spaceBefore=20,
            fontName='Helvetica-Bold'
        ))

        styles.add(ParagraphStyle(
            name='CustomHeading2',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=self.company_colors['secondary'],
            spaceAfter=8,
            spaceBefore=15,
            fontName='Helvetica-Bold'
        ))

        # Executive summary style
        styles.add(ParagraphStyle(
            name='ExecutiveSummary',
            parent=styles['Normal'],
            fontSize=11,
            textColor=black,
            spaceAfter=6,
            leftIndent=20,
            rightIndent=20,
            fontName='Helvetica'
        ))

        # Risk box styles
        styles.add(ParagraphStyle(
            name='RiskCritical',
            parent=styles['Normal'],
            fontSize=10,
            textColor=white,
            backColor=self.company_colors['danger'],
            leftIndent=10,
            rightIndent=10,
            spaceAfter=5,
            fontName='Helvetica-Bold'
        ))

        styles.add(ParagraphStyle(
            name='RiskHigh',
            parent=styles['Normal'],
            fontSize=10,
            textColor=white,
            backColor=HexColor('#f97316'),
            leftIndent=10,
            rightIndent=10,
            spaceAfter=5,
            fontName='Helvetica-Bold'
        ))

        # Code style
        if 'Code' not in styles:
            styles.add(ParagraphStyle(
                name='Code',
                parent=styles['Normal'],
                fontSize=9,
                textColor=HexColor('#1f2937'),
                backColor=HexColor('#f3f4f6'),
                leftIndent=20,
                rightIndent=20,
                fontName='Courier'
            ))

        return styles

    def generate_comprehensive_pdf_report(self, assessment_results: Dict[str, Any], output_filename: str = None) -> str:
        """Generate comprehensive PDF report from assessment results"""

        logger.info("📄 Generating comprehensive PDF report...")

        if output_filename is None:
            session_id = assessment_results.get('artemis_quantumsentinel_assessment', {}).get('assessment_id', 'unknown')
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"ARTEMIS_QUANTUMSENTINEL_COMPREHENSIVE_REPORT_{session_id}_{timestamp}.pdf"

        if not REPORTLAB_AVAILABLE:
            return self._generate_html_report_fallback(assessment_results, output_filename)

        try:
            # Create document
            doc = SimpleDocTemplate(
                output_filename,
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )

            # Build content
            content = []

            # Title Page
            content.extend(self._create_title_page(assessment_results))
            content.append(PageBreak())

            # Table of Contents
            content.extend(self._create_table_of_contents())
            content.append(PageBreak())

            # Executive Summary
            content.extend(self._create_executive_summary(assessment_results))
            content.append(PageBreak())

            # Assessment Overview
            content.extend(self._create_assessment_overview(assessment_results))
            content.append(PageBreak())

            # Module Results
            content.extend(self._create_module_results_section(assessment_results))
            content.append(PageBreak())

            # Risk Analysis
            content.extend(self._create_risk_analysis_section(assessment_results))
            content.append(PageBreak())

            # Recommendations
            content.extend(self._create_recommendations_section(assessment_results))
            content.append(PageBreak())

            # Technical Details
            content.extend(self._create_technical_details_section(assessment_results))
            content.append(PageBreak())

            # Appendices
            content.extend(self._create_appendices(assessment_results))

            # Build PDF
            doc.build(content)

            logger.info(f"✅ PDF report generated successfully: {output_filename}")
            return output_filename

        except Exception as e:
            logger.error(f"❌ PDF generation failed: {e}")
            return self._generate_html_report_fallback(assessment_results, output_filename.replace('.pdf', '.html'))

    def _create_title_page(self, results: Dict[str, Any]) -> List:
        """Create title page content"""

        content = []

        # Main title
        content.append(Paragraph(
            "🏹 ARTEMIS QUANTUMSENTINEL-NEXUS v5.0",
            self.styles['CustomTitle']
        ))

        content.append(Spacer(1, 20))

        content.append(Paragraph(
            "COMPREHENSIVE SECURITY ASSESSMENT REPORT",
            self.styles['CustomHeading1']
        ))

        content.append(Spacer(1, 40))

        # Assessment metadata
        assessment_info = results.get('artemis_quantumsentinel_assessment', {})

        assessment_data = [
            ['Assessment ID:', assessment_info.get('assessment_id', 'N/A')],
            ['Target Endpoint:', assessment_info.get('target_endpoint', 'N/A')],
            ['Assessment Date:', assessment_info.get('assessment_timestamp', 'N/A')[:10]],
            ['Completion Time:', assessment_info.get('completion_timestamp', 'N/A')[:19]],
            ['Duration:', f"{assessment_info.get('total_duration_seconds', 0):.1f} seconds"],
            ['Version:', assessment_info.get('version', '5.0')],
            ['Scope:', assessment_info.get('assessment_scope', 'comprehensive_quantum_level_security')]
        ]

        assessment_table = Table(assessment_data, colWidths=[2.5*inch, 3.5*inch])
        assessment_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), self.company_colors['secondary']),
            ('TEXTCOLOR', (0, 0), (0, -1), white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, black)
        ]))

        content.append(assessment_table)
        content.append(Spacer(1, 40))

        # Executive summary box
        exec_summary = results.get('executive_summary', {})

        content.append(Paragraph("EXECUTIVE SECURITY POSTURE", self.styles['CustomHeading2']))

        posture_data = [
            ['Overall Security Posture:', exec_summary.get('overall_security_posture', 'unknown').upper()],
            ['Overall Risk Level:', exec_summary.get('overall_risk_level', 'unknown').upper()],
            ['Critical Issues Identified:', str(exec_summary.get('critical_issues_identified', 0))],
            ['Business Impact Assessment:', exec_summary.get('business_impact_assessment', 'unknown')]
        ]

        posture_table = Table(posture_data, colWidths=[2.5*inch, 3.5*inch])

        # Color code based on risk level
        risk_level = exec_summary.get('overall_risk_level', 'unknown').lower()
        risk_color = self.risk_colors.get(risk_level, black)

        posture_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), self.company_colors['primary']),
            ('BACKGROUND', (1, 1), (1, 1), risk_color),  # Risk level row
            ('TEXTCOLOR', (0, 0), (0, -1), white),
            ('TEXTCOLOR', (1, 1), (1, 1), white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, black)
        ]))

        content.append(posture_table)

        # Footer
        content.append(Spacer(1, 60))
        content.append(Paragraph(
            "CONFIDENTIAL - FOR AUTHORIZED PERSONNEL ONLY",
            self.styles['ExecutiveSummary']
        ))

        content.append(Paragraph(
            f"Generated by ARTEMIS QUANTUMSENTINEL-NEXUS v5.0 on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}",
            self.styles['ExecutiveSummary']
        ))

        return content

    def _create_table_of_contents(self) -> List:
        """Create table of contents"""

        content = []

        content.append(Paragraph("TABLE OF CONTENTS", self.styles['CustomHeading1']))
        content.append(Spacer(1, 20))

        toc_items = [
            ("1. Executive Summary", "3"),
            ("2. Assessment Overview", "4"),
            ("3. Module Results", "5"),
            ("   3.1 Threat Modeling Results", "5"),
            ("   3.2 Adversarial ML Assessment", "6"),
            ("   3.3 Quantum Cryptography Analysis", "7"),
            ("   3.4 Zero-Day Prediction Results", "8"),
            ("   3.5 Compliance Validation", "9"),
            ("   3.6 Cognitive Security Assessment", "10"),
            ("4. Integrated Risk Analysis", "11"),
            ("5. Strategic Recommendations", "12"),
            ("6. Technical Implementation Details", "13"),
            ("7. Next Steps Roadmap", "14"),
            ("Appendix A: Methodology", "15"),
            ("Appendix B: Standards and Compliance", "16"),
            ("Appendix C: Detailed Findings", "17"),
        ]

        for item, page in toc_items:
            toc_line = f"{item} {'.' * (50 - len(item) - len(page))} {page}"
            content.append(Paragraph(toc_line, self.styles['Normal']))

        return content

    def _create_executive_summary(self, results: Dict[str, Any]) -> List:
        """Create executive summary section"""

        content = []

        content.append(Paragraph("1. EXECUTIVE SUMMARY", self.styles['CustomHeading1']))

        exec_summary = results.get('executive_summary', {})

        # Key findings
        content.append(Paragraph("KEY FINDINGS", self.styles['CustomHeading2']))

        findings = exec_summary.get('key_findings', [])
        for finding in findings:
            content.append(Paragraph(f"• {finding}", self.styles['Normal']))

        content.append(Spacer(1, 15))

        # Security posture assessment
        content.append(Paragraph("SECURITY POSTURE ASSESSMENT", self.styles['CustomHeading2']))

        posture_text = f"""
        The comprehensive ARTEMIS QUANTUMSENTINEL-NEXUS v5.0 assessment has evaluated the target system
        across {len(results.get('detailed_module_results', {}))} critical security domains.

        Overall Security Posture: <b>{exec_summary.get('overall_security_posture', 'unknown').upper()}</b>

        Risk Level: <b>{exec_summary.get('overall_risk_level', 'unknown').upper()}</b>

        Critical Issues Requiring Immediate Attention: <b>{exec_summary.get('critical_issues_identified', 0)}</b>

        Business Impact Assessment: <b>{exec_summary.get('business_impact_assessment', 'unknown')}</b>

        Assessment Confidence Level: <b>{exec_summary.get('confidence_level', 'unknown').upper()}</b>
        """

        content.append(Paragraph(posture_text, self.styles['ExecutiveSummary']))

        # Immediate actions required
        if exec_summary.get('immediate_actions_required', False):
            content.append(Spacer(1, 15))
            content.append(Paragraph("⚠️ IMMEDIATE ACTIONS REQUIRED", self.styles['RiskCritical']))

            action_text = """
            Critical security issues have been identified that require immediate executive attention
            and remediation. Failure to address these issues promptly may result in significant
            operational disruption, regulatory violations, and business impact.
            """
            content.append(Paragraph(action_text, self.styles['ExecutiveSummary']))

        # Business recommendations
        content.append(Spacer(1, 15))
        content.append(Paragraph("EXECUTIVE RECOMMENDATIONS", self.styles['CustomHeading2']))

        exec_recommendations = [
            "Prioritize immediate remediation of critical security findings",
            "Implement comprehensive security monitoring and incident response procedures",
            "Establish regular security assessment cycles using quantum-level testing",
            "Invest in staff training for emerging AI and quantum security threats",
            "Develop strategic security roadmap aligned with business objectives"
        ]

        for rec in exec_recommendations:
            content.append(Paragraph(f"• {rec}", self.styles['Normal']))

        return content

    def _create_assessment_overview(self, results: Dict[str, Any]) -> List:
        """Create assessment overview section"""

        content = []

        content.append(Paragraph("2. ASSESSMENT OVERVIEW", self.styles['CustomHeading1']))

        # Assessment methodology
        content.append(Paragraph("ASSESSMENT METHODOLOGY", self.styles['CustomHeading2']))

        methodology_text = """
        The ARTEMIS QUANTUMSENTINEL-NEXUS v5.0 platform represents the pinnacle of automated
        security assessment technology, combining artificial intelligence, quantum cryptography analysis,
        human behavioral assessment, and advanced threat modeling to provide comprehensive
        security evaluation across multiple domains.

        This assessment employed the following advanced testing modules:
        """
        content.append(Paragraph(methodology_text, self.styles['Normal']))
        content.append(Spacer(1, 10))

        # Module execution results
        module_results = results.get('module_execution_results', {})

        module_data = [['Module', 'Status', 'Duration (s)', 'Success']]

        for module_id, module_info in module_results.items():
            status_icon = "✅" if module_info.get('success', False) else "❌"
            module_data.append([
                module_id.replace('_', ' ').title(),
                module_info.get('status', 'unknown'),
                f"{module_info.get('duration_seconds', 0):.1f}",
                status_icon
            ])

        module_table = Table(module_data, colWidths=[2*inch, 1.5*inch, 1*inch, 0.8*inch])
        module_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.company_colors['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, HexColor('#f8f9fa')])
        ]))

        content.append(module_table)

        # Assessment scope
        content.append(Spacer(1, 15))
        content.append(Paragraph("ASSESSMENT SCOPE AND COVERAGE", self.styles['CustomHeading2']))

        scope_text = """
        The assessment covered the following security domains with quantum-level analysis depth:

        • Autonomous Threat Modeling with AI-powered attack trees and graph neural networks
        • Adversarial Machine Learning attacks including FGSM, PGD, and model extraction
        • Quantum-resistant cryptography analysis and post-quantum readiness assessment
        • Zero-day vulnerability prediction using transformer models and threat intelligence
        • Advanced HIPAA/GDPR compliance validation with regulatory risk assessment
        • Cognitive security testing including psychological manipulation and social engineering

        Each domain was assessed using state-of-the-art techniques and industry-leading methodologies
        to provide comprehensive coverage of modern and emerging security threats.
        """
        content.append(Paragraph(scope_text, self.styles['Normal']))

        return content

    def _create_module_results_section(self, results: Dict[str, Any]) -> List:
        """Create detailed module results section"""

        content = []

        content.append(Paragraph("3. DETAILED MODULE RESULTS", self.styles['CustomHeading1']))

        detailed_results = results.get('detailed_module_results', {})

        # Process each module
        for module_id, module_results in detailed_results.items():
            content.extend(self._create_module_subsection(module_id, module_results))
            content.append(Spacer(1, 20))

        return content

    def _create_module_subsection(self, module_id: str, module_results: Dict[str, Any]) -> List:
        """Create subsection for individual module results"""

        content = []

        module_name = module_id.replace('_', ' ').title()
        content.append(Paragraph(f"3.{len(content)+1} {module_name.upper()}", self.styles['CustomHeading2']))

        # Module-specific content based on type
        if module_id == 'threat_modeling':
            content.extend(self._create_threat_modeling_content(module_results))
        elif module_id == 'adversarial_ml':
            content.extend(self._create_adversarial_ml_content(module_results))
        elif module_id == 'quantum_crypto':
            content.extend(self._create_quantum_crypto_content(module_results))
        elif module_id == 'zero_day_prediction':
            content.extend(self._create_zero_day_content(module_results))
        elif module_id == 'compliance_validation':
            content.extend(self._create_compliance_content(module_results))
        elif module_id == 'cognitive_security':
            content.extend(self._create_cognitive_security_content(module_results))
        else:
            # Generic module content
            content.append(Paragraph(f"Results for {module_name}:", self.styles['Normal']))
            content.append(Paragraph(json.dumps(module_results, indent=2)[:500] + "...", self.styles['Code']))

        return content

    def _create_threat_modeling_content(self, results: Dict[str, Any]) -> List:
        """Create threat modeling specific content"""

        content = []

        content.append(Paragraph("THREAT MODEL ANALYSIS", self.styles['Normal']))

        # Extract key metrics
        model_metadata = results.get('model_metadata', {})
        threat_landscape = results.get('threat_landscape', {})

        threat_summary = [
            ['Total Threat Nodes:', str(model_metadata.get('total_threat_nodes', 0))],
            ['Total Attack Paths:', str(model_metadata.get('total_attack_paths', 0))],
            ['Critical Threats:', str(threat_landscape.get('critical_threats', 0))],
            ['High Threats:', str(threat_landscape.get('high_threats', 0))],
            ['Analysis Depth:', model_metadata.get('analysis_depth', 'standard')]
        ]

        threat_table = Table(threat_summary, colWidths=[2*inch, 1.5*inch])
        threat_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), self.company_colors['info']),
            ('TEXTCOLOR', (0, 0), (0, -1), white),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, black)
        ]))

        content.append(threat_table)
        content.append(Spacer(1, 10))

        # Risk assessment
        risk_assessment = results.get('risk_assessment', {})
        if risk_assessment:
            risk_text = f"""
            Risk Assessment Summary:
            • Overall Risk Score: {risk_assessment.get('overall_risk_score', 'N/A')}
            • Risk Level: {risk_assessment.get('risk_level', 'N/A')}
            • Critical Attack Paths: {risk_assessment.get('critical_paths', 0)}
            • High Risk Attack Paths: {risk_assessment.get('high_risk_paths', 0)}
            """
            content.append(Paragraph(risk_text, self.styles['Normal']))

        return content

    def _create_adversarial_ml_content(self, results: Dict[str, Any]) -> List:
        """Create adversarial ML specific content"""

        content = []

        content.append(Paragraph("ADVERSARIAL MACHINE LEARNING ASSESSMENT", self.styles['Normal']))

        # Attack summary
        attack_summary = results.get('attack_summary', {})
        ml_analysis = results.get('ml_security_analysis', {})

        ml_summary = [
            ['Total Tests Executed:', str(attack_summary.get('total_tests_executed', 0))],
            ['Successful Attacks:', str(attack_summary.get('successful_attacks', 0))],
            ['Failed Attacks:', str(attack_summary.get('failed_attacks', 0))],
            ['Detection Evasion Rate:', f"{attack_summary.get('detection_evasion_rate', 0):.1%}"],
            ['Attack Categories Tested:', str(attack_summary.get('attack_categories_tested', 0))]
        ]

        ml_table = Table(ml_summary, colWidths=[2*inch, 1.5*inch])
        ml_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), self.company_colors['warning']),
            ('TEXTCOLOR', (0, 0), (0, -1), white),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, black)
        ]))

        content.append(ml_table)
        content.append(Spacer(1, 10))

        # Vulnerability assessment
        vuln_assessment = ml_analysis.get('vulnerability_assessment', {})
        if vuln_assessment:
            vuln_text = f"""
            ML Security Analysis:
            • Overall Robustness Score: {vuln_assessment.get('overall_robustness_score', 'N/A')}
            • Attack Success Rate: {vuln_assessment.get('attack_success_rate', 0):.1%}
            • Average Attack Confidence: {vuln_assessment.get('average_attack_confidence', 0):.2f}
            • Detection Evasion Rate: {vuln_assessment.get('detection_evasion_rate', 0):.1%}
            """
            content.append(Paragraph(vuln_text, self.styles['Normal']))

        return content

    def _create_quantum_crypto_content(self, results: Dict[str, Any]) -> List:
        """Create quantum crypto specific content"""

        content = []

        content.append(Paragraph("QUANTUM CRYPTOGRAPHY ANALYSIS", self.styles['Normal']))

        # Vulnerability assessment
        vuln_assessment = results.get('vulnerability_assessment', {})
        compliance_status = results.get('compliance_status', {})

        quantum_summary = [
            ['Critical Vulnerabilities:', str(len(vuln_assessment.get('critical_vulnerabilities', [])))],
            ['High Risk Vulnerabilities:', str(len(vuln_assessment.get('high_risk_vulnerabilities', [])))],
            ['Quantum Safe Algorithms:', str(len(vuln_assessment.get('quantum_safe_algorithms', [])))],
            ['NIST PQC Compliance:', compliance_status.get('nist_pqc_compliance', 'unknown')],
            ['Compliance Score:', f"{compliance_status.get('compliance_score', 0):.1f}%"]
        ]

        quantum_table = Table(quantum_summary, colWidths=[2*inch, 1.5*inch])
        quantum_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), self.company_colors['secondary']),
            ('TEXTCOLOR', (0, 0), (0, -1), white),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, black)
        ]))

        content.append(quantum_table)
        content.append(Spacer(1, 10))

        # Risk analysis
        risk_analysis = results.get('risk_analysis', {})
        if risk_analysis:
            risk_text = f"""
            Quantum Cryptographic Risk Assessment:
            • Overall Quantum Risk Level: {risk_analysis.get('overall_quantum_risk_level', 'N/A')}
            • Immediate Action Required: {risk_analysis.get('risk_distribution', {}).get('immediate_action_required', 0)}
            • High Priority Items: {risk_analysis.get('risk_distribution', {}).get('high_priority', 0)}
            """
            content.append(Paragraph(risk_text, self.styles['Normal']))

        return content

    def _create_zero_day_content(self, results: Dict[str, Any]) -> List:
        """Create zero-day prediction specific content"""

        content = []

        content.append(Paragraph("ZERO-DAY VULNERABILITY PREDICTIONS", self.styles['Normal']))

        # Prediction summary
        predicted_vulns = results.get('predicted_vulnerabilities', [])
        risk_assessment = results.get('risk_assessment', {})

        zero_day_summary = [
            ['Total Predictions Generated:', str(len(predicted_vulns))],
            ['Critical Predictions:', str(len([p for p in predicted_vulns if p.get('severity') == 'critical']))],
            ['High Confidence Predictions:', str(risk_assessment.get('high_confidence_predictions', 0))],
            ['Immediate Threats (1-7 days):', str(len([p for p in predicted_vulns if '1-7 days' in p.get('predicted_exploitation_timeline', '')]))],
            ['Overall Risk Level:', risk_assessment.get('overall_risk_level', 'unknown')]
        ]

        zero_day_table = Table(zero_day_summary, colWidths=[2*inch, 1.5*inch])
        zero_day_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), self.company_colors['danger']),
            ('TEXTCOLOR', (0, 0), (0, -1), white),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, black)
        ]))

        content.append(zero_day_table)
        content.append(Spacer(1, 10))

        # Top predictions
        if predicted_vulns:
            content.append(Paragraph("Top Critical Predictions:", self.styles['Normal']))
            for i, pred in enumerate(predicted_vulns[:3]):
                pred_text = f"""
                {i+1}. {pred.get('vulnerability_type', 'Unknown').replace('_', ' ').title()}
                   Severity: {pred.get('severity', 'unknown').upper()}
                   Confidence: {pred.get('confidence', 'unknown')}
                   Timeline: {pred.get('predicted_exploitation_timeline', 'unknown')}
                """
                content.append(Paragraph(pred_text, self.styles['Normal']))

        return content

    def _create_compliance_content(self, results: Dict[str, Any]) -> List:
        """Create compliance validation specific content"""

        content = []

        content.append(Paragraph("REGULATORY COMPLIANCE ASSESSMENT", self.styles['Normal']))

        # Violation summary
        violation_analysis = results.get('violation_analysis', {})
        compliance_scores = results.get('compliance_scores', {})

        violation_summary = violation_analysis.get('violation_summary', {})

        compliance_summary = [
            ['Total Violations:', str(violation_summary.get('total_violations', 0))],
            ['Critical Violations:', str(violation_summary.get('critical_violations', 0))],
            ['High Risk Violations:', str(violation_summary.get('high_violations', 0))],
            ['Overall Compliance Score:', f"{compliance_scores.get('overall_compliance_score', 0):.1f}%"],
            ['Compliance Grade:', compliance_scores.get('compliance_grade', 'N/A')]
        ]

        compliance_table = Table(compliance_summary, colWidths=[2*inch, 1.5*inch])
        compliance_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), self.company_colors['success']),
            ('TEXTCOLOR', (0, 0), (0, -1), white),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, black)
        ]))

        content.append(compliance_table)
        content.append(Spacer(1, 10))

        # Risk assessment
        risk_assessment = results.get('risk_assessment', {})
        if risk_assessment:
            risk_text = f"""
            Compliance Risk Assessment:
            • Overall Risk Level: {risk_assessment.get('overall_risk_level', 'N/A')}
            • Regulatory Scrutiny Risk: {risk_assessment.get('regulatory_scrutiny_risk', {}).get('scrutiny_level', 'N/A')}
            • Business Continuity Risk: {risk_assessment.get('business_continuity_risk', {}).get('continuity_risk_level', 'N/A')}
            • Legal Action Probability: {risk_assessment.get('legal_action_probability', {}).get('legal_action_probability', 0)}%
            """
            content.append(Paragraph(risk_text, self.styles['Normal']))

        return content

    def _create_cognitive_security_content(self, results: Dict[str, Any]) -> List:
        """Create cognitive security specific content"""

        content = []

        content.append(Paragraph("COGNITIVE SECURITY AND HUMAN FACTORS", self.styles['Normal']))

        # Test results summary
        cognitive_scores = results.get('cognitive_security_scores', {})
        test_results = results.get('cognitive_test_results', [])

        cognitive_summary = [
            ['Total Cognitive Tests:', str(len(test_results))],
            ['Successful Attacks:', str(len([r for r in test_results if r.get('attack_successful', False)]))],
            ['Overall Security Score:', f"{cognitive_scores.get('overall_cognitive_security_score', 0):.1f}%"],
            ['Security Grade:', cognitive_scores.get('security_grade', 'N/A')],
            ['Trust Manipulation Rate:', f"{cognitive_scores.get('trust_manipulation_rate', 0):.1f}%"]
        ]

        cognitive_table = Table(cognitive_summary, colWidths=[2*inch, 1.5*inch])
        cognitive_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), HexColor('#8b5cf6')),
            ('TEXTCOLOR', (0, 0), (0, -1), white),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, black)
        ]))

        content.append(cognitive_table)
        content.append(Spacer(1, 10))

        # Human factor risks
        human_factor_risks = results.get('human_factor_risks', {})
        if human_factor_risks:
            risk_text = f"""
            Human Factor Risk Assessment:
            • Overall Human Factor Risk: {human_factor_risks.get('overall_human_factor_risk', 'N/A')}
            • Social Engineering Risk: {human_factor_risks.get('social_engineering_risk', 'N/A')}
            • Multi-Modal Attack Risk: {human_factor_risks.get('multi_modal_risk', 'N/A')}
            • Psychological Manipulation Risk: {human_factor_risks.get('psychological_manipulation_risk', 'N/A')}
            """
            content.append(Paragraph(risk_text, self.styles['Normal']))

        return content

    def _create_risk_analysis_section(self, results: Dict[str, Any]) -> List:
        """Create integrated risk analysis section"""

        content = []

        content.append(Paragraph("4. INTEGRATED RISK ANALYSIS", self.styles['CustomHeading1']))

        integrated_analysis = results.get('integrated_security_analysis', {})
        aggregated_risks = integrated_analysis.get('aggregated_risk_assessment', {})

        # Overall risk assessment
        content.append(Paragraph("OVERALL RISK ASSESSMENT", self.styles['CustomHeading2']))

        risk_summary = [
            ['Aggregate Risk Score:', f"{aggregated_risks.get('aggregate_risk_score', 0):.1f}/100"],
            ['Overall Risk Level:', aggregated_risks.get('overall_risk_level', 'unknown').upper()],
            ['Critical Issues Total:', str(aggregated_risks.get('critical_issues_total', 0))],
            ['Technical Risk:', f"{aggregated_risks.get('risk_distribution', {}).get('technical_risk', 0):.1f}"],
            ['Compliance Risk:', f"{aggregated_risks.get('risk_distribution', {}).get('compliance_risk', 0):.1f}"],
            ['Human Factor Risk:', f"{aggregated_risks.get('risk_distribution', {}).get('human_factor_risk', 0):.1f}"]
        ]

        risk_table = Table(risk_summary, colWidths=[2*inch, 2*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), self.company_colors['danger']),
            ('TEXTCOLOR', (0, 0), (0, -1), white),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, black)
        ]))

        content.append(risk_table)
        content.append(Spacer(1, 15))

        # Cross-module analysis
        cross_analysis = integrated_analysis.get('cross_module_analysis', {})
        if cross_analysis:
            content.append(Paragraph("CROSS-MODULE SECURITY ANALYSIS", self.styles['CustomHeading2']))

            cross_text = """
            The integrated analysis reveals correlations and dependencies between different security domains:

            • Security Pattern Analysis: Multiple attack vectors show coordinated exploitation potential
            • Threat Vector Correlations: AI and human-based attacks demonstrate synergistic effects
            • Defense Gap Analysis: Identified gaps in coordinated defense mechanisms
            • Attack Surface Mapping: Complex interdependencies increase overall risk exposure
            """
            content.append(Paragraph(cross_text, self.styles['Normal']))

        # Vulnerability correlations
        vuln_correlations = integrated_analysis.get('vulnerability_correlations', {})
        if vuln_correlations:
            content.append(Spacer(1, 15))
            content.append(Paragraph("VULNERABILITY CORRELATION ANALYSIS", self.styles['CustomHeading2']))

            clusters = vuln_correlations.get('vulnerability_clusters', {})
            if clusters:
                content.append(Paragraph("Identified vulnerability clusters that amplify risk:", self.styles['Normal']))
                for cluster_type, count in clusters.items():
                    content.append(Paragraph(f"• {cluster_type.replace('_', ' ').title()}: {count} instances", self.styles['Normal']))

        return content

    def _create_recommendations_section(self, results: Dict[str, Any]) -> List:
        """Create strategic recommendations section"""

        content = []

        content.append(Paragraph("5. STRATEGIC RECOMMENDATIONS", self.styles['CustomHeading1']))

        # Unified recommendations
        integrated_analysis = results.get('integrated_security_analysis', {})
        recommendations = integrated_analysis.get('unified_recommendations', [])

        # Group by priority
        critical_recs = [r for r in recommendations if r.get('priority') == 'critical']
        high_recs = [r for r in recommendations if r.get('priority') == 'high']
        medium_recs = [r for r in recommendations if r.get('priority') == 'medium']

        # Critical recommendations
        if critical_recs:
            content.append(Paragraph("⚠️ CRITICAL PRIORITY RECOMMENDATIONS", self.styles['RiskCritical']))
            content.append(Spacer(1, 5))

            for i, rec in enumerate(critical_recs, 1):
                rec_text = f"""
                {i}. {rec.get('recommendation', 'No description available')}
                   Category: {rec.get('category', 'general')}
                   Rationale: {rec.get('rationale', 'No rationale provided')}
                   Timeline: {rec.get('implementation_timeline', 'TBD')}
                """
                content.append(Paragraph(rec_text, self.styles['Normal']))
                content.append(Spacer(1, 5))

        # High priority recommendations
        if high_recs:
            content.append(Spacer(1, 10))
            content.append(Paragraph("HIGH PRIORITY RECOMMENDATIONS", self.styles['RiskHigh']))
            content.append(Spacer(1, 5))

            for i, rec in enumerate(high_recs[:5], 1):  # Limit to top 5
                rec_text = f"""
                {i}. {rec.get('recommendation', 'No description available')}
                   Category: {rec.get('category', 'general')}
                """
                content.append(Paragraph(rec_text, self.styles['Normal']))
                content.append(Spacer(1, 5))

        # Next steps roadmap
        roadmap = results.get('next_steps_roadmap', {})
        if roadmap:
            content.append(Spacer(1, 15))
            content.append(Paragraph("IMPLEMENTATION ROADMAP", self.styles['CustomHeading2']))

            for phase_name, phase_data in roadmap.items():
                if isinstance(phase_data, dict) and 'timeline' in phase_data:
                    content.append(Paragraph(f"{phase_name.replace('_', ' ').title()} ({phase_data.get('timeline', 'TBD')})", self.styles['Normal']))

                    actions = phase_data.get('actions', [])
                    for action in actions[:3]:  # Limit to top 3 per phase
                        if isinstance(action, dict):
                            content.append(Paragraph(f"• {action.get('recommendation', action.get('category', 'Unknown action'))}", self.styles['Normal']))
                        else:
                            content.append(Paragraph(f"• {action}", self.styles['Normal']))

                    content.append(Spacer(1, 8))

        return content

    def _create_technical_details_section(self, results: Dict[str, Any]) -> List:
        """Create technical implementation details section"""

        content = []

        content.append(Paragraph("6. TECHNICAL IMPLEMENTATION DETAILS", self.styles['CustomHeading1']))

        # Assessment metadata
        assessment_info = results.get('artemis_quantumsentinel_assessment', {})

        content.append(Paragraph("ASSESSMENT CONFIGURATION", self.styles['CustomHeading2']))

        config_data = [
            ['Assessment Version:', assessment_info.get('version', '5.0')],
            ['Assessment Scope:', assessment_info.get('assessment_scope', 'N/A')],
            ['Target Endpoint:', assessment_info.get('target_endpoint', 'N/A')],
            ['Total Duration:', f"{assessment_info.get('total_duration_seconds', 0):.1f} seconds"],
            ['Start Time:', assessment_info.get('assessment_timestamp', 'N/A')[:19]],
            ['Completion Time:', assessment_info.get('completion_timestamp', 'N/A')[:19]]
        ]

        config_table = Table(config_data, colWidths=[2*inch, 3*inch])
        config_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), self.company_colors['info']),
            ('TEXTCOLOR', (0, 0), (0, -1), white),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, black)
        ]))

        content.append(config_table)
        content.append(Spacer(1, 15))

        # Module execution summary
        content.append(Paragraph("MODULE EXECUTION SUMMARY", self.styles['CustomHeading2']))

        integrated_analysis = results.get('integrated_security_analysis', {})
        execution_summary = integrated_analysis.get('execution_summary', {})

        exec_text = f"""
        Assessment Execution Statistics:
        • Total Modules Configured: {execution_summary.get('total_modules', 'N/A')}
        • Successfully Executed: {execution_summary.get('successful_modules', 'N/A')}
        • Failed Modules: {execution_summary.get('failed_modules', 'N/A')}
        • Overall Success Rate: {execution_summary.get('overall_success_rate', 0):.1f}%

        Failed modules (if any):
        """
        content.append(Paragraph(exec_text, self.styles['Normal']))

        # List failed modules
        failed_modules = integrated_analysis.get('failed_modules', {})
        for module_name, error_msg in failed_modules.items():
            content.append(Paragraph(f"• {module_name}: {error_msg}", self.styles['Normal']))

        # Quantum insights
        quantum_insights = results.get('quantum_level_insights', {})
        if quantum_insights:
            content.append(Spacer(1, 15))
            content.append(Paragraph("QUANTUM-LEVEL SECURITY INSIGHTS", self.styles['CustomHeading2']))

            insights_text = f"""
            Advanced Security Maturity Assessment:
            • Quantum Security Readiness: {quantum_insights.get('quantum_security_readiness', 'N/A')}
            • AI Security Maturity: {quantum_insights.get('ai_security_maturity', 'N/A')}
            • Human Factor Resilience: {quantum_insights.get('human_factor_resilience', 'N/A')}
            • Regulatory Compliance Posture: {quantum_insights.get('regulatory_compliance_posture', 'N/A')}
            • Emerging Threat Preparedness: {quantum_insights.get('emerging_threat_preparedness', 'N/A')}
            • Defense Integration Effectiveness: {quantum_insights.get('defense_integration_effectiveness', 'N/A')}
            """
            content.append(Paragraph(insights_text, self.styles['Normal']))

        return content

    def _create_appendices(self, results: Dict[str, Any]) -> List:
        """Create appendices section"""

        content = []

        content.append(Paragraph("APPENDIX A: METHODOLOGY", self.styles['CustomHeading1']))

        methodology_text = """
        ARTEMIS QUANTUMSENTINEL-NEXUS v5.0 Methodology Overview:

        The assessment employs a multi-layered approach combining:

        1. Autonomous Threat Modeling using Graph Neural Networks
        2. Adversarial Machine Learning Testing (FGSM, PGD, Model Extraction)
        3. Quantum-Resistant Cryptography Analysis
        4. Zero-Day Vulnerability Prediction using Transformer Models
        5. Advanced Regulatory Compliance Validation (HIPAA/GDPR)
        6. Cognitive Security and Human Factor Assessment

        Each module operates independently but results are integrated through
        cross-correlation analysis to identify systemic vulnerabilities and
        defense gaps that may not be apparent through isolated testing.
        """
        content.append(Paragraph(methodology_text, self.styles['Normal']))

        content.append(PageBreak())
        content.append(Paragraph("APPENDIX B: STANDARDS AND COMPLIANCE", self.styles['CustomHeading1']))

        appendix_data = results.get('appendix', {})
        standards = appendix_data.get('standards_compliance', [])

        standards_text = f"""
        This assessment aligns with the following industry standards and frameworks:

        Standards Compliance: {', '.join(standards) if standards else 'N/A'}

        Assessment Confidence: {appendix_data.get('assessment_confidence', 'N/A')}

        Limitations and Assumptions:
        """
        content.append(Paragraph(standards_text, self.styles['Normal']))

        limitations = appendix_data.get('limitations_and_assumptions', [])
        for limitation in limitations:
            content.append(Paragraph(f"• {limitation}", self.styles['Normal']))

        return content

    def _generate_html_report_fallback(self, results: Dict[str, Any], output_filename: str) -> str:
        """Generate HTML report as fallback when reportlab is not available"""

        logger.info("📄 Generating HTML report (PDF libraries not available)...")

        html_filename = output_filename.replace('.pdf', '.html')

        # Create comprehensive HTML report
        html_content = self._generate_html_content(results)

        try:
            with open(html_filename, 'w', encoding='utf-8') as f:
                f.write(html_content)

            logger.info(f"✅ HTML report generated successfully: {html_filename}")

            # Try to convert to PDF using weasyprint or wkhtmltopdf if available
            pdf_filename = self._try_html_to_pdf_conversion(html_filename, output_filename)

            return pdf_filename if pdf_filename else html_filename

        except Exception as e:
            logger.error(f"❌ HTML report generation failed: {e}")
            return self._generate_json_report_fallback(results, output_filename)

    def _generate_html_content(self, results: Dict[str, Any]) -> str:
        """Generate comprehensive HTML content"""

        assessment_info = results.get('artemis_quantumsentinel_assessment', {})
        exec_summary = results.get('executive_summary', {})

        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>ARTEMIS QUANTUMSENTINEL-NEXUS v5.0 - Comprehensive Security Assessment</title>
            <style>
                body {{ font-family: 'Helvetica', Arial, sans-serif; margin: 0; padding: 20px; line-height: 1.6; }}
                .header {{ background: linear-gradient(135deg, #1f2937, #3b82f6); color: white; padding: 30px; text-align: center; margin-bottom: 30px; }}
                .title {{ font-size: 2.5em; margin-bottom: 10px; }}
                .subtitle {{ font-size: 1.5em; opacity: 0.9; }}
                .section {{ margin-bottom: 30px; padding: 20px; border-left: 4px solid #3b82f6; background: #f8f9fa; }}
                .section h2 {{ color: #1f2937; margin-top: 0; }}
                .risk-critical {{ background: #ef4444; color: white; padding: 10px; border-radius: 5px; }}
                .risk-high {{ background: #f97316; color: white; padding: 10px; border-radius: 5px; }}
                .risk-medium {{ background: #f59e0b; color: white; padding: 10px; border-radius: 5px; }}
                .risk-low {{ background: #10b981; color: white; padding: 10px; border-radius: 5px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background: #1f2937; color: white; }}
                .footer {{ text-align: center; margin-top: 50px; padding: 20px; color: #666; }}
            </style>
        </head>
        <body>
            <div class="header">
                <div class="title">🏹 ARTEMIS QUANTUMSENTINEL-NEXUS v5.0</div>
                <div class="subtitle">COMPREHENSIVE SECURITY ASSESSMENT REPORT</div>
                <p>Assessment ID: {assessment_info.get('assessment_id', 'N/A')} | Target: {assessment_info.get('target_endpoint', 'N/A')}</p>
                <p>Generated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</p>
            </div>

            <div class="section">
                <h2>🏢 Executive Summary</h2>
                <div class="risk-{exec_summary.get('overall_risk_level', 'medium')}">
                    <h3>Overall Security Posture: {exec_summary.get('overall_security_posture', 'unknown').upper()}</h3>
                    <p><strong>Risk Level:</strong> {exec_summary.get('overall_risk_level', 'unknown').upper()}</p>
                    <p><strong>Critical Issues:</strong> {exec_summary.get('critical_issues_identified', 0)}</p>
                    <p><strong>Business Impact:</strong> {exec_summary.get('business_impact_assessment', 'unknown')}</p>
                </div>

                <h3>Key Findings</h3>
                <ul>
        """

        for finding in exec_summary.get('key_findings', []):
            html += f"<li>{finding}</li>"

        html += """
                </ul>
            </div>
        """

        # Add module results
        detailed_results = results.get('detailed_module_results', {})
        if detailed_results:
            html += '<div class="section"><h2>📊 Module Results Summary</h2>'
            html += '<table><tr><th>Module</th><th>Status</th><th>Key Findings</th></tr>'

            for module_id, module_results in detailed_results.items():
                module_name = module_id.replace('_', ' ').title()
                html += f'<tr><td>{module_name}</td><td>✅ Completed</td><td>Detailed analysis completed</td></tr>'

            html += '</table></div>'

        # Add recommendations
        integrated_analysis = results.get('integrated_security_analysis', {})
        recommendations = integrated_analysis.get('unified_recommendations', [])

        if recommendations:
            html += '<div class="section"><h2>📋 Strategic Recommendations</h2>'

            critical_recs = [r for r in recommendations if r.get('priority') == 'critical']
            high_recs = [r for r in recommendations if r.get('priority') == 'high']

            if critical_recs:
                html += '<h3 class="risk-critical">⚠️ Critical Priority</h3><ul>'
                for rec in critical_recs:
                    html += f'<li><strong>{rec.get("recommendation", "N/A")}</strong><br>Category: {rec.get("category", "N/A")}</li>'
                html += '</ul>'

            if high_recs:
                html += '<h3 class="risk-high">High Priority</h3><ul>'
                for rec in high_recs[:5]:
                    html += f'<li>{rec.get("recommendation", "N/A")}</li>'
                html += '</ul>'

            html += '</div>'

        # Add technical details
        html += f"""
            <div class="section">
                <h2>🔧 Technical Assessment Details</h2>
                <table>
                    <tr><th>Metric</th><th>Value</th></tr>
                    <tr><td>Assessment Version</td><td>{assessment_info.get('version', '5.0')}</td></tr>
                    <tr><td>Duration</td><td>{assessment_info.get('total_duration_seconds', 0):.1f} seconds</td></tr>
                    <tr><td>Modules Executed</td><td>{len(detailed_results)}</td></tr>
                    <tr><td>Assessment Scope</td><td>{assessment_info.get('assessment_scope', 'comprehensive')}</td></tr>
                </table>
            </div>

            <div class="footer">
                <p><strong>CONFIDENTIAL - FOR AUTHORIZED PERSONNEL ONLY</strong></p>
                <p>Generated by ARTEMIS QUANTUMSENTINEL-NEXUS v5.0 | © 2025 Advanced Security Assessment Platform</p>
                <p>This report contains proprietary security assessment data and should be handled according to organizational data classification policies.</p>
            </div>
        </body>
        </html>
        """

        return html

    def _try_html_to_pdf_conversion(self, html_filename: str, pdf_filename: str) -> Optional[str]:
        """Try to convert HTML to PDF using available tools"""

        # Try wkhtmltopdf first
        try:
            result = subprocess.run(['wkhtmltopdf', html_filename, pdf_filename],
                                 capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                logger.info(f"✅ PDF generated using wkhtmltopdf: {pdf_filename}")
                return pdf_filename
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Try weasyprint
        try:
            import weasyprint
            weasyprint.HTML(filename=html_filename).write_pdf(pdf_filename)
            logger.info(f"✅ PDF generated using weasyprint: {pdf_filename}")
            return pdf_filename
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"⚠️ Weasyprint conversion failed: {e}")

        logger.info(f"ℹ️ HTML report available at: {html_filename}")
        return None

    def _generate_json_report_fallback(self, results: Dict[str, Any], output_filename: str) -> str:
        """Generate JSON report as final fallback"""

        json_filename = output_filename.replace('.pdf', '.json').replace('.html', '.json')

        try:
            with open(json_filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)

            logger.info(f"✅ JSON report generated as fallback: {json_filename}")
            return json_filename

        except Exception as e:
            logger.error(f"❌ JSON report generation failed: {e}")
            raise

def main():
    """Generate comprehensive PDF report from assessment JSON file"""
    import sys
    import json

    if len(sys.argv) != 2:
        print("Usage: python3 quantum_pdf_generator.py <assessment_json_file>")
        sys.exit(1)

    assessment_file = sys.argv[1]

    try:
        # Load the actual assessment results
        with open(assessment_file, 'r') as f:
            assessment_results = json.load(f)

        generator = QuantumPDFGenerator()

        # Generate output filename based on assessment ID
        assessment_id = assessment_results.get('artemis_assessment', {}).get('assessment_id', 'unknown')
        output_filename = f"ARTEMIS_COMPREHENSIVE_REPORT_{assessment_id}.pdf"

        output_file = generator.generate_comprehensive_pdf_report(
            assessment_results,
            output_filename
        )

        print(f"📄 Comprehensive report generated: {output_file}")

    except FileNotFoundError:
        print(f"Error: Assessment file '{assessment_file}' not found.")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in file '{assessment_file}'.")
        sys.exit(1)
    except Exception as e:
        print(f"Error generating report: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()