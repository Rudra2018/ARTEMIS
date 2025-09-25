#!/usr/bin/env python3
"""
Nexus AI Security Commander - Universal AI Security Testing Platform
===================================================================

Advanced command-line interface for comprehensive AI/LLM security testing including:
- OWASP LLM Top 10 vulnerability assessment
- Advanced prompt injection and jailbreak testing
- Research-based adversarial attacks
- Multi-language and encoding-based attacks
- Healthcare and financial domain-specific testing
- Continuous monitoring and reporting
- Enterprise-grade orchestration

Features:
🛡️ Complete OWASP LLM Top 10 compliance testing
🤖 Advanced AI-powered security assessment
🔍 Research-based attack techniques from academic sources
🌐 Multi-language attack vectors (Chinese, Arabic, Spanish, etc.)
🏥 Healthcare-specific security testing (HIPAA compliance)
💰 Financial services security testing (PCI-DSS compliance)
📊 Comprehensive reporting (JSON, PDF, HTML, SARIF)
🔄 Continuous security monitoring
🧠 Adaptive learning and improvement
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
import uuid

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from ai_tester_core.enterprise_security_orchestrator import (
    EnterpriseSecurityOrchestrator,
    SecurityAssessmentRequest,
    AssessmentMode,
    SecurityDomain
)
from ai_tester_core.advanced_llm_security_engine import VulnerabilityType

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/nexus_security_commander.log')
    ]
)

logger = logging.getLogger(__name__)

class NexusAISecurityCommander:
    """
    Nexus AI Security Commander - Universal Security Testing Platform

    The most advanced AI security testing platform featuring:
    - Complete OWASP LLM Top 10 vulnerability assessment
    - Advanced prompt injection and jailbreak techniques
    - Research-based adversarial attacks
    - Multi-domain security testing
    - Enterprise-grade reporting and compliance
    """

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or "configs/nexus_security_config.json"
        self.orchestrator = EnterpriseSecurityOrchestrator(config_path)

        # Platform branding
        self.platform_name = "⚡ NEXUS AI SECURITY COMMANDER"
        self.version = "2.0.0"
        self.tagline = "🛡️ Universal AI Security Testing Platform"

        # Statistics
        self.session_stats = {
            'session_start': datetime.now(),
            'assessments_run': 0,
            'vulnerabilities_found': 0,
            'compliance_assessments': 0
        }

    def display_banner(self):
        """Display platform banner"""
        banner = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║    {self.platform_name} v{self.version}                    ║
║    {self.tagline}                               ║
║                                                                              ║
║    🎯 OWASP LLM Top 10 Compliance • 🧠 AI-Powered Analysis                  ║
║    🔍 Advanced Threat Detection • 🌐 Multi-Language Support                 ║
║    🏥 Healthcare Security • 💰 Financial Compliance                         ║
║    📊 Enterprise Reporting • 🔄 Continuous Monitoring                       ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        print(banner)

    async def run_security_assessment(self,
                                    target_url: str,
                                    assessment_mode: str = 'comprehensive',
                                    security_domain: str = None,
                                    auth_config: Dict[str, Any] = None,
                                    output_file: str = None,
                                    format: str = 'json',
                                    vulnerability_focus: List[str] = None) -> Dict[str, Any]:
        """
        Run comprehensive AI security assessment

        Args:
            target_url: Target AI/LLM endpoint URL
            assessment_mode: rapid_scan, comprehensive, owasp_compliance, penetration_test
            security_domain: healthcare, financial, enterprise, consumer
            auth_config: Authentication configuration
            output_file: Output file path
            format: Output format (json, pdf, html, sarif)
            vulnerability_focus: Specific vulnerabilities to focus on

        Returns:
            Assessment results dictionary
        """
        print(f"\n🚀 INITIATING NEXUS AI SECURITY ASSESSMENT")
        print(f"🎯 Target: {target_url}")
        print(f"🔬 Mode: {assessment_mode.upper()}")
        if security_domain:
            print(f"🏢 Domain: {security_domain.upper()}")
        print("=" * 80)

        start_time = time.time()

        try:
            # Create assessment request
            request = SecurityAssessmentRequest(
                request_id=str(uuid.uuid4()),
                target_endpoint=target_url,
                assessment_mode=self._parse_assessment_mode(assessment_mode),
                security_domain=self._parse_security_domain(security_domain),
                auth_config=auth_config,
                custom_objectives=vulnerability_focus,
                metadata={
                    'initiated_by': 'nexus_cli',
                    'session_id': str(uuid.uuid4()),
                    'timestamp': datetime.now().isoformat()
                }
            )

            # Submit assessment
            assessment_id = await self.orchestrator.submit_assessment(request)
            print(f"📋 Assessment ID: {assessment_id}")

            # Monitor progress
            await self._monitor_assessment_progress(assessment_id)

            # Get final results
            result = None
            for assessment_result in self.orchestrator.get_assessment_history(1):
                if assessment_result.assessment_id == assessment_id:
                    result = assessment_result
                    break

            if not result:
                raise RuntimeError("Assessment completed but results not found")

            # Display results summary
            execution_time = time.time() - start_time
            await self._display_assessment_summary(result, execution_time)

            # Save results if requested
            if output_file:
                await self._save_assessment_results(result, output_file, format)
                print(f"📄 Results saved: {output_file}")

            # Update session statistics
            self.session_stats['assessments_run'] += 1
            self.session_stats['vulnerabilities_found'] += result.total_vulnerabilities

            return self._convert_result_to_dict(result)

        except Exception as e:
            logger.error(f"Assessment failed: {e}")
            print(f"❌ Assessment failed: {e}")
            return {'status': 'error', 'error': str(e)}

    async def run_owasp_compliance_assessment(self,
                                            target_url: str,
                                            auth_config: Dict[str, Any] = None,
                                            output_file: str = None) -> Dict[str, Any]:
        """Run OWASP LLM Top 10 compliance assessment"""
        print(f"\n🏛️ OWASP LLM TOP 10 COMPLIANCE ASSESSMENT")
        print(f"📋 Assessing compliance with OWASP LLM Top 10 security standards")
        print("=" * 80)

        return await self.run_security_assessment(
            target_url=target_url,
            assessment_mode='owasp_compliance',
            auth_config=auth_config,
            output_file=output_file,
            format='json'
        )

    async def run_healthcare_security_assessment(self,
                                               target_url: str,
                                               auth_config: Dict[str, Any] = None,
                                               output_file: str = None) -> Dict[str, Any]:
        """Run healthcare-specific security assessment"""
        print(f"\n🏥 HEALTHCARE AI SECURITY ASSESSMENT")
        print(f"🩺 HIPAA compliance and medical AI safety testing")
        print("=" * 80)

        return await self.run_security_assessment(
            target_url=target_url,
            assessment_mode='comprehensive',
            security_domain='healthcare',
            auth_config=auth_config,
            output_file=output_file,
            format='json'
        )

    async def run_financial_security_assessment(self,
                                              target_url: str,
                                              auth_config: Dict[str, Any] = None,
                                              output_file: str = None) -> Dict[str, Any]:
        """Run financial services security assessment"""
        print(f"\n💰 FINANCIAL AI SECURITY ASSESSMENT")
        print(f"🏦 PCI-DSS compliance and financial AI safety testing")
        print("=" * 80)

        return await self.run_security_assessment(
            target_url=target_url,
            assessment_mode='comprehensive',
            security_domain='financial',
            auth_config=auth_config,
            output_file=output_file,
            format='json'
        )

    async def run_penetration_test(self,
                                 target_url: str,
                                 auth_config: Dict[str, Any] = None,
                                 output_file: str = None) -> Dict[str, Any]:
        """Run advanced penetration testing"""
        print(f"\n⚔️ ADVANCED AI PENETRATION TESTING")
        print(f"🔓 Aggressive security testing with latest attack techniques")
        print("=" * 80)

        return await self.run_security_assessment(
            target_url=target_url,
            assessment_mode='penetration_test',
            auth_config=auth_config,
            output_file=output_file,
            format='json'
        )

    async def start_continuous_monitoring(self,
                                        target_url: str,
                                        interval_hours: int = 24,
                                        auth_config: Dict[str, Any] = None) -> str:
        """Start continuous security monitoring"""
        print(f"\n🔄 CONTINUOUS SECURITY MONITORING")
        print(f"📊 Monitoring {target_url} every {interval_hours} hours")
        print("=" * 80)

        monitor_id = await self.orchestrator.start_continuous_monitoring(
            target_endpoint=target_url,
            interval_hours=interval_hours
        )

        print(f"✅ Monitoring started with ID: {monitor_id}")
        return monitor_id

    async def get_platform_statistics(self) -> Dict[str, Any]:
        """Get comprehensive platform statistics"""
        orchestrator_metrics = self.orchestrator.get_platform_metrics()

        return {
            'platform_info': {
                'name': self.platform_name,
                'version': self.version,
                'uptime_hours': (datetime.now() - orchestrator_metrics['platform_uptime']).total_seconds() / 3600
            },
            'session_statistics': self.session_stats,
            'orchestrator_metrics': orchestrator_metrics,
            'capabilities': {
                'owasp_llm_top_10': 'Full Coverage',
                'advanced_attacks': 'Research-based techniques',
                'multi_language_support': ['English', 'Chinese', 'Arabic', 'Spanish'],
                'domain_expertise': ['Healthcare', 'Financial', 'Enterprise'],
                'reporting_formats': ['JSON', 'PDF', 'HTML', 'SARIF'],
                'continuous_monitoring': 'Enterprise-grade'
            }
        }

    async def _monitor_assessment_progress(self, assessment_id: str):
        """Monitor assessment progress and display updates"""
        print(f"\n⏳ Monitoring assessment progress...")

        last_progress = 0
        while True:
            status = self.orchestrator.get_assessment_status(assessment_id)

            if not status:
                break

            current_progress = status.get('progress', 0)
            current_phase = status.get('current_phase', 'unknown')

            if current_progress > last_progress:
                print(f"📊 Progress: {current_progress}% - {current_phase.replace('_', ' ').title()}")
                last_progress = current_progress

            if status.get('status') == 'completed':
                print(f"✅ Assessment completed successfully!")
                break
            elif status.get('status') == 'failed':
                error = status.get('error', 'Unknown error')
                print(f"❌ Assessment failed: {error}")
                break

            await asyncio.sleep(2)

    async def _display_assessment_summary(self, result, execution_time: float):
        """Display assessment results summary"""
        print(f"\n🎉 ASSESSMENT COMPLETE")
        print("=" * 80)
        print(f"⏱️  Duration: {execution_time:.1f} seconds")
        print(f"🎯 Security Grade: {result.overall_security_grade}")
        print(f"📊 Risk Score: {result.risk_score:.1f}/100")
        print(f"🚨 Risk Level: {result.risk_level}")
        print(f"🔍 Vulnerabilities Found: {result.total_vulnerabilities}")
        print(f"💥 Critical Issues: {result.critical_vulnerabilities}")
        print(f"⚠️  High Risk Issues: {result.high_vulnerabilities}")
        print(f"📋 OWASP Compliance: {result.owasp_compliance_score:.1f}%")
        print(f"🤖 AI Confidence: {result.ai_confidence:.2f}")

        # Display top findings
        if result.detailed_findings:
            print(f"\n🔍 TOP SECURITY FINDINGS:")
            print("-" * 50)

            # Get top 5 most critical findings
            critical_findings = [f for f in result.detailed_findings
                               if f.get('severity') in ['critical', 'high']][:5]

            for i, finding in enumerate(critical_findings, 1):
                severity_icon = "💥" if finding.get('severity') == 'critical' else "⚠️"
                print(f"{severity_icon} {i}. {finding.get('attack_type', 'Unknown').replace('_', ' ').title()}")
                print(f"    Confidence: {finding.get('confidence', 0):.2f}")

        # Display key recommendations
        if result.recommendations:
            print(f"\n💡 KEY RECOMMENDATIONS:")
            print("-" * 50)
            for i, rec in enumerate(result.recommendations[:5], 1):
                print(f"{i}. {rec}")

    async def _save_assessment_results(self, result, output_file: str, format: str):
        """Save assessment results to file"""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if format == 'json':
            result_dict = self._convert_result_to_dict(result)
            with open(output_file, 'w') as f:
                json.dump(result_dict, f, indent=2, default=str)
        else:
            # Use orchestrator's export functionality
            exported_data = await self.orchestrator.export_assessment_report(
                result.assessment_id, format
            )
            if exported_data:
                with open(output_file, 'w') as f:
                    f.write(exported_data)

    def _convert_result_to_dict(self, result) -> Dict[str, Any]:
        """Convert result object to dictionary"""
        return {
            'assessment_info': {
                'request_id': result.request_id,
                'assessment_id': result.assessment_id,
                'target_endpoint': result.target_endpoint,
                'assessment_mode': result.assessment_mode.value,
                'security_domain': result.security_domain.value if result.security_domain else None,
                'start_time': result.start_time.isoformat(),
                'end_time': result.end_time.isoformat(),
                'execution_time_seconds': result.execution_time_seconds
            },
            'security_assessment': {
                'overall_security_grade': result.overall_security_grade,
                'risk_score': result.risk_score,
                'risk_level': result.risk_level,
                'total_vulnerabilities': result.total_vulnerabilities,
                'critical_vulnerabilities': result.critical_vulnerabilities,
                'high_vulnerabilities': result.high_vulnerabilities,
                'owasp_compliance_score': result.owasp_compliance_score
            },
            'findings': {
                'vulnerability_breakdown': result.vulnerability_breakdown,
                'detailed_findings': result.detailed_findings,
                'recommendations': result.recommendations
            },
            'ai_analysis': {
                'ai_confidence': result.ai_confidence,
                'learning_insights': result.learning_insights,
                'attack_surface_analysis': result.attack_surface_analysis
            },
            'compliance': {
                'compliance_status': result.compliance_status,
                'executive_summary': result.executive_summary
            },
            'technical_report': result.technical_report
        }

    def _parse_assessment_mode(self, mode: str) -> AssessmentMode:
        """Parse assessment mode string to enum"""
        mode_mapping = {
            'rapid': AssessmentMode.RAPID_SCAN,
            'rapid_scan': AssessmentMode.RAPID_SCAN,
            'comprehensive': AssessmentMode.COMPREHENSIVE,
            'owasp': AssessmentMode.OWASP_COMPLIANCE,
            'owasp_compliance': AssessmentMode.OWASP_COMPLIANCE,
            'pentest': AssessmentMode.PENETRATION_TEST,
            'penetration_test': AssessmentMode.PENETRATION_TEST,
            'continuous': AssessmentMode.CONTINUOUS_MONITORING
        }
        return mode_mapping.get(mode.lower(), AssessmentMode.COMPREHENSIVE)

    def _parse_security_domain(self, domain: str) -> Optional[SecurityDomain]:
        """Parse security domain string to enum"""
        if not domain:
            return None

        domain_mapping = {
            'healthcare': SecurityDomain.HEALTHCARE,
            'medical': SecurityDomain.HEALTHCARE,
            'hipaa': SecurityDomain.HEALTHCARE,
            'financial': SecurityDomain.FINANCIAL,
            'fintech': SecurityDomain.FINANCIAL,
            'banking': SecurityDomain.FINANCIAL,
            'pci': SecurityDomain.FINANCIAL,
            'enterprise': SecurityDomain.ENTERPRISE,
            'business': SecurityDomain.ENTERPRISE,
            'consumer': SecurityDomain.CONSUMER,
            'critical': SecurityDomain.CRITICAL_INFRASTRUCTURE,
            'infrastructure': SecurityDomain.CRITICAL_INFRASTRUCTURE
        }
        return domain_mapping.get(domain.lower())


async def main():
    """Main entry point for Nexus AI Security Commander"""

    parser = argparse.ArgumentParser(
        description='Nexus AI Security Commander - Universal AI Security Testing Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🎯 ASSESSMENT MODES:
  rapid           Quick security scan (2-5 minutes)
  comprehensive   Full spectrum security assessment (15-30 minutes)
  owasp          OWASP LLM Top 10 compliance testing
  pentest        Advanced penetration testing
  continuous     Continuous security monitoring

🏢 SECURITY DOMAINS:
  healthcare     Healthcare/Medical AI security (HIPAA compliance)
  financial      Financial services AI security (PCI-DSS compliance)
  enterprise     Enterprise AI security assessment
  consumer       Consumer application security
  critical       Critical infrastructure security

📊 EXAMPLES:
  # Comprehensive AI security assessment
  %(prog)s https://api.example.com/ai --mode comprehensive --output report.json

  # OWASP LLM Top 10 compliance check
  %(prog)s https://llm.example.com --mode owasp --output compliance_report.pdf

  # Healthcare AI security assessment
  %(prog)s https://medical-ai.example.com --domain healthcare --output hipaa_report.json

  # Financial AI security testing
  %(prog)s https://fintech-ai.example.com --domain financial --mode pentest

  # Continuous monitoring
  %(prog)s https://prod-ai.example.com --continuous --interval 24

  # Advanced penetration testing with authentication
  %(prog)s https://secure-ai.example.com --mode pentest --auth-token YOUR_TOKEN

🛡️ FEATURES:
  ✅ Complete OWASP LLM Top 10 coverage
  ✅ Advanced prompt injection & jailbreak testing
  ✅ Multi-language attack vectors
  ✅ Domain-specific security testing
  ✅ Continuous monitoring capabilities
  ✅ Enterprise-grade reporting
  ✅ AI-powered analysis & learning
        """
    )

    # Basic arguments
    parser.add_argument('target', help='Target AI/LLM endpoint URL')
    parser.add_argument('--mode', '-m',
                       choices=['rapid', 'comprehensive', 'owasp', 'pentest', 'continuous'],
                       default='comprehensive',
                       help='Assessment mode (default: comprehensive)')

    # Domain and specialization
    parser.add_argument('--domain', '-d',
                       choices=['healthcare', 'financial', 'enterprise', 'consumer', 'critical'],
                       help='Security domain for specialized testing')

    # Authentication
    parser.add_argument('--auth-token', help='Bearer authentication token')
    parser.add_argument('--api-key', help='API key for authentication')
    parser.add_argument('--auth-header', help='Custom authentication header (format: "Header: Value")')

    # Output and reporting
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--format', '-f',
                       choices=['json', 'pdf', 'html', 'sarif'],
                       default='json',
                       help='Output format (default: json)')

    # Continuous monitoring
    parser.add_argument('--continuous', action='store_true',
                       help='Start continuous monitoring')
    parser.add_argument('--interval', type=int, default=24,
                       help='Monitoring interval in hours (default: 24)')

    # Advanced options
    parser.add_argument('--vulnerabilities', nargs='+',
                       help='Focus on specific vulnerabilities')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--stats', action='store_true',
                       help='Show platform statistics')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')

    # Special assessment types
    parser.add_argument('--owasp-compliance', action='store_true',
                       help='Run OWASP LLM Top 10 compliance assessment')
    parser.add_argument('--healthcare-assessment', action='store_true',
                       help='Run healthcare-specific security assessment')
    parser.add_argument('--financial-assessment', action='store_true',
                       help='Run financial services security assessment')

    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        # Initialize commander
        commander = NexusAISecurityCommander(args.config)
        commander.display_banner()

        # Show statistics if requested
        if args.stats:
            stats = await commander.get_platform_statistics()
            print("\n📊 PLATFORM STATISTICS")
            print("=" * 50)
            print(json.dumps(stats, indent=2, default=str))
            return

        # Prepare authentication configuration
        auth_config = {}
        if args.auth_token:
            auth_config['bearer_token'] = args.auth_token
        elif args.api_key:
            auth_config['api_key'] = args.api_key
        elif args.auth_header:
            header_parts = args.auth_header.split(':', 1)
            if len(header_parts) == 2:
                auth_config['custom_headers'] = {header_parts[0].strip(): header_parts[1].strip()}

        # Execute requested assessment
        if args.continuous:
            # Start continuous monitoring
            monitor_id = await commander.start_continuous_monitoring(
                target_url=args.target,
                interval_hours=args.interval,
                auth_config=auth_config if auth_config else None
            )
            print(f"✅ Continuous monitoring active with ID: {monitor_id}")
            print("⏳ Monitoring will continue in background...")
            return

        elif args.owasp_compliance:
            # OWASP compliance assessment
            result = await commander.run_owasp_compliance_assessment(
                target_url=args.target,
                auth_config=auth_config if auth_config else None,
                output_file=args.output
            )

        elif args.healthcare_assessment:
            # Healthcare security assessment
            result = await commander.run_healthcare_security_assessment(
                target_url=args.target,
                auth_config=auth_config if auth_config else None,
                output_file=args.output
            )

        elif args.financial_assessment:
            # Financial security assessment
            result = await commander.run_financial_security_assessment(
                target_url=args.target,
                auth_config=auth_config if auth_config else None,
                output_file=args.output
            )

        else:
            # Standard security assessment
            result = await commander.run_security_assessment(
                target_url=args.target,
                assessment_mode=args.mode,
                security_domain=args.domain,
                auth_config=auth_config if auth_config else None,
                output_file=args.output,
                format=args.format,
                vulnerability_focus=args.vulnerabilities
            )

        # Exit with appropriate code
        if result.get('status') == 'error':
            sys.exit(1)
        else:
            print(f"\n🎉 Assessment completed successfully!")
            sys.exit(0)

    except KeyboardInterrupt:
        print(f"\n🛑 Assessment interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Commander failed: {e}")
        print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Nexus AI Security Commander interrupted")
    except Exception as e:
        print(f"\n💥 Fatal error: {e}")
        sys.exit(1)