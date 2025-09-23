"""
Modular AI Security Tester - Advanced Agentic AI Security Testing Platform
==========================================================================

This is the main entry point for the modular AI security testing platform that
integrates specialized AI agents, machine learning, and adaptive pipeline orchestration.
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

# Add the parent directory to the Python path
sys.path.append(str(Path(__file__).parent.parent))

from ai_tester_core.pipeline_orchestrator import AdvancedPipelineOrchestrator, PipelineConfig
from ai_tester_core.learning_engine import AdaptiveLearningEngine
from ai_tester_core.knowledge_base import SecurityKnowledgeBase

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/modular_ai_security_tester.log')
    ]
)

logger = logging.getLogger(__name__)

class ModularAISecurityTester:
    """
    Main class for the modular AI security testing platform with
    agentic AI, machine learning, and adaptive capabilities
    """

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.config = self._load_config()

        # Initialize core components
        self.orchestrator = AdvancedPipelineOrchestrator(config_path)
        self.knowledge_base = SecurityKnowledgeBase()
        self.learning_engine = self.orchestrator.learning_engine

        # Platform statistics
        self.platform_stats = {
            'total_assessments': 0,
            'successful_assessments': 0,
            'total_vulnerabilities_found': 0,
            'platform_uptime': datetime.now(),
            'ml_model_updates': 0
        }

        # Setup alert system
        self._setup_alert_system()

    def _load_config(self) -> Dict[str, Any]:
        """Load platform configuration"""
        default_config = {
            'platform_name': 'Modular AI Security Tester',
            'version': '2.0.0',
            'enable_learning': True,
            'enable_monitoring': True,
            'enable_alerts': True,
            'auto_model_updates': True,
            'report_formats': ['json', 'pdf', 'html'],
            'knowledge_base_enabled': True,
            'continuous_learning': True,
            'adaptive_thresholds': True
        }

        if self.config_path and Path(self.config_path).exists():
            try:
                with open(self.config_path, 'r') as f:
                    loaded_config = json.load(f)
                default_config.update(loaded_config)
            except Exception as e:
                logger.warning(f"Failed to load config from {self.config_path}: {e}")

        return default_config

    def _setup_alert_system(self):
        """Setup alert system for the platform"""
        async def platform_alert_handler(alert_message: str, context: Any):
            logger.warning(f"PLATFORM ALERT: {alert_message}")
            # Here you could integrate with external alerting systems
            # like Slack, email, PagerDuty, etc.

        self.orchestrator.register_alert_callback(platform_alert_handler)

    async def run_comprehensive_assessment(self, target: str, output_file: Optional[str] = None) -> Dict[str, Any]:
        """Run comprehensive AI security assessment"""
        logger.info(f"🚀 Starting comprehensive AI security assessment for {target}")

        start_time = time.time()

        try:
            # Execute comprehensive pipeline
            result = await self.orchestrator.execute_template_pipeline(
                'comprehensive_ai_security_scan',
                target
            )

            # Update platform statistics
            self._update_platform_stats(result)

            # Generate comprehensive report
            report = await self._generate_comprehensive_report(result, target)

            # Save report if output file specified
            if output_file:
                await self._save_report(report, output_file)

            # Update knowledge base
            if self.config['knowledge_base_enabled']:
                await self.knowledge_base.update_from_assessment(result)

            execution_time = time.time() - start_time
            logger.info(f"✅ Comprehensive assessment completed in {execution_time:.2f} seconds")

            return {
                'status': 'completed',
                'target': target,
                'execution_time': execution_time,
                'result': result,
                'report': report,
                'platform_stats': self.platform_stats
            }

        except Exception as e:
            logger.error(f"❌ Comprehensive assessment failed: {e}")
            return {
                'status': 'failed',
                'target': target,
                'error': str(e),
                'execution_time': time.time() - start_time
            }

    async def run_rapid_assessment(self, target: str, output_file: Optional[str] = None) -> Dict[str, Any]:
        """Run rapid AI security assessment for quick feedback"""
        logger.info(f"⚡ Starting rapid AI security assessment for {target}")

        start_time = time.time()

        try:
            # Execute rapid pipeline
            result = await self.orchestrator.execute_template_pipeline(
                'rapid_ai_security_check',
                target
            )

            # Generate rapid report
            report = await self._generate_rapid_report(result, target)

            # Save report if output file specified
            if output_file:
                await self._save_report(report, output_file)

            execution_time = time.time() - start_time
            logger.info(f"✅ Rapid assessment completed in {execution_time:.2f} seconds")

            return {
                'status': 'completed',
                'target': target,
                'execution_time': execution_time,
                'result': result,
                'report': report
            }

        except Exception as e:
            logger.error(f"❌ Rapid assessment failed: {e}")
            return {
                'status': 'failed',
                'target': target,
                'error': str(e),
                'execution_time': time.time() - start_time
            }

    async def run_adaptive_assessment(self, target: str, objectives: List[str], output_file: Optional[str] = None) -> Dict[str, Any]:
        """Run adaptive AI security assessment based on ML recommendations"""
        logger.info(f"🧠 Starting adaptive AI security assessment for {target}")

        start_time = time.time()

        try:
            # Create adaptive pipeline using ML
            pipeline_config = await self.orchestrator.create_adaptive_pipeline(target, objectives)

            # Execute adaptive pipeline
            result = await self.orchestrator.execute_pipeline(pipeline_config)

            # Generate adaptive report
            report = await self._generate_adaptive_report(result, target, objectives)

            # Save report if output file specified
            if output_file:
                await self._save_report(report, output_file)

            # Learn from adaptive assessment
            if self.config['continuous_learning']:
                await self._process_adaptive_learning(result, objectives)

            execution_time = time.time() - start_time
            logger.info(f"✅ Adaptive assessment completed in {execution_time:.2f} seconds")

            return {
                'status': 'completed',
                'target': target,
                'execution_time': execution_time,
                'result': result,
                'report': report,
                'pipeline_config': pipeline_config
            }

        except Exception as e:
            logger.error(f"❌ Adaptive assessment failed: {e}")
            return {
                'status': 'failed',
                'target': target,
                'error': str(e),
                'execution_time': time.time() - start_time
            }

    async def start_continuous_monitoring(self, target: str, interval: int = 3600) -> str:
        """Start continuous security monitoring"""
        logger.info(f"📊 Starting continuous monitoring for {target}")

        try:
            monitoring_id = await self.orchestrator.start_continuous_monitoring(target, interval)

            logger.info(f"✅ Continuous monitoring started with ID: {monitoring_id}")
            return monitoring_id

        except Exception as e:
            logger.error(f"❌ Failed to start continuous monitoring: {e}")
            raise

    async def get_learning_insights(self) -> Dict[str, Any]:
        """Get comprehensive learning insights from the platform"""
        return {
            'learning_statistics': self.learning_engine.get_learning_statistics(),
            'knowledge_base_stats': await self.knowledge_base.get_statistics(),
            'platform_performance': self.orchestrator.get_orchestrator_metrics(),
            'recent_improvements': await self._get_recent_improvements()
        }

    async def update_ml_models(self) -> Dict[str, Any]:
        """Manually trigger ML model updates"""
        logger.info("🔄 Updating ML models...")

        try:
            # Save current models
            await self.learning_engine.save_models()

            # Update platform statistics
            self.platform_stats['ml_model_updates'] += 1

            logger.info("✅ ML models updated successfully")

            return {
                'status': 'success',
                'timestamp': datetime.now().isoformat(),
                'models_updated': ['agent_selection_model', 'parameter_optimization_model', 'vulnerability_prediction_model']
            }

        except Exception as e:
            logger.error(f"❌ Failed to update ML models: {e}")
            return {
                'status': 'failed',
                'error': str(e)
            }

    async def _generate_comprehensive_report(self, result, target: str) -> Dict[str, Any]:
        """Generate comprehensive assessment report"""
        all_findings = []
        agent_summaries = []

        for agent_result in result.agent_results:
            findings = agent_result.get('findings', [])
            all_findings.extend(findings)

            agent_summaries.append({
                'agent_type': agent_result.get('agent_type'),
                'execution_time': agent_result.get('execution_time'),
                'findings_count': len(findings),
                'confidence_score': agent_result.get('confidence_score'),
                'success': agent_result.get('success')
            })

        # Risk assessment
        risk_analysis = {
            'overall_risk_score': result.risk_score,
            'total_vulnerabilities': result.total_findings,
            'risk_distribution': {
                severity: len([f for f in all_findings if f.get('severity') == severity])
                for severity in ['critical', 'high', 'medium', 'low']
            },
            'top_risks': sorted(all_findings, key=lambda x: {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(x.get('severity', 'low'), 0), reverse=True)[:5]
        }

        return {
            'assessment_type': 'comprehensive',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'execution_summary': {
                'total_execution_time': result.execution_time,
                'pipeline_status': result.status,
                'agents_executed': len(agent_summaries)
            },
            'risk_analysis': risk_analysis,
            'agent_summaries': agent_summaries,
            'detailed_findings': all_findings,
            'recommendations': result.recommendations,
            'learning_insights': result.learning_insights,
            'knowledge_base_updates': await self.knowledge_base.get_recent_updates()
        }

    async def _generate_rapid_report(self, result, target: str) -> Dict[str, Any]:
        """Generate rapid assessment report"""
        all_findings = []
        for agent_result in result.agent_results:
            all_findings.extend(agent_result.get('findings', []))

        return {
            'assessment_type': 'rapid',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'execution_time': result.execution_time,
            'risk_score': result.risk_score,
            'total_findings': len(all_findings),
            'high_priority_findings': [f for f in all_findings if f.get('severity') in ['critical', 'high']],
            'recommendations': result.recommendations[:3],  # Top 3 recommendations
            'next_steps': [
                'Review high-priority findings',
                'Consider running comprehensive assessment',
                'Implement immediate security measures'
            ]
        }

    async def _generate_adaptive_report(self, result, target: str, objectives: List[str]) -> Dict[str, Any]:
        """Generate adaptive assessment report"""
        all_findings = []
        for agent_result in result.agent_results:
            all_findings.extend(agent_result.get('findings', []))

        return {
            'assessment_type': 'adaptive',
            'target': target,
            'objectives': objectives,
            'timestamp': datetime.now().isoformat(),
            'ml_optimization': {
                'pipeline_optimized': True,
                'parameters_adjusted': len(result.learning_insights.get('optimization_suggestions', [])),
                'effectiveness_score': result.learning_insights.get('effectiveness_scores', {})
            },
            'execution_summary': {
                'total_execution_time': result.execution_time,
                'risk_score': result.risk_score,
                'total_findings': len(all_findings)
            },
            'adaptive_insights': result.learning_insights,
            'findings': all_findings,
            'recommendations': result.recommendations,
            'learning_feedback': await self._generate_learning_feedback(result)
        }

    async def _save_report(self, report: Dict[str, Any], output_file: str):
        """Save report to file in specified format"""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        try:
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

            logger.info(f"📄 Report saved to {output_file}")

        except Exception as e:
            logger.error(f"❌ Failed to save report: {e}")

    async def _generate_pdf_report(self, report: Dict[str, Any], output_file: str):
        """Generate PDF report (placeholder for PDF generation)"""
        # This would use a library like ReportLab or WeasyPrint
        logger.info(f"PDF report generation not implemented yet. Saving as JSON instead.")
        json_file = output_file.replace('.pdf', '.json')
        with open(json_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

    async def _generate_html_report(self, report: Dict[str, Any], output_file: str):
        """Generate HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>AI Security Assessment Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
                .section { margin: 20px 0; }
                .finding { border-left: 4px solid #ff6b6b; padding: 10px; margin: 10px 0; }
                .finding.critical { border-left-color: #d63031; }
                .finding.high { border-left-color: #e17055; }
                .finding.medium { border-left-color: #fdcb6e; }
                .finding.low { border-left-color: #00b894; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>AI Security Assessment Report</h1>
                <p><strong>Target:</strong> {target}</p>
                <p><strong>Assessment Type:</strong> {assessment_type}</p>
                <p><strong>Timestamp:</strong> {timestamp}</p>
            </div>

            <div class="section">
                <h2>Risk Analysis</h2>
                <p><strong>Overall Risk Score:</strong> {risk_score}</p>
                <p><strong>Total Findings:</strong> {total_findings}</p>
            </div>

            <div class="section">
                <h2>Findings</h2>
                {findings_html}
            </div>

            <div class="section">
                <h2>Recommendations</h2>
                <ul>
                    {recommendations_html}
                </ul>
            </div>
        </body>
        </html>
        """

        # Generate findings HTML
        findings_html = ""
        for finding in report.get('detailed_findings', []):
            severity = finding.get('severity', 'low')
            findings_html += f"""
            <div class="finding {severity}">
                <h3>{finding.get('type', 'Unknown')} ({severity.upper()})</h3>
                <p>{finding.get('description', 'No description available')}</p>
            </div>
            """

        # Generate recommendations HTML
        recommendations_html = ""
        for rec in report.get('recommendations', []):
            recommendations_html += f"<li>{rec}</li>"

        # Fill template
        html_content = html_template.format(
            target=report.get('target', 'Unknown'),
            assessment_type=report.get('assessment_type', 'Unknown'),
            timestamp=report.get('timestamp', 'Unknown'),
            risk_score=report.get('risk_analysis', {}).get('overall_risk_score', 0),
            total_findings=report.get('risk_analysis', {}).get('total_vulnerabilities', 0),
            findings_html=findings_html,
            recommendations_html=recommendations_html
        )

        with open(output_file, 'w') as f:
            f.write(html_content)

    def _update_platform_stats(self, result):
        """Update platform statistics"""
        self.platform_stats['total_assessments'] += 1

        if result.status == 'completed':
            self.platform_stats['successful_assessments'] += 1

        self.platform_stats['total_vulnerabilities_found'] += result.total_findings

    async def _process_adaptive_learning(self, result, objectives: List[str]):
        """Process learning from adaptive assessment"""
        # This would implement feedback processing for ML improvement
        logger.info("Processing adaptive learning feedback...")

    async def _get_recent_improvements(self) -> Dict[str, Any]:
        """Get recent platform improvements"""
        return {
            'model_accuracy_improvements': 0.05,  # Example improvement
            'execution_time_optimization': 0.15,  # Example optimization
            'new_vulnerability_patterns': 3,  # Example new patterns
            'false_positive_reduction': 0.08  # Example reduction
        }

    async def _generate_learning_feedback(self, result) -> Dict[str, Any]:
        """Generate learning feedback for ML models"""
        return {
            'performance_feedback': {
                'execution_efficiency': 'good' if result.execution_time < 300 else 'needs_improvement',
                'finding_quality': 'high' if result.total_findings > 0 else 'low',
                'confidence_level': 'high' if all(ar.get('confidence_score', 0) > 0.7 for ar in result.agent_results) else 'medium'
            },
            'improvement_suggestions': [
                'Consider adjusting timeout parameters',
                'Review payload effectiveness',
                'Update detection thresholds'
            ]
        }

    async def shutdown(self):
        """Gracefully shutdown the platform"""
        logger.info("🔌 Shutting down Modular AI Security Tester...")

        # Shutdown orchestrator
        await self.orchestrator.shutdown()

        # Save final statistics
        stats_file = Path('logs/platform_statistics.json')
        with open(stats_file, 'w') as f:
            json.dump(self.platform_stats, f, indent=2, default=str)

        logger.info("✅ Platform shutdown complete")


async def main():
    """Main entry point for the modular AI security tester"""
    parser = argparse.ArgumentParser(description='Modular AI Security Tester')
    parser.add_argument('target', help='Target URL to assess')
    parser.add_argument('--mode', choices=['comprehensive', 'rapid', 'adaptive'], default='comprehensive',
                       help='Assessment mode')
    parser.add_argument('--objectives', nargs='+', help='Objectives for adaptive mode')
    parser.add_argument('--output', '-o', help='Output file for report')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--continuous', action='store_true', help='Start continuous monitoring')
    parser.add_argument('--interval', type=int, default=3600, help='Monitoring interval in seconds')
    parser.add_argument('--learning-insights', action='store_true', help='Show learning insights')
    parser.add_argument('--update-models', action='store_true', help='Update ML models')

    args = parser.parse_args()

    # Initialize platform
    print("🛡️  MODULAR AI SECURITY TESTER v2.0")
    print("🔬 Advanced Agentic AI Security Testing Platform")
    print("📋 ML-Enhanced Vulnerability Assessment & Learning")
    print("=" * 60)

    tester = ModularAISecurityTester(args.config)

    try:
        if args.learning_insights:
            # Show learning insights
            insights = await tester.get_learning_insights()
            print("\n🧠 LEARNING INSIGHTS")
            print("=" * 30)
            print(json.dumps(insights, indent=2, default=str))

        elif args.update_models:
            # Update ML models
            result = await tester.update_ml_models()
            print(f"\n🔄 ML Models Update: {result['status']}")

        elif args.continuous:
            # Start continuous monitoring
            monitoring_id = await tester.start_continuous_monitoring(args.target, args.interval)
            print(f"\n📊 Continuous monitoring started: {monitoring_id}")
            print("Press Ctrl+C to stop monitoring...")

            try:
                while True:
                    await asyncio.sleep(60)  # Keep running
            except KeyboardInterrupt:
                print("\n🛑 Stopping continuous monitoring...")

        else:
            # Run assessment
            if args.mode == 'comprehensive':
                result = await tester.run_comprehensive_assessment(args.target, args.output)
            elif args.mode == 'rapid':
                result = await tester.run_rapid_assessment(args.target, args.output)
            elif args.mode == 'adaptive':
                objectives = args.objectives or ['comprehensive', 'deep_analysis']
                result = await tester.run_adaptive_assessment(args.target, objectives, args.output)

            # Display results
            print(f"\n✅ Assessment Status: {result['status']}")
            print(f"⏱️  Execution Time: {result['execution_time']:.2f} seconds")

            if result['status'] == 'completed':
                pipeline_result = result['result']
                print(f"🎯 Risk Score: {pipeline_result.risk_score}")
                print(f"🔍 Total Findings: {pipeline_result.total_findings}")
                print(f"📊 Recommendations: {len(pipeline_result.recommendations)}")

                if args.output:
                    print(f"📄 Report saved to: {args.output}")

    except KeyboardInterrupt:
        print("\n🛑 Assessment interrupted by user")

    except Exception as e:
        print(f"\n❌ Assessment failed: {e}")
        logger.error(f"Assessment failed: {e}")

    finally:
        # Shutdown platform
        await tester.shutdown()


if __name__ == "__main__":
    asyncio.run(main())