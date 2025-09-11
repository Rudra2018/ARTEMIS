#!/usr/bin/env python3
"""
Main test runner script for AI Chatbot Testing Suite
Provides command-line interface for running various test suites
"""

import argparse
import sys
import os
import json
import logging
from datetime import datetime
from pathlib import Path

# Import test suites
from ai_chatbot_test_suite import AITestSuiteRunner
from api_integration_tests import APIIntegrationTestRunner
from config import ConfigManager, setup_environment, AIProvider

def setup_logging(log_level: str, output_dir: str):
    """Setup logging configuration"""
    log_dir = Path(output_dir)
    log_dir.mkdir(exist_ok=True)
    
    log_file = log_dir / f"test_run_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    return logging.getLogger(__name__)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="AI Chatbot Testing Suite - Comprehensive testing for LLM chatbots and AI platforms"
    )
    
    # Test suite selection
    parser.add_argument(
        '--suite', 
        choices=['all', 'core', 'api', 'security', 'performance', 'ml', 'edge'],
        default='all',
        help='Test suite to run (default: all)'
    )
    
    # Specific test class selection
    parser.add_argument(
        '--test-class',
        help='Run specific test class (e.g., LLMChatbotCoreTests)'
    )
    
    # Provider selection for API tests
    parser.add_argument(
        '--providers',
        nargs='+',
        choices=[p.value for p in AIProvider],
        help='Specific AI providers to test (for API integration tests)'
    )
    
    # Test execution options
    parser.add_argument(
        '--live',
        action='store_true',
        help='Run tests against live APIs (requires API keys)'
    )
    
    parser.add_argument(
        '--mock',
        action='store_true',
        default=True,
        help='Use mock responses (default, safer for CI/CD)'
    )
    
    parser.add_argument(
        '--parallel',
        type=int,
        default=1,
        help='Number of parallel test processes (default: 1)'
    )
    
    # Output and reporting options
    parser.add_argument(
        '--output-dir',
        default='test_results',
        help='Output directory for test results (default: test_results)'
    )
    
    parser.add_argument(
        '--report-format',
        choices=['json', 'html', 'junit', 'all'],
        default='json',
        help='Report format (default: json)'
    )
    
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Verbose output'
    )
    
    parser.add_argument(
        '--quiet',
        '-q',
        action='store_true',
        help='Quiet output (minimal logging)'
    )
    
    # Configuration options
    parser.add_argument(
        '--config',
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--save-config-template',
        action='store_true',
        help='Save a configuration template and exit'
    )
    
    parser.add_argument(
        '--validate-config',
        action='store_true',
        help='Validate configuration and exit'
    )
    
    # Performance options
    parser.add_argument(
        '--timeout',
        type=int,
        default=300,
        help='Test timeout in seconds (default: 300)'
    )
    
    parser.add_argument(
        '--max-retries',
        type=int,
        default=3,
        help='Maximum API request retries (default: 3)'
    )
    
    return parser.parse_args()

def run_core_tests(config_manager: ConfigManager, verbose: bool = False):
    """Run core LLM chatbot tests"""
    print("🤖 Running Core LLM Chatbot Tests...")
    runner = AITestSuiteRunner()
    results = runner.run_all_tests(verbose=verbose)
    return results

def run_api_integration_tests(config_manager: ConfigManager, providers: list = None, verbose: bool = False):
    """Run API integration tests"""
    print("🌐 Running API Integration Tests...")
    
    if providers:
        print(f"   Testing providers: {', '.join(providers)}")
    
    runner = APIIntegrationTestRunner()
    results = runner.run_all_tests(verbose=verbose)
    return results

def run_specific_suite(suite_name: str, config_manager: ConfigManager, verbose: bool = False):
    """Run specific test suite"""
    print(f"🎯 Running {suite_name} Test Suite...")
    
    suite_mapping = {
        'core': run_core_tests,
        'api': run_api_integration_tests,
        'security': lambda cm, v: run_test_class('SecuritySafetyTests', cm, v),
        'performance': lambda cm, v: run_test_class('PerformanceScalabilityTests', cm, v),
        'ml': lambda cm, v: run_test_class('MLModelTests', cm, v),
        'edge': lambda cm, v: run_test_class('EdgeCaseRobustnessTests', cm, v)
    }
    
    if suite_name in suite_mapping:
        return suite_mapping[suite_name](config_manager, verbose)
    else:
        print(f"❌ Unknown test suite: {suite_name}")
        return None

def run_test_class(test_class_name: str, config_manager: ConfigManager, verbose: bool = False):
    """Run specific test class"""
    print(f"🔍 Running {test_class_name}...")
    
    # Try to run from core test suite first
    try:
        runner = AITestSuiteRunner()
        results = runner.run_specific_suite(test_class_name)
        return results
    except ValueError:
        # Try API integration tests
        try:
            runner = APIIntegrationTestRunner()
            results = runner.run_specific_suite(test_class_name)
            return results
        except ValueError:
            print(f"❌ Test class not found: {test_class_name}")
            return None

def generate_reports(results: dict, output_dir: str, report_format: str):
    """Generate test reports in various formats"""
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    if report_format in ['json', 'all']:
        json_file = output_path / f"test_results_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"📄 JSON report saved to: {json_file}")
    
    if report_format in ['html', 'all']:
        html_file = output_path / f"test_results_{timestamp}.html"
        generate_html_report(results, html_file)
        print(f"🌐 HTML report saved to: {html_file}")
    
    if report_format in ['junit', 'all']:
        junit_file = output_path / f"test_results_{timestamp}.xml"
        generate_junit_report(results, junit_file)
        print(f"📋 JUnit report saved to: {junit_file}")

def generate_html_report(results: dict, output_file: Path):
    """Generate HTML test report"""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>AI Chatbot Test Results</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
            .suite {{ margin: 20px 0; padding: 15px; border-left: 4px solid #007cba; }}
            .passed {{ color: green; }}
            .failed {{ color: red; }}
            .error {{ color: orange; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🤖 AI Chatbot Test Results</h1>
            <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Total Tests:</strong> {results.get('total_tests', 0)}</p>
            <p><strong>Passed:</strong> <span class="passed">{results.get('passed', 0)}</span></p>
            <p><strong>Failed:</strong> <span class="failed">{results.get('failed', 0)}</span></p>
            <p><strong>Errors:</strong> <span class="error">{results.get('errors', 0)}</span></p>
            <p><strong>Success Rate:</strong> {results.get('overall_success_rate', 0):.2%}</p>
        </div>
    """
    
    if 'suite_results' in results:
        html_content += "<h2>Suite Results</h2>"
        for suite_name, suite_result in results['suite_results'].items():
            html_content += f"""
            <div class="suite">
                <h3>{suite_name}</h3>
                <table>
                    <tr><th>Metric</th><th>Value</th></tr>
                    <tr><td>Tests Run</td><td>{suite_result.get('tests_run', 0)}</td></tr>
                    <tr><td>Success Rate</td><td>{suite_result.get('success_rate', 0):.2%}</td></tr>
                    <tr><td>Failures</td><td class="failed">{suite_result.get('failures', 0)}</td></tr>
                    <tr><td>Errors</td><td class="error">{suite_result.get('errors', 0)}</td></tr>
                </table>
            </div>
            """
    
    html_content += """
    </body>
    </html>
    """
    
    with open(output_file, 'w') as f:
        f.write(html_content)

def generate_junit_report(results: dict, output_file: Path):
    """Generate JUnit XML test report"""
    junit_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<testsuites tests="{results.get('total_tests', 0)}" 
           failures="{results.get('failed', 0)}" 
           errors="{results.get('errors', 0)}" 
           time="0">
"""
    
    if 'suite_results' in results:
        for suite_name, suite_result in results['suite_results'].items():
            junit_content += f"""
    <testsuite name="{suite_name}" 
               tests="{suite_result.get('tests_run', 0)}" 
               failures="{suite_result.get('failures', 0)}" 
               errors="{suite_result.get('errors', 0)}" 
               time="0">
    </testsuite>
"""
    
    junit_content += "</testsuites>"
    
    with open(output_file, 'w') as f:
        f.write(junit_content)

def main():
    """Main entry point"""
    args = parse_arguments()
    
    # Handle special commands first
    if args.save_config_template:
        config_manager = ConfigManager()
        config_manager.save_config_template("test_config_template.json")
        print("✅ Configuration template saved to test_config_template.json")
        return 0
    
    # Initialize configuration
    config_manager = ConfigManager(args.config)
    
    if args.validate_config:
        validation = config_manager.validate_configuration()
        print("🔍 Configuration Validation Results:")
        print(json.dumps(validation, indent=2))
        return 0 if validation['valid'] else 1
    
    # Setup environment
    if not setup_environment():
        print("❌ Environment setup failed")
        return 1
    
    # Setup logging
    log_level = 'DEBUG' if args.verbose else ('ERROR' if args.quiet else 'INFO')
    logger = setup_logging(log_level, args.output_dir)
    
    logger.info("Starting AI Chatbot Testing Suite")
    logger.info(f"Configuration: {len(config_manager.get_available_providers())} providers configured")
    
    # Determine what tests to run
    results = None
    
    if args.test_class:
        # Run specific test class
        results = run_test_class(args.test_class, config_manager, args.verbose)
    elif args.suite == 'all':
        # Run all tests
        print("🚀 Running All Test Suites...")
        
        # Run core tests
        core_results = run_core_tests(config_manager, args.verbose)
        
        # Run API integration tests
        api_results = run_api_integration_tests(config_manager, args.providers, args.verbose)
        
        # Combine results
        results = {
            'total_tests': core_results.get('total_tests', 0) + api_results.get('total_tests', 0),
            'passed': core_results.get('passed', 0) + api_results.get('passed', 0),
            'failed': core_results.get('failed', 0) + api_results.get('failed', 0),
            'errors': core_results.get('errors', 0) + api_results.get('errors', 0),
            'suite_results': {
                **core_results.get('suite_results', {}),
                **api_results.get('suite_results', {})
            }
        }
        results['overall_success_rate'] = results['passed'] / results['total_tests'] if results['total_tests'] > 0 else 0
    
    else:
        # Run specific suite
        results = run_specific_suite(args.suite, config_manager, args.verbose)
    
    if results is None:
        logger.error("No test results generated")
        return 1
    
    # Generate reports
    if args.report_format:
        generate_reports(results, args.output_dir, args.report_format)
    
    # Print summary
    print("\n" + "="*60)
    print("🎯 TEST EXECUTION SUMMARY")
    print("="*60)
    print(f"Total Tests: {results.get('total_tests', 0)}")
    print(f"Passed: ✅ {results.get('passed', 0)}")
    print(f"Failed: ❌ {results.get('failed', 0)}")
    print(f"Errors: ⚠️  {results.get('errors', 0)}")
    print(f"Success Rate: {results.get('overall_success_rate', 0):.2%}")
    print("="*60)
    
    # Exit with appropriate code
    if results.get('failed', 0) > 0 or results.get('errors', 0) > 0:
        logger.warning("Tests completed with failures or errors")
        return 1
    else:
        logger.info("All tests passed successfully")
        return 0

if __name__ == "__main__":
    sys.exit(main())