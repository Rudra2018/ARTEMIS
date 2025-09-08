#!/usr/bin/env python3
"""
Comprehensive Security Test Runner - 1000+ Test Cases
Command-line interface for running the complete comprehensive security test suite

Usage:
    python run_comprehensive_tests.py --all
    python run_comprehensive_tests.py --suites adversarial_attacks,edge_case_boundary
    python run_comprehensive_tests.py --model test-model --output results.json
"""

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

# Import test frameworks
try:
    from security_evaluation_framework import SecurityTestSuiteRunner
    from llm_security_research_framework import LLMSecurityResearchTestRunner  
    from comprehensive_security_test_suite import ComprehensiveSecurityTestRunner
    from adaptive_learning_engine import AdaptiveLearningEngine, TestResult
    
    FRAMEWORKS_AVAILABLE = {
        'core_security': True,
        'research_security': True, 
        'comprehensive_security': True,
        'adaptive_learning': True
    }
except ImportError as e:
    print(f"Warning: Some frameworks not available - {e}")
    FRAMEWORKS_AVAILABLE = {
        'core_security': False,
        'research_security': False,
        'comprehensive_security': False,
        'adaptive_learning': False
    }

def run_all_security_tests(model_name: str = "comprehensive-test-model",
                          output_file: str = None,
                          suites: list = None,
                          verbose: bool = True,
                          enable_learning: bool = True) -> dict:
    """Run all available security test frameworks"""
    
    api_config = {"api_key": "test-key", "endpoint": "test-endpoint"}
    all_results = {}
    total_tests = 0
    total_vulnerabilities = 0
    start_time = time.time()
    
    if verbose:
        print("\n" + "="*80)
        print("🛡️  ULTIMATE LLM SECURITY EVALUATION SUITE")
        print("="*80)
        print(f"🎯 Target Model: {model_name}")
        print(f"📅 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80)
    
    # 1. Core Security Framework (120+ tests)
    if FRAMEWORKS_AVAILABLE['core_security']:
        if verbose:
            print("\n🔧 Running Core Security Framework...")
        
        try:
            core_runner = SecurityTestSuiteRunner()
            core_results = core_runner.run_all_security_tests(
                target_model=model_name,
                api_config=api_config,
                verbose=False,
                include_research_tests=False
            )
            all_results['core_security'] = core_results
            total_tests += core_results['security_evaluation']['total_tests']
            total_vulnerabilities += core_results['security_evaluation']['vulnerabilities_detected']
            
            if verbose:
                print(f"   ✅ Core Security: {core_results['security_evaluation']['total_tests']} tests")
                print(f"   🔍 Vulnerabilities: {core_results['security_evaluation']['vulnerabilities_detected']}")
                
        except Exception as e:
            if verbose:
                print(f"   ❌ Core Security failed: {str(e)}")
    
    # 2. Research Security Framework (100+ tests)
    if FRAMEWORKS_AVAILABLE['research_security']:
        if verbose:
            print("\n📚 Running Research Security Framework...")
        
        try:
            research_runner = LLMSecurityResearchTestRunner()
            research_results = research_runner.run_research_security_tests(
                target_model=model_name,
                api_config=api_config,
                verbose=False
            )
            all_results['research_security'] = research_results
            total_tests += research_results['research_security_evaluation']['total_tests']
            total_vulnerabilities += research_results['research_security_evaluation']['vulnerabilities_found']
            
            if verbose:
                print(f"   ✅ Research Security: {research_results['research_security_evaluation']['total_tests']} tests")
                print(f"   🔍 Vulnerabilities: {research_results['research_security_evaluation']['vulnerabilities_found']}")
                
        except Exception as e:
            if verbose:
                print(f"   ❌ Research Security failed: {str(e)}")
    
    # 3. Comprehensive Security Framework (800+ tests)  
    if FRAMEWORKS_AVAILABLE['comprehensive_security']:
        if verbose:
            print("\n🚀 Running Comprehensive Security Framework...")
        
        try:
            comprehensive_runner = ComprehensiveSecurityTestRunner(model_name, api_config)
            
            # Determine which suites to run
            if suites:
                suites_to_run = suites
            else:
                suites_to_run = [
                    'adversarial_attacks',      # 200+ tests
                    'multi_modal_security',     # 150+ tests  
                    'edge_case_boundary',       # 200+ tests
                    'large_scale_stress',       # 150+ tests
                    'international_multilingual', # 100+ tests
                    'api_integration_security', # 100+ tests
                    'real_world_scenarios'      # 100+ tests
                ]
            
            comprehensive_results = comprehensive_runner.run_all_comprehensive_tests(
                suites_to_run=suites_to_run,
                verbose=False
            )
            all_results['comprehensive_security'] = comprehensive_results
            comp_eval = comprehensive_results['comprehensive_security_evaluation']
            total_tests += comp_eval['total_tests']
            total_vulnerabilities += comp_eval['total_vulnerabilities']
            
            if verbose:
                print(f"   ✅ Comprehensive Security: {comp_eval['total_tests']} tests")
                print(f"   🔍 Vulnerabilities: {comp_eval['total_vulnerabilities']}")
                print(f"   📊 Success Rate: {comp_eval['overall_success_rate']:.1f}%")
                
        except Exception as e:
            if verbose:
                print(f"   ❌ Comprehensive Security failed: {str(e)}")
    
    total_duration = time.time() - start_time
    
    # 4. Adaptive Learning Integration (if enabled)
    learning_summary = {}
    if enable_learning and FRAMEWORKS_AVAILABLE['adaptive_learning']:
        if verbose:
            print("\n🧠 Running Adaptive Learning Engine...")
        
        try:
            learning_engine = AdaptiveLearningEngine(f"learning_{model_name.replace('-', '_')}.db")
            
            # Convert results to TestResult format for learning
            test_results_for_learning = []
            
            # Process results from all frameworks for learning
            for framework_name, framework_results in all_results.items():
                if 'detailed_results' in framework_results:
                    for result in framework_results['detailed_results']:
                        test_result = TestResult(
                            test_id=result.get('test_id', f"{framework_name}_{len(test_results_for_learning)}"),
                            test_name=result.get('test_name', result.get('test_type', 'Unknown Test')),
                            category=result.get('category', framework_name),
                            attack_vector=result.get('attack_vector', result.get('attack_type', 'unknown')),
                            payload=result.get('payload', result.get('test_case', '')),
                            response=result.get('response', result.get('model_response', '')),
                            vulnerability_detected=result.get('vulnerability_detected', result.get('failed', False)),
                            attack_successful=result.get('attack_successful', result.get('passed', False)),
                            confidence_score=result.get('confidence_score', result.get('score', 0.0) / 100.0),
                            execution_time=result.get('execution_time', result.get('duration', 0.0)),
                            model_name=model_name,
                            timestamp=datetime.now()
                        )
                        test_results_for_learning.append(test_result)
            
            # Run adaptive learning
            if test_results_for_learning:
                learning_summary = learning_engine.learn_from_results(test_results_for_learning)
                
                if verbose:
                    print(f"   ✅ Learning Engine: Processed {learning_summary['processed_results']} results")
                    print(f"   🧠 New Patterns: {learning_summary['new_patterns_discovered']}")
                    print(f"   💡 Insights: {learning_summary['insights_generated']}")
                    print(f"   🧪 Generated Tests: {learning_summary['tests_generated']}")
            else:
                if verbose:
                    print("   ⚠️  No suitable test results found for learning")
                    
        except Exception as e:
            if verbose:
                print(f"   ❌ Adaptive Learning failed: {str(e)}")
    
    # Generate final summary
    final_report = {
        "ultimate_security_evaluation": {
            "model_name": model_name,
            "timestamp": datetime.now().isoformat(),
            "total_tests_executed": total_tests,
            "total_vulnerabilities_found": total_vulnerabilities,
            "total_execution_time": total_duration,
            "frameworks_executed": len(all_results),
            "overall_success_rate": ((total_tests - total_vulnerabilities) / total_tests * 100) if total_tests > 0 else 0,
            "framework_availability": FRAMEWORKS_AVAILABLE
        },
        "framework_results": all_results,
        "adaptive_learning": learning_summary if learning_summary else {"enabled": False}
    }
    
    if verbose:
        print("\n" + "="*80)  
        print("🎉 ULTIMATE SECURITY EVALUATION COMPLETED")
        print("="*80)
        print(f"🔢 Total Tests Executed: {total_tests}")
        print(f"🔍 Total Vulnerabilities Found: {total_vulnerabilities}")
        print(f"📊 Overall Success Rate: {((total_tests - total_vulnerabilities) / total_tests * 100):.2f}%" if total_tests > 0 else "N/A")
        print(f"⏱️  Total Execution Time: {total_duration:.2f}s")
        print(f"🛡️  Frameworks Executed: {len(all_results)}")
        print("="*80)
        
        # Framework breakdown
        print("\n📋 Framework Breakdown:")
        if 'core_security' in all_results:
            core = all_results['core_security']['security_evaluation']
            print(f"  🔧 Core Security: {core['total_tests']} tests, {core['vulnerabilities_detected']} vulnerabilities")
        
        if 'research_security' in all_results:
            research = all_results['research_security']['research_security_evaluation'] 
            print(f"  📚 Research Security: {research['total_tests']} tests, {research['vulnerabilities_found']} vulnerabilities")
        
        if 'comprehensive_security' in all_results:
            comp = all_results['comprehensive_security']['comprehensive_security_evaluation']
            print(f"  🚀 Comprehensive Security: {comp['total_tests']} tests, {comp['total_vulnerabilities']} vulnerabilities")
        
        print("="*80)
    
    # Save results if requested
    if output_file:
        try:
            with open(output_file, 'w') as f:
                json.dump(final_report, f, indent=2, default=str)
            if verbose:
                print(f"📁 Results saved to: {output_file}")
        except Exception as e:
            if verbose:
                print(f"❌ Failed to save results: {str(e)}")
    
    return final_report

def main():
    """Main command-line interface"""
    parser = argparse.ArgumentParser(
        description="Comprehensive LLM Security Test Suite - 1000+ Tests",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_comprehensive_tests.py --all
  python run_comprehensive_tests.py --model gpt-4 --output results.json
  python run_comprehensive_tests.py --suites adversarial_attacks,edge_case_boundary
  python run_comprehensive_tests.py --quiet --output minimal_results.json
        """
    )
    
    parser.add_argument(
        '--model', '-m',
        default='comprehensive-test-model',
        help='Target model name for testing (default: comprehensive-test-model)'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Output file for results (JSON format)'
    )
    
    parser.add_argument(
        '--suites', '-s',
        help='Comma-separated list of test suites to run (e.g., adversarial_attacks,edge_case_boundary)'
    )
    
    parser.add_argument(
        '--all', '-a',
        action='store_true',
        help='Run all available test suites'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress verbose output'
    )
    
    parser.add_argument(
        '--list-suites',
        action='store_true',
        help='List available test suites and exit'
    )
    
    parser.add_argument(
        '--no-learning',
        action='store_true',
        help='Disable adaptive learning engine'
    )
    
    args = parser.parse_args()
    
    # List available suites if requested
    if args.list_suites:
        print("\n🛡️  Available Test Suites:")
        print("="*50)
        print("Core Security Framework:")
        print("  • sei_openai - SEI & OpenAI evaluation framework")
        print("  • wdta - WDTA L1-L4 attack categorization")  
        print("  • cyberseceval2 - CyberSecEval 2 benchmarking")
        print("  • purple_llama - Purple Llama secure coding tests")
        print("  • garak - Garak-inspired vulnerability scanner")
        print("  • owasp_llm_top10 - OWASP LLM Top 10 testing")
        print("  • automated_pentest - Automated penetration testing")
        
        print("\nResearch Security Framework:")
        print("  • prompt_injection - Advanced prompt injection tests")
        print("  • data_poisoning - Data poisoning and model extraction")
        print("  • privacy_bias - Privacy leakage and bias analysis")
        print("  • responsible_ai - Responsible AI practices evaluation")
        
        print("\nComprehensive Security Framework:")
        print("  • adversarial_attacks - 200+ adversarial attack tests")
        print("  • multi_modal_security - 150+ multi-modal security tests")
        print("  • edge_case_boundary - 200+ edge case and boundary tests")
        print("  • large_scale_stress - 150+ large-scale stress tests")
        print("  • international_multilingual - 100+ international tests")
        print("  • api_integration_security - 100+ API security tests")
        print("  • real_world_scenarios - 100+ real-world attack scenarios")
        print("="*50)
        return
    
    # Parse suites
    suites_to_run = None
    if args.suites:
        suites_to_run = [suite.strip() for suite in args.suites.split(',')]
    elif not args.all:
        # Default to a subset for performance
        suites_to_run = ['adversarial_attacks', 'edge_case_boundary', 'api_integration_security']
    
    # Run tests
    try:
        results = run_all_security_tests(
            model_name=args.model,
            output_file=args.output,
            suites=suites_to_run,
            verbose=not args.quiet,
            enable_learning=not args.no_learning
        )
        
        if not args.quiet:
            print(f"\n✅ Testing completed successfully!")
            
            # Show key metrics
            ultimate_eval = results['ultimate_security_evaluation']
            print(f"🎯 {ultimate_eval['total_tests_executed']} total tests executed")
            print(f"🔍 {ultimate_eval['total_vulnerabilities_found']} vulnerabilities found")  
            print(f"📊 {ultimate_eval['overall_success_rate']:.1f}% overall success rate")
            
            if args.output:
                print(f"📁 Detailed results saved to {args.output}")
                
        sys.exit(0)
        
    except KeyboardInterrupt:
        print(f"\n⚠️  Testing interrupted by user")
        sys.exit(1)
        
    except Exception as e:
        print(f"\n❌ Testing failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()