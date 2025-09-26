#!/usr/bin/env python3
"""
ARTEMIS PortSwigger AI Prompt Fuzzer
===================================

Command-line interface for running PortSwigger-style AI prompt fuzzing
using the integrated ARTEMIS security testing framework.

This tool combines the power of PortSwigger's AI Prompt Fuzzer payloads
with ARTEMIS's comprehensive security testing capabilities.

Usage:
    python artemis_portswigger_fuzzer.py <target_url> [options]

Features:
- Load PortSwigger XML payload files
- Use built-in PortSwigger-style payloads
- Advanced response analysis and validation
- Multiple output formats (JSON, HTML, text)
- Comprehensive reporting with security recommendations
"""

import argparse
import asyncio
import json
import logging
import sys
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

import aiohttp

# ARTEMIS imports
sys.path.append(str(Path(__file__).parent.parent))

try:
    from security_modules.agents.ai_fuzzing_agent.portswigger_adapter import (
        PortSwiggerFuzzingEngine, PortSwiggerConfig, PortSwiggerPayload
    )
    from security_modules.agents.ai_fuzzing_agent.fuzzing_agent import (
        AIFuzzingAgent, FuzzingConfig, FuzzingStrategy
    )
    from ai_tester_core.advanced_fuzzing_engine import (
        AdvancedFuzzingEngine, FuzzingStrategy as AdvancedFuzzingStrategy
    )
except ImportError as e:
    print(f"Error importing ARTEMIS modules: {e}")
    print("Please ensure you're running from the ARTEMIS root directory")
    sys.exit(1)


class PortSwiggerCLI:
    """Command-line interface for PortSwigger fuzzing"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def setup_logging(self, verbose: bool = False):
        """Setup logging configuration"""
        level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

    async def run_portswigger_fuzzing(self, args: argparse.Namespace) -> Dict[str, Any]:
        """Run PortSwigger-style fuzzing against target"""

        print(f"🏹 ARTEMIS PortSwigger AI Prompt Fuzzer")
        print(f"   Target: {args.target_url}")
        print(f"   Payloads: {args.payload_file or 'Built-in PortSwigger payloads'}")
        print(f"   Mode: {args.mode}")
        print("")

        # Create PortSwigger configuration
        config = PortSwiggerConfig(
            payload_file=args.payload_file,
            url_encode_payloads=args.url_encode,
            escape_quotes_and_backslashes=args.escape_quotes,
            min_keyword_occurrences=args.min_occurrences,
            verify_with_ai=args.ai_verification
        )

        # Initialize results
        results = {
            'target_url': args.target_url,
            'test_config': {
                'payload_file': args.payload_file,
                'mode': args.mode,
                'max_payloads': args.max_payloads,
                'timeout': args.timeout,
                'url_encode': args.url_encode,
                'escape_quotes': args.escape_quotes,
                'min_occurrences': args.min_occurrences
            },
            'test_results': [],
            'summary': {},
            'recommendations': []
        }

        try:
            async with aiohttp.ClientSession() as session:
                if args.mode == 'portswigger':
                    results = await self._run_portswigger_mode(session, args, config)
                elif args.mode == 'advanced':
                    results = await self._run_advanced_mode(session, args, config)
                elif args.mode == 'basic':
                    results = await self._run_basic_mode(session, args, config)
                else:
                    raise ValueError(f"Unknown mode: {args.mode}")

        except Exception as e:
            self.logger.error(f"Fuzzing failed: {e}")
            results['error'] = str(e)

        return results

    async def _run_portswigger_mode(self, session: aiohttp.ClientSession,
                                  args: argparse.Namespace,
                                  config: PortSwiggerConfig) -> Dict[str, Any]:
        """Run in PortSwigger-only mode"""

        print("🎯 Running PortSwigger mode...")

        # Create PortSwigger engine
        portswigger_engine = PortSwiggerFuzzingEngine(config, self.logger)

        # Get payloads
        ps_payloads = portswigger_engine.payloads[:args.max_payloads]
        print(f"   Loaded {len(ps_payloads)} PortSwigger payloads")

        # Test each payload
        test_results = []
        successful_tests = 0

        for i, ps_payload in enumerate(ps_payloads):
            print(f"   Testing payload {i+1}/{len(ps_payloads)}: {ps_payload.inject[:50]}...")

            try:
                result = await self._test_single_payload(
                    session, args.target_url, ps_payload, args.timeout
                )

                # Validate response using PortSwigger methodology
                artemis_payload = portswigger_engine.convert_to_artemis_payloads()[i]
                validation = portswigger_engine.validate_response(artemis_payload, result['response_body'])

                result.update({
                    'validation': validation,
                    'is_potential_break': validation['is_potential_break'],
                    'confidence': validation['confidence']
                })

                if validation['is_potential_break']:
                    successful_tests += 1
                    print(f"      ✅ POTENTIAL BREAK DETECTED (Confidence: {validation['confidence']:.2f})")
                else:
                    print(f"      ❌ No vulnerability detected")

                test_results.append(result)

            except Exception as e:
                self.logger.error(f"Error testing payload {i}: {e}")
                test_results.append({
                    'payload_id': f"ps_payload_{i}",
                    'payload': ps_payload.inject,
                    'error': str(e),
                    'is_potential_break': False
                })

        # Generate report
        report = portswigger_engine.generate_test_report(
            [(ps_payloads[i], test_results[i]) for i in range(len(test_results))]
        )

        print(f"\n📊 Test Summary:")
        print(f"   Total tests: {len(test_results)}")
        print(f"   Potential breaks: {successful_tests}")
        print(f"   Success rate: {successful_tests/len(test_results)*100:.1f}%")

        return {
            'target_url': args.target_url,
            'mode': 'portswigger',
            'test_results': test_results,
            'summary': report['summary'],
            'recommendations': report['recommendations'],
            'configuration': report['configuration']
        }

    async def _run_advanced_mode(self, session: aiohttp.ClientSession,
                                args: argparse.Namespace,
                                config: PortSwiggerConfig) -> Dict[str, Any]:
        """Run in advanced mode with full ARTEMIS capabilities"""

        print("🚀 Running Advanced mode...")

        # Create advanced fuzzing engine
        engine = AdvancedFuzzingEngine(session, self.logger)

        # Discover endpoints
        print("🔍 Discovering endpoints...")
        endpoints = await engine.discovery_engine.discover_endpoints(args.target_url, max_depth=2)
        print(f"   Found {len(endpoints)} endpoints")

        if not endpoints:
            print("   No endpoints found, creating basic endpoint info...")
            from ai_tester_core.advanced_fuzzing_engine import EndpointInfo
            endpoints = [EndpointInfo(
                url=args.target_url,
                methods={'POST', 'GET'},
                parameters={},
                response_patterns=['llm_response'],
                authentication_required=False
            )]

        # Run PortSwigger fuzzing on first endpoint
        endpoint = endpoints[0]
        results = await engine.fuzz_endpoint(
            endpoint,
            strategy=AdvancedFuzzingStrategy.PORTSWIGGER,
            max_tests=args.max_payloads,
            timeout=args.timeout
        )

        successful_tests = sum(1 for _, result in results
                             if result.get('result') == 'success')

        print(f"\n📊 Advanced Test Summary:")
        print(f"   Endpoints tested: {len(endpoints)}")
        print(f"   Total tests: {len(results)}")
        print(f"   Successful tests: {successful_tests}")

        return {
            'target_url': args.target_url,
            'mode': 'advanced',
            'endpoints_discovered': len(endpoints),
            'test_results': [result for _, result in results],
            'summary': {
                'total_tests': len(results),
                'successful_tests': successful_tests,
                'success_rate': successful_tests / len(results) if results else 0
            }
        }

    async def _run_basic_mode(self, session: aiohttp.ClientSession,
                            args: argparse.Namespace,
                            config: PortSwiggerConfig) -> Dict[str, Any]:
        """Run in basic mode with simple payload testing"""

        print("⚡ Running Basic mode...")

        # Create basic fuzzing agent
        fuzzing_config = FuzzingConfig(
            strategy=FuzzingStrategy.PORTSWIGGER,
            max_iterations=args.max_payloads,
            timeout=args.timeout
        )

        agent = AIFuzzingAgent(fuzzing_config)

        # Run fuzzing
        input_schema = {"message": "string", "input": "string"}
        report = await agent.fuzz_target(args.target_url, input_schema, "test input")

        print(f"\n📊 Basic Test Summary:")
        print(f"   Total tests: {report.total_payloads}")
        print(f"   Successful tests: {report.successful_tests}")
        print(f"   Vulnerabilities found: {report.vulnerabilities_found}")

        return {
            'target_url': args.target_url,
            'mode': 'basic',
            'test_results': [
                {
                    'payload_id': r.payload_id,
                    'payload': r.payload,
                    'response': r.response,
                    'vulnerability_detected': r.vulnerability_detected,
                    'confidence': r.confidence
                } for r in report.results
            ],
            'summary': {
                'total_tests': report.total_payloads,
                'successful_tests': report.successful_tests,
                'vulnerabilities_found': report.vulnerabilities_found,
                'execution_time': report.execution_time
            },
            'recommendations': report.recommendations
        }

    async def _test_single_payload(self, session: aiohttp.ClientSession,
                                 target_url: str, payload: PortSwiggerPayload,
                                 timeout: float) -> Dict[str, Any]:
        """Test a single PortSwigger payload against target"""

        start_time = time.time()

        try:
            # Prepare request data
            request_data = {
                "message": payload.inject,
                "input": payload.inject,
                "query": payload.inject,
                "prompt": payload.inject
            }

            timeout_config = aiohttp.ClientTimeout(total=timeout)

            async with session.post(target_url, json=request_data, timeout=timeout_config) as response:
                response_text = await response.text()
                response_time = time.time() - start_time

                return {
                    'payload_id': f"ps_{hash(payload.inject) & 0xFFFFFF:06x}",
                    'payload': payload.inject,
                    'expected_keywords': payload.keywords,
                    'response_code': response.status,
                    'response_body': response_text,
                    'response_time_ms': int(response_time * 1000),
                    'response_headers': dict(response.headers)
                }

        except asyncio.TimeoutError:
            return {
                'payload_id': f"ps_{hash(payload.inject) & 0xFFFFFF:06x}",
                'payload': payload.inject,
                'expected_keywords': payload.keywords,
                'error': 'Request timeout',
                'response_time_ms': int(timeout * 1000)
            }
        except Exception as e:
            return {
                'payload_id': f"ps_{hash(payload.inject) & 0xFFFFFF:06x}",
                'payload': payload.inject,
                'expected_keywords': payload.keywords,
                'error': str(e),
                'response_time_ms': int((time.time() - start_time) * 1000)
            }

    def save_results(self, results: Dict[str, Any], output_file: str, format_type: str):
        """Save results to file in specified format"""

        output_path = Path(output_file)

        if format_type == 'json':
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)

        elif format_type == 'html':
            self._save_html_report(results, output_path)

        elif format_type == 'txt':
            self._save_text_report(results, output_path)

        print(f"💾 Results saved to {output_path}")

    def _save_html_report(self, results: Dict[str, Any], output_path: Path):
        """Save HTML report"""
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>ARTEMIS PortSwigger Fuzzing Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .test-result {{ border: 1px solid #bdc3c7; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .success {{ background: #d5f4e6; border-color: #27ae60; }}
        .failure {{ background: #fadbd8; border-color: #e74c3c; }}
        .payload {{ background: #f8f9fa; padding: 10px; font-family: monospace; border-radius: 3px; }}
        .recommendations {{ background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🏹 ARTEMIS PortSwigger Fuzzing Report</h1>
        <p>Target: {results['target_url']}</p>
        <p>Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>

    <div class="summary">
        <h2>📊 Test Summary</h2>
        <p><strong>Total Tests:</strong> {results.get('summary', {}).get('total_tests', 0)}</p>
        <p><strong>Successful Tests:</strong> {results.get('summary', {}).get('successful_tests', 0)}</p>
        <p><strong>Success Rate:</strong> {results.get('summary', {}).get('success_rate', 0)*100:.1f}%</p>
    </div>

    <div class="recommendations">
        <h2>🛡️ Security Recommendations</h2>
        <ul>
        """

        for rec in results.get('recommendations', []):
            html_content += f"<li>{rec}</li>"

        html_content += """
        </ul>
    </div>

    <h2>🎯 Test Results</h2>
        """

        for i, test in enumerate(results.get('test_results', [])):
            is_success = test.get('is_potential_break', False) or test.get('vulnerability_detected', False)
            status_class = 'success' if is_success else 'failure'
            status_text = '✅ POTENTIAL BREAK' if is_success else '❌ No vulnerability'

            html_content += f"""
    <div class="test-result {status_class}">
        <h3>Test {i+1}: {status_text}</h3>
        <div class="payload"><strong>Payload:</strong> {test.get('payload', 'N/A')}</div>
        <p><strong>Response Code:</strong> {test.get('response_code', 'N/A')}</p>
        <p><strong>Response Time:</strong> {test.get('response_time_ms', 'N/A')}ms</p>
        {f"<p><strong>Confidence:</strong> {test.get('confidence', 0):.2f}</p>" if is_success else ""}
        {f"<p><strong>Error:</strong> {test.get('error')}</p>" if test.get('error') else ""}
    </div>
            """

        html_content += """
</body>
</html>
        """

        with open(output_path, 'w') as f:
            f.write(html_content)

    def _save_text_report(self, results: Dict[str, Any], output_path: Path):
        """Save text report"""
        with open(output_path, 'w') as f:
            f.write("🏹 ARTEMIS PortSwigger Fuzzing Report\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Target: {results['target_url']}\n")
            f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            summary = results.get('summary', {})
            f.write("📊 TEST SUMMARY\n")
            f.write("-" * 20 + "\n")
            f.write(f"Total Tests: {summary.get('total_tests', 0)}\n")
            f.write(f"Successful Tests: {summary.get('successful_tests', 0)}\n")
            f.write(f"Success Rate: {summary.get('success_rate', 0)*100:.1f}%\n\n")

            f.write("🛡️ RECOMMENDATIONS\n")
            f.write("-" * 20 + "\n")
            for rec in results.get('recommendations', []):
                f.write(f"• {rec}\n")
            f.write("\n")

            f.write("🎯 DETAILED RESULTS\n")
            f.write("-" * 20 + "\n")
            for i, test in enumerate(results.get('test_results', [])):
                is_success = test.get('is_potential_break', False) or test.get('vulnerability_detected', False)
                status = "✅ POTENTIAL BREAK" if is_success else "❌ No vulnerability"

                f.write(f"\nTest {i+1}: {status}\n")
                f.write(f"Payload: {test.get('payload', 'N/A')}\n")
                f.write(f"Response Code: {test.get('response_code', 'N/A')}\n")
                f.write(f"Response Time: {test.get('response_time_ms', 'N/A')}ms\n")
                if is_success:
                    f.write(f"Confidence: {test.get('confidence', 0):.2f}\n")
                if test.get('error'):
                    f.write(f"Error: {test.get('error')}\n")


def create_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser"""

    parser = argparse.ArgumentParser(
        description="ARTEMIS PortSwigger AI Prompt Fuzzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic PortSwigger fuzzing with built-in payloads
  python artemis_portswigger_fuzzer.py https://api.example.com/chat

  # Use custom PortSwigger XML file
  python artemis_portswigger_fuzzer.py https://api.example.com/chat --payload-file payloads.xml

  # Advanced mode with endpoint discovery
  python artemis_portswigger_fuzzer.py https://api.example.com --mode advanced --max-payloads 50

  # Save detailed HTML report
  python artemis_portswigger_fuzzer.py https://api.example.com/chat --output report.html --format html
        """
    )

    # Required arguments
    parser.add_argument('target_url', help='Target URL to fuzz')

    # Payload options
    parser.add_argument('--payload-file', '-p', help='PortSwigger XML payload file')
    parser.add_argument('--max-payloads', '-n', type=int, default=20,
                       help='Maximum number of payloads to test (default: 20)')

    # Mode options
    parser.add_argument('--mode', '-m', choices=['portswigger', 'advanced', 'basic'],
                       default='portswigger',
                       help='Fuzzing mode (default: portswigger)')

    # Request options
    parser.add_argument('--timeout', '-t', type=float, default=30.0,
                       help='Request timeout in seconds (default: 30)')
    parser.add_argument('--url-encode', action='store_true',
                       help='URL encode payloads')
    parser.add_argument('--escape-quotes', action='store_true',
                       help='Escape quotes and backslashes in payloads')

    # Analysis options
    parser.add_argument('--min-occurrences', type=int, default=1,
                       help='Minimum keyword occurrences for potential break (default: 1)')
    parser.add_argument('--ai-verification', action='store_true',
                       help='Use AI verification for response analysis')

    # Output options
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--format', '-f', choices=['json', 'html', 'txt'],
                       default='json', help='Output format (default: json)')

    # Logging options
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose logging')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Quiet mode (minimal output)')

    return parser


async def main():
    """Main entry point"""

    parser = create_parser()
    args = parser.parse_args()

    # Validate target URL
    parsed_url = urlparse(args.target_url)
    if not parsed_url.scheme or not parsed_url.netloc:
        print(f"❌ Invalid target URL: {args.target_url}")
        sys.exit(1)

    # Create CLI instance
    cli = PortSwiggerCLI()
    cli.setup_logging(args.verbose)

    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)

    try:
        # Run fuzzing
        results = await cli.run_portswigger_fuzzing(args)

        # Save results if requested
        if args.output:
            cli.save_results(results, args.output, args.format)
        else:
            # Print summary to console
            if not args.quiet:
                print(f"\n🎯 Final Summary:")
                summary = results.get('summary', {})
                print(f"   Total tests: {summary.get('total_tests', 0)}")
                print(f"   Potential breaks: {summary.get('successful_tests', 0)}")
                print(f"   Success rate: {summary.get('success_rate', 0)*100:.1f}%")

                if results.get('recommendations'):
                    print(f"\n🛡️ Security Recommendations:")
                    for rec in results['recommendations'][:3]:
                        print(f"   • {rec}")

    except KeyboardInterrupt:
        print("\n⚠️ Fuzzing interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())