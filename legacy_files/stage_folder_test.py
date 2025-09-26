#!/usr/bin/env python3
"""
ARTEMIS Enterprise Test - Halodoc Stage Folder Only
==================================================

Focused security testing on the "stage" folder endpoints from the
Concierge Service Postman collection, which includes:
1. Upsert Session
2. Get session conversations
3. Process Conversation (main LLM endpoint)
4. Retry Conversation
5. Inactivate sessions

This is a healthcare LLM system requiring HIPAA compliance testing.
"""

import asyncio
import json
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.append(str(Path(__file__).parent))

from tools.artemis_enterprise_commander import ARTEMISEnterpriseCommander, TestingMode
from ai_tester_core.postman_integration_engine import PostmanIntegrationEngine

async def extract_stage_folder_endpoints():
    """Extract only the stage folder endpoints for testing"""

    # Read the original collection
    collection_path = Path("~/Downloads/Concierge Service.postman_collection.json").expanduser()

    with open(collection_path, 'r') as f:
        original_collection = json.load(f)

    # Find and extract only the "stage" folder
    stage_folder = None
    for item in original_collection['item']:
        if item['name'] == 'stage':
            stage_folder = item
            break

    if not stage_folder:
        raise ValueError("Stage folder not found in collection")

    # Create a new collection with only the stage folder
    stage_only_collection = {
        "info": {
            "_postman_id": "artemis-stage-test",
            "name": "Halodoc Concierge Service - Stage Only",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            "_exporter_id": "artemis"
        },
        "item": [stage_folder]  # Only include the stage folder
    }

    # Save the stage-only collection
    stage_collection_path = Path("stage_only_collection.json")
    with open(stage_collection_path, 'w') as f:
        json.dump(stage_only_collection, f, indent=2)

    print(f"✅ Extracted stage folder with {len(stage_folder['item'])} endpoints")
    print(f"📄 Saved to: {stage_collection_path}")

    return stage_collection_path

async def analyze_stage_endpoints():
    """Analyze the stage endpoints for security testing"""

    print("\n🔍 ANALYZING STAGE FOLDER ENDPOINTS")
    print("=" * 50)

    # Extract stage folder
    stage_collection_path = await extract_stage_folder_endpoints()

    # Parse with ARTEMIS Postman engine
    engine = PostmanIntegrationEngine()
    collection = await engine.parse_collection(stage_collection_path)

    print(f"\n📊 COLLECTION ANALYSIS:")
    print(f"  • Collection Name: {collection.name}")
    print(f"  • Total Endpoints: {len(collection.endpoints)}")
    print(f"  • Base URLs: {len(collection.base_urls)}")

    # Analyze each endpoint
    print(f"\n🎯 ENDPOINT ANALYSIS:")
    for i, endpoint in enumerate(collection.endpoints, 1):
        print(f"\n  {i}. {endpoint.url}")
        print(f"     Method: {endpoint.method}")
        print(f"     Type: {endpoint.endpoint_type.value}")
        print(f"     Security Priority: {endpoint.security_priority}/10")
        print(f"     Injection Points: {len(endpoint.injection_points)}")
        print(f"     Healthcare Indicators: {endpoint.healthcare_indicators}")
        print(f"     LLM Indicators: {endpoint.llm_indicators}")

        # Show injection points
        if endpoint.injection_points:
            print(f"     🎯 Injection Points:")
            for ip in endpoint.injection_points[:3]:  # Show first 3
                print(f"        - {ip.location}.{ip.field_name} (priority: {ip.injection_priority})")

    # Show testing profile
    print(f"\n⚙️ TESTING PROFILE:")
    profile = collection.testing_profile
    print(f"  • Intensity: {profile['intensity']}")
    print(f"  • Rate Limit Strategy: {profile['rate_limit_strategy']}")
    print(f"  • Recommended Tests: {', '.join(profile['recommended_tests'])}")
    print(f"  • Estimated Duration: {profile['estimated_duration_minutes']} minutes")
    print(f"  • Compliance Requirements: {', '.join(profile['compliance_requirements'])}")

    return stage_collection_path, collection

async def run_artemis_security_test():
    """Run comprehensive ARTEMIS security test on stage endpoints"""

    print("\n🏹 STARTING ARTEMIS ENTERPRISE SECURITY TEST")
    print("=" * 60)

    # Analyze endpoints first
    stage_collection_path, collection = await analyze_stage_endpoints()

    # Initialize ARTEMIS Enterprise Commander
    config = {
        'log_level': 'INFO',
        'use_openai': False,  # Use local models for this test
        'healthcare_focus': True
    }

    commander = ARTEMISEnterpriseCommander(config)

    try:
        print(f"\n🚀 LAUNCHING ARTEMIS ENTERPRISE TEST")
        print(f"   Target: Halodoc Concierge Service (Stage)")
        print(f"   Endpoints: {len(collection.endpoints)}")
        print(f"   Focus: Healthcare LLM Security + HIPAA Compliance")

        # Run comprehensive security test
        results = await commander.run_comprehensive_security_test(
            target="concierge-service.stage-k8s.halodoc.com",
            mode=TestingMode.COMPREHENSIVE,
            postman_collection=str(stage_collection_path),
            compliance_frameworks=['hipaa', 'gdpr', 'ai_ethics'],
            custom_config={
                'healthcare_focus': True,
                'llm_specific_tests': True,
                'conversation_flow_testing': True
            }
        )

        print(f"\n✅ ARTEMIS ENTERPRISE TEST COMPLETED SUCCESSFULLY!")

        # Show key findings
        print(f"\n🎯 KEY FINDINGS:")
        stats = results['statistics']
        print(f"  • Overall Security Score: {results.get('overall_security_score', 0):.1f}%")
        print(f"  • Total Tests Executed: {stats['total_tests']}")
        print(f"  • Vulnerabilities Found: {stats['vulnerabilities_found']}")
        print(f"  • Compliance Violations: {stats['compliance_violations']}")
        print(f"  • Test Duration: {results['duration_seconds']:.1f} seconds")

        # Healthcare-specific findings
        if 'compliance' in results['results']:
            compliance = results['results']['compliance']
            print(f"\n🏥 HEALTHCARE COMPLIANCE:")
            print(f"  • HIPAA Compliance Score: {compliance.get('overall_compliance_score', 0):.1f}%")
            print(f"  • Frameworks Tested: {', '.join(compliance.get('frameworks_tested', []))}")

        # LLM-specific findings
        if 'attacks' in results['results']:
            attacks = results['results']['attacks']
            print(f"\n🤖 LLM SECURITY TESTING:")
            print(f"  • Attack Vectors Tested: {attacks.get('attack_vectors_tested', 0)}")
            print(f"  • Successful Attacks: {attacks.get('successful_attacks', 0)}")

            # Show category breakdown
            if 'category_results' in attacks:
                print(f"  • Category Results:")
                for category, results_data in attacks['category_results'].items():
                    success_rate = (results_data['successful_tests'] / max(results_data['total_tests'], 1)) * 100
                    print(f"    - {category}: {success_rate:.1f}% success rate ({results_data['successful_tests']}/{results_data['total_tests']})")

        # Specific findings for conversation endpoints
        print(f"\n💬 CONVERSATION ENDPOINT ANALYSIS:")
        conversation_endpoints = [e for e in collection.endpoints if 'conversation' in e.url.lower()]
        print(f"  • Conversation Endpoints Found: {len(conversation_endpoints)}")

        for endpoint in conversation_endpoints:
            print(f"  • {endpoint.url}:")
            print(f"    - Method: {endpoint.method}")
            print(f"    - Security Priority: {endpoint.security_priority}/10")
            print(f"    - Message Injection Points: {len([ip for ip in endpoint.injection_points if 'message' in ip.field_name.lower()])}")

        # Risk assessment
        risk_level = "LOW"
        if stats['vulnerabilities_found'] > 5 or stats['compliance_violations'] > 2:
            risk_level = "HIGH"
        elif stats['vulnerabilities_found'] > 2 or stats['compliance_violations'] > 0:
            risk_level = "MEDIUM"

        print(f"\n⚠️  RISK ASSESSMENT: {risk_level}")

        # Recommendations
        print(f"\n📋 RECOMMENDATIONS:")
        recommendations = results.get('recommendations', [])[:5]  # Show top 5
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")

        return results

    except Exception as e:
        print(f"❌ ARTEMIS test failed: {str(e)}")
        raise
    finally:
        await commander.cleanup_session()

async def main():
    """Main execution function"""
    print("🏹 ARTEMIS ENTERPRISE - HALODOC STAGE FOLDER SECURITY TEST")
    print("=" * 70)
    print("Testing Halodoc Concierge Service Stage Endpoints Only")
    print("Focus: Healthcare LLM Security + HIPAA Compliance")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    try:
        results = await run_artemis_security_test()

        print(f"\n🎉 TEST COMPLETED SUCCESSFULLY!")
        print(f"📊 Results saved in comprehensive reports")
        print(f"🔍 Check generated JSON/YAML reports for detailed analysis")

        return results

    except Exception as e:
        print(f"\n❌ Test execution failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    # Run the test
    result = asyncio.run(main())