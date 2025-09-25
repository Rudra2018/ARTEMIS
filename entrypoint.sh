#!/bin/bash
# 🏹 ARTEMIS NEXUS AI - Docker Entrypoint Script

set -e

# Create necessary directories
mkdir -p /app/logs /app/reports /app/temp /app/ml_models /app/data

# Set proper ownership
chown -R artemis:artemis /app/logs /app/reports /app/temp /app/ml_models /app/data

echo "🏹 ARTEMIS NEXUS AI - Container Starting..."
echo "📁 Directories created and permissions set"
echo "🔧 Environment: $ARTEMIS_MODE"
echo ""

# If no command specified, show help
if [ $# -eq 0 ]; then
    echo "🎯 ARTEMIS NEXUS AI - Available Commands:"
    echo ""
    echo "Security Testing with Threat Intelligence:"
    echo "  python3 tools/final_comprehensive_test.py <target-url>"
    echo "  python3 tools/artemis_nexus_ai_commander.py <target-url>"
    echo "  python3 tools/comprehensive_artemis_testing.py <target-url>"
    echo ""
    echo "Advanced Features:"
    echo "  🧠 Advanced Threat Intelligence & Multi-Layer Detection"
    echo "  🎯 Predictive Risk Modeling & Behavioral Analysis"
    echo "  🚨 Real-time Threat Correlation & Escalation Paths"
    echo "  🛡️ Red Team Exercise Framework Integration"
    echo ""
    echo "Help & Information:"
    echo "  python3 tools/artemis_nexus_ai_commander.py --help"
    echo "  bash  # Interactive shell"
    echo ""
    echo "Example Usage:"
    echo "  python3 tools/final_comprehensive_test.py https://your-target.com"
    echo ""
    echo "🏹 Ready for Advanced AI Security Testing with Threat Intelligence!"
    exec bash
else
    # Execute the provided command
    exec "$@"
fi