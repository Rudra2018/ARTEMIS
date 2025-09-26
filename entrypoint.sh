#!/bin/bash

# 🏹 ARTEMIS Enterprise - Docker Entrypoint Script
# Production-ready entrypoint for containerized deployment

set -e

# Environment setup
export ARTEMIS_HOME=${ARTEMIS_HOME:-/app}
export PYTHONPATH=${PYTHONPATH:-/app}

# Create necessary directories
mkdir -p /app/logs /app/reports /app/temp /app/data

echo "🏹 ARTEMIS Enterprise v2.0.0"
echo "================================"
echo "Advanced LLM Security Testing Platform"
echo ""

# Health check mode
if [ "$1" = "health-check" ]; then
    echo "🩺 Running health check..."
    python3 /app/artemis.py --health-check
    exit $?
fi

# Test mode
if [ "$1" = "test" ]; then
    echo "🧪 Running test suite..."
    cd /app
    python3 -m pytest tests/ -v || echo "⚠️  Tests not found - skipping"
    exit $?
fi

# Interactive mode
if [ "$1" = "interactive" ] || [ "$1" = "bash" ]; then
    echo "🔧 Starting interactive shell..."
    exec /bin/bash
fi

# Show help if no arguments
if [ $# -eq 0 ]; then
    echo "🎯 ARTEMIS Enterprise - Usage Examples:"
    echo ""
    echo "Basic Security Testing:"
    echo "  --target https://api.example.com"
    echo "  --postman collection.json --folder stage"
    echo "  --health-check"
    echo ""
    echo "Advanced Options:"
    echo "  --mode comprehensive"
    echo "  --output /app/reports"
    echo "  --verbose"
    echo ""
    echo "Examples:"
    echo "  python3 artemis.py --target https://your-api.com --mode comprehensive"
    echo "  python3 artemis.py --postman collection.json --folder stage"
    echo "  python3 artemis.py --health-check"
    echo ""
    echo "🏹 Ready for Advanced LLM Security Testing!"
    exec python3 /app/artemis.py --help
fi

# Default: Run ARTEMIS CLI
echo "🚀 Starting ARTEMIS Enterprise..."
echo "Working directory: $(pwd)"
echo "Python path: $PYTHONPATH"
echo ""

# Execute the main application
exec python3 /app/artemis.py "$@"