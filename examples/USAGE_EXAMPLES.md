# 🛡️ Usage Examples - AI Security Testing Platform

## Quick Start Examples

### 1. Basic Web Application Testing

```bash
# Auto-detect and test any web application
python tools/generic_mvp_security_tester.py https://myapp.com

# Quick security check (2-5 minutes)
python tools/generic_mvp_security_tester.py https://myapp.com --mode quick

# Comprehensive assessment (15-30 minutes)
python tools/generic_mvp_security_tester.py https://myapp.com --mode comprehensive --output myapp_report.json
```

### 2. API Security Testing

```bash
# REST API testing
python tools/generic_mvp_security_tester.py https://api.myservice.com/v1 --mode auto

# GraphQL API testing
python tools/generic_mvp_security_tester.py https://api.myservice.com/graphql --mode comprehensive

# API with custom objectives
python tools/generic_mvp_security_tester.py https://api.myservice.com \
  --mode custom \
  --objectives api_security rate_limiting input_validation authentication
```

### 3. AI/ML Service Testing

```bash
# MCP server testing (like Zomato example)
python tools/generic_mvp_security_tester.py https://mcp-server.example.com/mcp --mode auto

# LLM service with prompt injection focus
python tools/generic_mvp_security_tester.py https://ai-service.com/chat \
  --mode custom \
  --objectives llm_security prompt_injection jailbreaking system_prompt_extraction
```

## Advanced Platform Examples

### 4. Advanced AI Security Testing

```bash
# Full modular AI platform assessment
python tools/modular_ai_security_tester.py https://target.com --mode comprehensive

# Rapid AI assessment
python tools/modular_ai_security_tester.py https://target.com --mode rapid --output rapid_report.json

# Adaptive AI optimization
python tools/modular_ai_security_tester.py https://target.com \
  --mode adaptive \
  --objectives comprehensive deep_analysis \
  --config configs/advanced_config.json
```

### 5. Continuous Monitoring

```bash
# Start continuous monitoring (every hour)
python tools/modular_ai_security_tester.py https://production-app.com \
  --continuous \
  --interval 3600

# Continuous monitoring with custom config
python tools/modular_ai_security_tester.py https://critical-service.com \
  --continuous \
  --interval 1800 \
  --config configs/monitoring_config.json
```

## Real-World Scenarios

### 6. Startup MVP Testing

```bash
# Quick security validation for MVP
python tools/generic_mvp_security_tester.py https://mvp.startup.com \
  --mode quick \
  --output reports/mvp_security_check.json

# Pre-launch comprehensive assessment
python tools/generic_mvp_security_tester.py https://staging.startup.com \
  --mode comprehensive \
  --output reports/pre_launch_assessment.json
```

### 7. Enterprise Application Assessment

```bash
# Enterprise web application
python tools/generic_mvp_security_tester.py https://enterprise-app.company.com \
  --mode comprehensive \
  --config configs/enterprise_config.json \
  --output reports/enterprise_security_assessment.json

# Microservices security testing
for service in auth user product order; do
  python tools/generic_mvp_security_tester.py https://$service.company.com \
    --mode auto \
    --output reports/${service}_security_report.json
done
```

### 8. AI Chatbot Security Testing

```bash
# ChatGPT-style service
python tools/generic_mvp_security_tester.py https://chat.ai-company.com \
  --mode custom \
  --objectives llm_security prompt_injection jailbreaking content_filtering \
  --output reports/chatbot_security.json

# Customer service bot
python tools/generic_mvp_security_tester.py https://support-bot.company.com \
  --mode comprehensive \
  --output reports/support_bot_assessment.json
```

## CI/CD Integration Examples

### 9. Jenkins Pipeline

```bash
#!/bin/bash
# Jenkins security testing stage
echo "Running security assessment..."

python tools/generic_mvp_security_tester.py $TARGET_URL \
  --mode quick \
  --output reports/pipeline_security_${BUILD_NUMBER}.json

# Check exit code
if [ $? -eq 0 ]; then
  echo "Security assessment passed"
else
  echo "Security issues found - check report"
  exit 1
fi
```

### 10. GitHub Actions

```yaml
name: Security Assessment
on: [push, pull_request]

jobs:
  security-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install aiohttp numpy dnspython

      - name: Run security assessment
        run: |
          python tools/generic_mvp_security_tester.py ${{ secrets.STAGING_URL }} \
            --mode quick \
            --output security_report.json

      - name: Upload security report
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: security_report.json
```

## Custom Configuration Examples

### 11. Custom Testing Objectives

```bash
# E-commerce security focus
python tools/generic_mvp_security_tester.py https://shop.example.com \
  --mode custom \
  --objectives payment_security pci_compliance sql_injection xss authentication \
  --output ecommerce_security.json

# Financial services focus
python tools/generic_mvp_security_tester.py https://fintech.example.com \
  --mode custom \
  --objectives encryption data_protection access_control audit_logging \
  --output fintech_security.json

# Healthcare application focus
python tools/generic_mvp_security_tester.py https://health.example.com \
  --mode custom \
  --objectives hipaa_compliance data_encryption access_control audit_trails \
  --output healthcare_security.json
```

### 12. Custom Configuration Files

```bash
# Use custom configuration for specific requirements
python tools/generic_mvp_security_tester.py https://target.com \
  --config examples/sample_configs/mvp_testing_config.json \
  --mode comprehensive

# High-security environment configuration
python tools/modular_ai_security_tester.py https://secure-app.com \
  --config configs/high_security_config.json \
  --mode comprehensive
```

## Learning and Analytics Examples

### 13. Platform Analytics

```bash
# View platform statistics
python tools/generic_mvp_security_tester.py --stats

# View detailed learning insights
python tools/modular_ai_security_tester.py --learning-insights

# Update ML models manually
python tools/modular_ai_security_tester.py --update-models
```

### 14. Performance Monitoring

```bash
# Monitor platform performance
python tools/generic_mvp_security_tester.py --stats | jq '.platform_stats'

# View agent effectiveness
python tools/modular_ai_security_tester.py --learning-insights | jq '.learning_statistics.agent_performance'
```

## Output Format Examples

### 15. Different Output Formats

```bash
# JSON output (default)
python tools/generic_mvp_security_tester.py https://target.com --output report.json

# HTML report
python tools/generic_mvp_security_tester.py https://target.com --output report.html --format html

# Multiple formats
python tools/generic_mvp_security_tester.py https://target.com \
  --output report \
  --format json,html
```

## Troubleshooting Examples

### 16. Debug and Verbose Output

```bash
# Enable debug logging
PYTHONPATH=. LOGLEVEL=DEBUG python tools/generic_mvp_security_tester.py https://target.com

# Verbose output with timing
python tools/generic_mvp_security_tester.py https://target.com --verbose --timing

# Test specific agent
python -c "
from ai_tester_core.agents.llm_security_agent import LLMSecurityAgent
agent = LLMSecurityAgent()
print('Agent capabilities:', agent.get_capabilities())
"
```

### 17. Error Handling

```bash
# Test with timeout handling
timeout 300 python tools/generic_mvp_security_tester.py https://slow-target.com --mode quick

# Test with retry logic
python tools/generic_mvp_security_tester.py https://unreliable-target.com \
  --mode auto \
  --retry 3
```

## Sample Report Analysis

### 18. Report Processing

```bash
# Extract key metrics from report
cat report.json | jq '.executive_summary'

# Get high-severity findings
cat report.json | jq '.detailed_results.findings_by_category.high[]'

# Extract recommendations
cat report.json | jq '.detailed_results.recommendations[]'

# Get AI insights
cat report.json | jq '.ai_insights'
```

### 19. Batch Processing

```bash
#!/bin/bash
# Test multiple targets
targets=(
  "https://app1.company.com"
  "https://api.company.com"
  "https://admin.company.com"
)

for target in "${targets[@]}"; do
  echo "Testing $target..."
  python tools/generic_mvp_security_tester.py "$target" \
    --mode auto \
    --output "reports/$(basename $target)_report.json"
done

echo "All assessments complete!"
```

## Integration Examples

### 20. API Integration

```python
#!/usr/bin/env python3
"""
Example: Integrate security testing into your application
"""

import asyncio
import subprocess
import json

async def run_security_assessment(target_url):
    """Run security assessment and return results"""

    cmd = [
        'python', 'tools/generic_mvp_security_tester.py',
        target_url,
        '--mode', 'quick',
        '--output', 'temp_report.json'
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        with open('temp_report.json', 'r') as f:
            return json.load(f)
    else:
        return {'error': result.stderr}

# Usage
if __name__ == "__main__":
    target = "https://myapp.com"
    report = asyncio.run(run_security_assessment(target))

    print(f"Risk Level: {report.get('executive_summary', {}).get('overall_risk', 'Unknown')}")
    print(f"Security Grade: {report.get('executive_summary', {}).get('security_grade', 'Unknown')}")
```

---

## 🎯 Common Use Cases Summary

| Use Case | Command | Duration | Best For |
|----------|---------|----------|----------|
| **MVP Validation** | `--mode quick` | 2-5 min | Startups, rapid feedback |
| **Pre-Production** | `--mode comprehensive` | 15-30 min | Before deployment |
| **API Testing** | `--mode auto` | 5-15 min | REST/GraphQL APIs |
| **AI Service Testing** | `--mode custom --objectives llm_security` | 10-20 min | LLM/AI services |
| **Continuous Monitoring** | `--continuous` | Ongoing | Production monitoring |
| **Enterprise Assessment** | `--mode comprehensive --config enterprise` | 30-60 min | Large applications |

---

**💡 Pro Tips:**

1. **Start with `--mode auto`** - Let AI choose the best strategy
2. **Use `--mode quick`** for CI/CD integration
3. **Save reports** with `--output` for tracking over time
4. **Custom objectives** for specific security requirements
5. **Monitor learning insights** to track platform improvement

For more examples and detailed documentation, see the main [README.md](../README.md) and [README_MODULAR_AI.md](../README_MODULAR_AI.md).