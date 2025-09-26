# 🏹 ARTEMIS Enterprise
## Advanced LLM Security Testing Platform

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/artemis-security/artemis-enterprise)
[![Python](https://img.shields.io/badge/python-3.11+-green.svg)](https://python.org)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://docker.com)
[![OWASP](https://img.shields.io/badge/OWASP-LLM%20Top%2010-red.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![HIPAA](https://img.shields.io/badge/compliance-HIPAA%20%7C%20GDPR-green.svg)](https://www.hhs.gov/hipaa)

**ARTEMIS Enterprise** is a comprehensive security testing platform specifically designed for Large Language Models (LLMs) and AI-powered applications. It provides enterprise-grade security assessment capabilities with focus on healthcare compliance, OWASP LLM Top 10 vulnerabilities, and advanced attack vector detection.

## 🌟 Key Features

### 🎯 **Advanced Security Testing**
- **100+ Attack Vectors** categorized by OWASP LLM Top 10
- **Postman Collection Integration** for automated endpoint discovery
- **Multi-Modal Testing** (text, images, documents)
- **AI-Driven Adaptive Mutation** for intelligent payload evolution

### 🏥 **Healthcare & Compliance Focus**
- **HIPAA Compliance Testing** with PHI protection validation
- **GDPR Data Privacy** assessment capabilities
- **Healthcare Boundary Testing** for medical AI systems
- **Regulatory Compliance Reporting** with detailed audit trails

### 📊 **Professional Reporting**
- **PDF Security Reports** with executive summaries
- **JSON/HTML/CSV Exports** for integration with CI/CD
- **Vulnerability Evidence** with proof-of-concept demonstrations
- **Remediation Roadmaps** with cost and timeline estimates

### 🚀 **Enterprise Features**
- **Docker-Ready Deployment** with production configurations
- **Scalable Testing Architecture** for large-scale assessments
- **Real-time Monitoring** and progress tracking
- **CLI & Web Interface** for flexible usage

## 🛠 Installation

### Prerequisites
- Python 3.11 or higher
- Docker (optional, recommended for production)
- 4GB+ RAM for optimal performance
- Network access to target systems

### 🐍 Python Installation

1. **Clone the repository:**
```bash
git clone https://github.com/artemis-security/artemis-enterprise.git
cd artemis-enterprise
```

2. **Create virtual environment:**
```bash
python3 -m venv artemis-env
source artemis-env/bin/activate  # On Windows: artemis-env\Scripts\activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

4. **Verify installation:**
```bash
python3 artemis.py --health-check
```

### 🐳 Docker Installation (Recommended)

1. **Build the image:**
```bash
docker build -t artemis-enterprise:latest .
```

2. **Run health check:**
```bash
docker run --rm artemis-enterprise:latest --health-check
```

3. **Quick test:**
```bash
docker run --rm -v $(pwd)/reports:/app/reports artemis-enterprise:latest \
  --target https://jsonplaceholder.typicode.com/posts/1 --mode quick
```

## 🚀 Quick Start

### Basic Usage

**Test a single endpoint:**
```bash
python3 artemis.py --target https://api.example.com --mode comprehensive
```

**Test with Postman collection:**
```bash
python3 artemis.py --postman collection.json --folder production
```

**Healthcare-focused testing:**
```bash
python3 artemis.py --postman healthcare-api.json --mode comprehensive \
  --config config/hipaa-compliance.yaml
```

### Advanced Usage

**Comprehensive security assessment:**
```bash
python3 artemis.py \
  --target https://api.healthcare.com \
  --postman collection.json \
  --folder stage \
  --mode comprehensive \
  --output ./security-reports \
  --verbose
```

**Docker deployment:**
```bash
docker run --rm \
  -v $(pwd)/collections:/app/collections \
  -v $(pwd)/reports:/app/reports \
  artemis-enterprise:latest \
  --postman /app/collections/api.json \
  --mode comprehensive
```

## 📋 Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `--target` | Target system URL or identifier | `--target https://api.example.com` |
| `--postman` | Postman collection JSON file | `--postman collection.json` |
| `--folder` | Specific folder to test from collection | `--folder stage` |
| `--mode` | Testing mode (quick/comprehensive) | `--mode comprehensive` |
| `--output` | Output directory for reports | `--output ./reports` |
| `--config` | Configuration file (YAML/JSON) | `--config config.yaml` |
| `--verbose` | Enable verbose logging | `--verbose` |
| `--health-check` | Run system health check | `--health-check` |
| `--version` | Show version information | `--version` |

## 🎯 Attack Categories

ARTEMIS Enterprise tests for vulnerabilities across multiple categories:

### OWASP LLM Top 10
- **LLM01** - Prompt Injection
- **LLM02** - Insecure Output Handling
- **LLM03** - Training Data Poisoning
- **LLM06** - Sensitive Information Disclosure
- **LLM07** - Insecure Plugin Design

### Healthcare-Specific Testing
- **HIPAA PHI Protection** - Tests protected health information handling
- **Medical Boundary Testing** - Validates healthcare professional verification
- **Emergency Override Controls** - Tests emergency access mechanisms
- **Insurance Data Protection** - Validates billing and insurance data security

### Advanced Attack Vectors
- **Function Call Injection** - Tests plugin and tool security
- **Context Poisoning** - Validates conversation flow integrity
- **Multi-turn Manipulation** - Tests conversation state security
- **Healthcare Impersonation** - Tests role-based access controls

## 🧪 Testing Examples

### Example 1: Healthcare API Assessment
```bash
# Test healthcare API with HIPAA compliance focus
python3 artemis.py \
  --target https://health-api.example.com \
  --mode comprehensive \
  --output reports/healthcare-assessment
```

### Example 2: Postman Collection Testing
```bash
# Test specific folder from Postman collection
python3 artemis.py \
  --postman collections/concierge-service.json \
  --folder stage \
  --mode comprehensive \
  --verbose
```

### Example 3: Quick Security Scan
```bash
# Quick security scan for CI/CD pipeline
python3 artemis.py \
  --target https://api.example.com \
  --mode quick \
  --output reports/quick-scan
```

## 📈 Sample Output

```
🏹 ARTEMIS Enterprise v2.0.0
================================
Advanced LLM Security Testing Platform

🚀 Starting ARTEMIS security assessment
   Target: Halodoc Concierge Service (Stage)
   Mode: comprehensive
   Session: 007f6a10

📋 Parsed 5 endpoints from Postman collection
🎯 Testing endpoint: Process Conversation
🎯 Testing endpoint: Retry Conversation
🎯 Testing endpoint: Upsert Session

✅ Assessment completed:
   Tests run: 49
   Vulnerabilities found: 3
   Security score: 93.9%

🎉 ARTEMIS Assessment Complete!
📊 Security Score: 93.9%
🎯 Tests Run: 49
⚠️  Vulnerabilities: 3
📋 Report: reports/artemis_security_report_007f6a10.json
```

## 🐳 Docker Usage

### Quick Test
```bash
# Health check
docker run --rm artemis-enterprise:latest --health-check

# Basic test
docker run --rm artemis-enterprise:latest \
  --target https://httpbin.org/json --mode quick
```

### Production Usage
```bash
# With mounted volumes
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/collections:/app/collections \
  artemis-enterprise:latest \
  --postman /app/collections/api.json \
  --mode comprehensive
```

### Interactive Mode
```bash
# Start interactive shell
docker run -it --rm artemis-enterprise:latest bash

# Inside container
python3 artemis.py --target https://api.example.com
```

## 🔧 Configuration

Create a `config.yaml` file:

```yaml
# ARTEMIS Enterprise Configuration
log_level: INFO
max_concurrent_tests: 10
request_timeout: 30

# Output formats
output_formats:
  - json
  - html
  - pdf

# Compliance frameworks
compliance_frameworks:
  - hipaa
  - gdpr

# Attack categories
attack_categories:
  - LLM01_Prompt_Injection
  - LLM06_Sensitive_Information_Disclosure
  - LLM07_Insecure_Plugin_Design
  - HIPAA_Compliance

# Healthcare focus
healthcare_focus: true
```

## 🏥 HIPAA Compliance Testing

ARTEMIS Enterprise provides specialized HIPAA compliance testing:

### What We Test
- **PHI Access Controls** - Validates patient data protection
- **Emergency Override** - Tests emergency access mechanisms
- **Healthcare Professional Verification** - Validates role-based access
- **Audit Logging** - Ensures compliance with audit requirements

### Sample HIPAA Test
```bash
python3 artemis.py \
  --postman healthcare-api.json \
  --mode comprehensive \
  --config config/hipaa-strict.yaml \
  --output reports/hipaa-compliance
```

## 🛡️ Security Architecture

ARTEMIS Enterprise uses a multi-layered security testing approach:

1. **Endpoint Discovery** - Automatic API endpoint identification
2. **Attack Vector Selection** - Context-aware attack selection
3. **Payload Generation** - Intelligent payload creation and mutation
4. **Response Analysis** - Advanced vulnerability detection
5. **Compliance Validation** - Regulatory compliance checking
6. **Report Generation** - Professional security reporting

## 🔍 Troubleshooting

### Common Issues

**1. Dependencies not found:**
```bash
pip install -r requirements.txt
```

**2. Permission errors (Docker):**
```bash
chmod +x artemis.py entrypoint.sh
```

**3. Network timeouts:**
```bash
# Use longer timeout
python3 artemis.py --config config/extended-timeout.yaml
```

**4. Memory issues:**
```bash
# Use quick mode
python3 artemis.py --mode quick
```

### Debug Mode
```bash
# Enable verbose output
python3 artemis.py --verbose --target https://api.example.com
```

## 📊 Report Formats

ARTEMIS generates multiple report formats:

- **JSON** - Machine-readable results for CI/CD integration
- **HTML** - Web-viewable reports with interactive elements
- **PDF** - Professional reports for executive presentation
- **CSV** - Spreadsheet-compatible vulnerability lists

## 🤝 Contributing

We welcome contributions! To contribute:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🚨 Important Notes

- **Authorized Testing Only** - Only test systems you own or have permission to test
- **Healthcare Data** - Follow all applicable healthcare data protection laws
- **Responsible Disclosure** - Report vulnerabilities responsibly
- **Legal Compliance** - Ensure compliance with local laws and regulations

## 🆘 Support & Documentation

- **Issues**: Report bugs and request features via GitHub Issues
- **Documentation**: Detailed guides available in the `docs/` directory
- **Examples**: Sample configurations and usage in `examples/` directory

---

**🏹 ARTEMIS Enterprise - Securing AI-powered applications**

*Professional LLM security testing for the enterprise*