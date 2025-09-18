# 🤖 Modular AI Security Agents

Independent microservices for specialized AI security testing with FastAPI REST APIs and comprehensive documentation.

## 🏗️ Architecture Overview

```
security_modules/agents/
├── ai_fuzzing_agent/           # Intelligent Fuzzing & Vulnerability Detection
├── threat_modeling_agent/      # STRIDE-based Threat Analysis
├── compliance_agent/           # Regulatory Compliance Assessment
├── sca_agent/                  # Software Composition Analysis
├── enhanced_orchestrator.py    # Agent Coordination & Risk Synthesis
└── agent_coordinator.py        # Task Distribution & Result Aggregation
```

## 🎯 AI Fuzzing Agent (Port 8001)

**Location**: `ai_fuzzing_agent/`

### **Core Capabilities**
- **Semantic Fuzzing** - Transformer-based intelligent payload generation
- **Multi-Strategy Testing** - 7 different fuzzing approaches
- **Real-time Detection** - Vulnerability classification and severity assessment
- **Async Processing** - High-performance concurrent testing

### **Fuzzing Strategies**
1. **Semantic** - AI-driven meaningful mutations
2. **Random** - Entropy-based payload generation
3. **Mutation** - Systematic input modifications
4. **Grammar-based** - Structured input generation
5. **Adversarial** - Attack pattern injection
6. **Boundary** - Edge case and limit testing
7. **Coverage-guided** - Code coverage optimization

### **API Endpoints**
- `POST /fuzz` - Execute fuzzing operation
- `GET /status/{session_id}` - Get fuzzing status
- `GET /strategies` - List available strategies
- `GET /report/{session_id}` - Get detailed results

### **Usage Example**
```bash
curl -X POST "http://localhost:8001/fuzz" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://api.example.com/chat",
    "strategy": "semantic",
    "max_iterations": 100,
    "base_input": "Hello, how can you help me?"
  }'
```

## 🔍 Threat Modeling Agent (Port 8002)

**Location**: `threat_modeling_agent/`

### **Core Capabilities**
- **STRIDE Analysis** - Comprehensive threat categorization
- **Attack Path Discovery** - Graph neural networks for multi-step attacks
- **Asset Analysis** - System component and data flow mapping
- **Risk Assessment** - Automated threat prioritization

### **STRIDE Categories**
- **Spoofing** - Identity impersonation threats
- **Tampering** - Data and code modification attacks
- **Repudiation** - Non-accountability issues
- **Information Disclosure** - Unauthorized data exposure
- **Denial of Service** - Availability disruption
- **Elevation of Privilege** - Unauthorized access escalation

### **API Endpoints**
- `POST /model` - Create threat model
- `GET /status/{session_id}` - Get modeling status
- `GET /methodologies` - List supported methodologies
- `GET /categories` - List threat categories

### **Usage Example**
```bash
curl -X POST "http://localhost:8002/model" \
  -H "Content-Type: application/json" \
  -d '{
    "system_name": "AI Chat Platform",
    "architecture": {
      "components": [
        {
          "name": "API Gateway",
          "type": "api_gateway",
          "internet_facing": true,
          "trust_level": 7
        }
      ]
    }
  }'
```

## 📋 Compliance Agent (Port 8003)

**Location**: `compliance_agent/`

### **Core Capabilities**
- **Multi-Framework Support** - GDPR, PCI-DSS, HIPAA, SOX, ISO 27001/27002
- **AI-Powered Analysis** - Intelligent policy interpretation
- **Gap Assessment** - Automated compliance gap identification
- **Remediation Planning** - Actionable improvement recommendations

### **Supported Frameworks**
- **GDPR** - General Data Protection Regulation
- **PCI-DSS** - Payment Card Industry Data Security Standard
- **HIPAA** - Health Insurance Portability and Accountability Act
- **SOX** - Sarbanes-Oxley Act
- **ISO 27001/27002** - Information Security Management Systems
- **SOC 2** - Service Organization Control 2

### **API Endpoints**
- `POST /assess` - Perform compliance assessment
- `GET /frameworks` - List supported frameworks
- `GET /report/{session_id}` - Get compliance report
- `GET /categories` - List control categories

### **Usage Example**
```bash
curl -X POST "http://localhost:8003/assess" \
  -H "Content-Type: application/json" \
  -d '{
    "frameworks": ["gdpr", "pci_dss"],
    "system_configuration": {
      "organization": "TechCorp",
      "data_types": ["personal_data", "payment_data"]
    }
  }'
```

## 🔍 Software Composition Analysis Agent (Port 8004)

**Location**: `sca_agent/`

### **Core Capabilities**
- **Multi-Package Manager Support** - npm, pip, maven, gradle, composer, go
- **CVE Detection** - Real-time vulnerability database integration
- **SBOM Generation** - CycloneDX and SPDX format support
- **License Analysis** - Automated compliance and risk assessment

### **Package Managers**
- **npm** - Node.js package manager
- **pip** - Python package installer
- **maven** - Java dependency management
- **gradle** - Build automation tool
- **composer** - PHP dependency manager
- **go** - Go module system

### **API Endpoints**
- `POST /scan` - Execute SCA scan
- `GET /sbom/{scan_id}` - Get Software Bill of Materials
- `GET /vulnerabilities/{component}` - Get component vulnerabilities
- `GET /package-managers` - List supported managers

### **Usage Example**
```bash
curl -X POST "http://localhost:8004/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "project_path": "/path/to/project",
    "project_name": "MyApp",
    "configuration": {
      "package_managers": ["npm", "pip"],
      "generate_sbom": true
    }
  }'
```

## 🎯 Enhanced Orchestrator

**Location**: `enhanced_orchestrator.py`

### **Core Capabilities**
- **Smart Task Distribution** - AI-driven workload optimization
- **Risk Synthesis** - Cross-agent result correlation
- **Parallel Execution** - Concurrent multi-agent operations
- **Resource Management** - Dynamic scaling and load balancing

### **Orchestration Strategies**
- **Sequential** - Step-by-step execution
- **Parallel** - Concurrent agent execution
- **Adaptive** - Dynamic strategy selection
- **Risk-based** - Priority-driven scheduling

## 🚀 Getting Started

### **Prerequisites**
```bash
pip install fastapi uvicorn pydantic networkx numpy asyncio
```

### **Start All Agents**
```bash
# Terminal 1: AI Fuzzing Agent
cd security_modules/agents/ai_fuzzing_agent && python api.py

# Terminal 2: Threat Modeling Agent
cd security_modules/agents/threat_modeling_agent && python api.py

# Terminal 3: Compliance Agent
cd security_modules/agents/compliance_agent && python api.py

# Terminal 4: SCA Agent
cd security_modules/agents/sca_agent && python api.py
```

### **API Documentation**
Each agent provides interactive API documentation:
- http://localhost:8001/docs (AI Fuzzing)
- http://localhost:8002/docs (Threat Modeling)
- http://localhost:8003/docs (Compliance)
- http://localhost:8004/docs (SCA)

## 🔧 Configuration

### **Agent Configuration**
Each agent can be configured via environment variables or config files:

```python
# Example configuration
config = {
    "max_concurrent_requests": 10,
    "timeout": 30,
    "log_level": "INFO",
    "database_url": "sqlite:///security.db"
}
```

### **Orchestrator Configuration**
```python
orchestrator_config = {
    "strategy": "adaptive",
    "max_agents": 4,
    "risk_threshold": 7.0,
    "parallel_execution": True
}
```

## 📊 Integration Examples

### **Python SDK Integration**
```python
import asyncio
import aiohttp

async def run_security_assessment():
    # Start fuzzing
    fuzzing_response = await call_agent_api(
        "http://localhost:8001/fuzz",
        {"target_url": "https://api.example.com", "strategy": "semantic"}
    )

    # Start threat modeling
    threat_response = await call_agent_api(
        "http://localhost:8002/model",
        {"system_name": "Chat API", "architecture": {...}}
    )

    # Aggregate results
    return {
        "fuzzing": fuzzing_response,
        "threats": threat_response
    }
```

### **CI/CD Pipeline Integration**
```yaml
# GitHub Actions example
- name: Security Assessment
  run: |
    python -m security_modules.agents.orchestrator \
      --targets api.example.com \
      --agents fuzzing,threat_modeling,compliance \
      --output security-report.json
```

## 🛡️ Security Considerations

### **Authentication**
- API key authentication recommended for production
- Rate limiting to prevent abuse
- Request/response validation

### **Network Security**
- TLS/SSL encryption for agent communication
- Network segmentation for sensitive operations
- Firewall rules for port access

### **Data Protection**
- Sensitive data encryption at rest
- Secure session management
- Audit logging for all operations

## 📈 Performance & Scaling

### **Performance Metrics**
- **Throughput**: 1000+ requests/minute per agent
- **Latency**: <500ms average response time
- **Concurrency**: 100+ simultaneous operations
- **Resource Usage**: <2GB RAM per agent

### **Scaling Options**
- **Horizontal Scaling**: Multiple agent instances
- **Load Balancing**: nginx or HAProxy
- **Container Deployment**: Docker/Kubernetes
- **Cloud Deployment**: AWS/GCP/Azure

## 🔍 Monitoring & Observability

### **Metrics Collection**
- Request/response times
- Error rates and types
- Resource utilization
- Security findings statistics

### **Logging**
- Structured JSON logging
- Centralized log aggregation
- Security event correlation
- Audit trail maintenance

## 🤝 Contributing

### **Development Setup**
```bash
git clone <repository>
cd security_modules/agents
pip install -e .[dev]
pytest tests/
```

### **Adding New Agents**
1. Create agent directory structure
2. Implement core agent logic
3. Add FastAPI REST API
4. Write comprehensive tests
5. Update orchestrator integration

## 📄 License

MIT License - see LICENSE file for details.

---

**⚠️ Security Notice**: These agents are for authorized security testing only. Ensure proper authorization before testing any systems.