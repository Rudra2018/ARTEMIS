# 🤖 AI Chatbot Testing Suite

An advanced, professional-grade testing framework for LLM AI chatbots with **1000+ test cases**, **adaptive learning engine**, and comprehensive security evaluation. Features modern web interface, real-time monitoring, multi-framework security testing, and intelligent learning capabilities.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-Educational-green.svg)
![Framework](https://img.shields.io/badge/Framework-Flask-red.svg)
![Tests](https://img.shields.io/badge/Tests-1000+-brightgreen.svg)
![Security](https://img.shields.io/badge/Security-Multi_Framework-red.svg)
![AI](https://img.shields.io/badge/AI-Adaptive_Learning-purple.svg)

## 🌟 Features

### 🧠 **Adaptive Learning Engine** ⭐ *NEW*
- **Pattern Recognition**: Analyzes attack vectors and response patterns using ML techniques
- **Dynamic Test Generation**: Creates new test cases based on discovered vulnerabilities
- **ML-based Prediction**: Predicts vulnerability likelihood using intelligent classifiers
- **Feedback Optimization**: Continuously improves testing strategies based on results
- **Persistent Learning**: SQLite database stores learning insights across sessions

### 🎯 **Comprehensive Security Testing**
- **1000+ Test Cases** across multiple security frameworks and attack methodologies
- **Core Security Framework** (120+ tests): SEI & OpenAI, WDTA L1-L4, CyberSecEval 2, Purple Llama, Garak, OWASP LLM Top 10
- **Research Security Framework** (100+ tests): Advanced prompt injection, data poisoning, privacy bias analysis
- **Comprehensive Security Framework** (800+ tests): Adversarial attacks, multi-modal security, edge cases, stress testing
- **Multi-Provider Support**: OpenAI, Claude, Google AI Studio, Meta AI, Hugging Face, Cohere, Azure OpenAI

### 🌐 **Modern Web Interface**
- **Real-time Dashboard** with adaptive learning metrics and live progress monitoring
- **Comprehensive Testing Page** with 1000+ test suite configuration
- **Interactive Test Execution** with WebSocket updates and detailed progress tracking
- **Visual Analytics** with security metrics, learning insights, and vulnerability reports
- **Professional Reports** (JSON, HTML, JUnit XML) with learning summaries

### 🔒 **Security & Safety**
- **Mock Mode** for safe testing without API costs or external dependencies
- **Secure API key management** with environment variable support
- **Rate limit compliance** and intelligent request throttling
- **Content filtering validation** and safety measure testing
- **Information leakage prevention** and data privacy protection

## 🚀 Quick Start

### 1. **Install Dependencies**
```bash
git clone <repository-url>
cd ai-chatbot-testing-suite
pip install -r requirements.txt
```

### 2. **Launch Web Interface**
```bash
# Easy one-command launch
python launch_ui.py

# Or manually
python web_app.py
```

### 3. **Access the Interface**
Open your browser to: **http://localhost:5000**

### 4. **Run Your First Comprehensive Test** ⭐ *Recommended*
1. Go to **"Comprehensive"** in the navigation
2. Select desired test suites (default: 650+ tests)
3. Enable **"Adaptive Learning Engine"** for intelligent testing
4. Click **"Start Comprehensive Testing"** and monitor real-time progress!

### 5. **Run Basic Tests**
1. Go to **"Basic Tests"**  
2. Select **"Advanced Security Tests"** for standard evaluation
3. Choose **"Mock Mode"** (no API keys needed)
4. Click **"Run Tests"** and watch progress!

### 6. **Command Line Interface**
```bash
# Run all 1000+ comprehensive security tests with adaptive learning
python run_comprehensive_tests.py --all

# Run specific test suites with learning disabled
python run_comprehensive_tests.py --suites adversarial_attacks,edge_case_boundary --no-learning

# Run with custom model and save results
python run_comprehensive_tests.py --model gpt-4 --output security_results.json

# Quick test with reduced output
python run_comprehensive_tests.py --suites adversarial_attacks --quiet

# List available test suites
python run_comprehensive_tests.py --list-suites
```

## 📁 Project Structure

```
ai-chatbot-testing-suite/
├── 🌐 Web Interface
│   ├── web_app.py              # Main Flask application with WebSocket
│   ├── launch_ui.py            # Easy launcher with auto-setup
│   └── templates/              # HTML templates
│       ├── dashboard.html      # Main dashboard with adaptive learning metrics
│       ├── comprehensive.html  # ⭐ Comprehensive testing with 1000+ tests
│       ├── test.html          # Basic test execution interface
│       ├── results.html       # Analytics and reporting
│       ├── config.html        # API configuration management
│       ├── docs.html          # Built-in documentation
│       └── base.html          # Base template
├── 🧪 Core Testing Framework
│   ├── ai_chatbot_test_suite.py   # Main test suites (200+ tests)
│   ├── api_integration_tests.py   # API integration tests
│   ├── security_evaluation_framework.py  # Advanced security testing (120+ tests)
│   ├── llm_security_research_framework.py # Research-based security tests (100+ tests)
│   ├── comprehensive_security_test_suite.py # Comprehensive testing (800+ tests)
│   ├── adaptive_learning_engine.py # ⭐ Adaptive learning engine with ML capabilities
│   ├── config.py                  # Configuration management
│   ├── run_tests.py               # Command-line test runner
│   └── run_comprehensive_tests.py # Comprehensive security test runner with learning
├── 🎨 Frontend Assets
│   └── static/
│       └── css/
│           └── style.css       # Modern responsive styles
├── 📋 Configuration
│   ├── requirements.txt        # All dependencies
│   └── README.md              # This documentation
└── 📊 Generated Content
    └── test_results/          # Test reports and analytics
```

## 🔌 Supported AI Providers

| Provider | Models | Features | Rate Limit |
|----------|---------|----------|------------|
| **OpenAI** | GPT-3.5, GPT-4, DALL-E | Chat, Images, Embeddings, Fine-tuning | 3,500 RPM |
| **Claude** | Claude 3 Haiku/Sonnet/Opus | Long context, Vision, Streaming | 100 RPM |
| **Google AI Studio** | Gemini Pro/Vision | Multimodal, Safety settings | 60 RPM |
| **Hugging Face** | Various open models | Text generation, Classification | 1,000 RPM |
| **Cohere** | Command models | Generate, Embed, Classify | 100 RPM |
| **Azure OpenAI** | GPT models | Enterprise features | 240 RPM |

## 🧪 Test Suites

### **Core LLM Tests** (`LLMChatbotCoreTests`)
- ✅ Basic conversation functionality
- ✅ Context maintenance across turns
- ✅ Multilingual support (French, Spanish, Japanese, etc.)
- ✅ Instruction following accuracy
- ✅ Knowledge cutoff handling
- ✅ Conversation coherence validation

### **ML Model Tests** (`MLModelTests`)
- ✅ Model accuracy evaluation
- ✅ Response consistency testing
- ✅ Bias detection and analysis
- ✅ Hallucination detection
- ✅ Safety alignment verification

### **API Integration Tests** (`APIIntegrationTests`)
- ✅ **OpenAI**: Chat completions, embeddings, images, fine-tuning
- ✅ **Claude**: Messages API, streaming, vision, long context
- ✅ **Google AI Studio**: Content generation, vision, safety settings
- ✅ **Hugging Face**: Text generation, classification, Q&A
- ✅ **Cross-platform**: Response consistency, capability comparison

### **Advanced Security & Safety Tests** (`SecurityEvaluationFramework`)

#### **Research-Based Security Frameworks**
- 🛡️ **SEI & OpenAI Evaluation**: Realistic task-based security testing methodology
- 🛡️ **WDTA Security Method**: L1-L4 attack categorization framework
- 🛡️ **CyberSecEval 2**: Comprehensive cybersecurity knowledge assessment  
- 🛡️ **Purple Llama CyberSecEval**: Secure coding and vulnerability detection tests
- 🛡️ **Garak-inspired Scanner**: LLM vulnerability probing system
- 🛡️ **OWASP LLM Top 10**: Industry-standard LLM security risk testing
- 🛡️ **Automated Penetration Testing**: Systematic security vulnerability assessment

#### **Security Test Coverage (120+ Tests)**
- **L1-L4 Attack Categories**: From basic prompt injection to sophisticated attacks
- **Prompt Injection Detection**: Multi-layer instruction manipulation resistance
- **Jailbreak Resistance**: Advanced bypass attempt detection and prevention
- **Adversarial Input Handling**: Encoding attacks, glitch tokens, continuation probes
- **Code Security Analysis**: Vulnerability detection in generated code
- **Social Engineering Resistance**: Human manipulation attempt detection
- **Information Disclosure Prevention**: System prompt extraction, sensitive data protection
- **Authentication & Session Security**: Access control and session management testing
- **Input Validation Testing**: Data sanitization and validation verification

#### **Security Metrics & Reporting**
- **Overall Security Score**: Comprehensive 0-100 security rating
- **Framework-Specific Scores**: Detailed scoring per security methodology
- **Vulnerability Detection**: Automated security issue identification
- **Risk Assessment**: Categorized severity levels (LOW/MEDIUM/HIGH/CRITICAL)
- **Mitigation Recommendations**: Actionable security improvement advice

#### **🔬 Research-Based Security Testing** (`LLMSecurityResearchFramework`)
*Based on "LLM Security: Vulnerabilities, Attacks, Defenses, and Countermeasures" by Aguilera-Martínez & Berzal (arXiv, March 2024)*

**Advanced Vulnerability Testing (100+ Additional Tests)**
- **Prompt Injection Vulnerabilities**: Direct/indirect injection, context manipulation, multi-turn attacks, template injection
- **Data Poisoning Detection**: Training data poisoning simulation, backdoor trigger detection, bias injection attempts
- **Model Extraction Attacks**: Parameter probing, weight extraction, architecture information disclosure
- **Privacy Leakage Testing**: Personal information extraction, PII reconstruction, conversation leakage
- **Membership Inference Attacks**: Training data membership detection, statistical inference testing
- **Property Inference Attacks**: Training data composition analysis, model capability extraction
- **Bias Amplification Analysis**: Gender, racial, socioeconomic, and age bias detection
- **Responsible AI Practices**: Transparency, accountability, fairness, and explainability evaluation

**Research-Based Security Metrics**
- **Attack Success Rate**: Percentage of successful security attacks
- **Defense Effectiveness**: 0-100 rating of defensive capabilities  
- **Responsible Practices Score**: Ethical AI implementation assessment
- **Vulnerability Breakdown**: Classification by research-defined categories
- **Attack Vector Analysis**: Success rates by attack methodology

#### **🚀 Comprehensive Attack Testing Suite** (`ComprehensiveSecurityTestSuite`)
*1000+ Advanced Security Test Cases Across Multiple Attack Vectors*

**Advanced Adversarial Attacks (200+ Tests)**
- **Semantic Adversarial**: Synonym substitution, metaphorical attacks, emotional manipulation, authority implication
- **Syntactic Manipulation**: Punctuation attacks, character spacing, symbol substitution, homoglyph attacks  
- **Unicode Exploitation**: Right-to-left override, bidirectional text, zero-width characters, combining characters
- **Encoding Manipulation**: Base64, URL, HTML, ROT13, Caesar cipher, hexadecimal, ASCII, binary, Morse code
- **Steganographic Attacks**: Acrostic patterns, word positioning, case patterns, semantic layers, metaphorical hiding
- **Contextual Manipulation**: Multi-turn conversation attacks, context window pollution, persona drift attacks
- **Cross-Linguistic Attacks**: Multi-language bypass, code-switching, transliteration, false language detection
- **Temporal Manipulation**: Time-based attacks, delayed execution, chronological pattern exploitation

**Multi-Modal Security Testing (150+ Tests)**  
- **Image-Based Attacks**: Metadata injection, steganographic text, QR code injection, adversarial OCR
- **Audio-Based Attacks**: Hidden frequency attacks, speech synthesis bypass, audio steganography
- **Video-Based Attacks**: Frame injection, deepfake detection bypass, temporal steganography
- **Mixed Media Attacks**: Cross-modal injection, format confusion, multi-channel attacks
- **File Upload Security**: Malicious file detection, format validation bypass, content type spoofing
- **OCR Manipulation**: Character recognition bypass, font-based attacks, layout exploitation

**Edge Case & Boundary Testing (200+ Tests)**
- **Input Length Boundaries**: Empty input, minimal input, maximum length, memory exhaustion attacks
- **Character Set Boundaries**: Null bytes, high ASCII, emoji floods, mathematical Unicode, Zalgo text
- **Rate Limit Testing**: Rapid request attacks, distributed load testing, quota bypass attempts  
- **Memory Exhaustion**: Resource consumption attacks, buffer overflow simulation, memory leak testing
- **Parser Breaking**: Malformed input handling, syntax error exploitation, format confusion
- **Error Handling**: Information disclosure through errors, exception manipulation, debug mode exploitation
- **Timeout Manipulation**: Response delay attacks, connection timeout exploitation, async attack patterns
- **Concurrent Requests**: Race condition testing, simultaneous attack coordination, thread safety validation

**Large-Scale Stress Testing (150+ Tests)**
- **Volume-Based Attacks**: High-frequency request flooding, batch processing abuse, throughput exhaustion
- **Distributed Attack Simulation**: Multi-source coordinated attacks, botnet simulation, geographic distribution
- **Resource Exhaustion**: CPU intensive attacks, memory consumption, disk space attacks, network saturation
- **Pattern Flooding**: Repetitive pattern attacks, algorithmic complexity exploitation, cache poisoning
- **Session Abuse**: Session hijacking, concurrent session attacks, session fixation, timeout exploitation
- **API Abuse Simulation**: Endpoint flooding, parameter manipulation, rate limit circumvention

**International & Multilingual Security (100+ Tests)**
- **RTL Language Attacks**: Arabic/Hebrew text manipulation, bidirectional override, script mixing
- **Ideographic Attacks**: Chinese/Japanese character exploitation, Unicode block mixing, font confusion
- **Cultural Context Attacks**: Culture-specific social engineering, regional dialect exploitation
- **Translation Bypass**: Machine translation manipulation, language detection bypass, encoding confusion

**API & Integration Security (100+ Tests)**  
- **Endpoint Security**: API route manipulation, method spoofing, parameter injection
- **Authentication Attacks**: Token manipulation, session replay, credential stuffing, OAuth bypass
- **Data Validation**: Input sanitization bypass, type confusion, schema validation attacks
- **Integration Bypass**: Service mesh attacks, microservice exploitation, inter-service communication abuse

**Real-World Attack Scenarios (100+ Tests)**
- **Social Engineering**: Phishing simulation, authority manipulation, trust exploitation, urgency tactics
- **Corporate Espionage**: Information gathering, competitive intelligence, trade secret extraction
- **Identity Theft**: Personal information extraction, credential harvesting, profile reconstruction  
- **Misinformation**: False information injection, narrative manipulation, fact distortion, propaganda tactics

### **Performance Tests** (`PerformanceScalabilityTests`)
- ⚡ Response time benchmarks
- ⚡ Throughput capacity testing
- ⚡ Memory usage stability
- ⚡ Cache efficiency validation
- ⚡ Concurrent request handling
- ⚡ Load balancing effectiveness

### **Edge Case Tests** (`EdgeCaseRobustnessTests`)
- 🔍 Empty and malformed input handling
- 🔍 Unicode and special character support
- 🔍 Extremely long input processing
- 🔍 Network interruption recovery
- 🔍 Concurrent conversation management

## ⚙️ Configuration

### **API Keys Setup**

**Option 1: Environment Variables (Recommended)**
```bash
export OPENAI_API_KEY="your-openai-key"
export CLAUDE_API_KEY="your-claude-key"
export GOOGLE_AI_STUDIO_API_KEY="your-google-key"
export HUGGINGFACE_API_KEY="your-hf-key"
export COHERE_API_KEY="your-cohere-key"
```

**Option 2: Web Interface**
1. Go to **Configuration** page
2. Enter API keys in the tabbed interface
3. Test connections individually
4. Save configuration

**Option 3: Configuration File**
```json
{
  "api_configs": {
    "openai": {
      "api_key": "your-openai-key",
      "model": "gpt-3.5-turbo"
    }
  }
}
```

### **Test Configuration**
- **Timeout**: Maximum test duration (default: 300s)
- **Max Retries**: API request retry attempts (default: 3)
- **Rate Limits**: Per-provider request limits
- **Mock Mode**: Use mock responses (no API costs)
- **Live Mode**: Test against real APIs

## 🎮 Usage Examples

### **Example 1: Security Audit**
```bash
# Command line
python run_tests.py --suite security --mock --verbose

# Or via web interface:
# 1. Go to Run Tests → Select "Security Tests"
# 2. Choose Mock Mode → Click "Run Tests"
# 3. Monitor real-time progress → Review results
```

### **Example 2: API Performance Benchmark**
```bash
# Test all configured providers
python run_tests.py --suite performance --live --providers openai claude google

# Web interface:
# 1. Configure multiple providers
# 2. Run "Performance Tests" with all providers
# 3. Compare results in analytics dashboard
```

### **Example 3: Comprehensive Testing**
```bash
# Full test suite with reporting
python run_tests.py --suite all --mock --report-format html --output-dir reports

# Web interface provides this automatically with visual progress
```

## 📊 Web Interface Guide

### **Dashboard** (`/`)
- **System Overview**: Provider status, test metrics
- **Quick Actions**: Run common test suites
- **Recent Results**: Latest test history
- **Real-time Charts**: Success rates, performance trends

### **Run Tests** (`/test`)
- **Interactive Selection**: Choose test suites visually
- **Provider Configuration**: Select which APIs to test
- **Real-time Monitoring**: Live progress with WebSocket updates
- **Execution Modes**: Mock (safe) vs Live (real API) testing

### **Results** (`/results`)
- **Visual Analytics**: Charts, graphs, trend analysis  
- **Filtering**: Search and filter test history
- **Export Options**: JSON, HTML, JUnit XML formats
- **Performance Insights**: Response times, success rates

### **Configuration** (`/config`)
- **API Management**: Secure key storage and validation
- **Connection Testing**: Test individual provider connections
- **Settings**: Rate limits, timeouts, test parameters
- **Validation**: Built-in configuration checker

### **Documentation** (`/docs`)
- **User Guide**: Complete usage instructions
- **API Reference**: Technical documentation
- **Troubleshooting**: Common issues and solutions
- **Examples**: Real-world usage scenarios

## 🔒 Security Features

### **API Key Security**
- Environment variable support
- Secure web form handling
- No keys stored in logs
- Connection validation

### **Testing Security**
- Mock mode prevents accidental API charges
- Rate limit compliance
- Request timeout protection
- Error handling and recovery

### **Content Safety**
- Prompt injection detection
- Jailbreak attempt identification  
- Content filtering validation
- Safety constraint testing

## 📈 Reporting & Analytics

### **Export Formats**
- **JSON**: Raw data for programmatic analysis
- **HTML**: Beautiful visual reports with charts
- **JUnit XML**: CI/CD pipeline integration
- **CSV**: Spreadsheet-compatible data

### **Visual Analytics**
- **Pie Charts**: Test status distribution
- **Line Graphs**: Success rate trends over time
- **Bar Charts**: Provider performance comparison
- **Progress Bars**: Real-time execution status

### **Metrics Tracked**
- Success/failure rates by provider and test type
- Response times and throughput measurements
- Error rates and types
- Resource utilization
- Test execution duration

## 🛠 Command Line Usage

### **Basic Commands**
```bash
# Run all tests in mock mode
python run_tests.py --suite all --mock

# Run security tests with live APIs  
python run_tests.py --suite security --live

# Generate HTML report
python run_tests.py --suite core --mock --report-format html

# Test specific providers
python run_tests.py --suite api --providers openai claude --live
```

### **Advanced Options**
```bash
# Custom timeout and retries
python run_tests.py --timeout 600 --max-retries 5

# Parallel execution
python run_tests.py --parallel 4

# Specific output directory
python run_tests.py --output-dir custom_reports

# Quiet mode for automation
python run_tests.py --quiet --report-format junit
```

## 🚨 Troubleshooting

### **Common Issues**

**🚫 Import Errors**
```bash
# Solution: Install all dependencies
pip install -r requirements.txt
```

**🚫 Port Already in Use**
```bash
# Solution: The launcher automatically finds an available port
python launch_ui.py
```

**🚫 API Connection Failures**
- Verify API keys in Configuration page
- Test individual connections
- Check rate limits and quotas
- Try Mock Mode first

**🚫 Tests Stuck in Running State**
- Cancel and restart the test
- Check system resources
- Review timeout settings
- Restart the application

### **Performance Tips**
- Use Mock Mode for development
- Configure appropriate timeouts
- Monitor system resources  
- Limit concurrent tests appropriately

## 🎯 Best Practices

### **Development Workflow**
1. **Start with Mock Mode** to understand the system
2. **Configure one provider** at a time
3. **Test individual suites** before running all tests
4. **Monitor resource usage** during execution
5. **Export and analyze** results regularly

### **Production Usage**  
1. **Set up proper API keys** with appropriate permissions
2. **Configure rate limits** to avoid hitting quotas
3. **Schedule regular tests** for continuous monitoring
4. **Set up automated reporting** for stakeholders
5. **Monitor success rates** and investigate failures

## 🔄 CI/CD Integration

### **GitHub Actions Example**
```yaml
name: AI Chatbot Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.8'
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run tests
        run: python run_tests.py --suite all --mock --report-format junit
      - name: Publish results
        uses: dorny/test-reporter@v1
        with:
          name: AI Test Results
          path: test_results/*.xml
          reporter: java-junit
```

## 📚 Research References

This testing suite incorporates cutting-edge security research and methodologies:

### **Core Security Frameworks**
- **SEI & OpenAI (2024)**: "Realistic task-based LLM security evaluation"
- **WDTA Security Method**: L1-L4 attack categorization framework
- **CyberSecEval 2**: Meta's cybersecurity evaluation benchmark
- **Purple Llama**: Meta's responsible AI safety toolkit
- **Garak**: LLM vulnerability scanner methodology
- **OWASP LLM Top 10**: Industry-standard LLM security risks

### **Research-Based Testing**
- **Aguilera-Martínez, F. & Berzal, F. (2024)**: *"LLM Security: Vulnerabilities, Attacks, Defenses, and Countermeasures"*, arXiv preprint
- **Comprehensive vulnerability taxonomy** covering prompt injection, data poisoning, privacy leakage
- **Advanced attack methodologies** including membership inference and model extraction
- **Responsible AI practices** evaluation framework
- **Defense effectiveness** assessment methodology

### **Academic Contributions**
The testing suite serves as a practical implementation of academic security research, bridging the gap between theoretical security analysis and real-world LLM evaluation. Test results can support security research and responsible AI development.

## 📋 Requirements

### **System Requirements**
- **Python 3.8+** (tested with 3.8-3.11)
- **Modern web browser** (Chrome, Firefox, Safari, Edge)
- **2GB+ RAM** for comprehensive testing
- **Internet connection** for live API testing

### **Dependencies**
All dependencies are specified in `requirements.txt`:
- **Flask + SocketIO**: Web interface and real-time updates
- **AI Libraries**: OpenAI, Anthropic, Google AI, etc.
- **Testing**: Pytest, unittest, mocking utilities
- **Data Analysis**: NumPy, Pandas, Scikit-learn
- **Security**: Cryptography, JWT handling
- **Utilities**: Configuration, logging, reporting

## 📄 License

This project is provided for educational and development purposes. Please respect API terms of service when testing with live endpoints.

## 🤝 Contributing

Contributions are welcome! This project uses:
- **Backend**: Flask + Socket.IO for real-time web interface
- **Frontend**: Bootstrap 5 + Chart.js for modern UI
- **Testing**: Pytest + unittest for comprehensive test coverage
- **Documentation**: Inline docs + web interface guide

## 🆘 Support

### **Getting Help**
1. **Built-in Documentation**: Visit `/docs` in the web interface
2. **Configuration Validator**: Use the validation tool in Configuration page
3. **Mock Mode Testing**: Test functionality without API dependencies  
4. **Error Logs**: Check browser console and server logs

### **Feature Requests**
This is an educational project showcasing comprehensive AI testing capabilities. The framework is designed to be extensible for additional providers and test types.

---

## 🚀 Get Started Now!

```bash
# Clone, install, and launch in one go:
git clone <repository-url>
cd ai-chatbot-testing-suite  
pip install -r requirements.txt
python launch_ui.py

# Then open http://localhost:5000 and start testing! 🎉
```

**Ready to test your AI chatbots like a pro?** This comprehensive suite provides everything you need for professional-grade AI testing with a modern, user-friendly interface.