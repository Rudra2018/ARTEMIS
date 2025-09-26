# ARTEMIS v5.0 - Project Structure

## Core Directory Structure

### 📁 core_engines/
Main ARTEMIS orchestration and reporting engines:
- `artemis_comprehensive_orchestrator.py` - Main security assessment orchestrator
- `quantum_orchestrator.py` - Advanced quantum security orchestrator
- `quantum_pdf_generator.py` - Comprehensive PDF report generator

### 📁 security_engines/
Advanced security analysis modules:
- `advanced_compliance_engine.py` - HIPAA/GDPR compliance validation
- `adversarial_ml_engine.py` - Machine learning security testing
- `cognitive_security_engine.py` - Cognitive threat analysis
- `quantum_crypto_analyzer.py` - Quantum cryptography assessment
- `quantum_threat_modeling.py` - Advanced threat modeling
- `zero_day_prediction_engine.py` - Zero-day vulnerability prediction

### 📁 assessment_results/
Generated assessment data:
- `ARTEMIS_COMPREHENSIVE_ASSESSMENT_*.json` - Raw assessment results

### 📁 reports/
Generated security reports and documentation

### 📁 legacy_files/
Previous versions and test files for reference

## Key Features

- **Comprehensive Security Testing**: 6 advanced security modules
- **Real HTTP Testing**: Actual API endpoint validation
- **Dynamic Reference IDs**: Unique identifiers for each test
- **Compliance Validation**: HIPAA/GDPR automated checks
- **Quantum-Level Security**: Advanced cryptographic analysis
- **AI-Powered Threats**: Machine learning attack detection

## Usage

1. **Run Comprehensive Assessment**:
   ```bash
   python3 core_engines/artemis_comprehensive_orchestrator.py
   ```

2. **Generate PDF Report**:
   ```bash
   python3 core_engines/quantum_pdf_generator.py assessment_results/ARTEMIS_*.json
   ```

## Assessment Modules

1. **Threat Modeling** - System architecture analysis
2. **Adversarial ML** - AI/ML security validation
3. **Quantum Cryptography** - Advanced crypto analysis
4. **Zero-Day Prediction** - Vulnerability forecasting
5. **Compliance Assessment** - Regulatory validation
6. **Cognitive Security** - Behavioral threat analysis

## Report Outputs

- **JSON Results**: Complete raw assessment data
- **PDF Reports**: Executive and technical documentation
- **HTML Reports**: Interactive security dashboards

---
*ARTEMIS v5.0 - Advanced Threat Recognition & Evaluation for Mission-Critical Infrastructure Security*