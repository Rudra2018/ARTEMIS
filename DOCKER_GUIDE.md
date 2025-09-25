# 🐳 ARTEMIS NEXUS AI - Docker Deployment Guide

> **The Ultimate AI Security Testing Platform - Now Containerized!**

[![Docker](https://img.shields.io/badge/Docker-Supported-blue?logo=docker)](https://hub.docker.com/)
[![Container](https://img.shields.io/badge/Container-Ready-green)](https://kubernetes.io/)
[![Security](https://img.shields.io/badge/Security-Enterprise%20Grade-red)](https://owasp.org/)

## 🚀 Quick Start

### Option 1: Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-username/ai-chatbot-security-tester.git
cd ai-chatbot-security-tester

# Start ARTEMIS NEXUS AI platform
docker-compose up -d

# View logs
docker-compose logs -f artemis-nexus-ai

# Access interactive shell
docker-compose exec artemis-nexus-ai bash
```

### Option 2: Direct Docker Build

```bash
# Build the image
docker build -t artemis-nexus-ai:latest .

# Run comprehensive security test
docker run --rm -v $(pwd)/reports:/app/reports artemis-nexus-ai:latest \
  python3 tools/final_comprehensive_test.py https://target.example.com

# Run interactive mode
docker run -it --rm artemis-nexus-ai:latest bash
```

## 🎯 Usage Examples

### Basic Security Assessment

```bash
# Quick security scan
docker-compose exec artemis-nexus-ai python3 tools/artemis_nexus_ai_commander.py \
  https://target.example.com --mode rapid

# Comprehensive OWASP LLM Top 10 assessment
docker-compose exec artemis-nexus-ai python3 tools/final_comprehensive_test.py \
  https://llm.target.com
```

### Healthcare AI Security Testing

```bash
# HIPAA compliance testing
docker-compose exec artemis-nexus-ai python3 tools/comprehensive_artemis_testing.py \
  https://medical-ai.example.com --healthcare --hipaa-compliance

# Multi-language healthcare testing
docker-compose exec artemis-nexus-ai python3 tools/final_comprehensive_test.py \
  https://health-chat.example.com --languages all
```

### Enterprise Security Testing

```bash
# Zero False Positive enterprise assessment
docker-compose exec artemis-nexus-ai python3 tools/enterprise_zero_fp_commander.py \
  https://enterprise-ai.example.com --comprehensive --zero-fp

# Multi-platform testing
docker-compose exec artemis-nexus-ai python3 tools/nexus_ai_security_commander.py \
  --targets https://ai1.example.com,https://ai2.example.com
```

## 📁 Volume Mounts & Data Persistence

### Default Mounts
```yaml
volumes:
  - ./reports:/app/reports:rw      # Security reports output
  - ./logs:/app/logs:rw           # Application logs
  - ./ml_models:/app/ml_models:rw # ML models and learning data
  - ./configs:/app/configs:ro     # Configuration files (read-only)
```

### Custom Volume Configuration
```bash
# Custom report directory
docker run -v /path/to/custom/reports:/app/reports artemis-nexus-ai:latest

# Custom configuration
docker run -v /path/to/config.json:/app/configs/custom.json artemis-nexus-ai:latest
```

## 🔧 Configuration

### Environment Variables

```bash
# Set environment variables
docker-compose exec artemis-nexus-ai env ARTEMIS_MODE=production \
  LOG_LEVEL=DEBUG \
  python3 tools/artemis_nexus_ai_commander.py
```

### Available Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ARTEMIS_MODE` | `development` | Platform mode (development/production) |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG/INFO/WARNING/ERROR) |
| `PYTHONPATH` | `/app` | Python path for imports |
| `MAX_CONCURRENT_TESTS` | `10` | Maximum concurrent security tests |
| `ML_LEARNING_ENABLED` | `true` | Enable machine learning features |

### Custom Configuration Files

```bash
# Use custom configuration
docker-compose exec artemis-nexus-ai python3 tools/artemis_nexus_ai_commander.py \
  --config /app/configs/enterprise_config.json \
  https://target.example.com
```

## 🏗️ Advanced Deployment

### With Database (Advanced Profile)

```bash
# Start with database support
docker-compose --profile advanced up -d

# View database status
docker-compose exec artemis-database sqlite3 /var/lib/sqlite/artemis.db ".tables"
```

### With Web Dashboard (Dashboard Profile)

```bash
# Start with web dashboard
docker-compose --profile dashboard up -d

# Access dashboard at http://localhost:3000
```

### Kubernetes Deployment

```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: artemis-nexus-ai
spec:
  replicas: 3
  selector:
    matchLabels:
      app: artemis-nexus-ai
  template:
    metadata:
      labels:
        app: artemis-nexus-ai
    spec:
      containers:
      - name: artemis-nexus-ai
        image: artemis-nexus-ai:latest
        ports:
        - containerPort: 8080
        env:
        - name: ARTEMIS_MODE
          value: "production"
        volumeMounts:
        - name: reports
          mountPath: /app/reports
      volumes:
      - name: reports
        persistentVolumeClaim:
          claimName: artemis-reports-pvc
```

## 🧪 Testing & Validation

### Test Docker Image

```bash
# Run comprehensive tests
docker-compose exec artemis-nexus-ai python3 -m pytest tests/ -v

# Test specific modules
docker-compose exec artemis-nexus-ai python3 tests/test_artemis_core.py

# Performance testing
docker-compose exec artemis-nexus-ai python3 tests/performance_test.py
```

### Health Checks

```bash
# Check container health
docker-compose exec artemis-nexus-ai python3 -c "
import sys
from ai_tester_core.learning_engine import AdaptiveLearningEngine
try:
    engine = AdaptiveLearningEngine()
    print('✅ ARTEMIS NEXUS AI - Healthy')
    sys.exit(0)
except Exception as e:
    print(f'❌ Health check failed: {e}')
    sys.exit(1)
"
```

## 🔒 Security Best Practices

### Container Security

```bash
# Run with non-root user (already configured)
docker-compose exec artemis-nexus-ai whoami  # Should output: artemis

# Check security context
docker-compose exec artemis-nexus-ai id
# uid=1000(artemis) gid=1000(artemis) groups=1000(artemis)
```

### Network Security

```bash
# Use custom network
docker network create artemis-secure-network
docker-compose -f docker-compose.secure.yml up -d
```

### Secrets Management

```bash
# Use Docker secrets for sensitive data
echo "your-api-key" | docker secret create artemis-api-key -
```

## 📊 Monitoring & Logging

### Container Logs

```bash
# View real-time logs
docker-compose logs -f artemis-nexus-ai

# Export logs
docker-compose logs artemis-nexus-ai > artemis-logs.txt

# Filter logs by level
docker-compose logs artemis-nexus-ai | grep ERROR
```

### Performance Monitoring

```bash
# Container resource usage
docker stats artemis-nexus-ai-platform

# Detailed container info
docker inspect artemis-nexus-ai-platform
```

## 🚨 Troubleshooting

### Common Issues

#### Port Already in Use
```bash
# Check what's using port 8080
lsof -i :8080

# Use different port
docker-compose -f docker-compose.yml up -d -p 8081:8080
```

#### Permission Issues
```bash
# Fix volume permissions
sudo chown -R 1000:1000 ./reports ./logs ./ml_models
```

#### Memory Issues
```bash
# Increase Docker memory limit in Docker Desktop
# Or add memory limits to docker-compose.yml:
services:
  artemis-nexus-ai:
    deploy:
      resources:
        limits:
          memory: 4G
        reservations:
          memory: 2G
```

#### Network Connectivity
```bash
# Test network connectivity from container
docker-compose exec artemis-nexus-ai ping google.com

# Check DNS resolution
docker-compose exec artemis-nexus-ai nslookup target.example.com
```

## 🔄 Updates & Maintenance

### Update Container

```bash
# Pull latest changes
git pull origin main

# Rebuild and restart
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Cleanup

```bash
# Remove all containers and volumes
docker-compose down -v

# Clean up Docker system
docker system prune -a

# Remove specific image
docker rmi artemis-nexus-ai:latest
```

## 📈 Production Deployment

### Production docker-compose.yml

```yaml
version: '3.8'
services:
  artemis-nexus-ai:
    build: .
    image: artemis-nexus-ai:production
    environment:
      - ARTEMIS_MODE=production
      - LOG_LEVEL=WARNING
    deploy:
      replicas: 3
      resources:
        limits:
          memory: 4G
          cpus: '2'
    restart: always
    healthcheck:
      test: ["CMD", "python3", "-c", "import sys; sys.exit(0)"]
      interval: 30s
      timeout: 10s
      retries: 3
```

## 📞 Support

### Getting Help

```bash
# View help for any tool
docker-compose exec artemis-nexus-ai python3 tools/artemis_nexus_ai_commander.py --help

# Interactive mode
docker-compose exec artemis-nexus-ai python3 -i
```

### Debug Mode

```bash
# Enable debug logging
docker-compose exec artemis-nexus-ai env LOG_LEVEL=DEBUG \
  python3 tools/final_comprehensive_test.py https://target.example.com
```

---

## 🎯 Example Complete Workflow

```bash
# 1. Start the platform
docker-compose up -d

# 2. Run comprehensive security assessment
docker-compose exec artemis-nexus-ai python3 tools/final_comprehensive_test.py \
  https://your-ai-service.com

# 3. Generate professional report
docker-compose exec artemis-nexus-ai python3 scripts/report_generators/generate_real_results_report.py

# 4. View results
docker-compose exec artemis-nexus-ai ls -la reports/

# 5. Cleanup
docker-compose down
```

**🏹 ARTEMIS NEXUS AI - Containerized for Scale • Enterprise Ready • Security First**