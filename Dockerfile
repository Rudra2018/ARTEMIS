# 🏹 ARTEMIS NEXUS AI - Docker Image
# Advanced AI Security Testing Platform with Quantum-Level Analysis
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    ARTEMIS_HOME=/app \
    PYTHONPATH=/app

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /app/{logs,reports,temp,ml_models,data} \
    && mkdir -p /app/ai_tester_core/{learning_data,knowledge_base}

# Copy requirements first for better caching
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Install additional dependencies for comprehensive testing
RUN pip install --no-cache-dir \
    aiohttp \
    asyncio \
    numpy \
    scikit-learn \
    matplotlib \
    seaborn \
    reportlab \
    requests \
    beautifulsoup4 \
    lxml \
    pytest \
    pytest-asyncio

# Copy the entire project
COPY . /app/

# Make scripts executable
RUN chmod +x /app/tools/*.py \
    && chmod +x /app/bootstrap_repo.sh

# Create non-root user for security
RUN groupadd -r artemis && useradd -r -g artemis artemis \
    && chown -R artemis:artemis /app

# Switch to non-root user
USER artemis

# Expose port for web interface (if needed)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import sys; sys.exit(0)" || exit 1

# Default command - ARTEMIS NEXUS AI Commander
CMD ["python3", "tools/artemis_nexus_ai_commander.py", "--help"]

# Labels for better maintainability
LABEL maintainer="ARTEMIS NEXUS AI Team" \
      version="2.0.0" \
      description="Advanced AI Security Testing Platform with Quantum-Level Analysis" \
      org.opencontainers.image.title="ARTEMIS NEXUS AI" \
      org.opencontainers.image.description="Comprehensive AI Security Testing with OWASP LLM Top 10 + Healthcare + Multi-Language Support" \
      org.opencontainers.image.version="2.0.0" \
      org.opencontainers.image.vendor="ARTEMIS NEXUS AI"