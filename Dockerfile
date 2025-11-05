# Cloud Security Analisys - Automated Multi-Cloud Extractor Container
# Lightweight Python 3.11 image for serverless execution in Cloud Run, ECS Fargate, Azure Container Apps, or CI/CD

FROM python:3.11-slim

# Prevent Python from writing pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies (required for some cloud CLI helpers if needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy python dependencies and install
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Default command runs full extraction and outputs documentation to /app/docs
ENTRYPOINT ["python3", "main.py"]
CMD ["--cloud", "ALL", "--domain", "all", "--output-dir", "/app/docs"]

# ==============================================================================
# Script Author: J. Saccomani (g-jsaccomani / jsaccomani@google.com)
# Project: Cloud Security Analisys Architecture & Requirements Framework
# ==============================================================================
