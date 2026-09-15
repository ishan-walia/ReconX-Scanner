# ReconX - Containerized Multi-Stage Python Image
FROM python:3.11-slim

# Security & environment hardening
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy dependencies
COPY requirements.txt /app/

# Install python dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy source files
COPY . /app/

# Create reports directory with appropriate permissions
RUN mkdir -p /app/reports && chmod 777 /app/reports

# Default non-root user
USER 1000:1000

# Set entrypoint to reconx CLI
ENTRYPOINT ["python", "reconx.py"]

# Default argument
CMD ["--help"]
