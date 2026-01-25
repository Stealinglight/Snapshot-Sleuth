# Snapshot-Sleuth Forensics Base Image
# This image provides the foundation for all forensic tool containers

FROM python:3.11-slim-bookworm

LABEL maintainer="Snapshot-Sleuth Team"
LABEL description="Base image for forensic analysis containers"

# Install system dependencies for forensic tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Sleuthkit for filesystem analysis
    sleuthkit \
    # libewf for E01 forensic image support
    libewf-dev \
    # Common utilities
    file \
    xxd \
    binutils \
    # Build dependencies (for Python packages)
    gcc \
    python3-dev \
    libffi-dev \
    # Cleanup
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Set working directory
WORKDIR /app

# Copy requirements first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/

# Create evidence mount point
RUN mkdir -p /mnt/evidence && chmod 755 /mnt/evidence

# Create output directory for results
RUN mkdir -p /output && chmod 755 /output

# Set Python path
ENV PYTHONPATH=/app/src:$PYTHONPATH
ENV PYTHONUNBUFFERED=1

# Default environment variables (overridden at runtime)
ENV CASE_ID=""
ENV SNAPSHOT_ID=""
ENV TOOL_NAME=""
ENV EVIDENCE_BUCKET=""
ENV HEARTBEAT_INTERVAL_SECONDS="30"

# Copy and set entrypoint
COPY entrypoint.py /app/entrypoint.py
RUN chmod +x /app/entrypoint.py

ENTRYPOINT ["python", "/app/entrypoint.py"]
