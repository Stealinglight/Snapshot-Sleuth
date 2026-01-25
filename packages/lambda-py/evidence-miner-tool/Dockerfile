# Evidence Miner Tool Container
# Extends forensics-base with artifact extraction capabilities

FROM forensics-base:latest

LABEL maintainer="Snapshot-Sleuth Team"
LABEL description="Evidence Miner forensic artifact extraction container"

# Install additional tools for artifact extraction
RUN apt-get update && apt-get install -y --no-install-recommends \
    # For parsing login records
    util-linux \
    # For Windows event log parsing (if needed)
    libevt1 \
    libevtx1 \
    # Additional filesystem tools
    attr \
    acl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install Python dependencies
COPY requirements.txt /tmp/evidence-miner-requirements.txt
RUN pip install --no-cache-dir -r /tmp/evidence-miner-requirements.txt

# Copy tool implementation
COPY tools/ /app/tools/

# Set tool name
ENV TOOL_NAME="evidence-miner"

# Default command (uses base entrypoint)
CMD ["python", "/app/entrypoint.py"]
