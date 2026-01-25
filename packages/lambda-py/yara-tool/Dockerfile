# YARA Tool Container
# Extends forensics-base with YARA scanning capabilities

FROM forensics-base:latest

LABEL maintainer="Snapshot-Sleuth Team"
LABEL description="YARA rule-based malware detection container"

# Install YARA dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    automake \
    libtool \
    make \
    gcc \
    pkg-config \
    libssl-dev \
    libjansson-dev \
    libmagic-dev \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install YARA from source for latest version
ARG YARA_VERSION=4.5.0
RUN cd /tmp && \
    curl -sSL https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz | tar xz && \
    cd yara-${YARA_VERSION} && \
    ./bootstrap.sh && \
    ./configure --enable-cuckoo --enable-magic --enable-dotnet && \
    make && \
    make install && \
    ldconfig && \
    cd / && rm -rf /tmp/yara-${YARA_VERSION}

# Install Python YARA bindings
COPY requirements.txt /tmp/yara-requirements.txt
RUN pip install --no-cache-dir -r /tmp/yara-requirements.txt

# Copy tool implementation
COPY tools/ /app/tools/

# Create rules cache directory
RUN mkdir -p /app/rules && chmod 755 /app/rules

# Set tool name
ENV TOOL_NAME="yara"

# Default command (uses base entrypoint)
CMD ["python", "/app/entrypoint.py"]
