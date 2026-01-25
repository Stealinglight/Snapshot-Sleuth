# Log2Timeline Tool Container
# Extends forensics-base with Plaso timeline generation

FROM forensics-base:latest

LABEL maintainer="Snapshot-Sleuth Team"
LABEL description="Log2Timeline/Plaso forensic timeline generation container"

# Install Plaso dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Required for Plaso
    python3-pip \
    python3-dev \
    # Libraries for various parsers
    liblzma-dev \
    zlib1g-dev \
    libbz2-dev \
    libffi-dev \
    libssl-dev \
    # SQLite for Plaso storage
    libsqlite3-dev \
    # Image parsing
    libjpeg-dev \
    libpng-dev \
    # For Windows registry parsing
    libregf1 \
    python3-libregf \
    # For Windows event logs
    libevt1 \
    libevtx1 \
    python3-libevt \
    python3-libevtx \
    # For ESE databases
    libesedb1 \
    python3-libesedb \
    # For OLE/compound files
    libolecf1 \
    python3-libolecf \
    # For filesystem metadata
    libfsntfs1 \
    python3-libfsntfs \
    # For SQLite databases
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install Plaso and dependencies
COPY requirements.txt /tmp/log2timeline-requirements.txt
RUN pip install --no-cache-dir -r /tmp/log2timeline-requirements.txt

# Copy tool implementation
COPY tools/ /app/tools/

# Create output directory for plaso files
RUN mkdir -p /output/plaso && chmod 755 /output/plaso

# Set tool name
ENV TOOL_NAME="log2timeline"

# Default command (uses base entrypoint)
CMD ["python", "/app/entrypoint.py"]
