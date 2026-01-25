# ClamAV Tool Container
# Extends forensics-base with ClamAV antivirus scanning

FROM forensics-base:latest

LABEL maintainer="Snapshot-Sleuth Team"
LABEL description="ClamAV malware scanning container"

# Install ClamAV
RUN apt-get update && apt-get install -y --no-install-recommends \
    clamav \
    clamav-daemon \
    clamav-freshclam \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create directories for ClamAV
RUN mkdir -p /var/lib/clamav /var/run/clamav /var/log/clamav \
    && chown -R clamav:clamav /var/lib/clamav /var/run/clamav /var/log/clamav

# Configure freshclam to not use mirrors (we'll download from S3)
RUN echo "DatabaseDirectory /var/lib/clamav" > /etc/clamav/freshclam.conf \
    && echo "UpdateLogFile /var/log/clamav/freshclam.log" >> /etc/clamav/freshclam.conf \
    && echo "LogTime yes" >> /etc/clamav/freshclam.conf

# Configure clamd
RUN echo "DatabaseDirectory /var/lib/clamav" > /etc/clamav/clamd.conf \
    && echo "LocalSocket /var/run/clamav/clamd.sock" >> /etc/clamav/clamd.conf \
    && echo "LogFile /var/log/clamav/clamd.log" >> /etc/clamav/clamd.conf \
    && echo "LogTime yes" >> /etc/clamav/clamd.conf \
    && echo "MaxFileSize 100M" >> /etc/clamav/clamd.conf \
    && echo "MaxScanSize 500M" >> /etc/clamav/clamd.conf \
    && echo "StreamMaxLength 100M" >> /etc/clamav/clamd.conf

# Install Python ClamAV bindings
COPY requirements.txt /tmp/clamav-requirements.txt
RUN pip install --no-cache-dir -r /tmp/clamav-requirements.txt

# Copy tool implementation
COPY tools/ /app/tools/

# Set tool name
ENV TOOL_NAME="clamav"

# Default command (uses base entrypoint)
CMD ["python", "/app/entrypoint.py"]
