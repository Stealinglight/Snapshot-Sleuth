"""
ClamAV Tool - Antivirus malware detection

Scans mounted snapshot filesystem using ClamAV to detect:
- Known malware signatures
- Viruses, trojans, worms
- Potentially unwanted programs (PUP)
- Suspicious patterns

Note: This tool is marked as "optional" in the workflow - failures
do not abort the overall forensic analysis.
"""

import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import boto3
import pyclamd
import structlog

# Import from forensics-base
import sys
sys.path.insert(0, '/app/src')

from snapshot_reader import EBSMountReader, FileEntry
from progress import ProgressReporter, PhaseInfo
from result_handler import (
    ResultHandler,
    NormalizedResult,
    Finding,
    FindingType,
    Severity,
    create_finding_id,
)

logger = structlog.get_logger(__name__)

# ClamAV signature severity mapping
SEVERITY_MAP = {
    # Known dangerous malware families
    "Trojan": Severity.HIGH,
    "Ransomware": Severity.CRITICAL,
    "Backdoor": Severity.CRITICAL,
    "Rootkit": Severity.CRITICAL,
    "Worm": Severity.HIGH,
    "Virus": Severity.HIGH,
    "Exploit": Severity.HIGH,
    "Packed": Severity.MEDIUM,
    "Cryptor": Severity.HIGH,
    "Downloader": Severity.MEDIUM,
    "Dropper": Severity.HIGH,
    "Keylogger": Severity.CRITICAL,
    "Spyware": Severity.HIGH,
    "Adware": Severity.LOW,
    "PUA": Severity.LOW,  # Potentially Unwanted Application
    "Phishing": Severity.MEDIUM,
    "Coinminer": Severity.MEDIUM,
    "Webshell": Severity.CRITICAL,
}

# MITRE ATT&CK mapping
MITRE_MAPPING = {
    "Trojan": ("TA0002", "T1204"),
    "Ransomware": ("TA0040", "T1486"),
    "Backdoor": ("TA0003", "T1547"),
    "Rootkit": ("TA0005", "T1014"),
    "Worm": ("TA0008", "T1080"),
    "Exploit": ("TA0001", "T1190"),
    "Keylogger": ("TA0009", "T1056"),
    "Spyware": ("TA0009", "T1005"),
    "Coinminer": ("TA0040", "T1496"),
    "Webshell": ("TA0003", "T1505.003"),
}


class ClamavTool:
    """
    ClamAV scanning tool for forensic analysis.

    Downloads virus definitions from S3 and scans the mounted
    snapshot filesystem for malware.
    """

    # Directories to skip during scan
    SKIP_DIRS = {
        'proc', 'sys', 'dev', 'run', 'snap',
        'node_modules', '__pycache__', '.git',
        'lost+found',
    }

    def __init__(
        self,
        config,
        reader: EBSMountReader,
        progress: ProgressReporter,
        result_handler: ResultHandler,
    ):
        self.config = config
        self.reader = reader
        self.progress = progress
        self.result_handler = result_handler
        self._definitions_version: str = "unknown"
        self._clamd: Optional[pyclamd.ClamdUnixSocket] = None
        self._s3 = boto3.client("s3", region_name=config.region)
        self._logger = logger.bind(tool="clamav", case_id=config.case_id)

    def run(self) -> NormalizedResult:
        """Execute ClamAV scanning on the mounted snapshot."""
        start_time = datetime.now(timezone.utc)
        findings: list[Finding] = []
        files_scanned = 0
        bytes_scanned = 0
        errors_count = 0

        # Define processing phases
        self.progress.define_phases([
            PhaseInfo("download", weight=0.15, description="Downloading virus definitions"),
            PhaseInfo("start", weight=0.05, description="Starting ClamAV daemon"),
            PhaseInfo("scan", weight=0.75, description="Scanning filesystem"),
            PhaseInfo("upload", weight=0.05, description="Uploading results"),
        ])

        try:
            # Phase 1: Download definitions
            with self.progress.phase("download"):
                self._download_definitions()

            # Phase 2: Start clamd
            with self.progress.phase("start"):
                self._start_clamd()

            # Phase 3: Scan filesystem
            with self.progress.phase("scan"):
                scan_results = self._scan_filesystem()
                findings = scan_results["findings"]
                files_scanned = scan_results["files_scanned"]
                bytes_scanned = scan_results["bytes_scanned"]
                errors_count = scan_results["errors"]

            # Phase 4: Upload raw results
            with self.progress.phase("upload"):
                self._upload_raw_results(findings)

            status = "success" if errors_count == 0 else "partial"

        except Exception as e:
            self._logger.error("ClamAV scan failed", error=str(e))
            status = "failed"
            errors_count += 1

        finally:
            self._stop_clamd()

        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()

        # Get ClamAV version
        try:
            version_output = subprocess.run(
                ["clamscan", "--version"],
                capture_output=True,
                text=True
            )
            tool_version = version_output.stdout.strip().split()[1] if version_output.returncode == 0 else "unknown"
        except Exception:
            tool_version = "unknown"

        return NormalizedResult(
            tool_name="clamav",
            case_id=self.config.case_id,
            snapshot_id=self.config.snapshot_id,
            status=status,
            started_at=start_time,
            completed_at=end_time,
            duration_seconds=duration,
            findings=findings,
            files_scanned=files_scanned,
            bytes_scanned=bytes_scanned,
            errors_count=errors_count,
            tool_version=tool_version,
            signature_version=self._definitions_version,
            metadata={
                "definitions_source": self.config.signature_bucket,
            },
        )

    def _download_definitions(self) -> None:
        """Download ClamAV definitions from S3."""
        db_dir = "/var/lib/clamav"
        bucket = self.config.signature_bucket
        prefix = f"{self.config.signature_prefix}clamav/"

        self._logger.info("Downloading ClamAV definitions", bucket=bucket, prefix=prefix)

        # Definition files to download
        db_files = ["main.cvd", "daily.cld", "bytecode.cld"]

        for db_file in db_files:
            key = f"{prefix}{db_file}"
            local_path = os.path.join(db_dir, db_file)

            try:
                self._s3.download_file(bucket, key, local_path)
                self._logger.debug("Downloaded definition file", file=db_file)
            except Exception as e:
                # Try alternate extension
                alt_file = db_file.replace(".cld", ".cvd") if ".cld" in db_file else db_file.replace(".cvd", ".cld")
                alt_key = f"{prefix}{alt_file}"
                try:
                    self._s3.download_file(bucket, alt_key, local_path.replace(db_file, alt_file))
                    self._logger.debug("Downloaded alternate definition file", file=alt_file)
                except Exception:
                    self._logger.warning(f"Could not download {db_file}", error=str(e))

        # Get version info
        try:
            version_key = f"{prefix}version.txt"
            response = self._s3.get_object(Bucket=bucket, Key=version_key)
            self._definitions_version = response["Body"].read().decode().strip()
        except Exception:
            # Try to get version from daily.cld
            try:
                result = subprocess.run(
                    ["sigtool", "--info", "/var/lib/clamav/daily.cld"],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    for line in result.stdout.split("\n"):
                        if "Version:" in line:
                            self._definitions_version = line.split(":")[1].strip()
                            break
            except Exception:
                self._definitions_version = datetime.now(timezone.utc).strftime("%Y%m%d")

        self._logger.info("Definitions downloaded", version=self._definitions_version)

    def _start_clamd(self) -> None:
        """Start the ClamAV daemon."""
        self._logger.info("Starting ClamAV daemon")

        # Start clamd in background
        subprocess.Popen(
            ["clamd"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # Wait for socket to be available
        socket_path = "/var/run/clamav/clamd.sock"
        max_wait = 60
        waited = 0

        while waited < max_wait:
            if os.path.exists(socket_path):
                try:
                    self._clamd = pyclamd.ClamdUnixSocket(socket_path)
                    if self._clamd.ping():
                        self._logger.info("ClamAV daemon started")
                        return
                except Exception:
                    pass

            import time
            time.sleep(1)
            waited += 1

        raise RuntimeError("ClamAV daemon failed to start")

    def _stop_clamd(self) -> None:
        """Stop the ClamAV daemon."""
        try:
            subprocess.run(["pkill", "clamd"], capture_output=True)
            self._logger.info("ClamAV daemon stopped")
        except Exception:
            pass

    def _scan_filesystem(self) -> dict:
        """Scan mounted filesystem with ClamAV."""
        findings: list[Finding] = []
        files_scanned = 0
        bytes_scanned = 0
        errors = 0

        mount_path = self.reader.get_access_path()

        # Use clamscan for recursive scanning (more reliable than clamd for large scans)
        self._logger.info("Starting ClamAV scan", path=mount_path)

        # Build exclusion patterns
        exclude_args = []
        for skip_dir in self.SKIP_DIRS:
            exclude_args.extend(["--exclude-dir", f"^{skip_dir}$"])

        # Run clamscan
        log_file = "/tmp/clamscan.log"
        cmd = [
            "clamscan",
            "-r",  # Recursive
            "-i",  # Only show infected files
            "--no-summary",  # Skip summary (we'll compute our own)
            f"--log={log_file}",
            "--max-filesize=100M",
            "--max-scansize=500M",
        ] + exclude_args + [mount_path]

        self._logger.debug("Running clamscan", cmd=" ".join(cmd))

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Process output in real-time for progress updates
        infected_pattern = re.compile(r"^(.+): (.+) FOUND$")
        scanned_count = 0

        for line in process.stdout:
            line = line.strip()
            if not line:
                continue

            # Check for infected file
            match = infected_pattern.match(line)
            if match:
                file_path = match.group(1)
                signature = match.group(2)

                finding = self._create_finding(file_path, signature, mount_path)
                findings.append(finding)
                self.progress.increment_findings()

                self._logger.info(
                    "Malware detected",
                    file=file_path,
                    signature=signature
                )

            scanned_count += 1
            if scanned_count % 1000 == 0:
                self.progress.set_metadata(files_checked=scanned_count)

        process.wait()

        # Parse log file for statistics
        try:
            with open(log_file, "r") as f:
                log_content = f.read()

            # Extract scan statistics from log
            scanned_match = re.search(r"Scanned files: (\d+)", log_content)
            if scanned_match:
                files_scanned = int(scanned_match.group(1))

            data_match = re.search(r"Data scanned: ([\d.]+) MB", log_content)
            if data_match:
                bytes_scanned = int(float(data_match.group(1)) * 1024 * 1024)

        except Exception as e:
            self._logger.warning("Could not parse scan log", error=str(e))
            # Estimate from directory walk
            for _, _, files in self.reader.walk("/", max_depth=10):
                files_scanned += len(files)
                bytes_scanned += sum(f.size for f in files)

        return {
            "findings": findings,
            "files_scanned": files_scanned,
            "bytes_scanned": bytes_scanned,
            "errors": errors,
        }

    def _create_finding(self, file_path: str, signature: str, mount_path: str) -> Finding:
        """Create a normalized Finding from ClamAV detection."""
        # Make path relative to mount
        rel_path = file_path
        if file_path.startswith(mount_path):
            rel_path = file_path[len(mount_path):]
        if not rel_path.startswith("/"):
            rel_path = "/" + rel_path

        # Determine severity and type from signature name
        severity = Severity.HIGH  # Default for malware
        finding_type = FindingType.MALWARE

        for keyword, sev in SEVERITY_MAP.items():
            if keyword.lower() in signature.lower():
                severity = sev
                break

        # Get MITRE mapping
        mitre_tactic = None
        mitre_technique = None
        for keyword, mapping in MITRE_MAPPING.items():
            if keyword.lower() in signature.lower():
                mitre_tactic, mitre_technique = mapping
                break

        # Get file metadata if available
        file_mtime = None
        file_size = 0
        try:
            entry = self.reader.stat(rel_path)
            file_mtime = entry.mtime
            file_size = entry.size
        except Exception:
            pass

        return Finding(
            id=create_finding_id("clamav", signature, rel_path),
            type=finding_type,
            severity=severity,
            title=f"ClamAV: {signature}",
            description=f"ClamAV detected malware signature '{signature}' in file",
            file_path=rel_path,
            timestamp=file_mtime,
            detected_at=datetime.now(timezone.utc),
            tool_name="clamav",
            rule_name=signature,
            confidence=0.95,  # ClamAV has high confidence for known signatures
            indicators=[signature],
            metadata={
                "signature": signature,
                "file_size": file_size,
            },
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
        )

    def _upload_raw_results(self, findings: list[Finding]) -> None:
        """Upload raw ClamAV output."""
        # Upload the scan log
        log_file = "/tmp/clamscan.log"
        if os.path.exists(log_file):
            with open(log_file, "rb") as f:
                self.result_handler.upload_raw_output(
                    f.read(),
                    "scan.log",
                    "text/plain"
                )

        self._logger.info("Raw results uploaded", findings_count=len(findings))
