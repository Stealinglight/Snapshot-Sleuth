"""
Log2Timeline Tool - Forensic timeline generation

Uses Plaso to extract timestamps from various forensic artifacts:
- File system metadata (MAC times)
- Windows Event Logs
- Windows Registry
- Browser history
- Application logs
- Authentication logs
- And many more sources

Produces:
- Plaso storage file (.plaso) for detailed analysis
- Normalized timeline events as findings
- JSON export for integration
"""

import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import structlog

# Import from forensics-base
import sys
sys.path.insert(0, '/app/src')

from snapshot_reader import EBSMountReader
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

# Event types that indicate potential security issues
SECURITY_EVENT_TYPES = {
    # Authentication events
    "windows:evtx:record": {
        "4624": ("Successful Logon", Severity.INFO),
        "4625": ("Failed Logon", Severity.MEDIUM),
        "4648": ("Explicit Credentials Logon", Severity.MEDIUM),
        "4672": ("Special Privileges Assigned", Severity.LOW),
        "4688": ("Process Creation", Severity.INFO),
        "4697": ("Service Installed", Severity.MEDIUM),
        "4698": ("Scheduled Task Created", Severity.MEDIUM),
        "4720": ("User Account Created", Severity.MEDIUM),
        "4732": ("Member Added to Security Group", Severity.MEDIUM),
        "7045": ("Service Installed", Severity.MEDIUM),
    },
    # Linux auth events
    "linux:utmp:event": {
        "USER_LOGIN": ("User Login", Severity.INFO),
        "USER_LOGOUT": ("User Logout", Severity.INFO),
    },
    "syslog:line": {
        "authentication failure": ("Auth Failure", Severity.MEDIUM),
        "Accepted publickey": ("SSH Key Auth", Severity.INFO),
        "Accepted password": ("SSH Password Auth", Severity.LOW),
        "session opened": ("Session Opened", Severity.INFO),
    },
}

# MITRE ATT&CK mappings for timeline events
MITRE_MAPPING = {
    "4624": ("TA0001", "T1078"),  # Valid Accounts
    "4625": ("TA0006", "T1110"),  # Brute Force
    "4648": ("TA0008", "T1021"),  # Remote Services
    "4697": ("TA0003", "T1543"),  # Create or Modify System Process
    "4698": ("TA0003", "T1053"),  # Scheduled Task
    "4720": ("TA0003", "T1136"),  # Create Account
    "7045": ("TA0003", "T1543"),  # Create or Modify System Process
    "authentication failure": ("TA0006", "T1110"),
    "Accepted publickey": ("TA0001", "T1078.004"),
}


class Log2TimelineTool:
    """
    Log2Timeline/Plaso forensic timeline generation tool.

    Extracts timestamps from forensic artifacts and generates
    a comprehensive timeline for incident analysis.
    """

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
        self._logger = logger.bind(tool="log2timeline", case_id=config.case_id)

        # Output paths
        self._plaso_file = f"/output/plaso/{config.case_id}.plaso"
        self._timeline_file = f"/output/plaso/{config.case_id}_timeline.json"

    def run(self) -> NormalizedResult:
        """Execute Log2Timeline on the mounted snapshot."""
        start_time = datetime.now(timezone.utc)
        findings: list[Finding] = []
        errors_count = 0
        events_processed = 0

        # Define processing phases
        self.progress.define_phases([
            PhaseInfo("extract", weight=0.70, description="Extracting timeline events"),
            PhaseInfo("analyze", weight=0.20, description="Analyzing timeline"),
            PhaseInfo("upload", weight=0.10, description="Uploading results"),
        ])

        try:
            # Phase 1: Run log2timeline extraction
            with self.progress.phase("extract"):
                events_processed = self._run_log2timeline()

            # Phase 2: Analyze timeline for security events
            with self.progress.phase("analyze"):
                findings = self._analyze_timeline()

            # Phase 3: Upload results
            with self.progress.phase("upload"):
                self._upload_results()

            status = "success"

        except Exception as e:
            self._logger.error("Log2Timeline failed", error=str(e))
            status = "failed"
            errors_count += 1

        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()

        # Get Plaso version
        try:
            result = subprocess.run(
                ["log2timeline.py", "--version"],
                capture_output=True,
                text=True
            )
            tool_version = result.stdout.strip() if result.returncode == 0 else "unknown"
        except Exception:
            tool_version = "unknown"

        return NormalizedResult(
            tool_name="log2timeline",
            case_id=self.config.case_id,
            snapshot_id=self.config.snapshot_id,
            status=status,
            started_at=start_time,
            completed_at=end_time,
            duration_seconds=duration,
            findings=findings,
            files_scanned=events_processed,
            bytes_scanned=0,
            errors_count=errors_count,
            tool_version=tool_version,
            metadata={
                "plaso_file": self._plaso_file,
                "events_extracted": events_processed,
            },
        )

    def _run_log2timeline(self) -> int:
        """Run log2timeline.py to extract events."""
        mount_path = self.reader.get_access_path()

        self._logger.info("Starting log2timeline extraction", source=mount_path)

        # Build log2timeline command
        cmd = [
            "log2timeline.py",
            "--status_view", "none",  # Disable interactive status
            "--logfile", "/tmp/log2timeline.log",
            "--storage-file", self._plaso_file,
            # Parsers to use (optimize for common forensic artifacts)
            "--parsers", self._get_parser_string(),
            # Source path
            mount_path,
        ]

        self._logger.debug("Running log2timeline", cmd=" ".join(cmd))

        # Run with progress monitoring
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        events_count = 0
        for line in process.stdout:
            line = line.strip()
            if not line:
                continue

            # Parse progress from log2timeline output
            if "Processing" in line or "Extracting" in line:
                self._logger.debug("log2timeline progress", line=line)

            # Count events
            if "events" in line.lower():
                import re
                match = re.search(r"(\d+)\s*events?", line, re.IGNORECASE)
                if match:
                    events_count = int(match.group(1))
                    self.progress.set_metadata(events_extracted=events_count)

        process.wait()

        if process.returncode != 0:
            self._logger.warning(
                "log2timeline returned non-zero exit code",
                returncode=process.returncode
            )

        # Get final event count from plaso file
        if os.path.exists(self._plaso_file):
            events_count = self._count_plaso_events()

        self._logger.info("Extraction complete", events=events_count)
        return events_count

    def _get_parser_string(self) -> str:
        """Get the parser configuration string for log2timeline."""
        # Use preset for Linux/general analysis
        # Can be customized based on detected OS
        parsers = [
            # Linux
            "linux",
            "syslog",
            "utmp",
            "bash_history",
            "zsh_extended_history",
            # General
            "sqlite",
            "filestat",
            # Web browsers
            "chrome_cache",
            "chrome_history",
            "firefox_cache",
            "firefox_history",
            # Applications
            "docker_json",
            "aws_elb_access",
            # Windows (if present)
            "winevt",
            "winevtx",
            "winreg",
        ]
        return ",".join(parsers)

    def _count_plaso_events(self) -> int:
        """Count events in plaso storage file."""
        try:
            result = subprocess.run(
                ["pinfo.py", "--storage-file", self._plaso_file],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "Events:" in line or "Number of events:" in line:
                        import re
                        match = re.search(r"(\d+)", line)
                        if match:
                            return int(match.group(1))
        except Exception as e:
            self._logger.warning("Could not count plaso events", error=str(e))

        return 0

    def _analyze_timeline(self) -> list[Finding]:
        """Analyze timeline for security-relevant events."""
        findings = []

        if not os.path.exists(self._plaso_file):
            self._logger.warning("Plaso file not found, skipping analysis")
            return findings

        # Export to JSON for analysis
        self._logger.info("Exporting timeline to JSON")

        cmd = [
            "psort.py",
            "--output-format", "json_line",
            "--write", self._timeline_file,
            "--storage-file", self._plaso_file,
        ]

        try:
            subprocess.run(cmd, capture_output=True, timeout=600)
        except subprocess.TimeoutExpired:
            self._logger.warning("psort timed out during export")
            return findings

        # Analyze JSON output for security events
        if os.path.exists(self._timeline_file):
            findings = self._parse_timeline_json()

        return findings

    def _parse_timeline_json(self) -> list[Finding]:
        """Parse timeline JSON and extract security-relevant findings."""
        findings = []
        event_counts = {}

        try:
            with open(self._timeline_file, "r") as f:
                for line_num, line in enumerate(f):
                    if line_num > 100000:  # Limit processing
                        self._logger.warning("Timeline too large, truncating analysis")
                        break

                    try:
                        event = json.loads(line)
                        finding = self._event_to_finding(event, event_counts)
                        if finding:
                            findings.append(finding)
                            self.progress.increment_findings()
                    except json.JSONDecodeError:
                        continue

        except Exception as e:
            self._logger.error("Error parsing timeline JSON", error=str(e))

        # Add summary findings for event clusters
        findings.extend(self._create_cluster_findings(event_counts))

        self._logger.info("Timeline analysis complete", findings=len(findings))
        return findings

    def _event_to_finding(self, event: dict, event_counts: dict) -> Optional[Finding]:
        """Convert a timeline event to a finding if security-relevant."""
        data_type = event.get("data_type", "")
        message = event.get("message", "")

        # Track event counts for clustering
        event_key = f"{data_type}:{message[:50]}"
        event_counts[event_key] = event_counts.get(event_key, 0) + 1

        # Check for security-relevant events
        if data_type in SECURITY_EVENT_TYPES:
            type_config = SECURITY_EVENT_TYPES[data_type]

            for pattern, (title, severity) in type_config.items():
                if pattern in message or pattern in str(event.get("event_identifier", "")):
                    # Get MITRE mapping
                    mitre_tactic = None
                    mitre_technique = None
                    if pattern in MITRE_MAPPING:
                        mitre_tactic, mitre_technique = MITRE_MAPPING[pattern]

                    return Finding(
                        id=create_finding_id(
                            "log2timeline",
                            f"{data_type}-{pattern}",
                            str(event.get("timestamp", ""))
                        ),
                        type=FindingType.TIMELINE_ANOMALY,
                        severity=severity,
                        title=f"Timeline: {title}",
                        description=message[:500],
                        file_path=event.get("filename", event.get("display_name", "")),
                        timestamp=self._parse_timestamp(event.get("timestamp")),
                        tool_name="log2timeline",
                        rule_name=f"{data_type}-{pattern}",
                        metadata={
                            "data_type": data_type,
                            "source": event.get("parser", ""),
                            "hostname": event.get("hostname", ""),
                            "username": event.get("username", ""),
                        },
                        mitre_tactic=mitre_tactic,
                        mitre_technique=mitre_technique,
                    )

        # Check for suspicious patterns in any event
        suspicious_patterns = [
            ("reverse shell", Severity.CRITICAL, "TA0011", "T1059"),
            ("nc -e", Severity.CRITICAL, "TA0011", "T1059"),
            ("bash -i", Severity.HIGH, "TA0011", "T1059"),
            ("/dev/tcp/", Severity.CRITICAL, "TA0011", "T1059"),
            ("mimikatz", Severity.CRITICAL, "TA0006", "T1003"),
            ("sekurlsa", Severity.CRITICAL, "TA0006", "T1003"),
            ("powershell -enc", Severity.HIGH, "TA0002", "T1059.001"),
            ("certutil -decode", Severity.MEDIUM, "TA0005", "T1140"),
        ]

        message_lower = message.lower()
        for pattern, severity, tactic, technique in suspicious_patterns:
            if pattern in message_lower:
                return Finding(
                    id=create_finding_id("log2timeline", pattern, str(event.get("timestamp", ""))),
                    type=FindingType.SUSPICIOUS_FILE,
                    severity=severity,
                    title=f"Suspicious activity: {pattern}",
                    description=f"Timeline event contains suspicious pattern: {message[:200]}",
                    file_path=event.get("filename", ""),
                    timestamp=self._parse_timestamp(event.get("timestamp")),
                    tool_name="log2timeline",
                    rule_name=f"suspicious-{pattern.replace(' ', '-')}",
                    mitre_tactic=tactic,
                    mitre_technique=technique,
                )

        return None

    def _parse_timestamp(self, timestamp) -> Optional[datetime]:
        """Parse timestamp from various formats."""
        if timestamp is None:
            return None

        if isinstance(timestamp, (int, float)):
            # Unix timestamp (microseconds)
            try:
                return datetime.fromtimestamp(timestamp / 1000000, tz=timezone.utc)
            except (ValueError, OSError):
                return None

        if isinstance(timestamp, str):
            try:
                return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                return None

        return None

    def _create_cluster_findings(self, event_counts: dict) -> list[Finding]:
        """Create findings for unusual event clusters."""
        findings = []

        # Look for high-frequency events that might indicate attacks
        for event_key, count in event_counts.items():
            if count > 100:  # Threshold for "unusual"
                data_type, message_prefix = event_key.split(":", 1)

                # Failed logins cluster
                if "4625" in event_key or "authentication failure" in event_key.lower():
                    findings.append(Finding(
                        id=create_finding_id("log2timeline", "auth-failure-cluster", event_key),
                        type=FindingType.TIMELINE_ANOMALY,
                        severity=Severity.HIGH,
                        title=f"Authentication failure cluster ({count} events)",
                        description=f"Detected {count} authentication failures, possible brute force attack",
                        tool_name="log2timeline",
                        rule_name="auth-failure-cluster",
                        metadata={"count": count, "event_type": data_type},
                        mitre_tactic="TA0006",
                        mitre_technique="T1110",
                    ))

        return findings

    def _upload_results(self) -> None:
        """Upload plaso file and timeline."""
        # Upload plaso storage file
        if os.path.exists(self._plaso_file):
            self.result_handler.upload_raw_file(
                self._plaso_file,
                "timeline.plaso",
                "application/octet-stream"
            )

        # Upload JSON timeline (compressed if large)
        if os.path.exists(self._timeline_file):
            file_size = os.path.getsize(self._timeline_file)

            if file_size > 50 * 1024 * 1024:  # > 50MB
                # Compress large files
                import gzip
                compressed_file = f"{self._timeline_file}.gz"
                with open(self._timeline_file, "rb") as f_in:
                    with gzip.open(compressed_file, "wb") as f_out:
                        f_out.writelines(f_in)

                self.result_handler.upload_raw_file(
                    compressed_file,
                    "timeline.json.gz",
                    "application/gzip"
                )
            else:
                self.result_handler.upload_raw_file(
                    self._timeline_file,
                    "timeline.json",
                    "application/json"
                )

        self._logger.info("Results uploaded")
