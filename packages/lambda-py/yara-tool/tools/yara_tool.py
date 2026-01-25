"""
YARA Tool - Rule-based malware and indicator detection

Scans mounted snapshot filesystem using YARA rules to detect:
- Malware signatures
- Suspicious patterns
- Indicators of compromise (IOCs)
- Custom threat intelligence rules
"""

import hashlib
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import boto3
import structlog
import yara

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

# Severity mapping based on YARA rule metadata
SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

# MITRE ATT&CK mapping for common rule categories
MITRE_MAPPING = {
    "malware": ("TA0002", "T1204"),  # Execution / User Execution
    "ransomware": ("TA0040", "T1486"),  # Impact / Data Encrypted
    "backdoor": ("TA0003", "T1547"),  # Persistence / Boot or Logon
    "trojan": ("TA0002", "T1204"),  # Execution / User Execution
    "webshell": ("TA0003", "T1505.003"),  # Persistence / Web Shell
    "miner": ("TA0040", "T1496"),  # Impact / Resource Hijacking
    "exploit": ("TA0001", "T1190"),  # Initial Access / Exploit
    "credential": ("TA0006", "T1003"),  # Credential Access / OS Credential Dumping
    "lateral": ("TA0008", "T1021"),  # Lateral Movement / Remote Services
    "exfil": ("TA0010", "T1041"),  # Exfiltration / Exfiltration Over C2
}


class YaraTool:
    """
    YARA scanning tool for forensic analysis.

    Downloads rules from S3, compiles them, and scans the mounted
    snapshot filesystem for matches.
    """

    # File extensions to scan (others are skipped for performance)
    SCAN_EXTENSIONS = {
        # Executables
        '.exe', '.dll', '.so', '.dylib', '.bin', '.elf',
        # Scripts
        '.py', '.rb', '.pl', '.sh', '.bash', '.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.js',
        # Web
        '.php', '.asp', '.aspx', '.jsp', '.cgi',
        # Documents (can contain macros)
        '.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm', '.ppt', '.pptx', '.pptm',
        '.pdf', '.rtf',
        # Archives
        '.zip', '.rar', '.7z', '.tar', '.gz',
        # Config files
        '.conf', '.cfg', '.ini', '.xml', '.json', '.yaml', '.yml',
        # No extension (common for Linux malware)
        '',
    }

    # Maximum file size to scan (skip very large files)
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

    # Directories to skip
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
        self._rules: Optional[yara.Rules] = None
        self._rules_version: str = "unknown"
        self._s3 = boto3.client("s3", region_name=config.region)
        self._logger = logger.bind(tool="yara", case_id=config.case_id)

    def run(self) -> NormalizedResult:
        """Execute YARA scanning on the mounted snapshot."""
        start_time = datetime.now(timezone.utc)
        findings: list[Finding] = []
        files_scanned = 0
        bytes_scanned = 0
        errors_count = 0

        # Define processing phases
        self.progress.define_phases([
            PhaseInfo("download", weight=0.1, description="Downloading YARA rules"),
            PhaseInfo("compile", weight=0.1, description="Compiling rules"),
            PhaseInfo("scan", weight=0.75, description="Scanning filesystem"),
            PhaseInfo("upload", weight=0.05, description="Uploading results"),
        ])

        try:
            # Phase 1: Download rules
            with self.progress.phase("download"):
                rules_dir = self._download_rules()

            # Phase 2: Compile rules
            with self.progress.phase("compile"):
                self._compile_rules(rules_dir)

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
            self._logger.error("YARA scan failed", error=str(e))
            status = "failed"
            errors_count += 1

        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()

        return NormalizedResult(
            tool_name="yara",
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
            tool_version=yara.__version__,
            signature_version=self._rules_version,
            metadata={
                "rules_source": self.config.signature_bucket,
                "scan_extensions": list(self.SCAN_EXTENSIONS),
                "max_file_size": self.MAX_FILE_SIZE,
            },
        )

    def _download_rules(self) -> str:
        """Download YARA rules from S3 signature bucket."""
        rules_dir = "/app/rules"
        os.makedirs(rules_dir, exist_ok=True)

        bucket = self.config.signature_bucket
        prefix = f"{self.config.signature_prefix}yara/rules/"

        self._logger.info("Downloading YARA rules", bucket=bucket, prefix=prefix)

        # List and download all rule files
        paginator = self._s3.get_paginator("list_objects_v2")
        rule_files = []

        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if key.endswith(".yar") or key.endswith(".yara"):
                    filename = os.path.basename(key)
                    local_path = os.path.join(rules_dir, filename)

                    self._s3.download_file(bucket, key, local_path)
                    rule_files.append(local_path)

                    self._logger.debug("Downloaded rule file", file=filename)

        # Get version from metadata file if exists
        try:
            version_key = f"{self.config.signature_prefix}yara/version.txt"
            response = self._s3.get_object(Bucket=bucket, Key=version_key)
            self._rules_version = response["Body"].read().decode().strip()
        except Exception:
            self._rules_version = datetime.now(timezone.utc).strftime("%Y%m%d")

        self._logger.info(
            "Rules downloaded",
            count=len(rule_files),
            version=self._rules_version
        )

        return rules_dir

    def _compile_rules(self, rules_dir: str) -> None:
        """Compile all YARA rules in directory."""
        rule_files = list(Path(rules_dir).glob("*.yar")) + list(Path(rules_dir).glob("*.yara"))

        if not rule_files:
            raise RuntimeError("No YARA rules found to compile")

        self._logger.info("Compiling YARA rules", count=len(rule_files))

        # Build filepaths dict for compilation
        filepaths = {
            f.stem: str(f) for f in rule_files
        }

        try:
            self._rules = yara.compile(filepaths=filepaths)
            self._logger.info("Rules compiled successfully")
        except yara.SyntaxError as e:
            self._logger.error("YARA syntax error", error=str(e))
            raise

    def _scan_filesystem(self) -> dict:
        """Scan mounted filesystem with YARA rules."""
        findings: list[Finding] = []
        files_scanned = 0
        bytes_scanned = 0
        errors = 0

        # Count total files for progress
        self._logger.info("Counting files to scan...")
        total_files = 0
        scannable_files = []

        for dirpath, dirs, files in self.reader.walk("/"):
            # Filter out skip directories
            dirs[:] = [d for d in dirs if d.name not in self.SKIP_DIRS]

            for f in files:
                if self._should_scan_file(f):
                    scannable_files.append(f)
                    total_files += 1

        self._logger.info("Starting scan", total_files=total_files)

        # Scan files with progress reporting
        for i, file_entry in enumerate(scannable_files):
            try:
                self.progress.item_progress(i + 1, total_files, file_entry.path)

                # Skip files that are too large
                if file_entry.size > self.MAX_FILE_SIZE:
                    self._logger.debug(
                        "Skipping large file",
                        path=file_entry.path,
                        size=file_entry.size
                    )
                    continue

                # Read file and scan
                file_path = os.path.join(
                    self.reader.get_access_path(),
                    file_entry.path.lstrip("/")
                )

                matches = self._rules.match(file_path, timeout=60)

                if matches:
                    for match in matches:
                        finding = self._match_to_finding(match, file_entry)
                        findings.append(finding)
                        self.progress.increment_findings()

                        self._logger.info(
                            "YARA match found",
                            rule=match.rule,
                            file=file_entry.path
                        )

                files_scanned += 1
                bytes_scanned += file_entry.size

            except yara.TimeoutError:
                self._logger.warning("Scan timeout", path=file_entry.path)
                errors += 1
                self.progress.increment_errors()

            except Exception as e:
                self._logger.warning(
                    "Error scanning file",
                    path=file_entry.path,
                    error=str(e)
                )
                errors += 1
                self.progress.increment_errors()

        return {
            "findings": findings,
            "files_scanned": files_scanned,
            "bytes_scanned": bytes_scanned,
            "errors": errors,
        }

    def _should_scan_file(self, entry: FileEntry) -> bool:
        """Determine if a file should be scanned."""
        if not entry.is_file:
            return False

        # Check extension
        ext = Path(entry.name).suffix.lower()
        if ext not in self.SCAN_EXTENSIONS and ext != '':
            return False

        # Skip empty files
        if entry.size == 0:
            return False

        return True

    def _match_to_finding(self, match: yara.Match, file_entry: FileEntry) -> Finding:
        """Convert YARA match to normalized Finding."""
        # Extract metadata from rule
        meta = match.meta or {}
        severity_str = meta.get("severity", "medium").lower()
        severity = SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

        # Determine finding type from tags or metadata
        finding_type = FindingType.SUSPICIOUS_FILE
        tags = [t.lower() for t in (match.tags or [])]

        if "malware" in tags or meta.get("malware"):
            finding_type = FindingType.MALWARE
        elif "credential" in tags:
            finding_type = FindingType.CREDENTIAL
        elif "persistence" in tags:
            finding_type = FindingType.PERSISTENCE
        elif "lateral" in tags:
            finding_type = FindingType.LATERAL_MOVEMENT
        elif "exfil" in tags:
            finding_type = FindingType.DATA_EXFILTRATION

        # Get MITRE mapping
        mitre_tactic = None
        mitre_technique = None
        for tag in tags:
            if tag in MITRE_MAPPING:
                mitre_tactic, mitre_technique = MITRE_MAPPING[tag]
                break

        # Build description
        description = meta.get("description", f"YARA rule '{match.rule}' matched")

        # Extract matched strings (limit to avoid huge findings)
        matched_strings = []
        for string_match in match.strings[:10]:
            matched_strings.append(f"{string_match.identifier}: {string_match.instances[0].matched_data[:50]!r}")

        return Finding(
            id=create_finding_id("yara", match.rule, file_entry.path),
            type=finding_type,
            severity=severity,
            title=f"YARA: {match.rule}",
            description=description,
            file_path=file_entry.path,
            timestamp=file_entry.mtime,
            detected_at=datetime.now(timezone.utc),
            tool_name="yara",
            rule_name=match.rule,
            rule_id=match.namespace,
            confidence=float(meta.get("confidence", 0.8)),
            indicators=matched_strings,
            related_files=[],
            metadata={
                "tags": match.tags or [],
                "meta": meta,
                "namespace": match.namespace,
                "file_size": file_entry.size,
                "file_permissions": file_entry.permissions,
            },
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
        )

    def _upload_raw_results(self, findings: list[Finding]) -> None:
        """Upload raw YARA output for archival."""
        # Create YARA-native format output
        raw_output = []
        for finding in findings:
            raw_output.append({
                "rule": finding.rule_name,
                "namespace": finding.metadata.get("namespace"),
                "file": finding.file_path,
                "tags": finding.metadata.get("tags", []),
                "meta": finding.metadata.get("meta", {}),
                "strings": finding.indicators,
            })

        import json
        raw_json = json.dumps(raw_output, indent=2, default=str)

        self.result_handler.upload_raw_output(
            raw_json.encode("utf-8"),
            "matches.json",
            "application/json"
        )

        self._logger.info("Raw results uploaded", findings_count=len(findings))
