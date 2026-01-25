"""
Result Handler - Standardized result upload and normalization

Handles:
- Uploading raw tool output to S3
- Converting to normalized JSON schema
- Uploading normalized results
- Generating summary metadata
"""

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import boto3
from botocore.config import Config
import structlog

logger = structlog.get_logger(__name__)


class Severity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(str, Enum):
    """Types of forensic findings."""
    MALWARE = "malware"
    SUSPICIOUS_FILE = "suspicious_file"
    CREDENTIAL = "credential"
    PERSISTENCE = "persistence"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    TIMELINE_ANOMALY = "timeline_anomaly"
    CONFIGURATION_ISSUE = "configuration_issue"
    OTHER = "other"


@dataclass
class Finding:
    """
    Normalized forensic finding.

    All tools produce findings in this standardized format,
    enabling unified querying, correlation, and reporting.
    """
    id: str
    type: FindingType
    severity: Severity
    title: str
    description: str

    # Location information
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    offset: Optional[int] = None

    # Time information
    timestamp: Optional[datetime] = None
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Tool-specific data
    tool_name: str = ""
    rule_name: Optional[str] = None
    rule_id: Optional[str] = None
    confidence: float = 1.0

    # Additional context
    indicators: list[str] = field(default_factory=list)
    related_files: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    # MITRE ATT&CK mapping
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "type": self.type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "filePath": self.file_path,
            "lineNumber": self.line_number,
            "offset": self.offset,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "detectedAt": self.detected_at.isoformat(),
            "toolName": self.tool_name,
            "ruleName": self.rule_name,
            "ruleId": self.rule_id,
            "confidence": self.confidence,
            "indicators": self.indicators,
            "relatedFiles": self.related_files,
            "metadata": self.metadata,
            "mitreTactic": self.mitre_tactic,
            "mitreTechnique": self.mitre_technique,
        }


@dataclass
class NormalizedResult:
    """
    Normalized tool execution result.

    This is the standard output format for all forensic tools.
    """
    tool_name: str
    case_id: str
    snapshot_id: str
    status: str  # success, partial, failed

    # Execution metadata
    started_at: datetime
    completed_at: datetime
    duration_seconds: float

    # Results
    findings: list[Finding] = field(default_factory=list)

    # Statistics
    files_scanned: int = 0
    bytes_scanned: int = 0
    errors_count: int = 0
    warnings_count: int = 0

    # Tool version info
    tool_version: str = ""
    signature_version: Optional[str] = None

    # Additional metadata
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "toolName": self.tool_name,
            "caseId": self.case_id,
            "snapshotId": self.snapshot_id,
            "status": self.status,
            "startedAt": self.started_at.isoformat(),
            "completedAt": self.completed_at.isoformat(),
            "durationSeconds": self.duration_seconds,
            "findings": [f.to_dict() for f in self.findings],
            "statistics": {
                "filesScanned": self.files_scanned,
                "bytesScanned": self.bytes_scanned,
                "findingsCount": len(self.findings),
                "errorsCount": self.errors_count,
                "warningsCount": self.warnings_count,
            },
            "severityCounts": self._count_by_severity(),
            "typeCounts": self._count_by_type(),
            "toolVersion": self.tool_version,
            "signatureVersion": self.signature_version,
            "metadata": self.metadata,
        }

    def _count_by_severity(self) -> dict[str, int]:
        """Count findings by severity."""
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def _count_by_type(self) -> dict[str, int]:
        """Count findings by type."""
        counts: dict[str, int] = {}
        for finding in self.findings:
            type_val = finding.type.value
            counts[type_val] = counts.get(type_val, 0) + 1
        return counts


class ResultHandler:
    """
    Handles uploading and organizing tool results in S3.

    Results are stored in the following structure:
    s3://evidence-bucket/cases/{case-id}/
    ├── metadata.json
    ├── summary.json
    ├── {tool-name}/
    │   ├── results.json      # Normalized format
    │   └── raw/              # Native tool output
    │       └── ...
    """

    def __init__(
        self,
        case_id: str,
        tool_name: str,
        evidence_bucket: str,
        region: str = "us-east-1",
    ):
        self.case_id = case_id
        self.tool_name = tool_name
        self.evidence_bucket = evidence_bucket
        self.region = region

        self._s3_client = boto3.client(
            "s3",
            region_name=region,
            config=Config(
                retries={"max_attempts": 3, "mode": "adaptive"}
            )
        )

        self._logger = logger.bind(
            case_id=case_id,
            tool=tool_name,
            bucket=evidence_bucket
        )

        self._base_prefix = f"cases/{case_id}/{tool_name}"

    def upload_raw_output(
        self,
        content: bytes,
        filename: str,
        content_type: str = "application/octet-stream"
    ) -> str:
        """
        Upload raw tool output to S3.

        Args:
            content: Raw output content
            filename: Filename for the output
            content_type: MIME type

        Returns:
            S3 URI of uploaded file
        """
        key = f"{self._base_prefix}/raw/{filename}"

        self._s3_client.put_object(
            Bucket=self.evidence_bucket,
            Key=key,
            Body=content,
            ContentType=content_type,
            ServerSideEncryption="aws:kms",
        )

        uri = f"s3://{self.evidence_bucket}/{key}"
        self._logger.info("Uploaded raw output", key=key, size=len(content))
        return uri

    def upload_raw_file(
        self,
        local_path: str,
        s3_filename: Optional[str] = None,
        content_type: str = "application/octet-stream"
    ) -> str:
        """
        Upload a local file as raw output.

        Args:
            local_path: Path to local file
            s3_filename: Optional S3 filename (defaults to local filename)
            content_type: MIME type

        Returns:
            S3 URI of uploaded file
        """
        path = Path(local_path)
        filename = s3_filename or path.name
        key = f"{self._base_prefix}/raw/{filename}"

        self._s3_client.upload_file(
            str(path),
            self.evidence_bucket,
            key,
            ExtraArgs={
                "ContentType": content_type,
                "ServerSideEncryption": "aws:kms",
            }
        )

        uri = f"s3://{self.evidence_bucket}/{key}"
        self._logger.info("Uploaded raw file", key=key, local_path=local_path)
        return uri

    def upload_raw_directory(self, local_dir: str, prefix: str = "") -> list[str]:
        """
        Upload entire directory as raw output.

        Args:
            local_dir: Path to local directory
            prefix: Optional prefix within raw/ directory

        Returns:
            List of S3 URIs for uploaded files
        """
        uris = []
        local_path = Path(local_dir)

        for file_path in local_path.rglob("*"):
            if file_path.is_file():
                relative = file_path.relative_to(local_path)
                s3_filename = f"{prefix}/{relative}" if prefix else str(relative)
                uri = self.upload_raw_file(str(file_path), s3_filename)
                uris.append(uri)

        self._logger.info(
            "Uploaded raw directory",
            local_dir=local_dir,
            files_count=len(uris)
        )
        return uris

    def upload_normalized_results(self, result: NormalizedResult) -> str:
        """
        Upload normalized results JSON.

        Args:
            result: NormalizedResult object

        Returns:
            S3 URI of results file
        """
        key = f"{self._base_prefix}/results.json"

        content = json.dumps(result.to_dict(), indent=2, default=str)

        self._s3_client.put_object(
            Bucket=self.evidence_bucket,
            Key=key,
            Body=content.encode("utf-8"),
            ContentType="application/json",
            ServerSideEncryption="aws:kms",
        )

        uri = f"s3://{self.evidence_bucket}/{key}"
        self._logger.info(
            "Uploaded normalized results",
            key=key,
            findings_count=len(result.findings)
        )
        return uri

    def get_results_uri(self) -> str:
        """Get the S3 URI where normalized results will be stored."""
        return f"s3://{self.evidence_bucket}/{self._base_prefix}/results.json"

    def get_raw_uri(self) -> str:
        """Get the S3 URI prefix for raw output."""
        return f"s3://{self.evidence_bucket}/{self._base_prefix}/raw/"


def create_finding_id(tool: str, rule: str, file_path: str) -> str:
    """
    Generate a deterministic finding ID.

    Args:
        tool: Tool name
        rule: Rule/signature name
        file_path: Path to file with finding

    Returns:
        Unique finding ID
    """
    import hashlib
    content = f"{tool}:{rule}:{file_path}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]
