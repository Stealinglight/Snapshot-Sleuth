"""
Heartbeat Emitter - EventBridge progress tracking

Emits regular heartbeat events to EventBridge for:
- Progress monitoring by Step Functions
- Stall detection (no heartbeat = potential issue)
- Dashboard/alerting integration
"""

import asyncio
import json
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

import boto3
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class HeartbeatConfig:
    """Configuration for heartbeat emission."""
    case_id: str
    tool_name: str
    snapshot_id: str
    interval_seconds: int = 30
    event_bus_name: str = "default"
    source: str = "snapshot-sleuth.forensics"
    detail_type: str = "ToolHeartbeat"
    region: str = field(default_factory=lambda: os.environ.get("AWS_REGION", "us-east-1"))


@dataclass
class ProgressInfo:
    """Current progress information."""
    percent_complete: float = 0.0
    current_phase: str = "initializing"
    items_processed: int = 0
    items_total: Optional[int] = None
    current_item: Optional[str] = None
    bytes_processed: int = 0
    bytes_total: Optional[int] = None
    findings_count: int = 0
    errors_count: int = 0
    warnings_count: int = 0
    metadata: dict = field(default_factory=dict)


class HeartbeatEmitter:
    """
    Emits regular heartbeat events to EventBridge.

    Heartbeats include:
    - Case and tool identification
    - Progress percentage
    - Current phase/activity
    - Timestamps for timing analysis

    The orchestration layer uses these heartbeats to:
    - Monitor task health
    - Detect stalls (no heartbeat for 3-5 minutes)
    - Update dashboards
    - Calculate ETAs
    """

    def __init__(self, config: HeartbeatConfig):
        self.config = config
        self._progress = ProgressInfo()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._start_time: Optional[datetime] = None
        self._last_heartbeat: Optional[datetime] = None
        self._heartbeat_count = 0

        # Initialize EventBridge client
        self._events_client = boto3.client(
            "events",
            region_name=config.region
        )

        self._logger = logger.bind(
            case_id=config.case_id,
            tool=config.tool_name,
            snapshot_id=config.snapshot_id
        )

    def start(self) -> None:
        """Start emitting heartbeats in background thread."""
        if self._running:
            self._logger.warning("Heartbeat emitter already running")
            return

        self._running = True
        self._start_time = datetime.now(timezone.utc)
        self._thread = threading.Thread(
            target=self._heartbeat_loop,
            daemon=True,
            name=f"heartbeat-{self.config.tool_name}"
        )
        self._thread.start()
        self._logger.info(
            "Heartbeat emitter started",
            interval_seconds=self.config.interval_seconds
        )

    def stop(self) -> None:
        """Stop emitting heartbeats."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        self._logger.info(
            "Heartbeat emitter stopped",
            total_heartbeats=self._heartbeat_count
        )

    def update_progress(
        self,
        percent_complete: Optional[float] = None,
        current_phase: Optional[str] = None,
        items_processed: Optional[int] = None,
        items_total: Optional[int] = None,
        current_item: Optional[str] = None,
        bytes_processed: Optional[int] = None,
        bytes_total: Optional[int] = None,
        findings_count: Optional[int] = None,
        errors_count: Optional[int] = None,
        warnings_count: Optional[int] = None,
        metadata: Optional[dict] = None
    ) -> None:
        """Update progress information for next heartbeat."""
        with self._lock:
            if percent_complete is not None:
                self._progress.percent_complete = min(100.0, max(0.0, percent_complete))
            if current_phase is not None:
                self._progress.current_phase = current_phase
            if items_processed is not None:
                self._progress.items_processed = items_processed
            if items_total is not None:
                self._progress.items_total = items_total
            if current_item is not None:
                self._progress.current_item = current_item
            if bytes_processed is not None:
                self._progress.bytes_processed = bytes_processed
            if bytes_total is not None:
                self._progress.bytes_total = bytes_total
            if findings_count is not None:
                self._progress.findings_count = findings_count
            if errors_count is not None:
                self._progress.errors_count = errors_count
            if warnings_count is not None:
                self._progress.warnings_count = warnings_count
            if metadata is not None:
                self._progress.metadata.update(metadata)

    def _heartbeat_loop(self) -> None:
        """Background loop for emitting heartbeats."""
        while self._running:
            try:
                self._emit_heartbeat()
            except Exception as e:
                self._logger.error(
                    "Failed to emit heartbeat",
                    error=str(e)
                )
            time.sleep(self.config.interval_seconds)

    def _emit_heartbeat(self) -> None:
        """Emit a single heartbeat event to EventBridge."""
        now = datetime.now(timezone.utc)

        with self._lock:
            progress_snapshot = ProgressInfo(
                percent_complete=self._progress.percent_complete,
                current_phase=self._progress.current_phase,
                items_processed=self._progress.items_processed,
                items_total=self._progress.items_total,
                current_item=self._progress.current_item,
                bytes_processed=self._progress.bytes_processed,
                bytes_total=self._progress.bytes_total,
                findings_count=self._progress.findings_count,
                errors_count=self._progress.errors_count,
                warnings_count=self._progress.warnings_count,
                metadata=dict(self._progress.metadata)
            )

        # Calculate elapsed time
        elapsed_seconds = 0
        if self._start_time:
            elapsed_seconds = (now - self._start_time).total_seconds()

        # Build event detail
        detail = {
            "caseId": self.config.case_id,
            "tool": self.config.tool_name,
            "snapshotId": self.config.snapshot_id,
            "timestamp": now.isoformat(),
            "heartbeatNumber": self._heartbeat_count + 1,
            "elapsedSeconds": int(elapsed_seconds),
            "progress": {
                "percentComplete": round(progress_snapshot.percent_complete, 2),
                "currentPhase": progress_snapshot.current_phase,
                "itemsProcessed": progress_snapshot.items_processed,
                "itemsTotal": progress_snapshot.items_total,
                "currentItem": progress_snapshot.current_item,
                "bytesProcessed": progress_snapshot.bytes_processed,
                "bytesTotal": progress_snapshot.bytes_total,
                "findingsCount": progress_snapshot.findings_count,
                "errorsCount": progress_snapshot.errors_count,
                "warningsCount": progress_snapshot.warnings_count,
            },
            "metadata": progress_snapshot.metadata
        }

        # Emit to EventBridge
        response = self._events_client.put_events(
            Entries=[
                {
                    "Source": self.config.source,
                    "DetailType": self.config.detail_type,
                    "Detail": json.dumps(detail),
                    "EventBusName": self.config.event_bus_name,
                }
            ]
        )

        # Check for failures
        if response.get("FailedEntryCount", 0) > 0:
            failed = response.get("Entries", [{}])[0]
            self._logger.warning(
                "Heartbeat event failed",
                error_code=failed.get("ErrorCode"),
                error_message=failed.get("ErrorMessage")
            )
        else:
            self._heartbeat_count += 1
            self._last_heartbeat = now
            self._logger.debug(
                "Heartbeat emitted",
                heartbeat_number=self._heartbeat_count,
                percent_complete=progress_snapshot.percent_complete
            )

    def emit_final_heartbeat(self, status: str, summary: Optional[dict] = None) -> None:
        """
        Emit a final heartbeat indicating task completion.

        Args:
            status: Final status (completed, failed, timeout)
            summary: Optional summary data to include
        """
        now = datetime.now(timezone.utc)

        elapsed_seconds = 0
        if self._start_time:
            elapsed_seconds = (now - self._start_time).total_seconds()

        detail = {
            "caseId": self.config.case_id,
            "tool": self.config.tool_name,
            "snapshotId": self.config.snapshot_id,
            "timestamp": now.isoformat(),
            "heartbeatNumber": self._heartbeat_count + 1,
            "elapsedSeconds": int(elapsed_seconds),
            "final": True,
            "status": status,
            "progress": {
                "percentComplete": 100.0 if status == "completed" else self._progress.percent_complete,
                "currentPhase": "completed" if status == "completed" else "failed",
                "findingsCount": self._progress.findings_count,
                "errorsCount": self._progress.errors_count,
            },
            "summary": summary or {}
        }

        try:
            self._events_client.put_events(
                Entries=[
                    {
                        "Source": self.config.source,
                        "DetailType": "ToolCompleted",
                        "Detail": json.dumps(detail),
                        "EventBusName": self.config.event_bus_name,
                    }
                ]
            )
            self._logger.info(
                "Final heartbeat emitted",
                status=status,
                total_heartbeats=self._heartbeat_count + 1,
                elapsed_seconds=elapsed_seconds
            )
        except Exception as e:
            self._logger.error(
                "Failed to emit final heartbeat",
                error=str(e)
            )

    def __enter__(self):
        """Context manager - start on enter."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager - stop on exit."""
        if exc_type is not None:
            self.emit_final_heartbeat(
                status="failed",
                summary={"error": str(exc_val)}
            )
        self.stop()
        return False
