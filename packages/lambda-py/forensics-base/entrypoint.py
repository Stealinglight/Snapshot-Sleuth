#!/usr/bin/env python3
"""
Forensic Tool Entrypoint Wrapper

This script serves as the common entrypoint for all forensic tool containers.
It provides:
- Environment validation
- Heartbeat initialization
- Standardized tool invocation
- Result handling
- Error management and reporting

Tools implement a standard interface and are dynamically loaded based on
the TOOL_NAME environment variable.
"""

import importlib
import os
import sys
import traceback
from datetime import datetime, timezone
from typing import Any, Optional

import structlog

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)

# Import base components
from src.heartbeat import HeartbeatEmitter, HeartbeatConfig
from src.progress import ProgressReporter
from src.result_handler import ResultHandler, NormalizedResult
from src.snapshot_reader import (
    EBSMountReader,
    AccessConfig,
    ReaderType,
    create_reader,
)


class ToolConfig:
    """Configuration loaded from environment variables."""

    def __init__(self):
        self.case_id = self._require_env("CASE_ID")
        self.snapshot_id = self._require_env("SNAPSHOT_ID")
        self.tool_name = self._require_env("TOOL_NAME")
        self.evidence_bucket = self._require_env("EVIDENCE_BUCKET")

        # Optional configuration
        self.region = os.environ.get("AWS_REGION", "us-east-1")
        self.mount_path = os.environ.get("MOUNT_PATH", "/mnt/evidence")
        self.output_path = os.environ.get("OUTPUT_PATH", "/output")
        self.heartbeat_interval = int(
            os.environ.get("HEARTBEAT_INTERVAL_SECONDS", "30")
        )
        self.event_bus_name = os.environ.get("EVENT_BUS_NAME", "default")
        self.signature_bucket = os.environ.get("SIGNATURE_BUCKET", "")
        self.signature_prefix = os.environ.get("SIGNATURE_PREFIX", "signatures/")

        # Debug mode
        self.debug = os.environ.get("DEBUG", "false").lower() == "true"

    def _require_env(self, name: str) -> str:
        """Get required environment variable or raise error."""
        value = os.environ.get(name)
        if not value:
            raise ValueError(f"Required environment variable not set: {name}")
        return value


class ToolInterface:
    """
    Abstract interface that all forensic tools must implement.

    Tools should create a module with a class that extends this interface.
    """

    def __init__(
        self,
        config: ToolConfig,
        reader: EBSMountReader,
        progress: ProgressReporter,
        result_handler: ResultHandler,
    ):
        self.config = config
        self.reader = reader
        self.progress = progress
        self.result_handler = result_handler

    def run(self) -> NormalizedResult:
        """
        Execute the forensic tool.

        Returns:
            NormalizedResult containing findings and metadata
        """
        raise NotImplementedError("Tools must implement run()")


def load_tool_class(tool_name: str) -> type:
    """
    Dynamically load the tool class based on tool name.

    Tools are expected to be in modules named:
    - tools.yara_tool.YaraTool
    - tools.clamav_tool.ClamavTool
    - tools.evidence_miner_tool.EvidenceMinerTool
    - tools.log2timeline_tool.Log2TimelineTool
    """
    tool_mapping = {
        "yara": ("tools.yara_tool", "YaraTool"),
        "clamav": ("tools.clamav_tool", "ClamavTool"),
        "evidence-miner": ("tools.evidence_miner_tool", "EvidenceMinerTool"),
        "log2timeline": ("tools.log2timeline_tool", "Log2TimelineTool"),
    }

    if tool_name not in tool_mapping:
        raise ValueError(f"Unknown tool: {tool_name}")

    module_name, class_name = tool_mapping[tool_name]
    module = importlib.import_module(module_name)
    return getattr(module, class_name)


def main() -> int:
    """
    Main entrypoint for forensic tool execution.

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    start_time = datetime.now(timezone.utc)

    try:
        # Load configuration
        config = ToolConfig()

        logger.info(
            "Starting forensic tool",
            tool=config.tool_name,
            case_id=config.case_id,
            snapshot_id=config.snapshot_id,
        )

        # Initialize heartbeat emitter
        heartbeat_config = HeartbeatConfig(
            case_id=config.case_id,
            tool_name=config.tool_name,
            snapshot_id=config.snapshot_id,
            interval_seconds=config.heartbeat_interval,
            event_bus_name=config.event_bus_name,
            region=config.region,
        )
        heartbeat = HeartbeatEmitter(heartbeat_config)

        # Initialize progress reporter
        progress = ProgressReporter(heartbeat)

        # Initialize snapshot reader
        access_config = AccessConfig(
            snapshot_id=config.snapshot_id,
            region=config.region,
            mount_path=config.mount_path,
            read_only=True,
        )
        reader = create_reader(ReaderType.EBS_MOUNT, access_config)

        # Initialize result handler
        result_handler = ResultHandler(
            case_id=config.case_id,
            tool_name=config.tool_name,
            evidence_bucket=config.evidence_bucket,
            region=config.region,
        )

        # Load and instantiate tool
        tool_class = load_tool_class(config.tool_name)
        tool = tool_class(config, reader, progress, result_handler)

        # Start heartbeat and run tool
        with heartbeat:
            # Initialize reader
            import asyncio
            asyncio.run(reader.initialize())

            # Execute tool
            result = tool.run()

            # Upload results
            result_handler.upload_normalized_results(result)

            # Emit final heartbeat
            heartbeat.emit_final_heartbeat(
                status="completed" if result.status == "success" else "partial",
                summary={
                    "findingsCount": len(result.findings),
                    "filesScanned": result.files_scanned,
                    "errorsCount": result.errors_count,
                }
            )

        # Cleanup
        asyncio.run(reader.cleanup())

        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()

        logger.info(
            "Tool execution completed",
            tool=config.tool_name,
            status=result.status,
            findings_count=len(result.findings),
            duration_seconds=duration,
        )

        return 0 if result.status == "success" else 0  # Partial is still success

    except Exception as e:
        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()

        logger.error(
            "Tool execution failed",
            error=str(e),
            traceback=traceback.format_exc(),
            duration_seconds=duration,
        )

        # Try to emit failure heartbeat
        try:
            if "heartbeat" in locals():
                heartbeat.emit_final_heartbeat(
                    status="failed",
                    summary={"error": str(e)}
                )
        except Exception:
            pass

        return 1


if __name__ == "__main__":
    sys.exit(main())
