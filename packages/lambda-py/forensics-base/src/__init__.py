"""
Snapshot-Sleuth Forensics Base Package

This package provides shared functionality for all forensic tool containers:
- SnapshotReader implementations for storage access
- Heartbeat emission for progress tracking
- Result upload and normalization
- Common forensic utilities
"""

__version__ = "2.0.0"

from .snapshot_reader import (
    SnapshotReader,
    EBSMountReader,
    AccessConfig,
    FileEntry,
)
from .heartbeat import HeartbeatEmitter
from .result_handler import ResultHandler, NormalizedResult, Finding
from .progress import ProgressReporter

__all__ = [
    # Snapshot access
    "SnapshotReader",
    "EBSMountReader",
    "AccessConfig",
    "FileEntry",
    # Progress tracking
    "HeartbeatEmitter",
    "ProgressReporter",
    # Results
    "ResultHandler",
    "NormalizedResult",
    "Finding",
]
