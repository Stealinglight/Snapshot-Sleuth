"""
Progress Reporter - Unified progress tracking for forensic tools

Provides a high-level interface for tools to report progress,
integrating with the HeartbeatEmitter for EventBridge updates.
"""

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Iterator, Optional, TypeVar

import structlog

from .heartbeat import HeartbeatEmitter

logger = structlog.get_logger(__name__)

T = TypeVar("T")


@dataclass
class PhaseInfo:
    """Information about a processing phase."""
    name: str
    weight: float = 1.0  # Relative weight for progress calculation
    description: str = ""


class ProgressReporter:
    """
    High-level progress reporting for forensic tools.

    Manages phases of processing and automatically calculates
    overall progress percentage based on phase completion.

    Example:
        reporter = ProgressReporter(heartbeat_emitter)
        reporter.define_phases([
            PhaseInfo("scan", weight=0.3, description="Scanning filesystem"),
            PhaseInfo("analyze", weight=0.5, description="Analyzing files"),
            PhaseInfo("report", weight=0.2, description="Generating report"),
        ])

        with reporter.phase("scan"):
            for i, file in enumerate(files):
                reporter.item_progress(i + 1, len(files), file)
                process_file(file)

        with reporter.phase("analyze"):
            # ...
    """

    def __init__(self, heartbeat: HeartbeatEmitter):
        self._heartbeat = heartbeat
        self._phases: list[PhaseInfo] = []
        self._current_phase_index: int = -1
        self._phase_progress: float = 0.0
        self._logger = logger

    def define_phases(self, phases: list[PhaseInfo]) -> None:
        """
        Define the processing phases for this tool.

        Args:
            phases: List of PhaseInfo objects defining phases
        """
        # Normalize weights to sum to 1.0
        total_weight = sum(p.weight for p in phases)
        self._phases = [
            PhaseInfo(
                name=p.name,
                weight=p.weight / total_weight,
                description=p.description
            )
            for p in phases
        ]
        self._current_phase_index = -1
        self._phase_progress = 0.0
        self._logger.info(
            "Phases defined",
            phases=[p.name for p in self._phases]
        )

    @contextmanager
    def phase(self, name: str):
        """
        Context manager for a processing phase.

        Args:
            name: Name of the phase to enter

        Yields:
            None

        Example:
            with reporter.phase("scanning"):
                # do scanning work
        """
        # Find phase index
        phase_index = next(
            (i for i, p in enumerate(self._phases) if p.name == name),
            None
        )
        if phase_index is None:
            self._logger.warning(f"Unknown phase: {name}, using default")
            # Create a temporary phase
            self._phases.append(PhaseInfo(name=name, weight=0.1))
            phase_index = len(self._phases) - 1

        self._current_phase_index = phase_index
        self._phase_progress = 0.0

        phase = self._phases[phase_index]
        self._logger.info(
            "Entering phase",
            phase=name,
            description=phase.description
        )

        self._heartbeat.update_progress(
            current_phase=name,
            percent_complete=self._calculate_overall_progress()
        )

        try:
            yield
        finally:
            # Mark phase as complete
            self._phase_progress = 1.0
            self._heartbeat.update_progress(
                percent_complete=self._calculate_overall_progress()
            )
            self._logger.info("Phase complete", phase=name)

    def item_progress(
        self,
        current: int,
        total: int,
        item_name: Optional[str] = None
    ) -> None:
        """
        Report progress within current phase by item count.

        Args:
            current: Current item number (1-based)
            total: Total number of items
            item_name: Optional name of current item
        """
        if total > 0:
            self._phase_progress = current / total

        self._heartbeat.update_progress(
            percent_complete=self._calculate_overall_progress(),
            items_processed=current,
            items_total=total,
            current_item=item_name
        )

    def byte_progress(
        self,
        bytes_done: int,
        bytes_total: int,
        current_file: Optional[str] = None
    ) -> None:
        """
        Report progress within current phase by bytes processed.

        Args:
            bytes_done: Bytes processed so far
            bytes_total: Total bytes to process
            current_file: Optional name of current file
        """
        if bytes_total > 0:
            self._phase_progress = bytes_done / bytes_total

        self._heartbeat.update_progress(
            percent_complete=self._calculate_overall_progress(),
            bytes_processed=bytes_done,
            bytes_total=bytes_total,
            current_item=current_file
        )

    def increment_findings(self, count: int = 1) -> None:
        """Increment the findings count."""
        self._heartbeat.update_progress(
            findings_count=(self._heartbeat._progress.findings_count or 0) + count
        )

    def increment_errors(self, count: int = 1) -> None:
        """Increment the errors count."""
        self._heartbeat.update_progress(
            errors_count=(self._heartbeat._progress.errors_count or 0) + count
        )

    def increment_warnings(self, count: int = 1) -> None:
        """Increment the warnings count."""
        self._heartbeat.update_progress(
            warnings_count=(self._heartbeat._progress.warnings_count or 0) + count
        )

    def set_metadata(self, **kwargs) -> None:
        """Set additional metadata for heartbeats."""
        self._heartbeat.update_progress(metadata=kwargs)

    def _calculate_overall_progress(self) -> float:
        """
        Calculate overall progress based on completed phases.

        Returns:
            Progress percentage (0-100)
        """
        if not self._phases:
            return 0.0

        completed_weight = sum(
            p.weight for i, p in enumerate(self._phases)
            if i < self._current_phase_index
        )

        current_weight = 0.0
        if 0 <= self._current_phase_index < len(self._phases):
            current_weight = (
                self._phases[self._current_phase_index].weight *
                self._phase_progress
            )

        return (completed_weight + current_weight) * 100.0

    def wrap_iterator(
        self,
        items: Iterator[T],
        total: int,
        item_name_fn: Optional[Callable[[T], str]] = None
    ) -> Iterator[T]:
        """
        Wrap an iterator to automatically report progress.

        Args:
            items: Iterator to wrap
            total: Total number of items
            item_name_fn: Optional function to extract item name

        Yields:
            Items from the iterator

        Example:
            for file in reporter.wrap_iterator(files, len(files), lambda f: f.name):
                process_file(file)
        """
        for i, item in enumerate(items, 1):
            name = item_name_fn(item) if item_name_fn else None
            self.item_progress(i, total, name)
            yield item
