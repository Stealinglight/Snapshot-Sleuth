"""
Snapshot Reader - Storage access abstraction layer

Provides a strategy pattern interface for accessing EBS snapshot data.
Implementations:
- EBSMountReader: Primary approach using mounted EBS volumes (Phase 1)
- ColdSnapReader: Fallback for small snapshots (future)
- EBSDirectReader: Direct API access (Phase 3)
"""

import os
import stat
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Iterator, Optional, List, BinaryIO

import structlog

logger = structlog.get_logger(__name__)


class ReaderType(Enum):
    """Available snapshot reader implementations."""
    EBS_MOUNT = "ebs_mount"
    COLDSNAP = "coldsnap"
    EBS_DIRECT = "ebs_direct"


@dataclass
class AccessConfig:
    """Configuration for snapshot access."""
    snapshot_id: str
    region: str = "us-east-1"
    mount_path: str = "/mnt/evidence"
    read_only: bool = True
    timeout_seconds: int = 300
    # EBS Direct API specific (future)
    block_size: int = 512 * 1024  # 512KB blocks
    max_concurrent_reads: int = 10


@dataclass
class FileEntry:
    """Represents a file or directory entry."""
    path: str
    name: str
    size: int
    is_directory: bool
    is_file: bool
    is_symlink: bool
    mode: int
    uid: int
    gid: int
    atime: Optional[datetime] = None
    mtime: Optional[datetime] = None
    ctime: Optional[datetime] = None
    # Extended attributes
    inode: Optional[int] = None
    link_count: int = 1
    symlink_target: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    @property
    def permissions(self) -> str:
        """Return human-readable permissions string."""
        return stat.filemode(self.mode)

    @property
    def is_executable(self) -> bool:
        """Check if file has execute permission."""
        return bool(self.mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))

    @property
    def is_setuid(self) -> bool:
        """Check if file has setuid bit."""
        return bool(self.mode & stat.S_ISUID)

    @property
    def is_setgid(self) -> bool:
        """Check if file has setgid bit."""
        return bool(self.mode & stat.S_ISGID)


class SnapshotReader(ABC):
    """
    Abstract base class for snapshot data access.

    Implements the strategy pattern to allow different access methods
    while maintaining a consistent interface for forensic tools.
    """

    def __init__(self, config: AccessConfig):
        self.config = config
        self._initialized = False
        self._logger = logger.bind(
            snapshot_id=config.snapshot_id,
            reader_type=self.reader_type.value
        )

    @property
    @abstractmethod
    def reader_type(self) -> ReaderType:
        """Return the type of this reader implementation."""
        pass

    @abstractmethod
    async def initialize(self) -> None:
        """
        Initialize the reader and prepare for access.

        This may involve mounting volumes, establishing connections,
        or other setup operations.
        """
        pass

    @abstractmethod
    def get_access_path(self) -> str:
        """
        Return the filesystem path where snapshot data is accessible.

        For mounted volumes, this is the mount point.
        For API-based access, this may be a virtual path.
        """
        pass

    @abstractmethod
    def read_file(self, path: str) -> bytes:
        """
        Read entire file contents.

        Args:
            path: Relative path within the snapshot

        Returns:
            File contents as bytes

        Raises:
            FileNotFoundError: If file doesn't exist
            PermissionError: If access is denied
            IOError: For other read errors
        """
        pass

    @abstractmethod
    def read_file_chunked(
        self,
        path: str,
        chunk_size: int = 1024 * 1024
    ) -> Iterator[bytes]:
        """
        Read file in chunks for memory-efficient processing.

        Args:
            path: Relative path within the snapshot
            chunk_size: Size of each chunk in bytes (default 1MB)

        Yields:
            File content chunks
        """
        pass

    @abstractmethod
    def open_file(self, path: str) -> BinaryIO:
        """
        Open file for reading and return file handle.

        Args:
            path: Relative path within the snapshot

        Returns:
            Binary file handle (caller must close)
        """
        pass

    @abstractmethod
    def list_directory(self, path: str = "/") -> List[FileEntry]:
        """
        List contents of a directory.

        Args:
            path: Relative path to directory

        Returns:
            List of FileEntry objects for directory contents
        """
        pass

    @abstractmethod
    def walk(
        self,
        path: str = "/",
        max_depth: Optional[int] = None
    ) -> Iterator[tuple[str, List[FileEntry], List[FileEntry]]]:
        """
        Walk directory tree recursively.

        Args:
            path: Starting path
            max_depth: Maximum recursion depth (None for unlimited)

        Yields:
            Tuples of (dirpath, directories, files)
        """
        pass

    @abstractmethod
    def stat(self, path: str) -> FileEntry:
        """
        Get file/directory metadata.

        Args:
            path: Relative path to file or directory

        Returns:
            FileEntry with metadata
        """
        pass

    @abstractmethod
    def exists(self, path: str) -> bool:
        """Check if path exists."""
        pass

    @abstractmethod
    def is_file(self, path: str) -> bool:
        """Check if path is a regular file."""
        pass

    @abstractmethod
    def is_directory(self, path: str) -> bool:
        """Check if path is a directory."""
        pass

    @abstractmethod
    async def cleanup(self) -> None:
        """
        Clean up resources.

        This should unmount volumes, close connections, and
        release any held resources.
        """
        pass

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensure cleanup."""
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(self.cleanup())
            else:
                loop.run_until_complete(self.cleanup())
        except RuntimeError:
            asyncio.run(self.cleanup())
        return False


class EBSMountReader(SnapshotReader):
    """
    SnapshotReader implementation using mounted EBS volumes.

    This is the primary access method for Phase 1 of the Fargate migration.
    The EBS volume is created from the snapshot and mounted read-only
    at the configured mount path.
    """

    @property
    def reader_type(self) -> ReaderType:
        return ReaderType.EBS_MOUNT

    async def initialize(self) -> None:
        """
        Verify the EBS volume is mounted and accessible.

        Note: Actual volume creation and mounting is handled by
        the orchestration layer (Step Functions / ECS task definition).
        This method validates the mount is ready.
        """
        mount_path = Path(self.config.mount_path)

        if not mount_path.exists():
            raise RuntimeError(
                f"Mount path does not exist: {self.config.mount_path}"
            )

        if not mount_path.is_dir():
            raise RuntimeError(
                f"Mount path is not a directory: {self.config.mount_path}"
            )

        # Check if mount is accessible
        try:
            list(mount_path.iterdir())
        except PermissionError as e:
            raise PermissionError(
                f"Cannot access mount path: {self.config.mount_path}"
            ) from e

        self._initialized = True
        self._logger.info(
            "EBS mount reader initialized",
            mount_path=self.config.mount_path
        )

    def get_access_path(self) -> str:
        return self.config.mount_path

    def _resolve_path(self, path: str) -> Path:
        """Resolve relative path to absolute path within mount."""
        # Normalize and make relative
        path = path.lstrip("/")
        full_path = Path(self.config.mount_path) / path

        # Security: ensure path doesn't escape mount point
        try:
            resolved = full_path.resolve()
            mount_resolved = Path(self.config.mount_path).resolve()
            if not str(resolved).startswith(str(mount_resolved)):
                raise ValueError(f"Path escapes mount point: {path}")
        except (OSError, ValueError) as e:
            raise ValueError(f"Invalid path: {path}") from e

        return full_path

    def read_file(self, path: str) -> bytes:
        file_path = self._resolve_path(path)

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        if not file_path.is_file():
            raise IsADirectoryError(f"Path is not a file: {path}")

        return file_path.read_bytes()

    def read_file_chunked(
        self,
        path: str,
        chunk_size: int = 1024 * 1024
    ) -> Iterator[bytes]:
        file_path = self._resolve_path(path)

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                yield chunk

    def open_file(self, path: str) -> BinaryIO:
        file_path = self._resolve_path(path)

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        return open(file_path, "rb")

    def list_directory(self, path: str = "/") -> List[FileEntry]:
        dir_path = self._resolve_path(path)

        if not dir_path.exists():
            raise FileNotFoundError(f"Directory not found: {path}")

        if not dir_path.is_dir():
            raise NotADirectoryError(f"Path is not a directory: {path}")

        entries = []
        for item in dir_path.iterdir():
            try:
                entries.append(self._path_to_entry(item, path))
            except (OSError, PermissionError) as e:
                self._logger.warning(
                    "Failed to stat entry",
                    path=str(item),
                    error=str(e)
                )

        return entries

    def walk(
        self,
        path: str = "/",
        max_depth: Optional[int] = None
    ) -> Iterator[tuple[str, List[FileEntry], List[FileEntry]]]:
        """Walk directory tree with optional depth limit."""
        start_path = self._resolve_path(path)
        start_depth = len(start_path.parts)

        for root, dirs, files in os.walk(start_path):
            root_path = Path(root)
            current_depth = len(root_path.parts) - start_depth

            if max_depth is not None and current_depth > max_depth:
                dirs.clear()  # Don't recurse deeper
                continue

            # Convert to relative path from mount
            rel_root = "/" + str(root_path.relative_to(self.config.mount_path))

            dir_entries = []
            file_entries = []

            for d in dirs:
                try:
                    entry = self._path_to_entry(root_path / d, rel_root)
                    dir_entries.append(entry)
                except (OSError, PermissionError):
                    pass

            for f in files:
                try:
                    entry = self._path_to_entry(root_path / f, rel_root)
                    file_entries.append(entry)
                except (OSError, PermissionError):
                    pass

            yield rel_root, dir_entries, file_entries

    def _path_to_entry(self, path: Path, parent: str) -> FileEntry:
        """Convert Path to FileEntry with full metadata."""
        st = path.lstat()  # lstat to not follow symlinks

        entry = FileEntry(
            path=f"{parent.rstrip('/')}/{path.name}",
            name=path.name,
            size=st.st_size,
            is_directory=stat.S_ISDIR(st.st_mode),
            is_file=stat.S_ISREG(st.st_mode),
            is_symlink=stat.S_ISLNK(st.st_mode),
            mode=st.st_mode,
            uid=st.st_uid,
            gid=st.st_gid,
            atime=datetime.fromtimestamp(st.st_atime),
            mtime=datetime.fromtimestamp(st.st_mtime),
            ctime=datetime.fromtimestamp(st.st_ctime),
            inode=st.st_ino,
            link_count=st.st_nlink,
        )

        if entry.is_symlink:
            try:
                entry.symlink_target = os.readlink(path)
            except OSError:
                pass

        return entry

    def stat(self, path: str) -> FileEntry:
        file_path = self._resolve_path(path)

        if not file_path.exists():
            raise FileNotFoundError(f"Path not found: {path}")

        parent = str(Path(path).parent)
        return self._path_to_entry(file_path, parent)

    def exists(self, path: str) -> bool:
        try:
            file_path = self._resolve_path(path)
            return file_path.exists()
        except ValueError:
            return False

    def is_file(self, path: str) -> bool:
        try:
            file_path = self._resolve_path(path)
            return file_path.is_file()
        except ValueError:
            return False

    def is_directory(self, path: str) -> bool:
        try:
            file_path = self._resolve_path(path)
            return file_path.is_dir()
        except ValueError:
            return False

    async def cleanup(self) -> None:
        """
        Cleanup for EBS mount reader.

        Note: Actual volume unmounting and deletion is handled by
        the orchestration layer (Step Functions cleanup task).
        """
        self._initialized = False
        self._logger.info("EBS mount reader cleanup complete")


# Factory function for creating readers
def create_reader(
    reader_type: ReaderType,
    config: AccessConfig
) -> SnapshotReader:
    """
    Factory function to create appropriate SnapshotReader instance.

    Args:
        reader_type: Type of reader to create
        config: Access configuration

    Returns:
        SnapshotReader implementation

    Raises:
        ValueError: If reader type is not supported
    """
    readers = {
        ReaderType.EBS_MOUNT: EBSMountReader,
        # Future implementations:
        # ReaderType.COLDSNAP: ColdSnapReader,
        # ReaderType.EBS_DIRECT: EBSDirectReader,
    }

    reader_class = readers.get(reader_type)
    if reader_class is None:
        raise ValueError(f"Unsupported reader type: {reader_type}")

    return reader_class(config)
