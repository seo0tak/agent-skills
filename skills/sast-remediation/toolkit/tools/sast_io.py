"""Local cooperating-writer lock and collision-free single-file replacement.

Locks are advisory and released by the OS when a process exits. The lock file
stays in place; never unlink it while other processes may hold the same inode.
These helpers do not provide a multi-file or distributed transaction.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import tempfile


@contextmanager
def writer_lock(root: Path):
    path = root / ".sast-write.lock"
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    if path.is_symlink():
        raise ValueError("writer lock must not be a symlink")
    descriptor = os.open(path, flags, 0o600)
    try:
        if os.name == "nt":
            import msvcrt
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        # Closing also releases locks after exceptions; crash cleanup is OS-owned.
        os.close(descriptor)


def write_text_atomic(path: Path, content: str) -> None:
    """Replace one file, retaining permissions; callers lock read/modify/write."""
    write_bytes_atomic(path, content.encode("utf-8"))


def write_bytes_atomic(path: Path, content: bytes) -> None:
    """Also preserve malformed/non-text originals when writing recovery backups."""
    if path.is_symlink():
        raise ValueError(f"refusing symlink destination: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            if path.exists():
                os.chmod(temporary_path, path.stat().st_mode & 0o777)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)
