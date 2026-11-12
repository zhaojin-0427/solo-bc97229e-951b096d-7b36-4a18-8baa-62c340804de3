"""File-system primitives shared by ingestion, inspection and repair.

All writes are crash-safe: bytes land in a unique ``.part`` sibling first, are
hashed/verified, and only then atomically ``os.replace``d onto their final
path. A process killed mid-operation can therefore never leave a truncated
"final" object that callers might mistake for the real thing; a startup sweep
removes the orphaned parts.
"""
from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import config


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%fZ")

# Suffixes used for in-progress / pre-commit files; also matched by the sweep.
PART_SUFFIX = ".part"
BACKUP_SUFFIX_PATTERN = ".bak-"

_CHUNK = 1024 * 1024


def sha256_file(path: Path) -> str:
    """Return the hex SHA-256 of a file, streaming it in chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_write(directory: Path, final_name: str, content: bytes) -> tuple[Path, Path]:
    """Write ``content`` into ``directory/final_name`` atomically.

    Returns ``(temp_path, final_path)``. The caller is expected to verify the
    temp file (e.g. hash it) and then call :func:`commit_atomic_write`. If the
    surrounding DB transaction rolls back, delete ``temp_path``.
    """
    directory.mkdir(parents=True, exist_ok=True)
    temp_path = directory / f".{final_name}.{uuid.uuid4().hex}{PART_SUFFIX}"
    # Single write + fsync so a crash cannot leave a partially flushed part.
    fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        os.write(fd, content)
        os.fsync(fd)
    finally:
        os.close(fd)
    return temp_path, directory / final_name


def commit_atomic_write(temp_path: Path, final_path: Path) -> None:
    """Promote a verified part to its final name (same-fs atomic rename)."""
    os.replace(temp_path, final_path)
    # Best-effort directory fsync so the rename itself survives power loss.
    try:
        dir_fd = os.open(final_path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass


def quarantine_target(center_id: str, run_id: str, instance_id: int) -> Path:
    """Deterministic, collision-free location inside the quarantine area."""
    return (
        config.QUARANTINE_DIR
        / center_id
        / f"run-{run_id}"
        / f"instance-{instance_id}.dcm"
    )

def sweep_parts() -> None:
    """Remove leftovers from an interrupted process at startup.

    * ``.part`` files never had a committed DB row -> always safe to delete.
    * ``.bak-*`` files are the pre-replacement bytes of an existing object. The
      DB transaction never committed, so the backup must be restored to its
      final name rather than discarded.
    """
    for root in (config.STORAGE_DIR, config.QUARANTINE_DIR):
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            name = path.name
            if name.endswith(PART_SUFFIX):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            elif BACKUP_SUFFIX_PATTERN in name:
                # Name shape: .<final>.bak-<hex> -> restore <final>.
                final_name = name[1:].rsplit(BACKUP_SUFFIX_PATTERN, 1)[0]
                final_path = path.with_name(final_name)
                try:
                    if not final_path.exists():
                        path.replace(final_path)
                    else:
                        path.unlink()
                except FileNotFoundError:
                    pass
