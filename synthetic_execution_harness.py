"""Disposable regular-file-only destructive execution probe.

This synthetic-only module can create only a brand-new private regular file
and destructively overwrite only its already-held descriptor. It refuses
block devices, cannot adopt existing files, persists an ATTEMPTING tombstone
before overwrite, and never clears that tombstone.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import threading
from typing import Any

POLICY_VERSION = "phase6e-synthetic-regular-file-execution-v1"
ATTEMPTING = "ATTEMPTING"
DEFAULT_SIZE = 64 * 1024
MAX_SIZE = 4 * 1024 * 1024
_CHUNK = 4096


class SyntheticExecutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class SyntheticExecutionResult:
    medium_id: str
    bytes_overwritten: int
    write_returned: bool
    synthetic_pattern_verified: bool
    sanitization_verified: bool
    production_execution: bool
    real_block_device_accessed: bool
    automatic_replay_allowed: bool
    attempt_state: str

    def __copy__(self):
        raise SyntheticExecutionError("result cannot be copied")

    def __deepcopy__(self, memo):
        raise SyntheticExecutionError("result cannot be deep-copied")

    def __reduce__(self):
        raise SyntheticExecutionError("result cannot be serialized")

    def __reduce_ex__(self, protocol):
        raise SyntheticExecutionError("result cannot be serialized")


_TOKEN = object()


def _private_dir(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return (
        stat.S_ISDIR(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == 0o700
    )


def _hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


class DisposableSyntheticMedium:
    __slots__ = (
        "_root", "_path", "_marker", "_medium_id", "_fd", "_size",
        "_dev", "_ino", "_lock", "_attempted", "_closed",
    )

    def __init__(
        self, token: object, *, root: Path, path: Path, marker: Path,
        medium_id: str, fd: int, size: int, dev: int, ino: int,
    ):
        if token is not _TOKEN:
            raise TypeError("use create_disposable_synthetic_medium()")
        self._root = root
        self._path = path
        self._marker = marker
        self._medium_id = medium_id
        self._fd = fd
        self._size = size
        self._dev = dev
        self._ino = ino
        self._lock = threading.Lock()
        self._attempted = False
        self._closed = False

    @property
    def medium_id(self):
        return self._medium_id

    @property
    def size_bytes(self):
        return self._size

    @property
    def synthetic_only(self):
        return True

    @property
    def production_eligible(self):
        return False

    @property
    def real_block_device_supported(self):
        return False

    @property
    def attempted(self):
        return self._attempted

    def _validate_locked(self):
        if self._closed or self._fd < 0 or not _private_dir(self._root):
            raise SyntheticExecutionError("medium is not live/private")
        try:
            fi = os.fstat(self._fd)
            pi = os.lstat(self._path)
        except OSError as exc:
            raise SyntheticExecutionError("medium identity unavailable") from exc
        if (
            not stat.S_ISREG(fi.st_mode)
            or not stat.S_ISREG(pi.st_mode)
            or stat.S_ISLNK(pi.st_mode)
            or fi.st_uid != os.geteuid()
            or pi.st_uid != os.geteuid()
            or stat.S_IMODE(fi.st_mode) != 0o600
            or stat.S_IMODE(pi.st_mode) != 0o600
            or fi.st_dev != self._dev
            or fi.st_ino != self._ino
            or pi.st_dev != self._dev
            or pi.st_ino != self._ino
            or fi.st_size != self._size
            or pi.st_size != self._size
        ):
            raise SyntheticExecutionError("medium is not exact private regular file")

    def close(self):
        with self._lock:
            if self._closed:
                return
            fd = self._fd
            self._fd = -1
            self._closed = True
        os.close(fd)

    def __enter__(self):
        with self._lock:
            self._validate_locked()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()
        return False

    def __copy__(self):
        raise SyntheticExecutionError("medium cannot be copied")

    def __deepcopy__(self, memo):
        raise SyntheticExecutionError("medium cannot be deep-copied")

    def __reduce__(self):
        raise SyntheticExecutionError("medium cannot be serialized")

    def __reduce_ex__(self, protocol):
        raise SyntheticExecutionError("medium cannot be serialized")


def create_disposable_synthetic_medium(root: Any, *, size_bytes: int = DEFAULT_SIZE):
    root = Path(root)
    if not _private_dir(root):
        raise SyntheticExecutionError("root must be owner-only 0700 directory")
    if type(size_bytes) is not int or size_bytes <= 0 or size_bytes > MAX_SIZE:
        raise SyntheticExecutionError("size outside bounded synthetic range")

    medium_id = "xesynth_" + secrets.token_hex(32)
    path = root / f"{medium_id}.bin"
    marker = root / f"{medium_id}.attempting.json"
    flags = (
        os.O_RDWR | os.O_CREAT | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )

    fd = None
    try:
        fd = os.open(path, flags, 0o600)
        os.fchmod(fd, 0o600)
        pattern = b"\xA5" * min(_CHUNK, size_bytes)
        offset = 0
        while offset < size_bytes:
            chunk = pattern[: min(len(pattern), size_bytes - offset)]
            written = os.pwrite(fd, chunk, offset)
            if written != len(chunk):
                raise SyntheticExecutionError("initialization incomplete")
            offset += written
        os.fsync(fd)
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size != size_bytes
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise SyntheticExecutionError("new medium validation failed")
        return DisposableSyntheticMedium(
            _TOKEN, root=root, path=path, marker=marker,
            medium_id=medium_id, fd=fd, size=size_bytes,
            dev=info.st_dev, ino=info.st_ino,
        )
    except BaseException:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        raise


def _persist_attempt_locked(medium: DisposableSyntheticMedium):
    record = {
        "automatic_replay_allowed": False,
        "medium_id": medium._medium_id,
        "policy_version": POLICY_VERSION,
        "production_execution": False,
        "real_block_device_accessed": False,
        "state": ATTEMPTING,
        "st_dev": medium._dev,
        "st_ino": medium._ino,
        "size_bytes": medium._size,
    }
    record["record_hash"] = _hash(record)
    encoded = (
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    flags = (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )

    marker_fd = None
    directory_fd = None
    try:
        marker_fd = os.open(medium._marker, flags, 0o600)
        os.fchmod(marker_fd, 0o600)
        offset = 0
        while offset < len(encoded):
            written = os.write(marker_fd, encoded[offset:])
            if written <= 0:
                raise SyntheticExecutionError("attempt tombstone write stalled")
            offset += written
        os.fsync(marker_fd)
        os.close(marker_fd)
        marker_fd = None

        directory_fd = os.open(
            medium._root,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        os.fsync(directory_fd)
    except FileExistsError as exc:
        raise SyntheticExecutionError(
            "ATTEMPTING tombstone exists; replay refused"
        ) from exc
    finally:
        if marker_fd is not None:
            os.close(marker_fd)
        if directory_fd is not None:
            os.close(directory_fd)


def execute_disposable_synthetic_zero_pass(medium: Any):
    if type(medium) is not DisposableSyntheticMedium:
        raise SyntheticExecutionError("exact disposable medium required")

    with medium._lock:
        if medium._attempted:
            raise SyntheticExecutionError("single-attempt; replay refused")

        medium._validate_locked()
        _persist_attempt_locked(medium)
        medium._attempted = True
        medium._validate_locked()

        zeroes = b"\x00" * min(_CHUNK, medium._size)
        offset = 0
        while offset < medium._size:
            chunk = zeroes[: min(len(zeroes), medium._size - offset)]
            written = os.pwrite(medium._fd, chunk, offset)
            if written != len(chunk):
                raise SyntheticExecutionError("synthetic overwrite incomplete")
            offset += written

        os.fsync(medium._fd)
        medium._validate_locked()

        offset = 0
        while offset < medium._size:
            length = min(_CHUNK, medium._size - offset)
            observed = os.pread(medium._fd, length, offset)
            if len(observed) != length or any(observed):
                raise SyntheticExecutionError("zero-pattern verification failed")
            offset += length

        medium._validate_locked()
        return SyntheticExecutionResult(
            medium_id=medium._medium_id,
            bytes_overwritten=medium._size,
            write_returned=True,
            synthetic_pattern_verified=True,
            sanitization_verified=False,
            production_execution=False,
            real_block_device_accessed=False,
            automatic_replay_allowed=False,
            attempt_state=ATTEMPTING,
        )


__all__ = [
    "ATTEMPTING", "DEFAULT_SIZE", "MAX_SIZE", "POLICY_VERSION",
    "DisposableSyntheticMedium", "SyntheticExecutionError",
    "SyntheticExecutionResult", "create_disposable_synthetic_medium",
    "execute_disposable_synthetic_zero_pass",
]
