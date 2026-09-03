"""Isolated synthetic loop-backed block-device execution harness.

This module is intentionally NOT a production execution seam.

It accepts only a Linux loop block device whose backing file is an exact
private synthetic regular file and whose device was not active in an
internally-created pre-allocation snapshot.

It does not allocate or detach loop devices, does not use sudo, does not
construct production sanitization commands, and does not integrate with
execution_seam.py.

A successful result remains explicitly synthetic and must never be treated as
proof that a real physical drive was sanitized.
"""

from __future__ import annotations

import copy
import glob
import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Any


LOOP_MAJOR = 7
MIN_SYNTHETIC_SIZE = 2 * 1024 * 1024
MAX_SYNTHETIC_SIZE = 64 * 1024 * 1024
MAX_BOUNDED_WRITE = 1024 * 1024

_TOKEN = object()
_LOOP_RE = re.compile(r"^/dev/loop([0-9]+)$")


class SyntheticBlockDeviceError(RuntimeError):
    pass


def _refuse_copy_pickle() -> SyntheticBlockDeviceError:
    return SyntheticBlockDeviceError(
        "synthetic block-device authorities are non-copyable "
        "and non-serializable"
    )


class LoopDeviceSnapshot:
    __slots__ = ("_token", "_active")

    def __init__(self, token: object, active: frozenset[str]) -> None:
        if token is not _TOKEN:
            raise SyntheticBlockDeviceError(
                "loop snapshot must be internally generated"
            )
        object.__setattr__(self, "_token", token)
        object.__setattr__(self, "_active", active)

    def __setattr__(self, name: str, value: Any) -> None:
        raise SyntheticBlockDeviceError(
            "loop snapshot is immutable"
        )

    def __copy__(self) -> Any:
        raise _refuse_copy_pickle()

    def __deepcopy__(self, memo: Any) -> Any:
        raise _refuse_copy_pickle()

    def __reduce__(self) -> Any:
        raise _refuse_copy_pickle()

    def __reduce_ex__(self, protocol: int) -> Any:
        raise _refuse_copy_pickle()


def _active_loop_devices() -> frozenset[str]:
    active: set[str] = set()

    for entry in glob.glob("/sys/class/block/loop[0-9]*"):
        base = os.path.basename(entry)

        if not re.fullmatch(r"loop[0-9]+", base):
            continue

        backing = f"/sys/class/block/{base}/loop/backing_file"

        try:
            with open(backing, "r", encoding="utf-8") as fh:
                value = fh.read().strip()
        except FileNotFoundError:
            # A loop block node may exist without being configured.
            continue
        except OSError as exc:
            # Any other inability to inspect pre-test loop state is
            # ambiguous and must fail closed rather than omit a loop
            # from the exclusion snapshot.
            raise SyntheticBlockDeviceError(
                "cannot completely inspect preexisting loop devices"
            ) from exc

        if value:
            active.add(f"/dev/{base}")

    return frozenset(active)


def snapshot_active_loop_devices() -> LoopDeviceSnapshot:
    """Capture active loop devices BEFORE caller-controlled allocation."""
    return LoopDeviceSnapshot(_TOKEN, _active_loop_devices())


def _read_sysfs_text(path: str, label: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            value = fh.read().strip()
    except OSError as exc:
        raise SyntheticBlockDeviceError(
            f"cannot read exact loop {label}"
        ) from exc

    if not value:
        raise SyntheticBlockDeviceError(
            f"exact loop {label} is empty"
        )

    return value


def _read_sysfs_nonnegative_int(
    path: str,
    label: str,
) -> int:
    raw = _read_sysfs_text(path, label)

    try:
        value = int(raw, 10)
    except ValueError as exc:
        raise SyntheticBlockDeviceError(
            f"exact loop {label} is not an integer"
        ) from exc

    if value < 0:
        raise SyntheticBlockDeviceError(
            f"exact loop {label} is negative"
        )

    return value


def _real_backing_path(loop_path: str) -> str:
    match = _LOOP_RE.fullmatch(loop_path)
    if match is None:
        raise SyntheticBlockDeviceError(
            "synthetic target must be exact /dev/loopN"
        )

    base = os.path.basename(loop_path)
    root = f"/sys/class/block/{base}"

    raw = _read_sysfs_text(
        f"{root}/loop/backing_file",
        "backing-file identity",
    )

    if not raw.startswith("/"):
        raw = "/" + raw

    backing_real = os.path.realpath(raw)

    offset = _read_sysfs_nonnegative_int(
        f"{root}/loop/offset",
        "backing offset",
    )
    sizelimit = _read_sysfs_nonnegative_int(
        f"{root}/loop/sizelimit",
        "size limit",
    )
    read_only = _read_sysfs_nonnegative_int(
        f"{root}/ro",
        "read-only flag",
    )
    sectors = _read_sysfs_nonnegative_int(
        f"{root}/size",
        "device size",
    )

    if offset != 0:
        raise SyntheticBlockDeviceError(
            "synthetic loop must use zero backing-file offset"
        )

    if sizelimit != 0:
        raise SyntheticBlockDeviceError(
            "synthetic loop must not use a size limit"
        )

    if read_only != 0:
        raise SyntheticBlockDeviceError(
            "synthetic loop must be kernel-writable"
        )

    try:
        backing_stat = os.stat(backing_real)
    except OSError as exc:
        raise SyntheticBlockDeviceError(
            "cannot stat exact loop backing file"
        ) from exc

    # Linux block sysfs reports this value in 512-byte sectors.
    loop_size = sectors * 512

    if loop_size != backing_stat.st_size:
        raise SyntheticBlockDeviceError(
            "synthetic loop capacity differs from full backing image"
        )

    return backing_real


def _device_is_mounted(major: int, minor: int) -> bool:
    identity = f"{major}:{minor}"

    try:
        with open(
            "/proc/self/mountinfo",
            "r",
            encoding="utf-8",
        ) as fh:
            for line in fh:
                fields = line.split()
                if len(fields) >= 3 and fields[2] == identity:
                    return True
    except OSError as exc:
        raise SyntheticBlockDeviceError(
            "cannot verify mount state"
        ) from exc

    return False


def _device_has_children(loop_path: str) -> bool:
    base = os.path.basename(loop_path)
    return bool(glob.glob(f"/sys/class/block/{base}p[0-9]*"))


def _validate_private_backing_image(
    backing_image: str,
) -> tuple[str, os.stat_result]:
    path = os.fspath(backing_image)

    if not os.path.isabs(path):
        raise SyntheticBlockDeviceError(
            "synthetic backing image path must be absolute"
        )

    try:
        lst = os.lstat(path)
    except OSError as exc:
        raise SyntheticBlockDeviceError(
            "cannot inspect synthetic backing image"
        ) from exc

    if stat.S_ISLNK(lst.st_mode):
        raise SyntheticBlockDeviceError(
            "synthetic backing image must not be a symlink"
        )

    if not stat.S_ISREG(lst.st_mode):
        raise SyntheticBlockDeviceError(
            "synthetic backing image must be a regular file"
        )

    if lst.st_uid != os.getuid():
        raise SyntheticBlockDeviceError(
            "synthetic backing image must be owned by current user"
        )

    if stat.S_IMODE(lst.st_mode) != 0o600:
        raise SyntheticBlockDeviceError(
            "synthetic backing image must have mode 0600"
        )

    if not (
        MIN_SYNTHETIC_SIZE
        <= lst.st_size
        <= MAX_SYNTHETIC_SIZE
    ):
        raise SyntheticBlockDeviceError(
            "synthetic backing image size is outside bounded limits"
        )

    if lst.st_size % 512 != 0:
        raise SyntheticBlockDeviceError(
            "synthetic backing image size must be 512-byte aligned"
        )

    return os.path.realpath(path), lst


class DisposableLoopBlockMedium:
    __slots__ = (
        "_token",
        "_loop_path",
        "_backing_path",
        "_fd",
        "_rdev",
        "_major",
        "_minor",
        "_size",
        "_image_dev",
        "_image_ino",
        "_consumed",
        "_closed",
    )

    def __init__(
        self,
        token: object,
        *,
        loop_path: str,
        backing_path: str,
        fd: int,
        rdev: int,
        major: int,
        minor: int,
        size: int,
        image_dev: int,
        image_ino: int,
    ) -> None:
        if token is not _TOKEN:
            raise SyntheticBlockDeviceError(
                "synthetic loop medium must be internally acquired"
            )

        object.__setattr__(self, "_token", token)
        object.__setattr__(self, "_loop_path", loop_path)
        object.__setattr__(self, "_backing_path", backing_path)
        object.__setattr__(self, "_fd", fd)
        object.__setattr__(self, "_rdev", rdev)
        object.__setattr__(self, "_major", major)
        object.__setattr__(self, "_minor", minor)
        object.__setattr__(self, "_size", size)
        object.__setattr__(self, "_image_dev", image_dev)
        object.__setattr__(self, "_image_ino", image_ino)
        object.__setattr__(self, "_consumed", False)
        object.__setattr__(self, "_closed", False)

    def __setattr__(self, name: str, value: Any) -> None:
        raise SyntheticBlockDeviceError(
            "synthetic loop medium authority is immutable"
        )

    @property
    def loop_path(self) -> str:
        return self._loop_path

    @property
    def major_minor(self) -> str:
        return f"{self._major}:{self._minor}"

    @property
    def size_bytes(self) -> int:
        return self._size

    @property
    def consumed(self) -> bool:
        return self._consumed

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        if self._closed:
            return
        object.__setattr__(self, "_closed", True)
        os.close(self._fd)

    def __enter__(self) -> "DisposableLoopBlockMedium":
        if self._closed:
            raise SyntheticBlockDeviceError(
                "synthetic loop medium is closed"
            )
        return self

    def __exit__(
        self,
        exc_type: Any,
        exc: Any,
        tb: Any,
    ) -> None:
        self.close()

    def __copy__(self) -> Any:
        raise _refuse_copy_pickle()

    def __deepcopy__(self, memo: Any) -> Any:
        raise _refuse_copy_pickle()

    def __reduce__(self) -> Any:
        raise _refuse_copy_pickle()

    def __reduce_ex__(self, protocol: int) -> Any:
        raise _refuse_copy_pickle()


def acquire_disposable_loop_block_medium(
    snapshot: LoopDeviceSnapshot,
    *,
    loop_path: str,
    backing_image: str,
    expected_major_minor: str,
) -> DisposableLoopBlockMedium:
    """Acquire one exact newly-allocated synthetic loop device.

    The caller must create `snapshot` before allocating the disposable loop.

    This function never allocates a loop itself and never accepts physical
    drives or loops that were active in that snapshot.
    """
    if (
        not isinstance(snapshot, LoopDeviceSnapshot)
        or snapshot._token is not _TOKEN
    ):
        raise SyntheticBlockDeviceError(
            "an internally generated pre-allocation loop snapshot is required"
        )

    if not isinstance(loop_path, str):
        raise SyntheticBlockDeviceError(
            "loop path must be a string"
        )

    match = _LOOP_RE.fullmatch(loop_path)
    if match is None:
        raise SyntheticBlockDeviceError(
            "synthetic target must be exact /dev/loopN"
        )

    if loop_path in snapshot._active:
        raise SyntheticBlockDeviceError(
            "preexisting loop devices cannot be adopted"
        )

    expected_match = re.fullmatch(
        r"([0-9]+):([0-9]+)",
        expected_major_minor,
    )
    if expected_match is None:
        raise SyntheticBlockDeviceError(
            "expected MAJ:MIN is malformed"
        )

    expected_major = int(expected_match.group(1))
    expected_minor = int(expected_match.group(2))

    if expected_major != LOOP_MAJOR:
        raise SyntheticBlockDeviceError(
            "expected block major must be Linux loop major 7"
        )

    suffix_minor = int(match.group(1))

    if expected_minor != suffix_minor:
        raise SyntheticBlockDeviceError(
            "expected minor does not match /dev/loopN"
        )

    backing_real, backing_stat = _validate_private_backing_image(
        backing_image
    )

    try:
        path_stat = os.lstat(loop_path)
    except OSError as exc:
        raise SyntheticBlockDeviceError(
            "cannot inspect synthetic loop target"
        ) from exc

    if stat.S_ISLNK(path_stat.st_mode):
        raise SyntheticBlockDeviceError(
            "synthetic loop path must not be a symlink"
        )

    if not stat.S_ISBLK(path_stat.st_mode):
        raise SyntheticBlockDeviceError(
            "synthetic target must be block-special"
        )

    path_major = os.major(path_stat.st_rdev)
    path_minor = os.minor(path_stat.st_rdev)

    if path_major != LOOP_MAJOR:
        raise SyntheticBlockDeviceError(
            "physical/non-loop block devices are forbidden"
        )

    if (
        path_major != expected_major
        or path_minor != expected_minor
    ):
        raise SyntheticBlockDeviceError(
            "target MAJ:MIN differs from expected identity"
        )

    if _device_has_children(loop_path):
        raise SyntheticBlockDeviceError(
            "synthetic loop device must have no child devices"
        )

    if _device_is_mounted(path_major, path_minor):
        raise SyntheticBlockDeviceError(
            "mounted loop devices are forbidden"
        )

    if _real_backing_path(loop_path) != backing_real:
        raise SyntheticBlockDeviceError(
            "loop backing file differs from disposable synthetic image"
        )

    flags = os.O_RDWR

    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC

    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd: int | None = None

    try:
        fd = os.open(loop_path, flags)

        os.set_inheritable(fd, False)

        if os.get_inheritable(fd):
            raise SyntheticBlockDeviceError(
                "synthetic block descriptor is inheritable"
            )

        info = os.fstat(fd)

        if not stat.S_ISBLK(info.st_mode):
            raise SyntheticBlockDeviceError(
                "opened descriptor is not block-special"
            )

        if info.st_rdev != path_stat.st_rdev:
            raise SyntheticBlockDeviceError(
                "descriptor target identity differs from guarded path"
            )

        if os.major(info.st_rdev) != LOOP_MAJOR:
            raise SyntheticBlockDeviceError(
                "opened descriptor is not a Linux loop device"
            )

        if (
            os.major(info.st_rdev) != expected_major
            or os.minor(info.st_rdev) != expected_minor
        ):
            raise SyntheticBlockDeviceError(
                "descriptor MAJ:MIN differs from expected identity"
            )

        if _device_is_mounted(expected_major, expected_minor):
            raise SyntheticBlockDeviceError(
                "loop became mounted during acquisition"
            )

        if _real_backing_path(loop_path) != backing_real:
            raise SyntheticBlockDeviceError(
                "loop backing identity changed during acquisition"
            )

        (
            latest_backing_path,
            latest_backing,
        ) = _validate_private_backing_image(
            backing_real
        )

        if latest_backing_path != backing_real:
            raise SyntheticBlockDeviceError(
                "synthetic backing image path identity changed"
            )

        if (
            latest_backing.st_dev != backing_stat.st_dev
            or latest_backing.st_ino != backing_stat.st_ino
            or latest_backing.st_size != backing_stat.st_size
        ):
            raise SyntheticBlockDeviceError(
                "synthetic backing image identity changed"
            )

        return DisposableLoopBlockMedium(
            _TOKEN,
            loop_path=loop_path,
            backing_path=backing_real,
            fd=fd,
            rdev=info.st_rdev,
            major=expected_major,
            minor=expected_minor,
            size=backing_stat.st_size,
            image_dev=backing_stat.st_dev,
            image_ino=backing_stat.st_ino,
        )

    except BaseException:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        raise


class SyntheticBlockResult:
    __slots__ = (
        "_token",
        "loop_major_minor",
        "write_offset",
        "write_length",
        "before_sha256",
        "after_sha256",
        "synthetic_pattern_verified",
        "outside_region_verified",
        "sanitization_verified",
        "production_execution",
        "block_special_device_accessed",
        "physical_drive_accessed",
        "synthetic_loop_block_device_accessed",
        "automatic_replay_allowed",
    )

    def __init__(
        self,
        token: object,
        *,
        loop_major_minor: str,
        write_offset: int,
        write_length: int,
        before_sha256: str,
        after_sha256: str,
    ) -> None:
        if token is not _TOKEN:
            raise SyntheticBlockDeviceError(
                "synthetic result must be internally generated"
            )

        object.__setattr__(self, "_token", token)
        object.__setattr__(
            self, "loop_major_minor", loop_major_minor
        )
        object.__setattr__(self, "write_offset", write_offset)
        object.__setattr__(self, "write_length", write_length)
        object.__setattr__(self, "before_sha256", before_sha256)
        object.__setattr__(self, "after_sha256", after_sha256)

        object.__setattr__(
            self, "synthetic_pattern_verified", True
        )
        object.__setattr__(
            self, "outside_region_verified", True
        )

        # These values are intentionally conservative.
        object.__setattr__(
            self, "sanitization_verified", False
        )
        object.__setattr__(
            self, "production_execution", False
        )

        # A Linux loop device is genuinely block-special, but it is
        # synthetic media backed by the exact private image rather than
        # a physical drive.
        object.__setattr__(
            self, "block_special_device_accessed", True
        )
        object.__setattr__(
            self, "physical_drive_accessed", False
        )
        object.__setattr__(
            self,
            "synthetic_loop_block_device_accessed",
            True,
        )
        object.__setattr__(
            self, "automatic_replay_allowed", False
        )

    def __setattr__(self, name: str, value: Any) -> None:
        raise SyntheticBlockDeviceError(
            "synthetic block result is immutable"
        )

    def __copy__(self) -> Any:
        raise _refuse_copy_pickle()

    def __deepcopy__(self, memo: Any) -> Any:
        raise _refuse_copy_pickle()

    def __reduce__(self) -> Any:
        raise _refuse_copy_pickle()

    def __reduce_ex__(self, protocol: int) -> Any:
        raise _refuse_copy_pickle()


def _pread_exact(fd: int, size: int, offset: int) -> bytes:
    parts: list[bytes] = []
    remaining = size
    position = offset

    while remaining:
        chunk = os.pread(fd, remaining, position)
        if not chunk:
            raise SyntheticBlockDeviceError(
                "short synthetic block-device read"
            )
        parts.append(chunk)
        position += len(chunk)
        remaining -= len(chunk)

    return b"".join(parts)


def _revalidate_medium(
    medium: DisposableLoopBlockMedium,
) -> None:
    if (
        not isinstance(medium, DisposableLoopBlockMedium)
        or medium._token is not _TOKEN
    ):
        raise SyntheticBlockDeviceError(
            "wrong synthetic block medium"
        )

    if medium._closed:
        raise SyntheticBlockDeviceError(
            "synthetic loop medium is closed"
        )

    try:
        path_stat = os.lstat(medium._loop_path)
        info = os.fstat(medium._fd)
    except OSError as exc:
        raise SyntheticBlockDeviceError(
            "cannot revalidate synthetic loop medium"
        ) from exc

    if (
        not stat.S_ISBLK(path_stat.st_mode)
        or not stat.S_ISBLK(info.st_mode)
    ):
        raise SyntheticBlockDeviceError(
            "synthetic loop identity is no longer block-special"
        )

    if (
        path_stat.st_rdev != medium._rdev
        or info.st_rdev != medium._rdev
    ):
        raise SyntheticBlockDeviceError(
            "synthetic loop device identity changed"
        )

    if os.major(info.st_rdev) != LOOP_MAJOR:
        raise SyntheticBlockDeviceError(
            "synthetic target is no longer a loop device"
        )

    if _device_has_children(medium._loop_path):
        raise SyntheticBlockDeviceError(
            "synthetic loop gained child devices"
        )

    if _device_is_mounted(medium._major, medium._minor):
        raise SyntheticBlockDeviceError(
            "synthetic loop became mounted"
        )

    if _real_backing_path(medium._loop_path) != medium._backing_path:
        raise SyntheticBlockDeviceError(
            "synthetic loop backing identity changed"
        )

    backing_path, image = _validate_private_backing_image(
        medium._backing_path
    )

    if backing_path != medium._backing_path:
        raise SyntheticBlockDeviceError(
            "synthetic backing image path identity changed"
        )

    if (
        image.st_dev != medium._image_dev
        or image.st_ino != medium._image_ino
        or image.st_size != medium._size
    ):
        raise SyntheticBlockDeviceError(
            "synthetic backing image identity changed"
        )

    if os.get_inheritable(medium._fd):
        raise SyntheticBlockDeviceError(
            "synthetic descriptor became inheritable"
        )


def execute_bounded_synthetic_pattern_pass(
    medium: DisposableLoopBlockMedium,
    *,
    offset: int,
    length: int,
    pattern_byte: int = 0x3C,
) -> SyntheticBlockResult:
    """Perform one in-process one-shot bounded write to an acquired loop medium.

    Consumption prevents reuse of this retained capability after success or
    failure. This function does not provide durable crash/restart replay
    protection; callers must never automatically replay an ambiguous attempt.
    """
    if (
        not isinstance(medium, DisposableLoopBlockMedium)
        or medium._token is not _TOKEN
    ):
        raise SyntheticBlockDeviceError(
            "wrong synthetic block medium"
        )

    if medium._closed:
        raise SyntheticBlockDeviceError(
            "synthetic loop medium is closed"
        )

    if medium._consumed:
        raise SyntheticBlockDeviceError(
            "synthetic loop medium is one-shot and already consumed"
        )

    if not isinstance(offset, int) or not isinstance(length, int):
        raise SyntheticBlockDeviceError(
            "bounded write geometry must be integer"
        )

    if offset < 0 or length <= 0:
        raise SyntheticBlockDeviceError(
            "invalid bounded write geometry"
        )

    if length > MAX_BOUNDED_WRITE:
        raise SyntheticBlockDeviceError(
            "bounded synthetic write is too large"
        )

    end = offset + length

    if end > medium._size:
        raise SyntheticBlockDeviceError(
            "bounded write exceeds synthetic medium"
        )

    if (
        not isinstance(pattern_byte, int)
        or not 0 <= pattern_byte <= 255
    ):
        raise SyntheticBlockDeviceError(
            "pattern byte must be in range 0..255"
        )

    # Consumption happens before any destructive I/O.
    # Any failure after this point remains non-replayable.
    object.__setattr__(medium, "_consumed", True)

    _revalidate_medium(medium)

    before = _pread_exact(medium._fd, medium._size, 0)
    before_sha = hashlib.sha256(before).hexdigest()

    pattern = bytes((pattern_byte,)) * length

    written = 0
    while written < length:
        count = os.pwrite(
            medium._fd,
            pattern[written:],
            offset + written,
        )
        if count <= 0:
            raise SyntheticBlockDeviceError(
                "short/zero synthetic block-device write"
            )
        written += count

    os.fsync(medium._fd)

    _revalidate_medium(medium)

    after = _pread_exact(medium._fd, medium._size, 0)

    if after[offset:end] != pattern:
        raise SyntheticBlockDeviceError(
            "synthetic bounded region did not verify"
        )

    if before[:offset] != after[:offset]:
        raise SyntheticBlockDeviceError(
            "bytes before synthetic bounded region changed"
        )

    if before[end:] != after[end:]:
        raise SyntheticBlockDeviceError(
            "bytes after synthetic bounded region changed"
        )

    after_sha = hashlib.sha256(after).hexdigest()

    return SyntheticBlockResult(
        _TOKEN,
        loop_major_minor=medium.major_minor,
        write_offset=offset,
        write_length=length,
        before_sha256=before_sha,
        after_sha256=after_sha,
    )
