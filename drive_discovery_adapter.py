"""Bounded, read-only host collection for :mod:`drive_discovery`.

This adapter only captures evidence and invokes the existing pure parser. It
does not make sanitization or destructive-authority decisions.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import math
from numbers import Real
import subprocess
from types import MappingProxyType

from drive_discovery import PhysicalDrive, parse_lsblk_json

LSBLK_COMMAND = (
    "lsblk", "--json", "--bytes", "--output",
    "NAME,KNAME,PATH,TYPE,SIZE,MODEL,SERIAL,TRAN,ROTA,RM,RO,WWN,PKNAME,FSTYPE,MOUNTPOINTS",
)
FINDMNT_ROOT_COMMAND = (
    "findmnt", "--json", "--target", "/", "--output", "TARGET,SOURCE",
)
SAFE_COMMAND_ENV = MappingProxyType({
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C",
})
DEFAULT_TIMEOUT_SECONDS = 5
MAX_STDOUT_BYTES = 1_048_576
MAX_STDERR_BYTES = 65_536


class DiscoveryCollectionError(RuntimeError):
    """A fixed host-discovery command or its response was invalid."""


@dataclass(frozen=True)
class DiscoverySnapshot:
    """Raw discovery evidence and immutable interpreted observations."""

    captured_lsblk_json: bytes
    protected_sources: tuple[str, ...]
    drives: tuple[PhysicalDrive, ...]


def _positive_number(value: object, name: str) -> Real:
    if (isinstance(value, bool) or not isinstance(value, Real)
            or not math.isfinite(value) or value <= 0):
        raise DiscoveryCollectionError(f"{name} must be a positive number")
    return value


def _positive_integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise DiscoveryCollectionError(f"{name} must be a positive integer")
    return value


def _run_fixed_command(command: tuple[str, ...], *, timeout: Real,
                       max_stdout_bytes: int, max_stderr_bytes: int) -> bytes:
    try:
        completed = subprocess.run(
            command, shell=False, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            timeout=timeout, env=SAFE_COMMAND_ENV,
        )
    except subprocess.TimeoutExpired as exc:
        raise DiscoveryCollectionError(f"{command[0]} timed out") from exc
    except OSError as exc:
        raise DiscoveryCollectionError(f"could not execute {command[0]}") from exc

    stdout, stderr = completed.stdout, completed.stderr
    if not isinstance(stdout, bytes) or not isinstance(stderr, bytes):
        raise DiscoveryCollectionError(f"{command[0]} returned non-byte output")
    if len(stdout) > max_stdout_bytes:
        raise DiscoveryCollectionError(f"{command[0]} stdout exceeded limit")
    if len(stderr) > max_stderr_bytes:
        raise DiscoveryCollectionError(f"{command[0]} stderr exceeded limit")
    if completed.returncode != 0:
        raise DiscoveryCollectionError(
            f"{command[0]} exited with status {completed.returncode}"
        )
    return stdout


def _parse_root_source(captured_findmnt_json: bytes) -> str:
    try:
        document = json.loads(captured_findmnt_json)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise DiscoveryCollectionError("findmnt returned malformed JSON") from exc
    if not isinstance(document, dict):
        raise DiscoveryCollectionError("findmnt top-level value must be an object")
    filesystems = document.get("filesystems")
    if not isinstance(filesystems, list):
        raise DiscoveryCollectionError("findmnt filesystems must be an array")
    if len(filesystems) != 1:
        raise DiscoveryCollectionError("findmnt must return exactly one filesystem")
    entry = filesystems[0]
    if not isinstance(entry, dict):
        raise DiscoveryCollectionError("findmnt filesystem entry must be an object")
    if entry.get("target") != "/":
        raise DiscoveryCollectionError("findmnt target must be exactly /")
    source = entry.get("source")
    if not isinstance(source, str):
        raise DiscoveryCollectionError("findmnt source must be a string")
    if not source.strip():
        raise DiscoveryCollectionError("findmnt source must not be blank")
    return source


def collect_current_drive_discovery(
    *, timeout_seconds: Real = DEFAULT_TIMEOUT_SECONDS,
    max_stdout_bytes: int = MAX_STDOUT_BYTES,
    max_stderr_bytes: int = MAX_STDERR_BYTES,
) -> DiscoverySnapshot:
    """Collect fixed ``lsblk``/``findmnt`` evidence and parse observations."""
    timeout = _positive_number(timeout_seconds, "timeout_seconds")
    stdout_limit = _positive_integer(max_stdout_bytes, "max_stdout_bytes")
    stderr_limit = _positive_integer(max_stderr_bytes, "max_stderr_bytes")
    captured_lsblk_json = _run_fixed_command(
        LSBLK_COMMAND, timeout=timeout, max_stdout_bytes=stdout_limit,
        max_stderr_bytes=stderr_limit,
    )
    captured_findmnt_json = _run_fixed_command(
        FINDMNT_ROOT_COMMAND, timeout=timeout, max_stdout_bytes=stdout_limit,
        max_stderr_bytes=stderr_limit,
    )
    root_source = _parse_root_source(captured_findmnt_json)
    protected_sources = (root_source,)
    drives = parse_lsblk_json(
        captured_lsblk_json, protected_sources=protected_sources,
    )
    return DiscoverySnapshot(captured_lsblk_json, protected_sources, drives)


__all__ = [
    "DiscoveryCollectionError", "DiscoverySnapshot", "LSBLK_COMMAND",
    "FINDMNT_ROOT_COMMAND", "SAFE_COMMAND_ENV", "DEFAULT_TIMEOUT_SECONDS",
    "MAX_STDOUT_BYTES", "MAX_STDERR_BYTES", "collect_current_drive_discovery",
]
