"""Bounded, read-only host collection for :mod:`drive_discovery`."""
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
FINDMNT_REAL_COMMAND = (
    "findmnt", "--json", "--list", "--kernel", "--real", "--output",
    "TARGET,SOURCE,FSTYPE",
)
SWAPON_COMMAND = (
    "swapon", "--show=NAME,TYPE", "--raw", "--noheadings",
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
    captured_lsblk_json: bytes
    protected_sources: tuple[str, ...]
    drives: tuple[PhysicalDrive, ...]
    captured_findmnt_root_json: bytes
    captured_findmnt_real_json: bytes
    captured_swapon_output: bytes

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
        completed = subprocess.run(command, shell=False, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            timeout=timeout, env=SAFE_COMMAND_ENV)
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
        raise DiscoveryCollectionError(f"{command[0]} exited with status {completed.returncode}")
    return stdout

def _json_object(data: bytes, label: str) -> dict:
    try:
        value = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise DiscoveryCollectionError(f"{label} returned malformed JSON") from exc
    if not isinstance(value, dict):
        raise DiscoveryCollectionError(f"{label} top-level value must be an object")
    return value

def _parse_root_source(data: bytes) -> str:
    filesystems = _json_object(data, "findmnt").get("filesystems")
    if not isinstance(filesystems, list) or len(filesystems) != 1:
        raise DiscoveryCollectionError("findmnt must return exactly one filesystem")
    entry = filesystems[0]
    if not isinstance(entry, dict) or entry.get("target") != "/":
        raise DiscoveryCollectionError("findmnt root entry is invalid")
    source = entry.get("source")
    if not isinstance(source, str) or not source.strip():
        raise DiscoveryCollectionError("findmnt source must be a nonblank string")
    return source

def _parse_real_sources(data: bytes, root_source: str) -> tuple[str, ...]:
    filesystems = _json_object(data, "findmnt --real").get("filesystems")
    if not isinstance(filesystems, list):
        raise DiscoveryCollectionError("findmnt --real filesystems must be an array")
    critical = []
    roots = []
    families = ("/boot", "/usr", "/var", "/etc", "/bin", "/sbin", "/lib", "/lib64")
    for entry in filesystems:
        if not isinstance(entry, dict) or "children" in entry:
            raise DiscoveryCollectionError("findmnt --real must be flat object entries")
        target, source, fstype = entry.get("target"), entry.get("source"), entry.get("fstype")
        if (not isinstance(target, str) or not target.strip() or
                not isinstance(source, str) or not source.strip() or
                (fstype is not None and not isinstance(fstype, str))):
            raise DiscoveryCollectionError("findmnt --real entry is invalid")
        if target == "/":
            roots.append(source)
        if any(target == family or target.startswith(family + "/") for family in families):
            critical.append(source)
    if roots != [root_source]:
        raise DiscoveryCollectionError("findmnt root observations disagree")
    return tuple(critical)

def _parse_swapon(data: bytes) -> tuple[str, ...]:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise DiscoveryCollectionError("swapon output is not UTF-8") from exc
    partitions = []
    for line in text.splitlines():
        if not line.strip():
            continue
        content = line.rstrip(" \t")
        if not content:
            continue
        try:
            name, swap_type = content.rsplit(None, 1)
        except ValueError as exc:
            raise DiscoveryCollectionError("malformed swapon line") from exc
        if not name or name != name.strip() or swap_type not in ("file", "partition"):
            raise DiscoveryCollectionError("invalid swapon line")
        if swap_type == "partition":
            partitions.append(name)
    return tuple(partitions)

def collect_current_drive_discovery(*, timeout_seconds: Real = DEFAULT_TIMEOUT_SECONDS,
    max_stdout_bytes: int = MAX_STDOUT_BYTES,
    max_stderr_bytes: int = MAX_STDERR_BYTES) -> DiscoverySnapshot:
    timeout = _positive_number(timeout_seconds, "timeout_seconds")
    out_limit = _positive_integer(max_stdout_bytes, "max_stdout_bytes")
    err_limit = _positive_integer(max_stderr_bytes, "max_stderr_bytes")
    kwargs = dict(timeout=timeout, max_stdout_bytes=out_limit, max_stderr_bytes=err_limit)
    lsblk = _run_fixed_command(LSBLK_COMMAND, **kwargs)
    root_data = _run_fixed_command(FINDMNT_ROOT_COMMAND, **kwargs)
    real_data = _run_fixed_command(FINDMNT_REAL_COMMAND, **kwargs)
    swap_data = _run_fixed_command(SWAPON_COMMAND, **kwargs)
    root = _parse_root_source(root_data)
    critical = _parse_real_sources(real_data, root)
    swaps = _parse_swapon(swap_data)
    protected = (root,) + tuple(sorted(set(critical) - {root})) + tuple(sorted(set(swaps) - {root} - set(critical)))
    drives = parse_lsblk_json(lsblk, protected_sources=protected)
    return DiscoverySnapshot(lsblk, protected, drives, root_data, real_data, swap_data)

__all__ = ["DiscoveryCollectionError", "DiscoverySnapshot", "LSBLK_COMMAND",
 "FINDMNT_ROOT_COMMAND", "FINDMNT_REAL_COMMAND", "SWAPON_COMMAND", "SAFE_COMMAND_ENV",
 "DEFAULT_TIMEOUT_SECONDS", "MAX_STDOUT_BYTES", "MAX_STDERR_BYTES",
 "collect_current_drive_discovery"]
