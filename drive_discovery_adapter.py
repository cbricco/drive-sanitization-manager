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
    "NAME,KNAME,PATH,TYPE,SIZE,MODEL,SERIAL,TRAN,ROTA,RM,RO,WWN,PKNAME,FSTYPE,MOUNTPOINTS,UUID,PARTUUID,LABEL",
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
FSTAB_COMMAND = (
    "findmnt", "--fstab", "--json", "--list", "--output",
    "TARGET,SOURCE,FSTYPE",
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
    captured_findmnt_fstab_json: bytes

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

_CRITICAL_FAMILIES = ("/", "/boot", "/usr", "/var", "/etc", "/bin",
                      "/sbin", "/lib", "/lib64")
_NETWORK_FSTYPES = frozenset(("cifs", "smb3", "nfs", "nfs4", "sshfs", "9p",
                              "ceph", "glusterfs", "afs"))

def _critical_target(target: str) -> bool:
    return any(target == family or (family != "/" and
               target.startswith(family + "/")) for family in _CRITICAL_FAMILIES)

def _lsblk_identifier_index(data: bytes) -> dict[str, dict[str, list[str]]]:
    devices = _json_object(data, "lsblk").get("blockdevices")
    if not isinstance(devices, list):
        raise DiscoveryCollectionError("lsblk blockdevices must be an array")
    index = {key: {} for key in ("uuid", "partuuid", "label")}
    def visit(entry: object) -> None:
        if not isinstance(entry, dict):
            raise DiscoveryCollectionError("lsblk device entry is invalid")
        path = entry.get("path")
        for key in index:
            value = entry.get(key)
            if value is not None:
                if not isinstance(value, str) or not value:
                    raise DiscoveryCollectionError(f"lsblk {key} is invalid")
                if not isinstance(path, str) or not path:
                    raise DiscoveryCollectionError("identified lsblk device has no path")
                index[key].setdefault(value, []).append(path)
        children = entry.get("children", [])
        if not isinstance(children, list):
            raise DiscoveryCollectionError("lsblk children must be an array")
        for child in children:
            visit(child)
    for device in devices:
        visit(device)
    return index

def _resolve_configured_source(source: str,
        index: dict[str, dict[str, list[str]]]) -> str:
    forms = (("UUID=", "uuid"), ("PARTUUID=", "partuuid"),
             ("LABEL=", "label"), ("/dev/disk/by-uuid/", "uuid"),
             ("/dev/disk/by-partuuid/", "partuuid"),
             ("/dev/disk/by-label/", "label"))
    for prefix, key in forms:
        if source.startswith(prefix):
            identifier = source[len(prefix):]
            if not identifier:
                raise DiscoveryCollectionError("configured identifier is empty")
            matches = index[key].get(identifier, [])
            if len(matches) != 1:
                raise DiscoveryCollectionError(
                    f"configured {key} source must match exactly one device")
            return matches[0]
    if source.startswith("/dev/"):
        return source
    raise DiscoveryCollectionError("unsupported configured local block source")

def _parse_fstab_sources(data: bytes, lsblk: bytes) -> tuple[str, ...]:
    filesystems = _json_object(data, "findmnt --fstab").get("filesystems")
    if not isinstance(filesystems, list):
        raise DiscoveryCollectionError("findmnt --fstab filesystems must be an array")
    index = None
    protected = []
    for entry in filesystems:
        if not isinstance(entry, dict):
            raise DiscoveryCollectionError("findmnt --fstab entry is invalid")
        target = entry.get("target")
        if not isinstance(target, str) or not target.strip():
            raise DiscoveryCollectionError("findmnt --fstab target is invalid")
        source, fstype = entry.get("source"), entry.get("fstype")
        relevant = _critical_target(target) or fstype == "swap"
        if not relevant:
            continue
        if (not isinstance(source, str) or not source.strip() or
                not isinstance(fstype, str) or not fstype.strip()):
            raise DiscoveryCollectionError("relevant findmnt --fstab entry is invalid")
        if fstype.lower() in _NETWORK_FSTYPES:
            continue
        if fstype == "swap" and source.startswith("/") and not source.startswith("/dev/"):
            continue
        if index is None:
            index = _lsblk_identifier_index(lsblk)
        protected.append(_resolve_configured_source(source, index))
    return tuple(protected)

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
    fstab_data = _run_fixed_command(FSTAB_COMMAND, **kwargs)
    root = _parse_root_source(root_data)
    critical = _parse_real_sources(real_data, root)
    swaps = _parse_swapon(swap_data)
    configured = _parse_fstab_sources(fstab_data, lsblk)
    live = (root,) + tuple(sorted(set(critical) - {root})) + tuple(sorted(set(swaps) - {root} - set(critical)))
    protected = live + tuple(sorted(set(configured) - set(live)))
    drives = parse_lsblk_json(lsblk, protected_sources=protected)
    return DiscoverySnapshot(lsblk, protected, drives, root_data, real_data, swap_data, fstab_data)

__all__ = ["DiscoveryCollectionError", "DiscoverySnapshot", "LSBLK_COMMAND",
 "FINDMNT_ROOT_COMMAND", "FINDMNT_REAL_COMMAND", "SWAPON_COMMAND", "FSTAB_COMMAND",
 "SAFE_COMMAND_ENV",
 "DEFAULT_TIMEOUT_SECONDS", "MAX_STDOUT_BYTES", "MAX_STDERR_BYTES",
 "collect_current_drive_discovery"]
