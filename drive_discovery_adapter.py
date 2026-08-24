"""Bounded, read-only host collection for :mod:`drive_discovery`."""
from __future__ import annotations
from dataclasses import dataclass
import json
import math
from numbers import Real
import os
import re
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
CRYPTTAB_PATH = "/etc/crypttab"
CMDLINE_PATH = "/proc/cmdline"
RESUME_PATH = "/etc/initramfs-tools/conf.d/resume"
SYSTEMD_SYSTEM_PATH = "/etc/systemd/system"
MDADM_PATHS = ("/etc/mdadm/mdadm.conf", "/etc/mdadm.conf")
LVM_BACKUP_PATH = "/etc/lvm/backup"
MAX_CONFIG_BYTES = 65_536
MAX_SYSTEMD_ENTRIES = 4_096
MAX_SYSTEMD_UNIT_BYTES = 65_536
MAX_SYSTEMD_TOTAL_BYTES = 1_048_576

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

def _read_fixed_text(path: str, limit: int, label: str) -> str | None:
    try:
        with open(path, "rb") as stream:
            data = stream.read(limit + 1)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise DiscoveryCollectionError(f"could not read {label}") from exc
    if len(data) > limit:
        raise DiscoveryCollectionError(f"{label} exceeded limit")
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise DiscoveryCollectionError(f"{label} is not UTF-8") from exc

def _check_crypttab(path: str = CRYPTTAB_PATH) -> None:
    text = _read_fixed_text(path, MAX_CONFIG_BYTES, "crypttab")
    if text is None:
        return
    for line in text.splitlines():
        active = line.split("#", 1)[0].strip()
        if not active:
            continue
        if len(active.split()) < 2:
            raise DiscoveryCollectionError("malformed active crypttab configuration")
        raise DiscoveryCollectionError("unsupported active crypttab configuration")

def _disabled_resume(value: str) -> bool:
    return value.lower() == "none"

def _check_resume(cmdline_path: str = CMDLINE_PATH,
                  resume_path: str = RESUME_PATH) -> None:
    cmdline = _read_fixed_text(cmdline_path, MAX_CONFIG_BYTES, "kernel command line")
    if cmdline is None:
        raise DiscoveryCollectionError("kernel command line is absent")
    for token in cmdline.split():
        if token == "resume" or token.startswith("resume="):
            if not token.startswith("resume=") or not token[7:]:
                raise DiscoveryCollectionError("malformed kernel resume configuration")
            if not _disabled_resume(token[7:]):
                raise DiscoveryCollectionError("unsupported kernel resume configuration")
    text = _read_fixed_text(resume_path, MAX_CONFIG_BYTES, "initramfs resume configuration")
    if text is None:
        return
    for line in text.splitlines():
        active = line.split("#", 1)[0].strip()
        if not active:
            continue
        match = re.fullmatch(r"RESUME\s*=\s*(\S+)", active)
        if not match:
            raise DiscoveryCollectionError("malformed active resume configuration")
        if not _disabled_resume(match.group(1)):
            raise DiscoveryCollectionError("unsupported initramfs resume configuration")

def _systemd_escape_path(path: str) -> str:
    escaped = []
    for component in path.strip("/").split("/"):
        value = ""
        for byte in component.encode("utf-8"):
            character = chr(byte)
            if ((character.isascii() and character.isalnum()) or character in "_:."):
                value += character
            else:
                value += f"\\x{byte:02x}"
        escaped.append(value)
    return "-".join(escaped)

def _proven_snap_unit(name: str, text: str) -> bool:
    if not name.startswith("snap-") or not name.endswith(".mount"):
        return False
    section = None
    values: dict[str, list[str]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if section == "Mount" and "=" in line:
            key, value = line.split("=", 1)
            values.setdefault(key.strip(), []).append(value.strip())
    what, where, filesystem_type = (
        values.get("What"), values.get("Where"), values.get("Type"))
    prefix = "/var/lib/snapd/snaps/"
    if (not what or len(what) != 1 or not where or len(where) != 1 or
            filesystem_type != ["squashfs"] or
            not what[0].startswith(prefix) or not what[0].endswith(".snap") or
            "/" in what[0][len(prefix):] or not where[0].startswith("/snap/") or
            where[0] == "/snap/"):
        return False
    return name == _systemd_escape_path(where[0]) + ".mount"

def _check_systemd_units(root: str = SYSTEMD_SYSTEM_PATH,
                         max_entries: int = MAX_SYSTEMD_ENTRIES,
                         max_unit_bytes: int = MAX_SYSTEMD_UNIT_BYTES,
                         max_total_bytes: int = MAX_SYSTEMD_TOTAL_BYTES) -> None:
    inspected = total = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except FileNotFoundError:
            if directory == root:
                return
            raise DiscoveryCollectionError("systemd configuration changed during scan")
        except OSError as exc:
            raise DiscoveryCollectionError("could not inspect systemd configuration") from exc
        for entry in entries:
            inspected += 1
            if inspected > max_entries:
                raise DiscoveryCollectionError("systemd entry count exceeded limit")
            try:
                if entry.is_dir(follow_symlinks=False):
                    pending.append(entry.path)
                    continue
                if not entry.name.endswith((".mount", ".swap")):
                    continue
                if entry.is_symlink():
                    target = os.readlink(entry.path)
                    if target == "/dev/null":
                        continue
                    expected = os.path.join(root, entry.name)
                    if target != expected:
                        raise DiscoveryCollectionError("unsupported systemd unit symlink")
                    unit_path = expected
                elif entry.is_file(follow_symlinks=False):
                    unit_path = entry.path
                else:
                    raise DiscoveryCollectionError("unsupported systemd unit entry")
            except OSError as exc:
                raise DiscoveryCollectionError("could not inspect systemd unit") from exc
            text = _read_fixed_text(unit_path, max_unit_bytes, "systemd storage unit")
            if text is None:
                raise DiscoveryCollectionError("systemd unit disappeared during scan")
            total += len(text.encode("utf-8"))
            if total > max_total_bytes:
                raise DiscoveryCollectionError("systemd unit bytes exceeded limit")
            if entry.name.endswith(".swap") or not _proven_snap_unit(entry.name, text):
                raise DiscoveryCollectionError("unsupported persistent systemd storage unit")

def _check_special_topology(data: bytes) -> None:
    devices = _json_object(data, "lsblk").get("blockdevices")
    if not isinstance(devices, list):
        raise DiscoveryCollectionError("lsblk blockdevices must be an array")
    pending = list(devices)
    while pending:
        entry = pending.pop()
        if not isinstance(entry, dict):
            raise DiscoveryCollectionError("lsblk device entry is invalid")
        kind = entry.get("type")
        if not isinstance(kind, str) or not kind:
            raise DiscoveryCollectionError("lsblk device type is invalid")
        lowered = kind.lower()
        if lowered in ("crypt", "lvm", "dm") or lowered.startswith(("md", "raid")):
            raise DiscoveryCollectionError("unsupported block topology")
        children = entry.get("children", [])
        if not isinstance(children, list):
            raise DiscoveryCollectionError("lsblk children must be an array")
        pending.extend(children)

def _check_mdadm(paths: tuple[str, ...] = MDADM_PATHS) -> None:
    for path in paths:
        text = _read_fixed_text(path, MAX_CONFIG_BYTES, "mdadm configuration")
        if text is None:
            continue
        for line in text.splitlines():
            active = line.split("#", 1)[0].strip()
            if active and active.split(None, 1)[0].upper() == "ARRAY":
                if len(active.split()) < 2:
                    raise DiscoveryCollectionError("malformed mdadm ARRAY configuration")
                raise DiscoveryCollectionError("unsupported mdadm ARRAY configuration")

def _check_lvm_backup(path: str = LVM_BACKUP_PATH) -> None:
    try:
        entries = list(os.scandir(path))
    except FileNotFoundError:
        return
    except OSError as exc:
        raise DiscoveryCollectionError("could not inspect LVM backup metadata") from exc
    if entries:
        raise DiscoveryCollectionError("unsupported dormant LVM metadata")

def _check_coverage_sentinel(lsblk: bytes) -> None:
    _check_crypttab()
    _check_resume()
    _check_systemd_units()
    _check_mdadm()
    _check_lvm_backup()

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
    _check_coverage_sentinel(lsblk)
    root = _parse_root_source(root_data)
    critical = _parse_real_sources(real_data, root)
    swaps = _parse_swapon(swap_data)
    configured = _parse_fstab_sources(fstab_data, lsblk)
    live = (root,) + tuple(sorted(set(critical) - {root})) + tuple(sorted(set(swaps) - {root} - set(critical)))
    protected = live + tuple(sorted(set(configured) - set(live)))
    drives = parse_lsblk_json(lsblk, protected_sources=protected)
    _check_special_topology(lsblk)
    return DiscoverySnapshot(lsblk, protected, drives, root_data, real_data, swap_data, fstab_data)

__all__ = ["DiscoveryCollectionError", "DiscoverySnapshot", "LSBLK_COMMAND",
 "FINDMNT_ROOT_COMMAND", "FINDMNT_REAL_COMMAND", "SWAPON_COMMAND", "FSTAB_COMMAND",
 "SAFE_COMMAND_ENV",
 "DEFAULT_TIMEOUT_SECONDS", "MAX_STDOUT_BYTES", "MAX_STDERR_BYTES",
 "collect_current_drive_discovery"]
