"""Pure models and parsing for already-captured ``lsblk --json --bytes`` output.

This module is observational.  In particular, none of its results authorize or
express eligibility for a destructive operation.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
from typing import Any, Iterable, Mapping, Optional, Tuple, Union


class DiscoveryError(ValueError):
    """The supplied discovery document is not valid lsblk-shaped JSON."""


@dataclass(frozen=True)
class BlockDevice:
    """An immutable block-device observation, including its reported children."""

    name: Optional[str] = None
    kname: Optional[str] = None
    path: Optional[str] = None
    type: Optional[str] = None
    size: Optional[int] = None
    model: Optional[str] = None
    serial: Optional[str] = None
    transport: Optional[str] = None
    rotational: Optional[bool] = None
    removable: Optional[bool] = None
    read_only: Optional[bool] = None
    wwn: Optional[str] = None
    parent_name: Optional[str] = None
    filesystem_type: Optional[str] = None
    mountpoints: Optional[Tuple[Optional[str], ...]] = None
    children: Tuple["BlockDevice", ...] = ()

    @property
    def tran(self) -> Optional[str]:
        return self.transport

    @property
    def rota(self) -> Optional[bool]:
        return self.rotational

    @property
    def rm(self) -> Optional[bool]:
        return self.removable

    @property
    def ro(self) -> Optional[bool]:
        return self.read_only

    @property
    def pkname(self) -> Optional[str]:
        return self.parent_name

    @property
    def fstype(self) -> Optional[str]:
        return self.filesystem_type

    def descendants(self) -> Tuple["BlockDevice", ...]:
        result = []
        for child in self.children:
            result.append(child)
            result.extend(child.descendants())
        return tuple(result)


@dataclass(frozen=True)
class PhysicalDrive:
    """A physical-disk observation with conservative aggregate annotations."""

    device: BlockDevice
    mounted: bool = False
    observed_mountpoints: Tuple[str, ...] = ()
    protected: bool = False
    protection_reasons: Tuple[str, ...] = ()
    review_required: bool = False
    review_reasons: Tuple[str, ...] = ()
    ambiguous: bool = False
    system_protected: bool = False

    # Direct identity properties keep the small public model convenient.
    @property
    def name(self): return self.device.name
    @property
    def kname(self): return self.device.kname
    @property
    def path(self): return self.device.path
    @property
    def type(self): return self.device.type
    @property
    def size(self): return self.device.size
    @property
    def model(self): return self.device.model
    @property
    def serial(self): return self.device.serial
    @property
    def transport(self): return self.device.transport
    @property
    def tran(self): return self.device.transport
    @property
    def rotational(self): return self.device.rotational
    @property
    def rota(self): return self.device.rotational
    @property
    def removable(self): return self.device.removable
    @property
    def rm(self): return self.device.removable
    @property
    def read_only(self): return self.device.read_only
    @property
    def ro(self): return self.device.read_only
    @property
    def wwn(self): return self.device.wwn
    @property
    def parent_name(self): return self.device.parent_name
    @property
    def pkname(self): return self.device.parent_name
    @property
    def filesystem_type(self): return self.device.filesystem_type
    @property
    def fstype(self): return self.device.filesystem_type
    @property
    def mountpoints(self): return self.device.mountpoints
    @property
    def children(self): return self.device.children
    @property
    def system(self): return self.system_protected


def _optional_string(value: Any, location: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise DiscoveryError(f"{location} must be a string or null")
    return value


def _optional_bool(value: Any, location: str) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    raise DiscoveryError(f"{location} must be boolean, 0, 1, or null")


def _size(value: Any, location: str) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise DiscoveryError(f"{location} must be a non-negative integer or null")
    return value


def _mountpoints(item: Mapping[str, Any], location: str) -> Optional[Tuple[Optional[str], ...]]:
    if "mountpoints" in item:
        raw = item["mountpoints"]
        if raw is None:
            return None
        if not isinstance(raw, list):
            raise DiscoveryError(f"{location}.mountpoints must be an array or null")
        values = []
        for index, value in enumerate(raw):
            values.append(_optional_string(value, f"{location}.mountpoints[{index}]"))
        return tuple(values)
    if "mountpoint" in item:
        value = _optional_string(item["mountpoint"], f"{location}.mountpoint")
        return (value,) if value is not None else None
    return None


def _parse_device(item: Any, location: str) -> BlockDevice:
    if not isinstance(item, dict):
        raise DiscoveryError(f"{location} must be an object")
    device_type = item.get("type")
    if not isinstance(device_type, str) or not device_type.strip():
        raise DiscoveryError(f"{location}.type must be a non-empty string")
    raw_children = item.get("children", [])
    if raw_children is None:
        raw_children = []
    if not isinstance(raw_children, list):
        raise DiscoveryError(f"{location}.children must be an array or null")
    children = tuple(
        _parse_device(child, f"{location}.children[{index}]")
        for index, child in enumerate(raw_children)
    )
    return BlockDevice(
        name=_optional_string(item.get("name"), f"{location}.name"),
        kname=_optional_string(item.get("kname"), f"{location}.kname"),
        path=_optional_string(item.get("path"), f"{location}.path"),
        type=device_type,
        size=_size(item.get("size"), f"{location}.size"),
        model=_optional_string(item.get("model"), f"{location}.model"),
        serial=_optional_string(item.get("serial"), f"{location}.serial"),
        transport=_optional_string(item.get("tran"), f"{location}.tran"),
        rotational=_optional_bool(item.get("rota"), f"{location}.rota"),
        removable=_optional_bool(item.get("rm"), f"{location}.rm"),
        read_only=_optional_bool(item.get("ro"), f"{location}.ro"),
        wwn=_optional_string(item.get("wwn"), f"{location}.wwn"),
        parent_name=_optional_string(item.get("pkname"), f"{location}.pkname"),
        filesystem_type=_optional_string(item.get("fstype"), f"{location}.fstype"),
        mountpoints=_mountpoints(item, location),
        children=children,
    )


def _identifiers(device: BlockDevice) -> Tuple[str, ...]:
    values = []
    for value in (device.path, device.name, device.kname):
        if value:
            values.append(value)
            if not value.startswith("/dev/"):
                values.append("/dev/" + value)
    return tuple(values)



def _usable_strong_identity(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def parse_lsblk_json(
    captured_json: Union[str, bytes], *, protected_sources: Iterable[str] = ()
) -> Tuple[PhysicalDrive, ...]:
    """Parse captured lsblk JSON without inspecting or changing the host."""
    if not isinstance(captured_json, (str, bytes)):
        raise DiscoveryError("captured JSON must be str or bytes")
    try:
        document = json.loads(captured_json)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise DiscoveryError("malformed JSON") from exc
    if not isinstance(document, dict):
        raise DiscoveryError("top-level JSON value must be an object")
    devices = document.get("blockdevices")
    if not isinstance(devices, list):
        raise DiscoveryError("blockdevices must be an array")

    try:
        protected = tuple(protected_sources)
    except TypeError as exc:
        raise DiscoveryError("protected_sources must be an iterable of strings") from exc
    if any(not isinstance(source, str) or not source.strip() for source in protected):
        raise DiscoveryError("protected_sources must contain non-empty strings")
    protected_set = frozenset(protected)

    parsed = tuple(
        _parse_device(item, f"blockdevices[{index}]")
        for index, item in enumerate(devices)
    )
    physical_trees = tuple(
        ((device,) + device.descendants())
        for device in parsed
        if device.type == "disk"
    )

    aliases_by_tree = tuple(
        frozenset(
            identifier
            for member in tree
            for identifier in _identifiers(member)
        )
        for tree in physical_trees
    )
    alias_owners = {}
    for index, aliases in enumerate(aliases_by_tree):
        for alias in aliases:
            alias_owners.setdefault(alias, []).append(index)
    ambiguous_aliases = sorted(
        alias for alias, indexes in alias_owners.items() if len(indexes) > 1
    )
    if ambiguous_aliases:
        raise DiscoveryError(
            "topology identifier maps to multiple physical disks: "
            + ", ".join(ambiguous_aliases)
        )

    source_owners = {
        source: tuple(
            index for index, aliases in enumerate(aliases_by_tree) if source in aliases
        )
        for source in protected_set
    }
    multiply_matched = sorted(
        source for source, indexes in source_owners.items() if len(indexes) > 1
    )
    if multiply_matched:
        raise DiscoveryError(
            "protected source matched multiple physical disks: "
            + ", ".join(multiply_matched)
        )

    drives = []
    matched_sources = set()
    for tree, aliases in zip(physical_trees, aliases_by_tree):
        device = tree[0]
        mountpoints = tuple(
            mountpoint
            for member in tree
            for mountpoint in (member.mountpoints or ())
            if mountpoint is not None
        )
        matches = sorted(
            source
            for source in protected_set
            if source in aliases
        )
        matched_sources.update(matches)
        protection_reasons = tuple(
            f"protected source {source} matches disk or descendant" for source in matches
        )
        review_reasons = []
        if not _usable_strong_identity(device.serial) and not _usable_strong_identity(device.wwn):
            review_reasons.append("missing strong identity (serial and WWN)")
        if device.size == 0:
            review_reasons.append("reported size is zero bytes")
        drives.append(PhysicalDrive(
            device=device,
            mounted=bool(mountpoints),
            observed_mountpoints=mountpoints,
            protected=bool(protection_reasons),
            system_protected=bool(protection_reasons),
            protection_reasons=protection_reasons,
            review_required=bool(review_reasons),
            review_reasons=tuple(review_reasons),
        ))

    unmatched = protected_set - matched_sources
    if unmatched:
        raise DiscoveryError(
            "protected source did not match a physical disk or descendant: "
            + ", ".join(sorted(unmatched))
        )

    duplicates = {}
    for index, drive in enumerate(drives):
        for kind, value in (("serial", drive.serial), ("WWN", drive.wwn)):
            if _usable_strong_identity(value):
                duplicates.setdefault((kind, value.strip().casefold()), []).append(index)
    reasons_by_index = {index: [] for index in range(len(drives))}
    for (kind, value), indexes in sorted(duplicates.items()):
        if len(indexes) > 1:
            reason = f"duplicate strong identity: {kind} {value}"
            for index in indexes:
                reasons_by_index[index].append(reason)
    for index, extra_reasons in reasons_by_index.items():
        if extra_reasons:
            drive = drives[index]
            drives[index] = replace(
                drive,
                protected=True,
                protection_reasons=drive.protection_reasons + tuple(extra_reasons),
                review_required=True,
                review_reasons=drive.review_reasons + tuple(extra_reasons),
                ambiguous=True,
            )
    return tuple(drives)


__all__ = ["DiscoveryError", "BlockDevice", "PhysicalDrive", "parse_lsblk_json"]
