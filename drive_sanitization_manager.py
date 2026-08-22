"""Non-destructive Version 1 records foundation for Drive Sanitization Manager.

This module stores supplied record data only.  It never inspects a device and a
record's existence never implies that sanitization succeeded.
"""

from __future__ import annotations

import csv
import io
import json
import os
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional

SCHEMA_VERSION = 1


class RecordError(ValueError):
    """Base error for invalid or unsupported persisted records."""


class MalformedRecordError(RecordError):
    """The persisted record is not a valid Version 1 record."""


class UnsupportedSchemaVersionError(RecordError):
    """The persisted record uses an unsupported schema version."""


class OutputExistsError(FileExistsError):
    """An output was protected from being overwritten."""


class DuplicateIdentifierError(RecordError):
    """An intake identifier is already present in the batch."""


class InvalidStatusTransitionError(RecordError):
    """An intake workflow status transition is not permitted."""


BATCH_STATUSES = {"received", "in_progress", "complete", "failed", "incomplete", "review_needed"}
ELIGIBILITY_STATUSES = {"unknown", "eligible", "ineligible", "review_needed"}
SANITIZATION_STATUSES = {"not_started", "in_progress", "succeeded", "failed", "incomplete", "review_needed"}
VERIFICATION_RESULTS = {"not_performed", "passed", "failed", "incomplete", "review_needed"}
FINAL_STATUSES = {"pending", "complete", "failed", "incomplete", "review_needed"}
INTAKE_STATUSES = {"pending", "in_progress", "review_needed", "complete"}
INTAKE_TRANSITIONS = {
    "pending": {"in_progress", "review_needed"},
    "in_progress": {"review_needed", "complete"},
    "review_needed": {"in_progress", "complete"},
    "complete": set(),
}


def _require_text(value: Any, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise MalformedRecordError(f"{name} must be a non-empty string")


def _optional_text(value: Any, name: str) -> None:
    if value is not None and not isinstance(value, str):
        raise MalformedRecordError(f"{name} must be a string or null")


def _status(value: Any, name: str, allowed: set[str]) -> None:
    if value not in allowed:
        raise MalformedRecordError(f"{name} must be one of: {', '.join(sorted(allowed))}")


def _transition(current: str, target: str, name: str) -> str:
    _status(target, name, INTAKE_STATUSES)
    if target == current:
        return current
    if target not in INTAKE_TRANSITIONS[current]:
        raise InvalidStatusTransitionError(f"cannot change {name} from {current!r} to {target!r}")
    return target


def _identifier(value: Optional[str]) -> Optional[str]:
    """Normalize supplied identifiers for duplicate comparison only."""
    return value.strip().casefold() if isinstance(value, str) and value.strip() else None


def _write_new(path: os.PathLike[str] | str, content: bytes) -> None:
    target = os.fspath(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(target, flags, 0o666)
    except FileExistsError as exc:
        raise OutputExistsError(f"refusing to overwrite existing output: {target}") from exc
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written == 0:
                raise OSError("write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@dataclass(eq=True)
class DriveRecord:
    """A single drive's supplied identity, processing, and outcome record."""

    internal_record_id: str
    batch_job_id: str
    customer_asset_tag: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    capacity_bytes: Optional[int] = None
    capacity_human: Optional[str] = None
    media_type: Optional[str] = None
    interface_type: Optional[str] = None
    linux_device_path: Optional[str] = None
    stable_device_identifier: Optional[str] = None
    intake_timestamp: Optional[str] = None
    operator: Optional[str] = None
    initial_condition_notes: Optional[str] = None

    mounted: Optional[bool] = None
    system_protected: Optional[bool] = None
    protection_reason: Optional[str] = None
    health_smart_summary: Optional[str] = None
    intended_action: Optional[str] = None
    intended_disposition: Optional[str] = None
    sanitization_eligibility_status: str = "unknown"

    sanitization_status: str = "not_started"
    sanitization_method: Optional[str] = None
    sanitization_tool: Optional[str] = None
    sanitization_tool_version: Optional[str] = None
    sanitization_start_timestamp: Optional[str] = None
    sanitization_end_timestamp: Optional[str] = None
    sanitization_result: Optional[str] = None
    sanitization_failure_error: Optional[str] = None
    sanitization_measurements: Dict[str, Any] = field(default_factory=dict)
    sanitization_operator_notes: Optional[str] = None

    verification_required: Optional[bool] = None
    verification_method: Optional[str] = None
    verification_tool: Optional[str] = None
    verification_timestamp: Optional[str] = None
    verification_result: str = "not_performed"
    verification_failure_details: Optional[str] = None
    verification_reviewer_operator: Optional[str] = None
    verification_notes: Optional[str] = None

    raw_sanitization_log_reference: Optional[str] = None
    raw_verification_log_reference: Optional[str] = None
    source_intake_record_reference: Optional[str] = None
    report_path_reference: Optional[str] = None
    evidence_hashes: Dict[str, str] = field(default_factory=dict)

    final_status: str = "pending"
    final_disposition: Optional[str] = None
    disposition_timestamp: Optional[str] = None
    disposition_classification: Optional[str] = None
    disposition_notes: Optional[str] = None

    # Intake completion records inventory work only; it never represents a wipe.
    intake_status: str = "pending"
    intake_review_notes: Optional[str] = None

    _OPTIONAL_BOOL_FIELDS: ClassVar[set[str]] = {"mounted", "system_protected", "verification_required"}
    _DICT_FIELDS: ClassVar[set[str]] = {"sanitization_measurements", "evidence_hashes"}

    def validate(self) -> None:
        _require_text(self.internal_record_id, "internal_record_id")
        _require_text(self.batch_job_id, "batch_job_id")
        if self.capacity_bytes is not None and (type(self.capacity_bytes) is not int or self.capacity_bytes < 0):
            raise MalformedRecordError("capacity_bytes must be a non-negative integer or null")
        for name in self._OPTIONAL_BOOL_FIELDS:
            if (value := getattr(self, name)) is not None and type(value) is not bool:
                raise MalformedRecordError(f"{name} must be a boolean or null")
        for item in fields(self):
            value = getattr(self, item.name)
            if item.name not in self._DICT_FIELDS and item.name not in self._OPTIONAL_BOOL_FIELDS and item.name != "capacity_bytes":
                _optional_text(value, item.name)
        _status(self.sanitization_eligibility_status, "sanitization_eligibility_status", ELIGIBILITY_STATUSES)
        _status(self.sanitization_status, "sanitization_status", SANITIZATION_STATUSES)
        _status(self.verification_result, "verification_result", VERIFICATION_RESULTS)
        _status(self.final_status, "final_status", FINAL_STATUSES)
        _status(self.intake_status, "intake_status", INTAKE_STATUSES)
        if not isinstance(self.sanitization_measurements, dict):
            raise MalformedRecordError("sanitization_measurements must be an object")
        if not isinstance(self.evidence_hashes, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in self.evidence_hashes.items()
        ):
            raise MalformedRecordError("evidence_hashes must be an object containing string values")

    def transition_intake(self, status: str) -> None:
        """Apply a controlled intake transition without changing sanitization state."""
        self.validate()
        self.intake_status = _transition(self.intake_status, status, "intake_status")

    @classmethod
    def from_dict(cls, data: Any) -> "DriveRecord":
        if not isinstance(data, dict):
            raise MalformedRecordError("each drive must be a JSON object")
        expected = {item.name for item in fields(cls)}
        # Job 1 JSON omitted intake fields; defaults preserve compatibility.
        values = dict(data)
        values.setdefault("intake_status", "pending")
        values.setdefault("intake_review_notes", None)
        missing = expected - values.keys()
        unknown = values.keys() - expected
        if missing:
            raise MalformedRecordError(f"drive record is missing fields: {', '.join(sorted(missing))}")
        if unknown:
            raise MalformedRecordError(f"drive record has unknown fields: {', '.join(sorted(unknown))}")
        record = cls(**values)
        record.validate()
        return record


@dataclass(eq=True)
class BatchRecord:
    """A batch and all of its drive records."""

    batch_job_id: str
    customer_organization_reference: str
    customer_job_reference_number: str
    date_received: str
    authorization_reference_notes: Optional[str]
    processing_date: Optional[str]
    operator_technician: str
    overall_batch_status: str
    final_batch_disposition: Optional[str]
    general_notes: Optional[str]
    creation_timestamp: str
    last_updated_timestamp: str
    drives: List[DriveRecord] = field(default_factory=list)
    schema_version: int = SCHEMA_VERSION
    total_drive_count: Optional[int] = None
    intake_status: str = "pending"
    intake_review_notes: Optional[str] = None

    def __post_init__(self) -> None:
        if self.total_drive_count is None:
            self.total_drive_count = len(self.drives)

    def validate(self) -> None:
        if type(self.schema_version) is not int:
            raise MalformedRecordError("schema_version must be an integer")
        if self.schema_version != SCHEMA_VERSION:
            raise UnsupportedSchemaVersionError(
                f"unsupported schema version {self.schema_version!r}; supported version is {SCHEMA_VERSION}"
            )
        for name in (
            "batch_job_id", "customer_organization_reference", "customer_job_reference_number",
            "date_received", "operator_technician", "creation_timestamp", "last_updated_timestamp",
        ):
            _require_text(getattr(self, name), name)
        for name in ("authorization_reference_notes", "processing_date", "final_batch_disposition", "general_notes"):
            _optional_text(getattr(self, name), name)
        _status(self.overall_batch_status, "overall_batch_status", BATCH_STATUSES)
        _status(self.intake_status, "intake_status", INTAKE_STATUSES)
        _optional_text(self.intake_review_notes, "intake_review_notes")
        if type(self.total_drive_count) is not int or self.total_drive_count < 0:
            raise MalformedRecordError("total_drive_count must be a non-negative integer")
        if not isinstance(self.drives, list):
            raise MalformedRecordError("drives must be an array")
        if self.total_drive_count != len(self.drives):
            raise MalformedRecordError("total_drive_count does not match the number of drives")
        seen: Dict[str, set[str]] = {
            "internal_record_id": set(),
            "customer_asset_tag": set(),
            "serial_number": set(),
            "stable_device_identifier": set(),
        }
        for drive in self.drives:
            if not isinstance(drive, DriveRecord):
                raise MalformedRecordError("drives must contain DriveRecord values")
            drive.validate()
            if drive.batch_job_id != self.batch_job_id:
                raise MalformedRecordError("drive batch_job_id does not match its batch")
            for name, values in seen.items():
                normalized = _identifier(getattr(drive, name))
                if normalized is not None and normalized in values:
                    raise DuplicateIdentifierError(f"{name} values must be unique within a batch")
                if normalized is not None:
                    values.add(normalized)

    def add_drive(self, drive: DriveRecord) -> None:
        """Validate and add one technician-supplied drive intake record."""
        if self.intake_status == "complete":
            raise InvalidStatusTransitionError("cannot add a drive to a completed intake batch")
        if not isinstance(drive, DriveRecord):
            raise MalformedRecordError("drive must be a DriveRecord")
        if drive.batch_job_id != self.batch_job_id:
            raise MalformedRecordError("drive batch_job_id does not match its batch")
        previous_count = self.total_drive_count
        self.drives.append(drive)
        self.total_drive_count = len(self.drives)
        try:
            self.validate()
        except Exception:
            self.drives.pop()
            self.total_drive_count = previous_count
            raise
        if self.intake_status == "pending":
            self.intake_status = "in_progress"

    def transition_intake(self, status: str) -> None:
        """Move the batch through intake after validating all supplied records."""
        self.validate()
        if status == "complete" and not self.drives:
            raise InvalidStatusTransitionError("cannot complete intake for a batch with no drives")
        if status == "complete" and any(drive.intake_status != "complete" for drive in self.drives):
            raise InvalidStatusTransitionError("cannot complete batch intake until every drive intake is complete")
        self.intake_status = _transition(self.intake_status, status, "intake_status")

    def to_dict(self) -> Dict[str, Any]:
        self.validate()
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Any) -> "BatchRecord":
        if not isinstance(data, dict):
            raise MalformedRecordError("batch record must be a JSON object")
        version = data.get("schema_version")
        if type(version) is not int:
            raise MalformedRecordError("schema_version must be an integer")
        if version != SCHEMA_VERSION:
            raise UnsupportedSchemaVersionError(
                f"unsupported schema version {version!r}; supported version is {SCHEMA_VERSION}"
            )
        expected = {item.name for item in fields(cls)}
        values = dict(data)
        values.setdefault("intake_status", "pending")
        values.setdefault("intake_review_notes", None)
        missing = expected - values.keys()
        unknown = values.keys() - expected
        if missing:
            raise MalformedRecordError(f"batch record is missing fields: {', '.join(sorted(missing))}")
        if unknown:
            raise MalformedRecordError(f"batch record has unknown fields: {', '.join(sorted(unknown))}")
        raw_drives = values.get("drives")
        if not isinstance(raw_drives, list):
            raise MalformedRecordError("drives must be an array")
        values["drives"] = [DriveRecord.from_dict(item) for item in raw_drives]
        record = cls(**values)
        record.validate()
        return record


CSV_FIELDS = [
    "schema_version", "batch_job_id", "customer_organization_reference", "customer_job_reference_number",
    "date_received", "processing_date", "overall_batch_status", "internal_record_id", "customer_asset_tag",
    "manufacturer", "model", "serial_number", "capacity_bytes", "capacity_human", "media_type",
    "interface_type", "stable_device_identifier", "sanitization_eligibility_status", "sanitization_status",
    "sanitization_method", "sanitization_result", "sanitization_failure_error", "sanitization_start_timestamp",
    "sanitization_end_timestamp", "verification_required", "verification_method", "verification_result",
    "verification_failure_details", "verification_timestamp", "final_status", "final_disposition",
    "disposition_timestamp", "disposition_classification", "batch_intake_status",
    "batch_intake_review_notes", "drive_intake_status", "drive_intake_review_notes",
]


def save_json(batch: BatchRecord, path: os.PathLike[str] | str) -> None:
    """Validate and durably create a new authoritative JSON record."""
    payload = json.dumps(batch.to_dict(), indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
    _write_new(path, payload.encode("utf-8"))


def load_json(path: os.PathLike[str] | str) -> BatchRecord:
    """Load and validate a Version 1 authoritative JSON record."""
    try:
        with Path(path).open("r", encoding="utf-8") as stream:
            data = json.load(stream)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise MalformedRecordError(f"malformed JSON record: {exc}") from exc
    except OSError:
        raise
    try:
        return BatchRecord.from_dict(data)
    except (MalformedRecordError, UnsupportedSchemaVersionError):
        raise
    except (TypeError, ValueError) as exc:
        raise MalformedRecordError(f"malformed record: {exc}") from exc


def export_csv(batch: BatchRecord, path: os.PathLike[str] | str) -> None:
    """Create a spreadsheet-compatible CSV containing one row per drive."""
    batch.validate()
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_FIELDS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    batch_values = asdict(batch)
    for drive in batch.drives:
        row = {name: batch_values.get(name) for name in CSV_FIELDS}
        drive_values = asdict(drive)
        row.update({name: drive_values.get(name) for name in CSV_FIELDS if name in drive_values})
        row.update({
            "batch_intake_status": batch.intake_status,
            "batch_intake_review_notes": batch.intake_review_notes,
            "drive_intake_status": drive.intake_status,
            "drive_intake_review_notes": drive.intake_review_notes,
        })
        writer.writerow(row)
    _write_new(path, output.getvalue().encode("utf-8-sig"))
