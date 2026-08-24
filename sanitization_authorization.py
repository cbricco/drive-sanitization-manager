"""Fail-closed Phase 5 sanitization prerequisite evaluation.

The public positive path obtains current evidence through the fixed Phase 4
collector and timestamps that collection internally.

A positive result means only that deterministic prerequisites were met for one
exact request and one exact observed target.  It is not human approval and it
does not grant or perform destructive execution.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Any, Optional

from drive_discovery import (
    DiscoveryError,
    PhysicalDrive,
    parse_lsblk_json,
)
from drive_discovery_adapter import (
    DiscoveryCollectionError,
    DiscoverySnapshot,
    collect_current_drive_discovery,
)
from drive_sanitization_manager import (
    DriveRecord,
    RecordError,
)


POLICY_VERSION = "phase5-auth-v2"
SCHEMA_VERSION = 1

EVIDENCE_ORIGIN = "phase4-current-collector-v1"

MAX_DISCOVERY_AGE_SECONDS = 60
MAX_FUTURE_SKEW_SECONDS = 5
MAX_REQUEST_AGE_SECONDS = 300
PREREQUISITE_LIFETIME_SECONDS = 300

STATUS_PREREQUISITES_MET = "prerequisites_met"
STATUS_REFUSED = "refused"
STATUS_REVIEW_REQUIRED = "review_required"
STATUS_EVALUATION_FAILED = "evaluation_failed"

SUPPORTED_OPERATIONS = frozenset({"sanitize"})

# Deliberately non-executable.  A real destructive method belongs to Phase 6.
NON_EXECUTABLE_METHOD_PROFILES = frozenset({
    "phase5-policy-only",
})


class AuthorizationError(ValueError):
    """Authorization request or evidence could not be safely interpreted."""


@dataclass(frozen=True)
class AuthorizationRequest:
    request_id: str
    batch_job_id: str
    internal_record_id: str
    operation: str
    method_profile_id: str
    record_snapshot_hash: str
    created_at_utc: str
    schema_version: int = SCHEMA_VERSION


@dataclass(frozen=True)
class TargetIdentityBinding:
    path: str
    serial: Optional[str]
    wwn: Optional[str]
    size_bytes: int
    model: Optional[str]
    transport: Optional[str]
    read_only: bool
    mounted: bool
    protected: bool
    system_protected: bool
    review_required: bool
    ambiguous: bool


@dataclass(frozen=True)
class AuthorizationDecision:
    decision_id: str
    policy_version: str
    schema_version: int
    evidence_origin: str
    request_id: str
    request_hash: Optional[str]
    record_snapshot_hash: Optional[str]
    discovery_snapshot_hash: Optional[str]
    target_binding_hash: Optional[str]
    status: str
    reason_codes: tuple[str, ...]
    evaluated_at_utc: str
    discovery_captured_at_utc: str
    prerequisite_valid_until_utc: Optional[str]
    target_binding: Optional[TargetIdentityBinding]


_REASON_CLASS = {
    # Evidence / authority-context failures.
    "REQUEST_SCHEMA_INVALID": STATUS_EVALUATION_FAILED,
    "REQUEST_TIMESTAMP_INVALID": STATUS_EVALUATION_FAILED,
    "REQUEST_STALE": STATUS_EVALUATION_FAILED,
    "INTERNAL_CLOCK_INVALID": STATUS_EVALUATION_FAILED,
    "DISCOVERY_COLLECTION_FAILED": STATUS_EVALUATION_FAILED,
    "DISCOVERY_EVIDENCE_INVALID": STATUS_EVALUATION_FAILED,
    "DISCOVERY_EVIDENCE_MISMATCH": STATUS_EVALUATION_FAILED,
    "DISCOVERY_STALE": STATUS_EVALUATION_FAILED,
    "RECORD_INVALID": STATUS_EVALUATION_FAILED,
    "RECORD_SNAPSHOT_MISMATCH": STATUS_EVALUATION_FAILED,
    "STRONG_IDENTITY_MISSING": STATUS_EVALUATION_FAILED,
    "MALFORMED_RECORD_SERIAL": STATUS_EVALUATION_FAILED,
    "MALFORMED_RECORD_STABLE_IDENTIFIER": STATUS_EVALUATION_FAILED,
    "MALFORMED_DISCOVERED_SERIAL": STATUS_EVALUATION_FAILED,
    "MALFORMED_DISCOVERED_WWN": STATUS_EVALUATION_FAILED,
    "TARGET_NOT_PRESENT": STATUS_EVALUATION_FAILED,
    "MULTIPLE_TARGET_MATCHES": STATUS_EVALUATION_FAILED,
    "DUPLICATE_SERIAL": STATUS_EVALUATION_FAILED,
    "DUPLICATE_STABLE_IDENTIFIER": STATUS_EVALUATION_FAILED,
    "IDENTITY_COMPONENTS_DIVERGE": STATUS_EVALUATION_FAILED,
    "CAPACITY_UNKNOWN": STATUS_EVALUATION_FAILED,
    "CAPACITY_INVALID": STATUS_EVALUATION_FAILED,
    "READ_ONLY_STATE_UNKNOWN": STATUS_EVALUATION_FAILED,
    "TARGET_PATH_INVALID": STATUS_EVALUATION_FAILED,

    # Hard policy refusals.
    "BATCH_ID_MISMATCH": STATUS_REFUSED,
    "RECORD_ID_MISMATCH": STATUS_REFUSED,
    "OPERATION_MISSING": STATUS_REFUSED,
    "OPERATION_UNSUPPORTED": STATUS_REFUSED,
    "METHOD_PROFILE_MISSING": STATUS_REFUSED,
    "METHOD_PROFILE_UNSUPPORTED": STATUS_REFUSED,
    "INTENDED_ACTION_MISSING": STATUS_REFUSED,
    "INTENDED_ACTION_MISMATCH": STATUS_REFUSED,
    "RECORDED_SYSTEM_PROTECTED": STATUS_REFUSED,
    "RECORD_MARKED_INELIGIBLE": STATUS_REFUSED,
    "RECORD_SANITIZATION_STATE_NOT_READY": STATUS_REFUSED,
    "TARGET_IDENTITY_CHANGED": STATUS_REFUSED,
    "SERIAL_MISMATCH": STATUS_REFUSED,
    "STABLE_IDENTIFIER_MISMATCH": STATUS_REFUSED,
    "DEVICE_PATH_CHANGED": STATUS_REFUSED,
    "CAPACITY_MISMATCH": STATUS_REFUSED,
    "SYSTEM_STORAGE": STATUS_REFUSED,
    "PROTECTED_STORAGE": STATUS_REFUSED,
    "TARGET_MOUNTED": STATUS_REFUSED,
    "TARGET_READ_ONLY": STATUS_REFUSED,

    # Evidence requiring operator investigation.
    "RECORD_REVIEW_REQUIRED": STATUS_REVIEW_REQUIRED,
    "RECORD_ELIGIBILITY_UNKNOWN": STATUS_REVIEW_REQUIRED,
    "RECORD_INTAKE_INCOMPLETE": STATUS_REVIEW_REQUIRED,
    "RECORDED_SYSTEM_STATE_UNKNOWN": STATUS_REVIEW_REQUIRED,
    "RECORDED_MOUNTED_REVIEW_REQUIRED": STATUS_REVIEW_REQUIRED,
    "RECORDED_MOUNT_STATE_UNKNOWN": STATUS_REVIEW_REQUIRED,
    "TARGET_AMBIGUOUS": STATUS_REVIEW_REQUIRED,
    "TARGET_REVIEW_REQUIRED": STATUS_REVIEW_REQUIRED,
    "MODEL_MISMATCH_REVIEW_REQUIRED": STATUS_REVIEW_REQUIRED,
}

_STATUS_PRECEDENCE = {
    STATUS_PREREQUISITES_MET: 0,
    STATUS_REVIEW_REQUIRED: 1,
    STATUS_REFUSED: 2,
    STATUS_EVALUATION_FAILED: 3,
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _aware_utc(value: Any) -> Optional[datetime]:
    if not isinstance(value, datetime):
        return None

    if value.tzinfo is None or value.utcoffset() is None:
        return None

    return value.astimezone(timezone.utc)


def _iso_utc(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _require_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AuthorizationError(
            f"{name} must be a non-empty string"
        )

    return value.strip()


def _parse_utc(value: Any, name: str) -> datetime:
    text = _require_text(value, name)

    try:
        parsed = datetime.fromisoformat(
            text[:-1] + "+00:00"
            if text.endswith("Z")
            else text
        )
    except ValueError as exc:
        raise AuthorizationError(
            f"{name} must be an ISO-8601 timestamp"
        ) from exc

    parsed = _aware_utc(parsed)

    if parsed is None:
        raise AuthorizationError(
            f"{name} must include a timezone"
        )

    return parsed


def _canonical_hash(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _contains_forbidden_control(value: str) -> bool:
    return any(
        ord(character) < 32 or ord(character) == 127
        for character in value
    )


def _identity(
    value: Any,
    malformed_reason: str,
    reasons: list[str],
) -> Optional[str]:
    if value is None:
        return None

    if not isinstance(value, str):
        reasons.append(malformed_reason)
        return None

    stripped = value.strip()

    if not stripped:
        return None

    if _contains_forbidden_control(stripped):
        reasons.append(malformed_reason)
        return None

    return stripped


def _candidate_identity(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None

    stripped = value.strip()

    if not stripped:
        return None

    if _contains_forbidden_control(stripped):
        return None

    return stripped


def _path_is_valid(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and not _contains_forbidden_control(value.strip())
    )


def record_snapshot_hash(record: DriveRecord) -> str:
    """Hash every record field that can affect this Phase 5 policy."""

    record.validate()

    payload = {
        "schema_version": SCHEMA_VERSION,
        "internal_record_id": record.internal_record_id,
        "batch_job_id": record.batch_job_id,
        "model": record.model,
        "serial_number": record.serial_number,
        "capacity_bytes": record.capacity_bytes,
        "linux_device_path": record.linux_device_path,
        "stable_device_identifier":
            record.stable_device_identifier,
        "mounted": record.mounted,
        "system_protected": record.system_protected,
        "intended_action": record.intended_action,
        "sanitization_eligibility_status":
            record.sanitization_eligibility_status,
        "sanitization_status": record.sanitization_status,
        "intake_status": record.intake_status,
    }

    return _canonical_hash(payload)


def _snapshot_shape_valid(
    snapshot: Any,
) -> bool:
    if not isinstance(snapshot, DiscoverySnapshot):
        return False

    byte_fields = (
        "captured_lsblk_json",
        "captured_findmnt_root_json",
        "captured_findmnt_real_json",
        "captured_swapon_output",
        "captured_findmnt_fstab_json",
    )

    if any(
        not isinstance(getattr(snapshot, name), bytes)
        for name in byte_fields
    ):
        return False

    if (
        not isinstance(snapshot.protected_sources, tuple)
        or any(
            not isinstance(source, str)
            or not source.strip()
            for source in snapshot.protected_sources
        )
    ):
        return False

    if (
        not isinstance(snapshot.drives, tuple)
        or any(
            not isinstance(drive, PhysicalDrive)
            for drive in snapshot.drives
        )
    ):
        return False

    return True


def discovery_snapshot_hash(
    snapshot: DiscoverySnapshot,
) -> str:
    if not _snapshot_shape_valid(snapshot):
        raise AuthorizationError(
            "discovery snapshot shape is invalid"
        )

    payload = {
        "schema_version": SCHEMA_VERSION,
        "captured_lsblk_json":
            snapshot.captured_lsblk_json.hex(),
        "protected_sources":
            list(snapshot.protected_sources),
        "captured_findmnt_root_json":
            snapshot.captured_findmnt_root_json.hex(),
        "captured_findmnt_real_json":
            snapshot.captured_findmnt_real_json.hex(),
        "captured_swapon_output":
            snapshot.captured_swapon_output.hex(),
        "captured_findmnt_fstab_json":
            snapshot.captured_findmnt_fstab_json.hex(),
    }

    return _canonical_hash(payload)


def build_authorization_request(
    record: DriveRecord,
    *,
    request_id: str,
    operation: str,
    method_profile_id: str,
) -> AuthorizationRequest:
    """Create a request with an internally obtained creation timestamp."""

    if not isinstance(record, DriveRecord):
        raise AuthorizationError(
            "record must be a DriveRecord"
        )

    try:
        record.validate()
    except RecordError as exc:
        raise AuthorizationError(
            "record is invalid"
        ) from exc

    _require_text(request_id, "request_id")
    _require_text(operation, "operation")
    _require_text(method_profile_id, "method_profile_id")

    now = _aware_utc(_utc_now())

    if now is None:
        raise AuthorizationError(
            "internal clock did not return an aware timestamp"
        )

    return AuthorizationRequest(
        request_id=request_id,
        batch_job_id=record.batch_job_id,
        internal_record_id=record.internal_record_id,
        operation=operation,
        method_profile_id=method_profile_id,
        record_snapshot_hash=record_snapshot_hash(record),
        created_at_utc=_iso_utc(now),
    )


def request_hash(
    request: AuthorizationRequest,
) -> str:
    return _canonical_hash(asdict(request))


def _derived_drives(
    snapshot: DiscoverySnapshot,
    reasons: list[str],
) -> Optional[tuple[PhysicalDrive, ...]]:
    if not _snapshot_shape_valid(snapshot):
        reasons.append("DISCOVERY_EVIDENCE_INVALID")
        return None

    try:
        independently_derived = parse_lsblk_json(
            snapshot.captured_lsblk_json,
            protected_sources=snapshot.protected_sources,
        )
    except DiscoveryError:
        reasons.append("DISCOVERY_EVIDENCE_INVALID")
        return None

    if independently_derived != snapshot.drives:
        reasons.append("DISCOVERY_EVIDENCE_MISMATCH")
        return None

    return independently_derived


def _matching_target(
    record: DriveRecord,
    drives: tuple[PhysicalDrive, ...],
    reasons: list[str],
) -> Optional[PhysicalDrive]:
    serial = _identity(
        record.serial_number,
        "MALFORMED_RECORD_SERIAL",
        reasons,
    )

    stable = _identity(
        record.stable_device_identifier,
        "MALFORMED_RECORD_STABLE_IDENTIFIER",
        reasons,
    )

    if serial is None and stable is None:
        reasons.append("STRONG_IDENTITY_MISSING")
        return None

    serial_matches: list[PhysicalDrive] = []
    stable_matches: list[PhysicalDrive] = []

    for drive in drives:
        fresh_serial = _candidate_identity(drive.serial)
        fresh_wwn = _candidate_identity(drive.wwn)

        if (
            serial is not None
            and fresh_serial == serial
        ):
            serial_matches.append(drive)

        if (
            stable is not None
            and stable in {fresh_serial, fresh_wwn}
        ):
            stable_matches.append(drive)

    if len(serial_matches) > 1:
        reasons.append("DUPLICATE_SERIAL")

    if len(stable_matches) > 1:
        reasons.append("DUPLICATE_STABLE_IDENTIFIER")

    if (
        len(serial_matches) > 1
        or len(stable_matches) > 1
    ):
        return None

    if serial is not None and stable is not None:
        if serial_matches and stable_matches:
            if serial_matches[0] is not stable_matches[0]:
                reasons.append(
                    "IDENTITY_COMPONENTS_DIVERGE"
                )
                return None

            return serial_matches[0]

        if serial_matches:
            reasons.append(
                "STABLE_IDENTIFIER_MISMATCH"
            )
            return serial_matches[0]

        if stable_matches:
            reasons.append("SERIAL_MISMATCH")
            return stable_matches[0]

        same_path = [
            drive
            for drive in drives
            if (
                isinstance(record.linux_device_path, str)
                and drive.path
                == record.linux_device_path
            )
        ]

        if len(same_path) == 1:
            reasons.append("TARGET_IDENTITY_CHANGED")
            return same_path[0]

        if len(same_path) > 1:
            reasons.append("MULTIPLE_TARGET_MATCHES")
            return None

        reasons.append("TARGET_NOT_PRESENT")
        return None

    matches = (
        serial_matches
        if serial is not None
        else stable_matches
    )

    if matches:
        return matches[0]

    same_path = [
        drive
        for drive in drives
        if (
            isinstance(record.linux_device_path, str)
            and drive.path == record.linux_device_path
        )
    ]

    if len(same_path) == 1:
        reasons.append("TARGET_IDENTITY_CHANGED")
        return same_path[0]

    if len(same_path) > 1:
        reasons.append("MULTIPLE_TARGET_MATCHES")
        return None

    reasons.append("TARGET_NOT_PRESENT")
    return None


def _target_binding(
    drive: PhysicalDrive,
) -> Optional[TargetIdentityBinding]:
    if not _path_is_valid(drive.path):
        return None

    if type(drive.size) is not int or drive.size <= 0:
        return None

    if type(drive.read_only) is not bool:
        return None

    return TargetIdentityBinding(
        path=drive.path,
        serial=drive.serial,
        wwn=drive.wwn,
        size_bytes=drive.size,
        model=drive.model,
        transport=drive.transport,
        read_only=drive.read_only,
        mounted=drive.mounted,
        protected=drive.protected,
        system_protected=drive.system_protected,
        review_required=drive.review_required,
        ambiguous=drive.ambiguous,
    )


def _decision_status(
    reasons: tuple[str, ...],
) -> str:
    if not reasons:
        return STATUS_PREREQUISITES_MET

    return max(
        (
            _REASON_CLASS.get(
                reason,
                STATUS_EVALUATION_FAILED,
            )
            for reason in reasons
        ),
        key=_STATUS_PRECEDENCE.__getitem__,
    )


def _safe_request_hash(
    request: Any,
) -> Optional[str]:
    try:
        return request_hash(request)
    except (TypeError, ValueError):
        return None


def _safe_record_hash(
    record: Any,
) -> Optional[str]:
    try:
        return record_snapshot_hash(record)
    except (
        RecordError,
        TypeError,
        AttributeError,
    ):
        return None


def _make_decision(
    request: Any,
    *,
    record_hash: Optional[str],
    snapshot_hash: Optional[str],
    binding: Optional[TargetIdentityBinding],
    reasons: list[str],
    captured_at: datetime,
    evaluated_at: datetime,
) -> AuthorizationDecision:
    reason_codes = tuple(dict.fromkeys(reasons))
    status = _decision_status(reason_codes)

    binding_hash = (
        _canonical_hash(asdict(binding))
        if binding is not None
        else None
    )

    req_hash = _safe_request_hash(request)

    valid_until = None

    if status == STATUS_PREREQUISITES_MET:
        valid_until = _iso_utc(
            evaluated_at
            + timedelta(
                seconds=PREREQUISITE_LIFETIME_SECONDS
            )
        )

    payload = {
        "policy_version": POLICY_VERSION,
        "schema_version": SCHEMA_VERSION,
        "evidence_origin": EVIDENCE_ORIGIN,
        "request_hash": req_hash,
        "record_snapshot_hash": record_hash,
        "discovery_snapshot_hash": snapshot_hash,
        "target_binding_hash": binding_hash,
        "status": status,
        "reason_codes": reason_codes,
        "evaluated_at_utc": _iso_utc(evaluated_at),
        "discovery_captured_at_utc":
            _iso_utc(captured_at),
        "prerequisite_valid_until_utc": valid_until,
    }

    raw_request_id = getattr(
        request,
        "request_id",
        "",
    )

    request_id = (
        raw_request_id
        if isinstance(raw_request_id, str)
        else ""
    )

    return AuthorizationDecision(
        decision_id=_canonical_hash(payload),
        policy_version=POLICY_VERSION,
        schema_version=SCHEMA_VERSION,
        evidence_origin=EVIDENCE_ORIGIN,
        request_id=request_id,
        request_hash=req_hash,
        record_snapshot_hash=record_hash,
        discovery_snapshot_hash=snapshot_hash,
        target_binding_hash=binding_hash,
        status=status,
        reason_codes=reason_codes,
        evaluated_at_utc=_iso_utc(evaluated_at),
        discovery_captured_at_utc=_iso_utc(captured_at),
        prerequisite_valid_until_utc=valid_until,
        target_binding=binding,
    )


def _evaluate_collected_evidence(
    request: AuthorizationRequest,
    record: DriveRecord,
    snapshot: DiscoverySnapshot,
    *,
    captured_at: datetime,
    evaluated_at: datetime,
) -> AuthorizationDecision:
    """Private deterministic evaluator for internally collected evidence."""

    reasons: list[str] = []

    request_created: Optional[datetime]

    try:
        _require_text(request.request_id, "request_id")
        _require_text(request.batch_job_id, "batch_job_id")
        _require_text(
            request.internal_record_id,
            "internal_record_id",
        )
        request_created = _parse_utc(
            request.created_at_utc,
            "created_at_utc",
        )
    except (
        AuthorizationError,
        AttributeError,
    ):
        request_created = None
        reasons.append("REQUEST_SCHEMA_INVALID")

    if (
        not isinstance(request, AuthorizationRequest)
        or request.schema_version != SCHEMA_VERSION
    ):
        reasons.append("REQUEST_SCHEMA_INVALID")

    if request_created is not None:
        request_age = evaluated_at - request_created

        if request_age < -timedelta(
            seconds=MAX_FUTURE_SKEW_SECONDS
        ):
            reasons.append("REQUEST_TIMESTAMP_INVALID")
        elif request_age > timedelta(
            seconds=MAX_REQUEST_AGE_SECONDS
        ):
            reasons.append("REQUEST_STALE")

    if request.batch_job_id != record.batch_job_id:
        reasons.append("BATCH_ID_MISMATCH")

    if (
        request.internal_record_id
        != record.internal_record_id
    ):
        reasons.append("RECORD_ID_MISMATCH")

    operation = (
        request.operation.strip()
        if isinstance(request.operation, str)
        else ""
    )

    method = (
        request.method_profile_id.strip()
        if isinstance(request.method_profile_id, str)
        else ""
    )

    if not operation:
        reasons.append("OPERATION_MISSING")
    elif operation not in SUPPORTED_OPERATIONS:
        reasons.append("OPERATION_UNSUPPORTED")

    if not method:
        reasons.append("METHOD_PROFILE_MISSING")
    elif method not in NON_EXECUTABLE_METHOD_PROFILES:
        reasons.append("METHOD_PROFILE_UNSUPPORTED")

    record_hash = _safe_record_hash(record)

    if record_hash is None:
        reasons.append("RECORD_INVALID")
    elif request.record_snapshot_hash != record_hash:
        reasons.append("RECORD_SNAPSHOT_MISMATCH")

    if (
        not isinstance(record.intended_action, str)
        or not record.intended_action.strip()
    ):
        reasons.append("INTENDED_ACTION_MISSING")
    elif (
        record.intended_action.strip()
        != operation
    ):
        reasons.append("INTENDED_ACTION_MISMATCH")

    if record.system_protected is True:
        reasons.append("RECORDED_SYSTEM_PROTECTED")
    elif record.system_protected is None:
        reasons.append("RECORDED_SYSTEM_STATE_UNKNOWN")

    if record.mounted is True:
        reasons.append(
            "RECORDED_MOUNTED_REVIEW_REQUIRED"
        )
    elif record.mounted is None:
        reasons.append(
            "RECORDED_MOUNT_STATE_UNKNOWN"
        )

    if record.sanitization_status != "not_started":
        reasons.append(
            "RECORD_SANITIZATION_STATE_NOT_READY"
        )

    if (
        record.sanitization_eligibility_status
        == "ineligible"
    ):
        reasons.append("RECORD_MARKED_INELIGIBLE")
    elif (
        record.sanitization_eligibility_status
        == "review_needed"
    ):
        reasons.append("RECORD_REVIEW_REQUIRED")
    elif (
        record.sanitization_eligibility_status
        == "unknown"
    ):
        reasons.append("RECORD_ELIGIBILITY_UNKNOWN")

    if record.intake_status != "complete":
        reasons.append("RECORD_INTAKE_INCOMPLETE")

    discovery_age = evaluated_at - captured_at

    if discovery_age < -timedelta(
        seconds=MAX_FUTURE_SKEW_SECONDS
    ):
        reasons.append("INTERNAL_CLOCK_INVALID")
    elif discovery_age > timedelta(
        seconds=MAX_DISCOVERY_AGE_SECONDS
    ):
        reasons.append("DISCOVERY_STALE")

    snapshot_hash: Optional[str]

    try:
        snapshot_hash = discovery_snapshot_hash(snapshot)
    except AuthorizationError:
        snapshot_hash = None
        reasons.append("DISCOVERY_EVIDENCE_INVALID")

    drives = _derived_drives(snapshot, reasons)

    target = None
    binding = None

    if drives is not None:
        target = _matching_target(
            record,
            drives,
            reasons,
        )

    if target is not None:
        fresh_serial = _identity(
            target.serial,
            "MALFORMED_DISCOVERED_SERIAL",
            reasons,
        )

        fresh_wwn = _identity(
            target.wwn,
            "MALFORMED_DISCOVERED_WWN",
            reasons,
        )

        record_serial = _candidate_identity(
            record.serial_number
        )

        stable = _candidate_identity(
            record.stable_device_identifier
        )

        if (
            record_serial is not None
            and fresh_serial != record_serial
        ):
            reasons.append("SERIAL_MISMATCH")

        if (
            stable is not None
            and stable not in {fresh_serial, fresh_wwn}
        ):
            reasons.append(
                "STABLE_IDENTIFIER_MISMATCH"
            )

        if not _path_is_valid(target.path):
            reasons.append("TARGET_PATH_INVALID")
        elif (
            not isinstance(record.linux_device_path, str)
            or not record.linux_device_path.strip()
            or target.path != record.linux_device_path
        ):
            reasons.append("DEVICE_PATH_CHANGED")

        if record.capacity_bytes is None:
            reasons.append("CAPACITY_UNKNOWN")
        elif (
            type(record.capacity_bytes) is not int
            or record.capacity_bytes <= 0
        ):
            reasons.append("CAPACITY_INVALID")
        elif (
            type(target.size) is not int
            or target.size <= 0
        ):
            reasons.append("CAPACITY_INVALID")
        elif target.size != record.capacity_bytes:
            reasons.append("CAPACITY_MISMATCH")

        if target.system_protected:
            reasons.append("SYSTEM_STORAGE")

        if target.protected:
            reasons.append("PROTECTED_STORAGE")

        if target.mounted:
            reasons.append("TARGET_MOUNTED")

        if target.ambiguous:
            reasons.append("TARGET_AMBIGUOUS")

        if target.review_required:
            reasons.append("TARGET_REVIEW_REQUIRED")

        if target.read_only is None:
            reasons.append("READ_ONLY_STATE_UNKNOWN")
        elif target.read_only:
            reasons.append("TARGET_READ_ONLY")

        if (
            isinstance(record.model, str)
            and record.model.strip()
            and isinstance(target.model, str)
            and target.model.strip()
            and (
                record.model.strip().casefold()
                != target.model.strip().casefold()
            )
        ):
            reasons.append(
                "MODEL_MISMATCH_REVIEW_REQUIRED"
            )

        binding = _target_binding(target)

        if binding is None:
            if not _path_is_valid(target.path):
                reasons.append("TARGET_PATH_INVALID")

            if (
                type(target.size) is not int
                or target.size <= 0
            ):
                reasons.append("CAPACITY_INVALID")

            if type(target.read_only) is not bool:
                reasons.append(
                    "READ_ONLY_STATE_UNKNOWN"
                )

    return _make_decision(
        request,
        record_hash=record_hash,
        snapshot_hash=snapshot_hash,
        binding=binding,
        reasons=reasons,
        captured_at=captured_at,
        evaluated_at=evaluated_at,
    )


def evaluate_current_authorization_prerequisites(
    request: AuthorizationRequest,
    record: DriveRecord,
) -> AuthorizationDecision:
    """Collect current Phase 4 evidence and evaluate it.

    The caller cannot substitute a snapshot, capture time, evaluation time,
    command, executable, or collection path through this public API.
    """

    captured_at = _aware_utc(_utc_now())

    if captured_at is None:
        epoch = datetime(
            1970,
            1,
            1,
            tzinfo=timezone.utc,
        )

        return _make_decision(
            request,
            record_hash=_safe_record_hash(record),
            snapshot_hash=None,
            binding=None,
            reasons=["INTERNAL_CLOCK_INVALID"],
            captured_at=epoch,
            evaluated_at=epoch,
        )

    if not isinstance(request, AuthorizationRequest):
        return _make_decision(
            request,
            record_hash=_safe_record_hash(record),
            snapshot_hash=None,
            binding=None,
            reasons=["REQUEST_SCHEMA_INVALID"],
            captured_at=captured_at,
            evaluated_at=captured_at,
        )

    record_hash = _safe_record_hash(record)

    if (
        not isinstance(record, DriveRecord)
        or record_hash is None
    ):
        return _make_decision(
            request,
            record_hash=None,
            snapshot_hash=None,
            binding=None,
            reasons=["RECORD_INVALID"],
            captured_at=captured_at,
            evaluated_at=captured_at,
        )

    try:
        snapshot = collect_current_drive_discovery()
    except (
        DiscoveryCollectionError,
        DiscoveryError,
    ):
        evaluated_at = _aware_utc(_utc_now())

        if evaluated_at is None:
            evaluated_at = captured_at

        return _make_decision(
            request,
            record_hash=_safe_record_hash(record),
            snapshot_hash=None,
            binding=None,
            reasons=["DISCOVERY_COLLECTION_FAILED"],
            captured_at=captured_at,
            evaluated_at=evaluated_at,
        )

    evaluated_at = _aware_utc(_utc_now())

    if evaluated_at is None:
        return _make_decision(
            request,
            record_hash=_safe_record_hash(record),
            snapshot_hash=None,
            binding=None,
            reasons=["INTERNAL_CLOCK_INVALID"],
            captured_at=captured_at,
            evaluated_at=captured_at,
        )

    return _evaluate_collected_evidence(
        request,
        record,
        snapshot,
        captured_at=captured_at,
        evaluated_at=evaluated_at,
    )


def decision_is_current(
    decision: AuthorizationDecision,
) -> bool:
    """Check the prerequisite window using the internal clock.

    True still does not represent human approval or execution authority.
    """

    if (
        decision.status
        != STATUS_PREREQUISITES_MET
    ):
        return False

    if (
        decision.prerequisite_valid_until_utc
        is None
    ):
        return False

    now = _aware_utc(_utc_now())

    if now is None:
        return False

    try:
        expires = _parse_utc(
            decision.prerequisite_valid_until_utc,
            "prerequisite_valid_until_utc",
        )
    except AuthorizationError:
        return False

    return now <= expires


__all__ = [
    "AuthorizationDecision",
    "AuthorizationError",
    "AuthorizationRequest",
    "TargetIdentityBinding",
    "POLICY_VERSION",
    "SCHEMA_VERSION",
    "EVIDENCE_ORIGIN",
    "MAX_DISCOVERY_AGE_SECONDS",
    "MAX_FUTURE_SKEW_SECONDS",
    "MAX_REQUEST_AGE_SECONDS",
    "PREREQUISITE_LIFETIME_SECONDS",
    "STATUS_PREREQUISITES_MET",
    "STATUS_REFUSED",
    "STATUS_REVIEW_REQUIRED",
    "STATUS_EVALUATION_FAILED",
    "build_authorization_request",
    "decision_is_current",
    "discovery_snapshot_hash",
    "evaluate_current_authorization_prerequisites",
    "record_snapshot_hash",
    "request_hash",
]
