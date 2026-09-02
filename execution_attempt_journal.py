"""Phase 6E-B3F-D durable non-executing execution-attempt boundary.

One ATTEMPTING record is durably persisted only while an exact active B3F-C
executor-ready capability still holds the established lock hierarchy:

    lease state -> B3E-F lifecycle -> B3A lifecycle -> authorization store
        -> execution-attempt journal

ATTEMPTING is a conservative pre-side-effect tombstone. It means only that the
future destructive executor boundary has been crossed and a destructive side
effect may or may not later occur, or may be ambiguous after interruption. It
does not mean execution completed, sanitization succeeded, or verification
succeeded. There is no completion, success, result, rollback, command,
child-process, device-I/O, or executor transition in this module.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile
from typing import Any

import execution_lease as leases
import executor_authorization as exauth
import executor_ready_capability as ready
import kernel_write_claim_acquisition as claims


EXECUTION_ATTEMPT_POLICY_VERSION = (
    "phase6e-b3f-d-durable-execution-attempt-v1"
)
EXECUTION_ATTEMPT_SCHEMA_VERSION = 1
EXECUTION_ATTEMPT_STATE_ATTEMPTING = "ATTEMPTING"
EXECUTION_ATTEMPT_STORE_MAX_BYTES = 1_048_576


class ExecutionAttemptError(RuntimeError):
    """Durable execution-attempt boundary failed closed."""


@dataclass(frozen=True)
class ExecutionAttemptRecord:
    attempt_id: str
    policy_version: str
    schema_version: int
    state: str

    authorization_id: str
    lease_binding_id: str
    handoff_id: str
    target_path: str
    target_major_minor: str
    target_binding_hash: str

    gate_id: str
    binding_id: str
    journal_policy_version: str
    journal_schema_version: int
    journal_state: str
    journal_entry_hash: str

    approval_id: str
    request_id: str
    request_hash: str
    record_snapshot_hash: str
    internal_record_id: str
    method_profile_id: str
    operation: str

    attempted_at_utc: str

    execution_started_proven: bool
    execution_returned: bool
    sanitization_verified: bool
    automatic_replay_allowed: bool
    requires_manual_review_if_interrupted: bool

    record_hash: str

    def __copy__(self) -> Any:
        raise ExecutionAttemptError(
            "execution-attempt records cannot be copied"
        )

    def __deepcopy__(self, memo: Any) -> Any:
        raise ExecutionAttemptError(
            "execution-attempt records cannot be deep-copied"
        )

    def __reduce__(self) -> Any:
        raise ExecutionAttemptError(
            "execution-attempt records cannot be serialized"
        )

    def __reduce_ex__(self, protocol: int) -> Any:
        raise ExecutionAttemptError(
            "execution-attempt records cannot be serialized"
        )


_CAPABILITY_TYPE = ready.ExecutorReadyCapability
_LEASE_TYPE = leases.ExecutionLease
_LEASE_SCOPE_TYPE = leases._LockedExecutionLeaseValidationScope
_AUTH_SCOPE_TYPE = exauth._LockedReservedExecutorAuthorizationScope
_CLAIM_SCOPE_TYPE = claims._LockedWriteClaimValidationScope


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_utc(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(
            value[:-1] + "+00:00"
            if value.endswith("Z")
            else value
        )
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _exact_text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and "\x00" not in value
        and "\n" not in value
        and "\r" not in value
    )


def _prefixed_hex(value: Any, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(prefix)
        and len(value) == len(prefix) + 64
        and all(
            character in "0123456789abcdef"
            for character in value[len(prefix):]
        )
    )


def _canonical_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _record_payload(record: ExecutionAttemptRecord) -> dict[str, Any]:
    payload = asdict(record)
    payload.pop("record_hash")
    return payload


def _record_integrity_valid(record: Any) -> bool:
    try:
        if type(record) is not ExecutionAttemptRecord:
            return False

        if (
            record.policy_version != EXECUTION_ATTEMPT_POLICY_VERSION
            or type(record.schema_version) is not int
            or record.schema_version != EXECUTION_ATTEMPT_SCHEMA_VERSION
            or record.state != EXECUTION_ATTEMPT_STATE_ATTEMPTING
            or not _prefixed_hex(record.attempt_id, "xeattempt_")
            or not _prefixed_hex(record.authorization_id, "xeauth_")
            or not _prefixed_hex(record.lease_binding_id, "xeli_")
        ):
            return False

        for value in (
            record.handoff_id,
            record.target_path,
            record.target_major_minor,
            record.target_binding_hash,
            record.gate_id,
            record.binding_id,
            record.journal_policy_version,
            record.journal_state,
            record.journal_entry_hash,
            record.approval_id,
            record.request_id,
            record.request_hash,
            record.record_snapshot_hash,
            record.internal_record_id,
            record.method_profile_id,
            record.operation,
        ):
            if not _exact_text(value):
                return False

        if type(record.journal_schema_version) is not int:
            return False

        attempted_at = _parse_utc(record.attempted_at_utc)
        if (
            attempted_at is None
            or _iso_utc(attempted_at) != record.attempted_at_utc
        ):
            return False

        if (
            record.execution_started_proven is not False
            or record.execution_returned is not False
            or record.sanitization_verified is not False
            or record.automatic_replay_allowed is not False
            or record.requires_manual_review_if_interrupted is not True
        ):
            return False

        return record.record_hash == _canonical_hash(
            _record_payload(record)
        )
    except Exception:
        return False


class DurableExecutionAttemptJournal:
    """Private restart-safe ATTEMPTING-only anti-replay journal."""

    def __init__(self, path: Any) -> None:
        try:
            self._path = Path(os.fspath(path))
        except (TypeError, ValueError) as exc:
            raise ExecutionAttemptError(
                "execution-attempt journal path is invalid"
            ) from exc

        if not self._path.is_absolute() or not self._path.name:
            raise ExecutionAttemptError(
                "execution-attempt journal path must be absolute"
            )

        self._lock_path = self._path.with_name(
            self._path.name + ".lock"
        )

    @property
    def path(self) -> Path:
        return self._path

    def _validate_parent(self) -> None:
        try:
            info = os.lstat(self._path.parent)
        except OSError as exc:
            raise ExecutionAttemptError(
                "execution-attempt journal parent is unavailable"
            ) from exc

        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise ExecutionAttemptError(
                "execution-attempt journal parent is not private and trusted"
            )

    @staticmethod
    def _validate_file(info: os.stat_result, label: str) -> None:
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > EXECUTION_ATTEMPT_STORE_MAX_BYTES
        ):
            raise ExecutionAttemptError(
                f"{label} is not private and trusted"
            )

    def _open_lock(self) -> int:
        self._validate_parent()

        if not hasattr(os, "O_NOFOLLOW"):
            raise ExecutionAttemptError(
                "platform lacks no-follow file support"
            )

        if os.path.lexists(self._lock_path):
            try:
                existing = os.lstat(self._lock_path)
            except OSError as exc:
                raise ExecutionAttemptError(
                    "execution-attempt lock could not be inspected"
                ) from exc
            self._validate_file(
                existing,
                "execution-attempt lock file",
            )

        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC

        try:
            fd = os.open(self._lock_path, flags, 0o600)
        except OSError as exc:
            raise ExecutionAttemptError(
                "execution-attempt lock could not be opened safely"
            ) from exc

        try:
            self._validate_file(
                os.fstat(fd),
                "execution-attempt lock file",
            )
            fcntl.flock(fd, fcntl.LOCK_EX)
            return fd
        except Exception:
            os.close(fd)
            raise

    @staticmethod
    def _close_lock(fd: int) -> None:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _read_locked(self) -> list[ExecutionAttemptRecord]:
        if not os.path.lexists(self._path):
            return []

        flags = os.O_RDONLY | os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC

        try:
            fd = os.open(self._path, flags)
        except OSError as exc:
            raise ExecutionAttemptError(
                "execution-attempt journal could not be opened safely"
            ) from exc

        try:
            self._validate_file(
                os.fstat(fd),
                "execution-attempt journal",
            )
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, 65_536)
                if not chunk:
                    break
                total += len(chunk)
                if total > EXECUTION_ATTEMPT_STORE_MAX_BYTES:
                    raise ExecutionAttemptError(
                        "execution-attempt journal exceeds size limit"
                    )
                chunks.append(chunk)
        finally:
            os.close(fd)

        raw = b"".join(chunks)
        if not raw:
            raise ExecutionAttemptError(
                "execution-attempt journal is empty"
            )

        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ExecutionAttemptError(
                "execution-attempt journal is malformed"
            ) from exc

        if (
            not isinstance(document, dict)
            or set(document) != {
                "policy_version",
                "schema_version",
                "entries",
                "store_hash",
            }
            or document["policy_version"]
            != EXECUTION_ATTEMPT_POLICY_VERSION
            or type(document["schema_version"]) is not int
            or document["schema_version"]
            != EXECUTION_ATTEMPT_SCHEMA_VERSION
            or not isinstance(document["entries"], list)
            or not _exact_text(document["store_hash"])
        ):
            raise ExecutionAttemptError(
                "execution-attempt journal document is invalid"
            )

        expected_keys = set(
            ExecutionAttemptRecord.__dataclass_fields__
        )
        entries = []
        for raw_entry in document["entries"]:
            if (
                not isinstance(raw_entry, dict)
                or set(raw_entry) != expected_keys
            ):
                raise ExecutionAttemptError(
                    "execution-attempt entry shape is invalid"
                )
            try:
                entry = ExecutionAttemptRecord(**raw_entry)
            except TypeError as exc:
                raise ExecutionAttemptError(
                    "execution-attempt entry could not be decoded"
                ) from exc
            if not _record_integrity_valid(entry):
                raise ExecutionAttemptError(
                    "execution-attempt entry integrity is invalid"
                )
            entries.append(entry)

        attempt_ids = [entry.attempt_id for entry in entries]
        if (
            attempt_ids != sorted(attempt_ids)
            or len(attempt_ids) != len(set(attempt_ids))
        ):
            raise ExecutionAttemptError(
                "execution-attempt IDs are duplicated or unsorted"
            )

        for attribute in (
            "authorization_id",
            "lease_binding_id",
            "handoff_id",
            "gate_id",
            "binding_id",
        ):
            values = [
                getattr(entry, attribute)
                for entry in entries
            ]
            if len(values) != len(set(values)):
                raise ExecutionAttemptError(
                    f"execution-attempt {attribute} values are duplicated"
                )

        payload = {
            "policy_version": EXECUTION_ATTEMPT_POLICY_VERSION,
            "schema_version": EXECUTION_ATTEMPT_SCHEMA_VERSION,
            "entries": [asdict(entry) for entry in entries],
        }
        if document["store_hash"] != _canonical_hash(payload):
            raise ExecutionAttemptError(
                "execution-attempt journal store hash is invalid"
            )

        return entries

    def _write_locked(
        self,
        entries: list[ExecutionAttemptRecord],
    ) -> None:
        ordered = sorted(
            entries,
            key=lambda entry: entry.attempt_id,
        )

        if any(
            not _record_integrity_valid(entry)
            for entry in ordered
        ):
            raise ExecutionAttemptError(
                "refusing to persist invalid execution-attempt entry"
            )

        for attribute in (
            "attempt_id",
            "authorization_id",
            "lease_binding_id",
            "handoff_id",
            "gate_id",
            "binding_id",
        ):
            values = [
                getattr(entry, attribute)
                for entry in ordered
            ]
            if len(values) != len(set(values)):
                raise ExecutionAttemptError(
                    f"refusing duplicate execution-attempt {attribute}"
                )

        payload = {
            "policy_version": EXECUTION_ATTEMPT_POLICY_VERSION,
            "schema_version": EXECUTION_ATTEMPT_SCHEMA_VERSION,
            "entries": [asdict(entry) for entry in ordered],
        }
        document = dict(payload)
        document["store_hash"] = _canonical_hash(payload)

        encoded = (
            json.dumps(
                document,
                sort_keys=True,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")

        if len(encoded) > EXECUTION_ATTEMPT_STORE_MAX_BYTES:
            raise ExecutionAttemptError(
                "execution-attempt journal exceeds size limit"
            )

        if os.path.lexists(self._path):
            try:
                self._validate_file(
                    os.lstat(self._path),
                    "execution-attempt journal",
                )
            except OSError as exc:
                raise ExecutionAttemptError(
                    "existing execution-attempt journal could not be inspected"
                ) from exc

        temp_fd = None
        temp_name = None
        try:
            temp_fd, temp_name = tempfile.mkstemp(
                prefix="." + self._path.name + ".tmp.",
                dir=str(self._path.parent),
            )
            os.fchmod(temp_fd, 0o600)

            offset = 0
            while offset < len(encoded):
                written = os.write(
                    temp_fd,
                    encoded[offset:],
                )
                if written <= 0:
                    raise ExecutionAttemptError(
                        "execution-attempt journal write did not progress"
                    )
                offset += written

            os.fsync(temp_fd)
            os.close(temp_fd)
            temp_fd = None

            os.replace(temp_name, self._path)
            temp_name = None

            verify_info = os.lstat(self._path)
            self._validate_file(
                verify_info,
                "execution-attempt journal",
            )

            directory_fd = os.open(
                self._path.parent,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)

        finally:
            if temp_fd is not None:
                os.close(temp_fd)
            if temp_name is not None:
                try:
                    os.unlink(temp_name)
                except FileNotFoundError:
                    pass

    def entry_for_authorization(
        self,
        authorization_id: Any,
    ) -> ExecutionAttemptRecord | None:
        if not _prefixed_hex(authorization_id, "xeauth_"):
            raise ExecutionAttemptError(
                "authorization_id is invalid"
            )

        lock_fd = self._open_lock()
        try:
            matches = [
                entry
                for entry in self._read_locked()
                if entry.authorization_id == authorization_id
            ]
            if len(matches) > 1:
                raise ExecutionAttemptError(
                    "execution-attempt authorization is duplicated"
                )
            return matches[0] if matches else None
        finally:
            self._close_lock(lock_fd)


_STORE_TYPE = DurableExecutionAttemptJournal


def _new_attempt_id() -> str:
    token = secrets.token_hex(32)
    attempt_id = "xeattempt_" + token
    if not _prefixed_hex(attempt_id, "xeattempt_"):
        raise ExecutionAttemptError(
            "fresh execution-attempt ID is invalid"
        )
    return attempt_id


def _active_capability_state(
    capability: Any,
) -> tuple[
    Any,
    Any,
    Any,
    Any,
    tuple[str, str, str, str],
    str,
    str,
]:
    if type(capability) is not _CAPABILITY_TYPE:
        raise ExecutionAttemptError(
            "execution attempt requires the exact B3F-C capability type"
        )

    if (
        capability.active is not True
        or capability.execution_authorized is not False
        or capability.execution_supported is not False
        or capability.executor_eligible is not False
        or capability.execution_performed is not False
        or capability.lease_consumed is not True
        or capability.requires_future_executor is not True
    ):
        raise ExecutionAttemptError(
            "B3F-C capability is not active in its non-executing consumed state"
        )

    lease = capability._lease
    lease_scope = capability._lease_scope
    authorization_scope = capability._authorization_scope
    identity = capability._identity
    lease_binding_id = capability._lease_binding_id
    authorization_id = capability._authorization_id

    if (
        type(lease) is not _LEASE_TYPE
        or type(lease_scope) is not _LEASE_SCOPE_TYPE
        or type(authorization_scope) is not _AUTH_SCOPE_TYPE
        or lease_scope._entered is not True
        or authorization_scope._entered is not True
        or not isinstance(identity, tuple)
        or len(identity) != 4
        or not all(_exact_text(value) for value in identity)
        or not _prefixed_hex(lease_binding_id, "xeli_")
        or not _prefixed_hex(authorization_id, "xeauth_")
        or lease._consumed is not True
        or not leases._internal_integrity_binding_valid(lease)
    ):
        raise ExecutionAttemptError(
            "active B3F-C private lock chain is unavailable or invalid"
        )

    if identity != (
        lease._handoff_id,
        lease._target_path,
        lease._target_major_minor,
        lease._target_binding_hash,
    ):
        raise ExecutionAttemptError(
            "B3F-C frozen identity no longer matches the consumed lease"
        )

    claim_scope = lease_scope._claim_scope
    if (
        type(claim_scope) is not _CLAIM_SCOPE_TYPE
        or claim_scope._entered is not True
    ):
        raise ExecutionAttemptError(
            "B3F-C capability lost its exact pinned B3E-F scope"
        )

    return (
        lease,
        lease_scope,
        claim_scope,
        authorization_scope,
        identity,
        lease_binding_id,
        authorization_id,
    )


def _reserved_record_matches(
    record: Any,
    *,
    identity: tuple[str, str, str, str],
    lease_binding_id: str,
    authorization_id: str,
) -> bool:
    return (
        type(record) is exauth.ExecutorAuthorizationRecord
        and exauth._record_integrity_valid(record)
        and record.state
        == exauth.EXECUTOR_AUTHORIZATION_STATE_RESERVED
        and record.authorization_id == authorization_id
        and record.lease_binding_id == lease_binding_id
        and (
            record.handoff_id,
            record.target_path,
            record.target_major_minor,
            record.target_binding_hash,
        )
        == identity
    )


def _final_pinned_safety_cycle(
    *,
    lease: Any,
    claim_scope: Any,
    identity: tuple[str, str, str, str],
) -> None:
    try:
        observed = claim_scope.revalidate_descriptor()
        if observed != identity[2]:
            raise ExecutionAttemptError(
                "final pinned descriptor identity differs from target"
            )

        leases._fresh_safety_cycle(
            scope=claim_scope,
            expected_identity=identity,
            arguments=lease._arguments,
        )

        observed_after = claim_scope.revalidate_descriptor()
        if observed_after != identity[2]:
            raise ExecutionAttemptError(
                "descriptor identity changed during final attempt safety cycle"
            )

        current_identity = claim_scope.identity
        if (
            current_identity != identity
            or lease._consumed is not True
            or not leases._internal_integrity_binding_valid(lease)
        ):
            raise ExecutionAttemptError(
                "live consumed lease/claim identity changed before attempt persistence"
            )

    except ExecutionAttemptError:
        raise
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise ExecutionAttemptError(
            "final pinned execution-attempt safety validation failed"
        ) from exc


def _build_record(
    *,
    authorization: exauth.ExecutorAuthorizationRecord,
    attempt_id: str,
    attempted_at_utc: str,
) -> ExecutionAttemptRecord:
    unsigned = ExecutionAttemptRecord(
        attempt_id=attempt_id,
        policy_version=EXECUTION_ATTEMPT_POLICY_VERSION,
        schema_version=EXECUTION_ATTEMPT_SCHEMA_VERSION,
        state=EXECUTION_ATTEMPT_STATE_ATTEMPTING,
        authorization_id=authorization.authorization_id,
        lease_binding_id=authorization.lease_binding_id,
        handoff_id=authorization.handoff_id,
        target_path=authorization.target_path,
        target_major_minor=authorization.target_major_minor,
        target_binding_hash=authorization.target_binding_hash,
        gate_id=authorization.gate_id,
        binding_id=authorization.binding_id,
        journal_policy_version=authorization.journal_policy_version,
        journal_schema_version=authorization.journal_schema_version,
        journal_state=authorization.journal_state,
        journal_entry_hash=authorization.journal_entry_hash,
        approval_id=authorization.approval_id,
        request_id=authorization.request_id,
        request_hash=authorization.request_hash,
        record_snapshot_hash=authorization.record_snapshot_hash,
        internal_record_id=authorization.internal_record_id,
        method_profile_id=authorization.method_profile_id,
        operation=authorization.operation,
        attempted_at_utc=attempted_at_utc,
        execution_started_proven=False,
        execution_returned=False,
        sanitization_verified=False,
        automatic_replay_allowed=False,
        requires_manual_review_if_interrupted=True,
        record_hash="sha256:" + ("0" * 64),
    )
    return ExecutionAttemptRecord(
        **{
            **asdict(unsigned),
            "record_hash": _canonical_hash(
                _record_payload(unsigned)
            ),
        }
    )


def record_execution_attempt(
    *,
    store: Any,
    capability: Any,
) -> ExecutionAttemptRecord:
    """Persist one ATTEMPTING tombstone before any future side effect."""

    if type(store) is not _STORE_TYPE:
        raise ExecutionAttemptError(
            "store must be the exact durable execution-attempt journal type"
        )

    (
        lease,
        _lease_scope,
        claim_scope,
        authorization_scope,
        identity,
        lease_binding_id,
        authorization_id,
    ) = _active_capability_state(capability)

    lock_fd = store._open_lock()
    try:
        # This lock is intentionally acquired last. All existing B3F-C locks
        # remain held while the final safety cycle and durable persistence run.
        authorization_before = authorization_scope.record
        if not _reserved_record_matches(
            authorization_before,
            identity=identity,
            lease_binding_id=lease_binding_id,
            authorization_id=authorization_id,
        ):
            raise ExecutionAttemptError(
                "exact RESERVED executor authorization is unavailable"
            )

        existing = store._read_locked()
        for entry in existing:
            if (
                entry.authorization_id == authorization_id
                or entry.lease_binding_id == lease_binding_id
                or entry.handoff_id == identity[0]
                or entry.gate_id == authorization_before.gate_id
                or entry.binding_id == authorization_before.binding_id
            ):
                raise ExecutionAttemptError(
                    "execution attempt already exists; automatic replay is refused"
                )

        _final_pinned_safety_cycle(
            lease=lease,
            claim_scope=claim_scope,
            identity=identity,
        )

        authorization_after = authorization_scope.record
        if (
            authorization_after != authorization_before
            or not _reserved_record_matches(
                authorization_after,
                identity=identity,
                lease_binding_id=lease_binding_id,
                authorization_id=authorization_id,
            )
        ):
            raise ExecutionAttemptError(
                "RESERVED authorization changed during final attempt validation"
            )

        attempt_id = _new_attempt_id()
        attempted_at_utc = _iso_utc(_utc_now())
        record = _build_record(
            authorization=authorization_after,
            attempt_id=attempt_id,
            attempted_at_utc=attempted_at_utc,
        )

        if not _record_integrity_valid(record):
            raise ExecutionAttemptError(
                "fresh execution-attempt record is invalid"
            )

        store._write_locked(existing + [record])

        persisted = store._read_locked()
        matches = [
            entry
            for entry in persisted
            if entry.attempt_id == record.attempt_id
        ]
        if len(matches) != 1 or matches[0] != record:
            raise ExecutionAttemptError(
                "durable execution-attempt verification failed"
            )

        return record

    finally:
        store._close_lock(lock_fd)


__all__ = [
    "EXECUTION_ATTEMPT_POLICY_VERSION",
    "EXECUTION_ATTEMPT_SCHEMA_VERSION",
    "EXECUTION_ATTEMPT_STATE_ATTEMPTING",
    "DurableExecutionAttemptJournal",
    "ExecutionAttemptError",
    "ExecutionAttemptRecord",
    "record_execution_attempt",
]
