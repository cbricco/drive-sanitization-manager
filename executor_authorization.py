"""Phase 6E-B3F-B durable non-executing executor-authorization boundary.

This module records and reserves a distinct trusted executor-authorization
event for one exact still-live B3F-A lease. It does not execute sanitization,
construct commands, open a block-device path, expose a descriptor, or claim
that authorization recording/reservation performed any destructive action.

The B3F-A xeli_ value is used only as exact live-lease identity/internal
integrity. It is not external authorization or cryptographic provenance.

AUTHORIZED and RESERVED durable states both block duplicate issuance for the
same lease/handoff/gate/binding. RESERVED is intentionally fail-closed and
must never be automatically retried after a crash.

A process restart clears the private exact-live-lease latch. Durable records
remain evidence/anti-replay state only; they cannot authorize a newly created
lease automatically.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile
import threading
from typing import Any, Optional

import execution_lease as leases
import sanitization_authorization as auth


EXECUTOR_AUTHORIZATION_POLICY_VERSION = (
    "phase6e-b3f-b-durable-executor-authorization-v1"
)
EXECUTOR_AUTHORIZATION_SCHEMA_VERSION = 1
EXECUTOR_AUTHORIZATION_STATE_AUTHORIZED = "AUTHORIZED"
EXECUTOR_AUTHORIZATION_STATE_RESERVED = "RESERVED"
EXECUTOR_AUTHORIZATION_STORE_MAX_BYTES = 1_048_576


class ExecutorAuthorizationError(RuntimeError):
    """Durable executor authorization failed closed."""


@dataclass(frozen=True)
class ExecutorAuthorizationRecord:
    authorization_id: str
    policy_version: str
    schema_version: int
    state: str

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

    authorized_at_utc: str
    reserved_at_utc: Optional[str]
    record_hash: str


_HANDOFF_TYPE = auth.ImmutableExecutionHandoffContract
_HANDOFF_INTEGRITY_VALIDATOR = auth._immutable_execution_handoff_integrity_valid
_JOURNAL_TYPE = auth.DurableExecutionGateConsumptionJournal
_JOURNAL_ENTRY_TYPE = auth.DurableExecutionGateJournalEntry
_JOURNAL_ENTRY_VALIDATOR = auth._durable_gate_journal_entry_integrity_valid
_COMPLETED_JOURNAL_STATE = auth.DURABLE_GATE_JOURNAL_STATE_COMPLETED
_LEASE_TYPE = leases.ExecutionLease
_LEASE_SCOPE_FACTORY = leases._locked_execution_lease_validation_scope

_LIVE_AUTHORIZATIONS_LOCK = threading.Lock()
_LIVE_AUTHORIZATIONS: dict[str, Any] = {}


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


def _canonical_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _exact_text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and "\x00" not in value
        and "\n" not in value
        and "\r" not in value
    )


def _xeli(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("xeli_")
        and len(value) == len("xeli_") + 64
        and all(
            character in "0123456789abcdef"
            for character in value[len("xeli_"):]
        )
    )


def _authorization_id(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("xeauth_")
        and len(value) == len("xeauth_") + 64
        and all(
            character in "0123456789abcdef"
            for character in value[len("xeauth_"):]
        )
    )


def _record_payload(record: ExecutorAuthorizationRecord) -> dict[str, Any]:
    payload = asdict(record)
    payload.pop("record_hash")
    return payload


def _record_integrity_valid(record: Any) -> bool:
    try:
        if type(record) is not ExecutorAuthorizationRecord:
            return False

        if (
            record.policy_version != EXECUTOR_AUTHORIZATION_POLICY_VERSION
            or type(record.schema_version) is not int
            or record.schema_version != EXECUTOR_AUTHORIZATION_SCHEMA_VERSION
            or record.state not in {
                EXECUTOR_AUTHORIZATION_STATE_AUTHORIZED,
                EXECUTOR_AUTHORIZATION_STATE_RESERVED,
            }
            or not _authorization_id(record.authorization_id)
            or not _xeli(record.lease_binding_id)
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

        authorized_at = _parse_utc(record.authorized_at_utc)
        if (
            authorized_at is None
            or _iso_utc(authorized_at) != record.authorized_at_utc
        ):
            return False

        if record.state == EXECUTOR_AUTHORIZATION_STATE_AUTHORIZED:
            if record.reserved_at_utc is not None:
                return False
        else:
            reserved_at = _parse_utc(record.reserved_at_utc)
            if (
                reserved_at is None
                or _iso_utc(reserved_at) != record.reserved_at_utc
                or reserved_at < authorized_at
            ):
                return False

        return record.record_hash == _canonical_hash(
            _record_payload(record)
        )
    except Exception:
        return False


class DurableExecutorAuthorizationStore:
    """Private restart-safe B3F-B authorization and anti-replay store."""

    def __init__(self, path: Any) -> None:
        try:
            self._path = Path(os.fspath(path))
        except (TypeError, ValueError) as exc:
            raise ExecutorAuthorizationError(
                "authorization-store path is invalid"
            ) from exc

        if not self._path.is_absolute() or not self._path.name:
            raise ExecutorAuthorizationError(
                "authorization-store path must be an absolute file path"
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
            raise ExecutorAuthorizationError(
                "authorization-store parent is unavailable"
            ) from exc

        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise ExecutorAuthorizationError(
                "authorization-store parent is not private and trusted"
            )

    @staticmethod
    def _validate_file(info: os.stat_result, label: str) -> None:
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > EXECUTOR_AUTHORIZATION_STORE_MAX_BYTES
        ):
            raise ExecutorAuthorizationError(
                f"{label} is not private and trusted"
            )

    def _open_lock(self) -> int:
        self._validate_parent()

        if not hasattr(os, "O_NOFOLLOW"):
            raise ExecutorAuthorizationError(
                "platform lacks no-follow file support"
            )

        if os.path.lexists(self._lock_path):
            try:
                existing = os.lstat(self._lock_path)
            except OSError as exc:
                raise ExecutorAuthorizationError(
                    "authorization lock could not be inspected"
                ) from exc
            self._validate_file(existing, "authorization lock file")

        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC

        try:
            fd = os.open(self._lock_path, flags, 0o600)
        except OSError as exc:
            raise ExecutorAuthorizationError(
                "authorization lock file could not be opened safely"
            ) from exc

        try:
            self._validate_file(
                os.fstat(fd),
                "authorization lock file",
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

    def _read_locked(self) -> list[ExecutorAuthorizationRecord]:
        if not os.path.lexists(self._path):
            return []

        flags = os.O_RDONLY | os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC

        try:
            fd = os.open(self._path, flags)
        except OSError as exc:
            raise ExecutorAuthorizationError(
                "authorization store could not be opened safely"
            ) from exc

        try:
            self._validate_file(os.fstat(fd), "authorization store")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, 65_536)
                if not chunk:
                    break
                total += len(chunk)
                if total > EXECUTOR_AUTHORIZATION_STORE_MAX_BYTES:
                    raise ExecutorAuthorizationError(
                        "authorization store exceeds size limit"
                    )
                chunks.append(chunk)
        finally:
            os.close(fd)

        raw = b"".join(chunks)
        if not raw:
            raise ExecutorAuthorizationError(
                "authorization store is empty"
            )

        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ExecutorAuthorizationError(
                "authorization store is malformed"
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
            != EXECUTOR_AUTHORIZATION_POLICY_VERSION
            or type(document["schema_version"]) is not int
            or document["schema_version"]
            != EXECUTOR_AUTHORIZATION_SCHEMA_VERSION
            or not isinstance(document["entries"], list)
            or not _exact_text(document["store_hash"])
        ):
            raise ExecutorAuthorizationError(
                "authorization-store document is invalid"
            )

        expected_keys = set(
            ExecutorAuthorizationRecord.__dataclass_fields__
        )
        entries = []
        for raw_entry in document["entries"]:
            if (
                not isinstance(raw_entry, dict)
                or set(raw_entry) != expected_keys
            ):
                raise ExecutorAuthorizationError(
                    "authorization entry shape is invalid"
                )
            try:
                entry = ExecutorAuthorizationRecord(**raw_entry)
            except TypeError as exc:
                raise ExecutorAuthorizationError(
                    "authorization entry could not be decoded"
                ) from exc
            if not _record_integrity_valid(entry):
                raise ExecutorAuthorizationError(
                    "authorization entry integrity is invalid"
                )
            entries.append(entry)

        ids = [entry.authorization_id for entry in entries]
        if ids != sorted(ids) or len(ids) != len(set(ids)):
            raise ExecutorAuthorizationError(
                "authorization IDs are duplicated or unsorted"
            )

        for attribute in (
            "lease_binding_id",
            "handoff_id",
            "gate_id",
            "binding_id",
        ):
            values = [getattr(entry, attribute) for entry in entries]
            if len(values) != len(set(values)):
                raise ExecutorAuthorizationError(
                    f"authorization {attribute} values are duplicated"
                )

        payload = {
            "policy_version": EXECUTOR_AUTHORIZATION_POLICY_VERSION,
            "schema_version": EXECUTOR_AUTHORIZATION_SCHEMA_VERSION,
            "entries": [asdict(entry) for entry in entries],
        }
        if document["store_hash"] != _canonical_hash(payload):
            raise ExecutorAuthorizationError(
                "authorization-store document hash is invalid"
            )

        return entries

    def _write_locked(
        self,
        entries: list[ExecutorAuthorizationRecord],
    ) -> None:
        ordered = sorted(
            entries,
            key=lambda entry: entry.authorization_id,
        )

        if any(
            not _record_integrity_valid(entry)
            for entry in ordered
        ):
            raise ExecutorAuthorizationError(
                "refusing to persist invalid authorization entry"
            )

        for attribute in (
            "authorization_id",
            "lease_binding_id",
            "handoff_id",
            "gate_id",
            "binding_id",
        ):
            values = [getattr(entry, attribute) for entry in ordered]
            if len(values) != len(set(values)):
                raise ExecutorAuthorizationError(
                    f"refusing duplicate authorization {attribute}"
                )

        payload = {
            "policy_version": EXECUTOR_AUTHORIZATION_POLICY_VERSION,
            "schema_version": EXECUTOR_AUTHORIZATION_SCHEMA_VERSION,
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

        if len(encoded) > EXECUTOR_AUTHORIZATION_STORE_MAX_BYTES:
            raise ExecutorAuthorizationError(
                "authorization store exceeds size limit"
            )

        if os.path.lexists(self._path):
            try:
                self._validate_file(
                    os.lstat(self._path),
                    "authorization store",
                )
            except OSError as exc:
                raise ExecutorAuthorizationError(
                    "existing authorization store could not be inspected"
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
                written = os.write(temp_fd, encoded[offset:])
                if written <= 0:
                    raise ExecutorAuthorizationError(
                        "authorization-store write did not progress"
                    )
                offset += written

            os.fsync(temp_fd)
            os.close(temp_fd)
            temp_fd = None

            os.replace(temp_name, self._path)
            temp_name = None

            self._validate_file(
                os.lstat(self._path),
                "authorization store",
            )

            directory_flags = os.O_RDONLY
            if hasattr(os, "O_DIRECTORY"):
                directory_flags |= os.O_DIRECTORY
            if hasattr(os, "O_CLOEXEC"):
                directory_flags |= os.O_CLOEXEC

            directory_fd = os.open(
                self._path.parent,
                directory_flags,
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)

        except ExecutorAuthorizationError:
            raise
        except OSError as exc:
            raise ExecutorAuthorizationError(
                "authorization-store atomic persistence failed"
            ) from exc
        finally:
            if temp_fd is not None:
                os.close(temp_fd)
            if (
                temp_name is not None
                and os.path.lexists(temp_name)
            ):
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass

    def _authorize(
        self,
        provenance: dict[str, Any],
    ) -> ExecutorAuthorizationRecord:
        lock_fd = self._open_lock()
        try:
            entries = self._read_locked()

            for existing in entries:
                if (
                    existing.lease_binding_id
                    == provenance["lease_binding_id"]
                    or existing.handoff_id == provenance["handoff_id"]
                    or existing.gate_id == provenance["gate_id"]
                    or existing.binding_id == provenance["binding_id"]
                ):
                    raise ExecutorAuthorizationError(
                        "lease/handoff/gate/binding already has durable executor authorization"
                    )

            authorization_id = None
            for _ in range(8):
                candidate = "xeauth_" + secrets.token_hex(32)
                if (
                    _authorization_id(candidate)
                    and all(
                        existing.authorization_id != candidate
                        for existing in entries
                    )
                ):
                    authorization_id = candidate
                    break

            if authorization_id is None:
                raise ExecutorAuthorizationError(
                    "could not allocate unique executor authorization ID"
                )

            now = _utc_now()
            if (
                not isinstance(now, datetime)
                or now.tzinfo is None
                or now.utcoffset() is None
            ):
                raise ExecutorAuthorizationError(
                    "internal authorization clock is invalid"
                )

            values = dict(provenance)
            values.update(
                authorization_id=authorization_id,
                policy_version=EXECUTOR_AUTHORIZATION_POLICY_VERSION,
                schema_version=EXECUTOR_AUTHORIZATION_SCHEMA_VERSION,
                state=EXECUTOR_AUTHORIZATION_STATE_AUTHORIZED,
                authorized_at_utc=_iso_utc(now),
                reserved_at_utc=None,
                record_hash="",
            )
            provisional = ExecutorAuthorizationRecord(**values)
            record = replace(
                provisional,
                record_hash=_canonical_hash(
                    _record_payload(provisional)
                ),
            )

            if not _record_integrity_valid(record):
                raise ExecutorAuthorizationError(
                    "constructed executor authorization is invalid"
                )

            self._write_locked(entries + [record])
            return record
        finally:
            self._close_lock(lock_fd)

    def _reserve(
        self,
        authorization_id: str,
        *,
        lease_binding_id: str,
        identity: tuple[str, str, str, str],
    ) -> ExecutorAuthorizationRecord:
        lock_fd = self._open_lock()
        try:
            entries = self._read_locked()
            matches = [
                entry
                for entry in entries
                if entry.authorization_id == authorization_id
            ]

            if len(matches) != 1:
                raise ExecutorAuthorizationError(
                    "executor authorization is unknown"
                )

            current = matches[0]
            if current.state != EXECUTOR_AUTHORIZATION_STATE_AUTHORIZED:
                raise ExecutorAuthorizationError(
                    "executor authorization is already reserved or unavailable"
                )

            if (
                current.lease_binding_id != lease_binding_id
                or (
                    current.handoff_id,
                    current.target_path,
                    current.target_major_minor,
                    current.target_binding_hash,
                )
                != identity
            ):
                raise ExecutorAuthorizationError(
                    "executor authorization does not match exact live lease"
                )

            now = _utc_now()
            if (
                not isinstance(now, datetime)
                or now.tzinfo is None
                or now.utcoffset() is None
            ):
                raise ExecutorAuthorizationError(
                    "internal reservation clock is invalid"
                )

            provisional = replace(
                current,
                state=EXECUTOR_AUTHORIZATION_STATE_RESERVED,
                reserved_at_utc=_iso_utc(now),
                record_hash="",
            )
            reserved = replace(
                provisional,
                record_hash=_canonical_hash(
                    _record_payload(provisional)
                ),
            )

            if not _record_integrity_valid(reserved):
                raise ExecutorAuthorizationError(
                    "constructed reservation is invalid"
                )

            self._write_locked([
                reserved if entry.authorization_id == authorization_id
                else entry
                for entry in entries
            ])
            return reserved
        finally:
            self._close_lock(lock_fd)

    def entry_for_authorization(
        self,
        authorization_id: Any,
    ) -> ExecutorAuthorizationRecord | None:
        if not _authorization_id(authorization_id):
            raise ExecutorAuthorizationError(
                "authorization_id is invalid"
            )

        lock_fd = self._open_lock()
        try:
            entries = self._read_locked()
            matches = [
                entry
                for entry in entries
                if entry.authorization_id == authorization_id
            ]
            if len(matches) > 1:
                raise ExecutorAuthorizationError(
                    "authorization ID is duplicated"
                )
            return matches[0] if matches else None
        finally:
            self._close_lock(lock_fd)


def _handoff_and_journal_provenance(
    handoff: Any,
    journal: Any,
) -> dict[str, Any]:
    if type(handoff) is not _HANDOFF_TYPE:
        raise ExecutorAuthorizationError(
            "handoff must be the exact published immutable execution handoff"
        )
    if _HANDOFF_INTEGRITY_VALIDATOR(handoff) is not True:
        raise ExecutorAuthorizationError(
            "immutable execution-handoff integrity is invalid"
        )
    if type(journal) is not _JOURNAL_TYPE:
        raise ExecutorAuthorizationError(
            "journal must be the exact durable execution-gate journal"
        )

    if (
        handoff.journal_state != _COMPLETED_JOURNAL_STATE
        or handoff.journal_policy_version
        != auth.DURABLE_GATE_JOURNAL_POLICY_VERSION
        or handoff.journal_schema_version
        != auth.DURABLE_GATE_JOURNAL_SCHEMA_VERSION
    ):
        raise ExecutorAuthorizationError(
            "handoff does not carry completed durable-gate provenance"
        )

    try:
        entry = journal.entry_for_binding(handoff.binding_id)
    except Exception as exc:
        raise ExecutorAuthorizationError(
            "completed durable journal entry is unavailable"
        ) from exc

    if (
        type(entry) is not _JOURNAL_ENTRY_TYPE
        or _JOURNAL_ENTRY_VALIDATOR(entry) is not True
        or entry.state != _COMPLETED_JOURNAL_STATE
        or entry.binding_id != handoff.binding_id
        or entry.gate_id != handoff.gate_id
        or entry.entry_hash != handoff.journal_entry_hash
        or entry.request_hash != handoff.request_hash
        or entry.record_snapshot_hash != handoff.record_snapshot_hash
        or entry.target_binding_hash != handoff.target_binding_hash
    ):
        raise ExecutorAuthorizationError(
            "completed durable journal evidence does not match handoff"
        )

    internal_record_id = getattr(
        handoff,
        "internal_record_id",
        "",
    )
    if not _exact_text(internal_record_id):
        raise ExecutorAuthorizationError(
            "handoff internal-record provenance is unavailable"
        )

    return {
        "gate_id": handoff.gate_id,
        "binding_id": handoff.binding_id,
        "journal_policy_version": handoff.journal_policy_version,
        "journal_schema_version": handoff.journal_schema_version,
        "journal_state": handoff.journal_state,
        "journal_entry_hash": handoff.journal_entry_hash,
        "approval_id": handoff.approval_id,
        "request_id": handoff.request_id,
        "request_hash": handoff.request_hash,
        "record_snapshot_hash": handoff.record_snapshot_hash,
        "internal_record_id": internal_record_id,
        "method_profile_id": handoff.method_profile_id,
        "operation": handoff.operation,
        "handoff_target_binding_hash": handoff.target_binding_hash,
        "handoff_id": handoff.handoff_id,
    }


def record_trusted_executor_authorization(
    *,
    store: Any,
    lease: Any,
    handoff: Any,
    journal: Any,
) -> ExecutorAuthorizationRecord:
    """Record one distinct trusted executor-authorization event.

    This trusted-core boundary is intended for a future trusted UI/event
    adapter after a separate real human executor-authorization gesture.
    The Python core does not itself prove that a physical human acted.
    """

    if type(store) is not DurableExecutorAuthorizationStore:
        raise ExecutorAuthorizationError("store is invalid")
    if type(lease) is not _LEASE_TYPE:
        raise ExecutorAuthorizationError(
            "lease is not the exact published B3F-A type"
        )

    handoff_provenance = _handoff_and_journal_provenance(
        handoff,
        journal,
    )

    with _LEASE_SCOPE_FACTORY(lease) as scope:
        identity = scope.identity
        lease_binding_id = (
            scope.execution_authorization_integrity_binding_id
        )

        if (
            identity[0] != handoff_provenance["handoff_id"]
            or identity[3]
            != handoff_provenance["handoff_target_binding_hash"]
        ):
            raise ExecutorAuthorizationError(
                "live execution lease does not match immutable handoff"
            )

        provenance = {
            "lease_binding_id": lease_binding_id,
            "handoff_id": identity[0],
            "target_path": identity[1],
            "target_major_minor": identity[2],
            "target_binding_hash": identity[3],
            "gate_id": handoff_provenance["gate_id"],
            "binding_id": handoff_provenance["binding_id"],
            "journal_policy_version": (
                handoff_provenance["journal_policy_version"]
            ),
            "journal_schema_version": (
                handoff_provenance["journal_schema_version"]
            ),
            "journal_state": handoff_provenance["journal_state"],
            "journal_entry_hash": handoff_provenance["journal_entry_hash"],
            "approval_id": handoff_provenance["approval_id"],
            "request_id": handoff_provenance["request_id"],
            "request_hash": handoff_provenance["request_hash"],
            "record_snapshot_hash": (
                handoff_provenance["record_snapshot_hash"]
            ),
            "internal_record_id": (
                handoff_provenance["internal_record_id"]
            ),
            "method_profile_id": (
                handoff_provenance["method_profile_id"]
            ),
            "operation": handoff_provenance["operation"],
        }

        # Store lock is deliberately acquired only after the live
        # lease -> B3E-F -> B3A hierarchy is already pinned.
        record = store._authorize(provenance)

        with _LIVE_AUTHORIZATIONS_LOCK:
            if record.authorization_id in _LIVE_AUTHORIZATIONS:
                raise ExecutorAuthorizationError(
                    "live authorization ID collision"
                )
            _LIVE_AUTHORIZATIONS[record.authorization_id] = lease

        return record


def reserve_executor_authorization(
    *,
    store: Any,
    authorization_id: Any,
    lease: Any,
) -> ExecutorAuthorizationRecord:
    """Durably reserve one authorization without executing anything."""

    if type(store) is not DurableExecutorAuthorizationStore:
        raise ExecutorAuthorizationError("store is invalid")
    if type(lease) is not _LEASE_TYPE:
        raise ExecutorAuthorizationError(
            "lease is not the exact published B3F-A type"
        )
    if not _authorization_id(authorization_id):
        raise ExecutorAuthorizationError(
            "authorization_id is invalid"
        )

    with _LEASE_SCOPE_FACTORY(lease) as scope:
        identity = scope.identity
        lease_binding_id = (
            scope.execution_authorization_integrity_binding_id
        )

        with _LIVE_AUTHORIZATIONS_LOCK:
            live_lease = _LIVE_AUTHORIZATIONS.get(
                authorization_id
            )

        if live_lease is not lease:
            raise ExecutorAuthorizationError(
                "durable authorization is not attached to this exact live lease; "
                "restart/recreation requires a new reviewed authorization chain"
            )

        # Authorization-store lock is last in the lock hierarchy.
        return store._reserve(
            authorization_id,
            lease_binding_id=lease_binding_id,
            identity=identity,
        )


__all__ = [
    "EXECUTOR_AUTHORIZATION_POLICY_VERSION",
    "EXECUTOR_AUTHORIZATION_SCHEMA_VERSION",
    "EXECUTOR_AUTHORIZATION_STATE_AUTHORIZED",
    "EXECUTOR_AUTHORIZATION_STATE_RESERVED",
    "ExecutorAuthorizationError",
    "ExecutorAuthorizationRecord",
    "DurableExecutorAuthorizationStore",
    "record_trusted_executor_authorization",
    "reserve_executor_authorization",
]
