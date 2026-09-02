"""Phase 6E-B3F-E private non-executing execution seam.

This module binds one exact active B3F-C capability to one exact durable
B3F-D ATTEMPTING record while preserving the established lock hierarchy:

    lease state -> B3E-F lifecycle -> B3A lifecycle
        -> executor-authorization store -> execution-attempt journal

The scope exposes no public descriptor or execution API. Its sole descriptor
bridge is private, one-shot, and valid only while every established lock
remains held. No device data I/O, command construction, child process,
execution engine, success/completion transition, or pathname reopening occurs here.
"""

from __future__ import annotations

import threading
from typing import Any

import execution_attempt_journal as attempt
import executor_authorization as exauth


EXECUTION_SEAM_POLICY_VERSION = (
    "phase6e-b3f-e-private-non-executing-execution-seam-v1"
)


class ExecutionSeamError(RuntimeError):
    """Private execution seam failed closed."""


_CONSTRUCTION_TOKEN = object()
_STORE_TYPE = attempt.DurableExecutionAttemptJournal
_ATTEMPT_RECORD_TYPE = attempt.ExecutionAttemptRecord


def _attempt_matches(
    record: Any,
    *,
    authorization: Any,
    identity: tuple[str, str, str, str],
    lease_binding_id: str,
    authorization_id: str,
) -> bool:
    try:
        if (
            type(record) is not _ATTEMPT_RECORD_TYPE
            or not attempt._record_integrity_valid(record)
            or record.state != attempt.EXECUTION_ATTEMPT_STATE_ATTEMPTING
            or record.execution_started_proven is not False
            or record.execution_returned is not False
            or record.sanitization_verified is not False
            or record.automatic_replay_allowed is not False
            or record.requires_manual_review_if_interrupted is not True
            or type(authorization) is not exauth.ExecutorAuthorizationRecord
            or not exauth._record_integrity_valid(authorization)
            or authorization.state
            != exauth.EXECUTOR_AUTHORIZATION_STATE_RESERVED
            or authorization.journal_state != exauth._COMPLETED_JOURNAL_STATE
            or authorization.authorization_id != authorization_id
            or authorization.lease_binding_id != lease_binding_id
            or (
                authorization.handoff_id,
                authorization.target_path,
                authorization.target_major_minor,
                authorization.target_binding_hash,
            )
            != identity
        ):
            return False

        fields = (
            "authorization_id",
            "lease_binding_id",
            "handoff_id",
            "target_path",
            "target_major_minor",
            "target_binding_hash",
            "gate_id",
            "binding_id",
            "journal_policy_version",
            "journal_schema_version",
            "journal_state",
            "journal_entry_hash",
            "approval_id",
            "request_id",
            "request_hash",
            "record_snapshot_hash",
            "internal_record_id",
            "method_profile_id",
            "operation",
        )
        return all(
            getattr(record, field) == getattr(authorization, field)
            for field in fields
        )
    except Exception:
        return False


def _persisted_exact(
    store: Any,
    expected: Any,
) -> bool:
    try:
        entries = store._read_locked()
        matches = [
            entry
            for entry in entries
            if entry.attempt_id == expected.attempt_id
        ]
        return len(matches) == 1 and matches[0] == expected
    except Exception:
        return False


def _claim_state_locked(
    claim_scope: Any,
    *,
    identity: tuple[str, str, str, str],
) -> tuple[Any, str, str, int]:
    try:
        (
            held_reference,
            claim_identity,
            pre_continuity_id,
            post_continuity_id,
            fd,
        ) = claim_scope._state_locked()
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise ExecutionSeamError(
            "private pinned write-claim state is unavailable"
        ) from exc

    if (
        claim_identity != identity
        or not isinstance(pre_continuity_id, str)
        or not pre_continuity_id
        or not isinstance(post_continuity_id, str)
        or not post_continuity_id
        or type(fd) is not int
        or fd < 0
    ):
        raise ExecutionSeamError(
            "private pinned write-claim state is inconsistent"
        )

    return (
        held_reference,
        pre_continuity_id,
        post_continuity_id,
        fd,
    )


class _LockedExecutionSeamScope:
    """One-shot private scope valid only inside an active B3F-C context."""

    __slots__ = (
        "_store",
        "_capability",
        "_attempt_record",
        "_entry_lock",
        "_used",
        "_entered",
        "_attempt_lock_fd",
        "_descriptor_issued",
        "_lease",
        "_lease_scope",
        "_claim_scope",
        "_authorization_scope",
        "_identity",
        "_lease_binding_id",
        "_authorization_id",
        "_authorization_record",
        "_held_reference",
        "_pre_continuity_id",
        "_post_continuity_id",
        "_fd",
    )

    def __init__(
        self,
        token: object,
        *,
        store: Any,
        capability: Any,
        attempt_record: Any,
    ) -> None:
        if token is not _CONSTRUCTION_TOKEN:
            raise TypeError(
                "_LockedExecutionSeamScope must be created by "
                "_locked_execution_seam_scope()"
            )
        if type(store) is not _STORE_TYPE:
            raise ExecutionSeamError(
                "attempt store is not the exact B3F-D journal type"
            )
        if type(attempt_record) is not _ATTEMPT_RECORD_TYPE:
            raise ExecutionSeamError(
                "attempt record is not the exact B3F-D record type"
            )
        if not attempt._record_integrity_valid(attempt_record):
            raise ExecutionSeamError(
                "attempt record integrity is invalid"
            )

        self._store = store
        self._capability = capability
        self._attempt_record = attempt_record
        self._entry_lock = threading.Lock()
        self._used = False
        self._entered = False
        self._attempt_lock_fd = None
        self._descriptor_issued = False
        self._lease = None
        self._lease_scope = None
        self._claim_scope = None
        self._authorization_scope = None
        self._identity = None
        self._lease_binding_id = None
        self._authorization_id = None
        self._authorization_record = None
        self._held_reference = None
        self._pre_continuity_id = None
        self._post_continuity_id = None
        self._fd = None

    def _require_entered(self) -> None:
        if self._entered is not True:
            raise ExecutionSeamError(
                "private execution seam is not active"
            )

    @staticmethod
    def _same_chain(
        before: tuple[Any, ...],
        after: tuple[Any, ...],
    ) -> bool:
        return (
            before[0] is after[0]
            and before[1] is after[1]
            and before[2] is after[2]
            and before[3] is after[3]
            and before[4] == after[4]
            and before[5] == after[5]
            and before[6] == after[6]
        )

    def __enter__(self) -> "_LockedExecutionSeamScope":
        with self._entry_lock:
            if self._used:
                raise ExecutionSeamError(
                    "private execution seam is single-use"
                )
            self._used = True

        chain_before = attempt._active_capability_state(
            self._capability
        )
        (
            lease,
            lease_scope,
            claim_scope,
            authorization_scope,
            identity,
            lease_binding_id,
            authorization_id,
        ) = chain_before

        if (
            lease.absolute_write_exclusion_guaranteed is not False
            or lease.ordinary_raw_writers_excluded is not False
            or lease.execution_supported is not False
            or lease.executor_eligible is not False
            or lease.execution_authorized is not False
            or lease.internal_integrity_binding_only is not True
            or lease.external_authorization_proven is not False
        ):
            raise ExecutionSeamError(
                "B3F-A conservative non-authorizing semantics changed"
            )

        lock_fd = self._store._open_lock()
        self._attempt_lock_fd = lock_fd

        try:
            authorization_before = authorization_scope.record
            if not _attempt_matches(
                self._attempt_record,
                authorization=authorization_before,
                identity=identity,
                lease_binding_id=lease_binding_id,
                authorization_id=authorization_id,
            ):
                raise ExecutionSeamError(
                    "ATTEMPTING record does not match the exact live authorization chain"
                )

            if not _persisted_exact(
                self._store,
                self._attempt_record,
            ):
                raise ExecutionSeamError(
                    "exact durable ATTEMPTING record is unavailable"
                )

            claim_before = _claim_state_locked(
                claim_scope,
                identity=identity,
            )

            attempt._final_pinned_safety_cycle(
                lease=lease,
                claim_scope=claim_scope,
                identity=identity,
            )

            observed = claim_scope.revalidate_descriptor()
            if observed != identity[2]:
                raise ExecutionSeamError(
                    "private descriptor identity differs from the exact target"
                )

            chain_after = attempt._active_capability_state(
                self._capability
            )
            if not self._same_chain(
                chain_before,
                chain_after,
            ):
                raise ExecutionSeamError(
                    "active B3F-C chain changed during seam validation"
                )

            authorization_after = authorization_scope.record
            if (
                authorization_after != authorization_before
                or not _attempt_matches(
                    self._attempt_record,
                    authorization=authorization_after,
                    identity=identity,
                    lease_binding_id=lease_binding_id,
                    authorization_id=authorization_id,
                )
            ):
                raise ExecutionSeamError(
                    "RESERVED authorization changed during seam validation"
                )

            if not _persisted_exact(
                self._store,
                self._attempt_record,
            ):
                raise ExecutionSeamError(
                    "durable ATTEMPTING record changed during seam validation"
                )

            claim_after = _claim_state_locked(
                claim_scope,
                identity=identity,
            )
            if (
                claim_after[0] is not claim_before[0]
                or claim_after[1:] != claim_before[1:]
            ):
                raise ExecutionSeamError(
                    "pinned B3E-F/B3A descriptor chain changed during seam validation"
                )

            self._lease = lease
            self._lease_scope = lease_scope
            self._claim_scope = claim_scope
            self._authorization_scope = authorization_scope
            self._identity = identity
            self._lease_binding_id = lease_binding_id
            self._authorization_id = authorization_id
            self._authorization_record = authorization_before
            self._held_reference = claim_before[0]
            self._pre_continuity_id = claim_before[1]
            self._post_continuity_id = claim_before[2]
            self._fd = claim_before[3]
            self._entered = True
            return self

        except BaseException:
            self._attempt_lock_fd = None
            self._store._close_lock(lock_fd)
            raise

    def _descriptor_locked(self) -> int:
        """Return the private already-held FD once, while every lock is held."""
        self._require_entered()

        if self._descriptor_issued:
            raise ExecutionSeamError(
                "private descriptor bridge is single-use"
            )

        chain_before = (
            self._lease,
            self._lease_scope,
            self._claim_scope,
            self._authorization_scope,
            self._identity,
            self._lease_binding_id,
            self._authorization_id,
        )
        chain_now = attempt._active_capability_state(
            self._capability
        )
        if not self._same_chain(chain_before, chain_now):
            raise ExecutionSeamError(
                "active B3F-C chain changed before private descriptor use"
            )

        assert self._claim_scope is not None
        assert self._lease is not None
        assert self._identity is not None
        assert self._authorization_scope is not None
        assert self._authorization_record is not None
        assert self._fd is not None

        attempt._final_pinned_safety_cycle(
            lease=self._lease,
            claim_scope=self._claim_scope,
            identity=self._identity,
        )

        observed = self._claim_scope.revalidate_descriptor()
        if observed != self._identity[2]:
            raise ExecutionSeamError(
                "descriptor identity changed before private descriptor use"
            )

        if self._authorization_scope.record != self._authorization_record:
            raise ExecutionSeamError(
                "RESERVED authorization changed before private descriptor use"
            )

        if not _persisted_exact(
            self._store,
            self._attempt_record,
        ):
            raise ExecutionSeamError(
                "durable ATTEMPTING record changed before private descriptor use"
            )

        claim_now = _claim_state_locked(
            self._claim_scope,
            identity=self._identity,
        )
        if (
            claim_now[0] is not self._held_reference
            or claim_now[1] != self._pre_continuity_id
            or claim_now[2] != self._post_continuity_id
            or claim_now[3] != self._fd
        ):
            raise ExecutionSeamError(
                "already-held private descriptor chain changed before use"
            )

        self._descriptor_issued = True
        return self._fd

    def __exit__(
        self,
        exc_type: Any,
        exc: BaseException | None,
        traceback: Any,
    ) -> bool:
        self._require_entered()

        lock_fd = self._attempt_lock_fd
        self._entered = False
        self._attempt_lock_fd = None
        self._fd = None
        self._held_reference = None
        self._pre_continuity_id = None
        self._post_continuity_id = None
        self._authorization_record = None
        self._authorization_id = None
        self._lease_binding_id = None
        self._identity = None
        self._authorization_scope = None
        self._claim_scope = None
        self._lease_scope = None
        self._lease = None

        if type(lock_fd) is not int or lock_fd < 0:
            raise ExecutionSeamError(
                "private execution seam lost its attempt-journal lock"
            )

        self._store._close_lock(lock_fd)
        return False

    def __copy__(self) -> Any:
        raise ExecutionSeamError(
            "private execution seams cannot be copied"
        )

    def __deepcopy__(self, memo: Any) -> Any:
        raise ExecutionSeamError(
            "private execution seams cannot be deep-copied"
        )

    def __reduce__(self) -> Any:
        raise ExecutionSeamError(
            "private execution seams cannot be serialized"
        )

    def __reduce_ex__(self, protocol: int) -> Any:
        raise ExecutionSeamError(
            "private execution seams cannot be serialized"
        )


def _locked_execution_seam_scope(
    *,
    store: Any,
    capability: Any,
    attempt_record: Any,
) -> _LockedExecutionSeamScope:
    """Return one private non-executing B3F-E locked seam scope."""
    return _LockedExecutionSeamScope(
        _CONSTRUCTION_TOKEN,
        store=store,
        capability=capability,
        attempt_record=attempt_record,
    )


__all__ = [
    "EXECUTION_SEAM_POLICY_VERSION",
    "ExecutionSeamError",
]
