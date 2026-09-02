"""Phase 6E-B3F-C non-executing executor-ready locked capability.

This module joins one exact durable RESERVED executor authorization to one
exact still-live B3F-A lease while the established lock hierarchy remains
held:

    lease state -> B3E-F lifecycle -> B3A lifecycle -> authorization store

Entering the context performs final fresh safety/descriptor validation and
atomically consumes the B3F-A lease. It does not construct a command, expose
a raw descriptor, perform device data I/O, execute sanitization, or create a
durable success/completed state.

If the context exits without a future executor, the lease remains consumed
and the durable authorization remains RESERVED. That state requires manual
review/new authorization rather than automatic replay.
"""

from __future__ import annotations

import threading
from typing import Any

import execution_lease as leases
import executor_authorization as exauth


EXECUTOR_READY_CAPABILITY_POLICY_VERSION = (
    "phase6e-b3f-c-non-executing-executor-ready-capability-v1"
)


class ExecutorReadyCapabilityError(RuntimeError):
    """Executor-ready locked capability failed closed."""


_CONSTRUCTION_TOKEN = object()
_LEASE_TYPE = leases.ExecutionLease
_STORE_TYPE = exauth.DurableExecutorAuthorizationStore
_LEASE_SCOPE_FACTORY = leases._locked_execution_lease_validation_scope
_RESERVED_SCOPE_FACTORY = (
    exauth._locked_reserved_executor_authorization_scope
)
_HANDOFF_PROVENANCE = exauth._handoff_and_journal_provenance


def _record_matches_final_provenance(
    record: Any,
    *,
    identity: tuple[str, str, str, str],
    lease_binding_id: str,
    provenance: dict[str, Any],
) -> bool:
    try:
        if (
            type(record) is not exauth.ExecutorAuthorizationRecord
            or record.state
            != exauth.EXECUTOR_AUTHORIZATION_STATE_RESERVED
            or record.lease_binding_id != lease_binding_id
            or (
                record.handoff_id,
                record.target_path,
                record.target_major_minor,
                record.target_binding_hash,
            )
            != identity
        ):
            return False

        checks = {
            "handoff_id": "handoff_id",
            "gate_id": "gate_id",
            "binding_id": "binding_id",
            "journal_policy_version": "journal_policy_version",
            "journal_schema_version": "journal_schema_version",
            "journal_state": "journal_state",
            "journal_entry_hash": "journal_entry_hash",
            "approval_id": "approval_id",
            "request_id": "request_id",
            "request_hash": "request_hash",
            "record_snapshot_hash": "record_snapshot_hash",
            "internal_record_id": "internal_record_id",
            "method_profile_id": "method_profile_id",
            "operation": "operation",
        }

        return all(
            getattr(record, record_name)
            == provenance[provenance_name]
            for record_name, provenance_name in checks.items()
        )

    except Exception:
        return False


class ExecutorReadyCapability:
    """Opaque one-shot capability valid only while all B3F-C locks are held."""

    __slots__ = (
        "_lease",
        "_store",
        "_authorization_id",
        "_handoff",
        "_journal",
        "_entry_lock",
        "_used",
        "_lease_consumed",
        "_active",
        "_lease_scope",
        "_authorization_scope",
        "_identity",
        "_lease_binding_id",
    )

    def __init__(
        self,
        token: object,
        *,
        lease: Any,
        store: Any,
        authorization_id: str,
        handoff: Any,
        journal: Any,
    ) -> None:
        if token is not _CONSTRUCTION_TOKEN:
            raise TypeError(
                "ExecutorReadyCapability must be created by "
                "prepare_executor_ready_capability()"
            )
        if type(lease) is not _LEASE_TYPE:
            raise ExecutorReadyCapabilityError(
                "lease is not the exact B3F-A type"
            )
        if type(store) is not _STORE_TYPE:
            raise ExecutorReadyCapabilityError(
                "store is not the exact B3F-B store type"
            )

        self._lease = lease
        self._store = store
        self._authorization_id = authorization_id
        self._handoff = handoff
        self._journal = journal
        self._entry_lock = threading.Lock()
        self._used = False
        self._lease_consumed = False
        self._active = False
        self._lease_scope = None
        self._authorization_scope = None
        self._identity = None
        self._lease_binding_id = None

    def _require_active(self) -> None:
        if self._active is not True:
            raise ExecutorReadyCapabilityError(
                "executor-ready capability is not active"
            )

    def __enter__(self) -> "ExecutorReadyCapability":
        with self._entry_lock:
            if self._used:
                raise ExecutorReadyCapabilityError(
                    "executor-ready capability is single-use"
                )
            self._used = True

        lease_scope = None
        authorization_scope = None
        lease_entered = False
        authorization_entered = False

        try:
            provenance = _HANDOFF_PROVENANCE(
                self._handoff,
                self._journal,
            )

            lease_scope = _LEASE_SCOPE_FACTORY(self._lease)
            lease_scope.__enter__()
            lease_entered = True

            identity = lease_scope.identity
            lease_binding_id = (
                lease_scope
                .execution_authorization_integrity_binding_id
            )

            if (
                identity[0] != provenance["handoff_id"]
                or identity[3]
                != provenance["handoff_target_binding_hash"]
            ):
                raise ExecutorReadyCapabilityError(
                    "live lease does not match immutable handoff provenance"
                )

            authorization_scope = _RESERVED_SCOPE_FACTORY(
                store=self._store,
                authorization_id=self._authorization_id,
                lease=self._lease,
                lease_binding_id=lease_binding_id,
                identity=identity,
            )
            authorization_scope.__enter__()
            authorization_entered = True

            record = authorization_scope.record
            if not _record_matches_final_provenance(
                record,
                identity=identity,
                lease_binding_id=lease_binding_id,
                provenance=provenance,
            ):
                raise ExecutorReadyCapabilityError(
                    "RESERVED authorization provenance does not match final live chain"
                )

            consumed_identity, consumed_binding_id = (
                lease_scope._consume_locked_for_executor_ready()
            )
            self._lease_consumed = True

            if (
                consumed_identity != identity
                or consumed_binding_id != lease_binding_id
            ):
                raise ExecutorReadyCapabilityError(
                    "final lease consumption changed locked identity"
                )

            record_after = authorization_scope.record
            if record_after != record:
                raise ExecutorReadyCapabilityError(
                    "RESERVED authorization changed during final lease consumption"
                )

            self._lease_scope = lease_scope
            self._authorization_scope = authorization_scope
            self._identity = identity
            self._lease_binding_id = lease_binding_id
            self._active = True
            return self

        except BaseException as exc:
            self._active = False
            self._identity = None
            self._lease_binding_id = None
            self._authorization_scope = None
            self._lease_scope = None

            try:
                if authorization_entered and authorization_scope is not None:
                    authorization_scope.__exit__(
                        type(exc),
                        exc,
                        exc.__traceback__,
                    )
            finally:
                if lease_entered and lease_scope is not None:
                    lease_scope.__exit__(
                        type(exc),
                        exc,
                        exc.__traceback__,
                    )
            raise

    def __exit__(
        self,
        exc_type: Any,
        exc: BaseException | None,
        traceback: Any,
    ) -> bool:
        self._require_active()

        authorization_scope = self._authorization_scope
        lease_scope = self._lease_scope

        self._active = False
        self._authorization_scope = None
        self._lease_scope = None
        self._identity = None
        self._lease_binding_id = None

        try:
            if authorization_scope is None:
                raise ExecutorReadyCapabilityError(
                    "executor-ready capability lost authorization-store pin"
                )
            authorization_scope.__exit__(
                exc_type,
                exc,
                traceback,
            )
        finally:
            if lease_scope is None:
                raise ExecutorReadyCapabilityError(
                    "executor-ready capability lost live lease pin"
                )
            lease_scope.__exit__(
                exc_type,
                exc,
                traceback,
            )

        return False

    @property
    def active(self) -> bool:
        return self._active

    @property
    def authorization_id(self) -> str:
        self._require_active()
        return self._authorization_id

    @property
    def handoff_id(self) -> str:
        self._require_active()
        assert self._identity is not None
        return self._identity[0]

    @property
    def target_path(self) -> str:
        self._require_active()
        assert self._identity is not None
        return self._identity[1]

    @property
    def target_major_minor(self) -> str:
        self._require_active()
        assert self._identity is not None
        return self._identity[2]

    @property
    def target_binding_hash(self) -> str:
        self._require_active()
        assert self._identity is not None
        return self._identity[3]

    @property
    def execution_authorized(self) -> bool:
        return False

    @property
    def execution_supported(self) -> bool:
        return False

    @property
    def executor_eligible(self) -> bool:
        return False

    @property
    def execution_performed(self) -> bool:
        return False

    @property
    def lease_consumed(self) -> bool:
        return self._lease_consumed

    @property
    def requires_future_executor(self) -> bool:
        return True

    def __copy__(self) -> Any:
        raise ExecutorReadyCapabilityError(
            "executor-ready capabilities cannot be copied"
        )

    def __deepcopy__(self, memo: Any) -> Any:
        raise ExecutorReadyCapabilityError(
            "executor-ready capabilities cannot be deep-copied"
        )

    def __reduce__(self) -> Any:
        raise ExecutorReadyCapabilityError(
            "executor-ready capabilities cannot be serialized"
        )

    def __reduce_ex__(self, protocol: int) -> Any:
        raise ExecutorReadyCapabilityError(
            "executor-ready capabilities cannot be serialized"
        )


def prepare_executor_ready_capability(
    *,
    lease: Any,
    store: Any,
    authorization_id: Any,
    handoff: Any,
    journal: Any,
) -> ExecutorReadyCapability:
    """Return one non-executing single-use B3F-C locked capability context."""

    if not isinstance(authorization_id, str) or not authorization_id:
        raise ExecutorReadyCapabilityError(
            "authorization_id is invalid"
        )

    return ExecutorReadyCapability(
        _CONSTRUCTION_TOKEN,
        lease=lease,
        store=store,
        authorization_id=authorization_id,
        handoff=handoff,
        journal=journal,
    )


__all__ = [
    "EXECUTOR_READY_CAPABILITY_POLICY_VERSION",
    "ExecutorReadyCapability",
    "ExecutorReadyCapabilityError",
    "prepare_executor_ready_capability",
]
