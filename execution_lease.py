"""Phase 6E-B3F-A R3 lifecycle-synchronized non-executing execution lease.

This module does not open a device, perform data I/O, construct commands, or
execute anything. It accepts only the exact live Phase 6E-B3E-F
HeldKernelWriteClaim and uses B3E-F's private lifecycle-locked validation scope
so descriptor validation cannot race B3E-F close().

Fresh trusted Phase 6E-B3D-A continuity plus B3D-B internal-integrity checking
is performed around already-held descriptor validation at both lease creation
and one-shot consumption.

The execution-authorization integrity binding is internal consistency evidence
only. It is not human authorization, executor authority, or cryptographic proof
of external provenance.

Linux O_EXCL remains coordination only:
absolute_write_exclusion_guaranteed == False
ordinary_raw_writers_excluded == False
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import secrets
import threading
from typing import Any

import held_target_safety_continuity as continuity
import kernel_write_claim_acquisition as claims


EXECUTION_LEASE_POLICY_VERSION = (
    "phase6e-b3f-a-r3-lifecycle-synchronized-execution-lease-v1"
)


class ExecutionLeaseError(RuntimeError):
    """The synchronized non-executing execution lease failed closed."""


_CONSTRUCTION_TOKEN = object()
_ISSUANCE_LOCK = threading.Lock()
_ISSUED_CLAIMS: dict[int, Any] = {}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


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

    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
    ):
        return None

    return parsed.astimezone(timezone.utc)


def _continuity_identity(
    decision: Any,
) -> tuple[str, str, str, str]:
    try:
        if (
            type(decision)
            is not continuity.HeldTargetSafetyContinuityDecision
        ):
            raise ExecutionLeaseError(
                "fresh trusted continuity result has the wrong type"
            )

        if (
            continuity
            ._held_target_safety_continuity_integrity_valid(
                decision
            )
            is not True
        ):
            raise ExecutionLeaseError(
                "fresh trusted continuity failed B3D-B integrity"
            )

        evaluated_at = _parse_utc(
            decision.evaluated_at_utc
        )
        valid_until = _parse_utc(
            decision.valid_until_utc
        )
        now = _utc_now()

        if (
            evaluated_at is None
            or valid_until is None
            or not isinstance(now, datetime)
            or now.tzinfo is None
            or now.utcoffset() is None
        ):
            raise ExecutionLeaseError(
                "fresh continuity freshness metadata is invalid"
            )

        now = now.astimezone(timezone.utc)

        if not (
            evaluated_at
            <= now
            <= valid_until
        ):
            raise ExecutionLeaseError(
                "fresh continuity result is not current"
            )

        if (
            decision.execution_supported is not False
            or decision.executor_eligible is not False
            or (
                decision
                .requires_separate_executor_authorization
                is not True
            )
        ):
            raise ExecutionLeaseError(
                "fresh continuity result is not non-authorizing"
            )

        identity = (
            decision.handoff_id,
            decision.target_path,
            decision.target_major_minor,
            decision.target_binding_hash,
        )

        if not all(
            isinstance(value, str) and bool(value)
            for value in identity
        ):
            raise ExecutionLeaseError(
                "fresh continuity identity is malformed"
            )

        return identity

    except ExecutionLeaseError:
        raise

    except Exception as exc:
        raise ExecutionLeaseError(
            "fresh continuity result could not be inspected safely"
        ) from exc


def _trusted_fresh_continuity(
    *,
    held_reference: Any,
    arguments: dict[str, Any],
) -> tuple[
    continuity.HeldTargetSafetyContinuityDecision,
    tuple[str, str, str, str],
]:
    try:
        decision = (
            continuity
            .revalidate_held_target_safety_continuity(
                held_reference=held_reference,
                **arguments,
            )
        )
    except BaseException as exc:
        if isinstance(
            exc,
            (KeyboardInterrupt, SystemExit),
        ):
            raise

        raise ExecutionLeaseError(
            "fresh trusted B3D-A continuity failed"
        ) from exc

    identity = _continuity_identity(
        decision
    )

    return decision, identity


def _canonical_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _binding_payload(
    *,
    nonce: str,
    identity: tuple[str, str, str, str],
    claim_pre_continuity_id: str,
    claim_post_continuity_id: str,
    lease_pre_continuity_id: str,
    lease_post_continuity_id: str,
) -> dict[str, str]:
    return {
        "nonce": nonce,
        "handoff_id": identity[0],
        "target_path": identity[1],
        "target_major_minor": identity[2],
        "target_binding_hash": identity[3],
        "claim_pre_continuity_id": claim_pre_continuity_id,
        "claim_post_continuity_id": claim_post_continuity_id,
        "lease_pre_continuity_id": lease_pre_continuity_id,
        "lease_post_continuity_id": lease_post_continuity_id,
    }


def _new_internal_integrity_binding(
    *,
    identity: tuple[str, str, str, str],
    claim_pre_continuity_id: str,
    claim_post_continuity_id: str,
    lease_pre_continuity_id: str,
    lease_post_continuity_id: str,
) -> tuple[str, str]:
    nonce = secrets.token_hex(32)

    if (
        not isinstance(nonce, str)
        or len(nonce) != 64
        or any(
            character not in "0123456789abcdef"
            for character in nonce
        )
    ):
        raise ExecutionLeaseError(
            "fresh internal-integrity nonce is invalid"
        )

    digest = _canonical_hash(
        _binding_payload(
            nonce=nonce,
            identity=identity,
            claim_pre_continuity_id=claim_pre_continuity_id,
            claim_post_continuity_id=claim_post_continuity_id,
            lease_pre_continuity_id=lease_pre_continuity_id,
            lease_post_continuity_id=lease_post_continuity_id,
        )
    )

    return nonce, "xeli_" + digest


def _scope_identity(
    scope: Any,
) -> tuple[
    tuple[str, str, str, str],
    str,
    str,
]:
    try:
        identity = scope.identity
        claim_pre = scope.claim_pre_continuity_id
        claim_post = scope.claim_post_continuity_id
    except Exception as exc:
        raise ExecutionLeaseError(
            "B3E-F locked validation scope is malformed"
        ) from exc

    if (
        not isinstance(identity, tuple)
        or len(identity) != 4
        or not all(
            isinstance(value, str) and bool(value)
            for value in identity
        )
        or not isinstance(claim_pre, str)
        or not claim_pre
        or not isinstance(claim_post, str)
        or not claim_post
    ):
        raise ExecutionLeaseError(
            "B3E-F locked scope identity is malformed"
        )

    return identity, claim_pre, claim_post


def _scope_revalidate_descriptor(
    scope: Any,
    expected_major_minor: str,
) -> None:
    try:
        observed = scope.revalidate_descriptor()
    except BaseException as exc:
        if isinstance(
            exc,
            (KeyboardInterrupt, SystemExit),
        ):
            raise

        raise ExecutionLeaseError(
            "synchronized B3E-F descriptor validation failed"
        ) from exc

    if observed != expected_major_minor:
        raise ExecutionLeaseError(
            "synchronized B3E-F descriptor identity is inconsistent"
        )


def _fresh_safety_cycle(
    *,
    scope: Any,
    expected_identity: tuple[str, str, str, str],
    arguments: dict[str, Any],
) -> tuple[str, str]:
    try:
        held_reference = scope.held_reference
    except Exception as exc:
        raise ExecutionLeaseError(
            "B3E-F scope did not provide its still-held B3A reference"
        ) from exc

    (
        before,
        before_identity,
    ) = _trusted_fresh_continuity(
        held_reference=held_reference,
        arguments=arguments,
    )

    if before_identity != expected_identity:
        raise ExecutionLeaseError(
            "pre-validation fresh continuity differs from the B3E-F claim"
        )

    _scope_revalidate_descriptor(
        scope,
        expected_identity[2],
    )

    (
        after,
        after_identity,
    ) = _trusted_fresh_continuity(
        held_reference=held_reference,
        arguments=arguments,
    )

    if (
        after_identity != expected_identity
        or after_identity != before_identity
    ):
        raise ExecutionLeaseError(
            "post-validation fresh continuity differs from the B3E-F claim"
        )

    _scope_revalidate_descriptor(
        scope,
        expected_identity[2],
    )

    current_identity, _, _ = _scope_identity(
        scope
    )

    if current_identity != expected_identity:
        raise ExecutionLeaseError(
            "B3E-F claim identity changed during synchronized safety cycle"
        )

    return (
        before.continuity_id,
        after.continuity_id,
    )


class ExecutionLease:
    """Opaque one-shot non-executing lease bound to one live B3E-F claim."""

    __slots__ = (
        "_write_claim",
        "_handoff_id",
        "_target_path",
        "_target_major_minor",
        "_target_binding_hash",
        "_claim_pre_continuity_id",
        "_claim_post_continuity_id",
        "_lease_pre_continuity_id",
        "_lease_post_continuity_id",
        "_integrity_nonce",
        "_execution_authorization_integrity_binding_id",
        "_arguments",
        "_consumed",
        "_state_lock",
    )

    def __init__(
        self,
        token: object,
        *,
        write_claim: claims.HeldKernelWriteClaim,
        identity: tuple[str, str, str, str],
        claim_pre_continuity_id: str,
        claim_post_continuity_id: str,
        lease_pre_continuity_id: str,
        lease_post_continuity_id: str,
        integrity_nonce: str,
        execution_authorization_integrity_binding_id: str,
        arguments: dict[str, Any],
    ) -> None:
        if token is not _CONSTRUCTION_TOKEN:
            raise TypeError(
                "ExecutionLease must be created by create_execution_lease()"
            )

        self._write_claim = write_claim
        (
            self._handoff_id,
            self._target_path,
            self._target_major_minor,
            self._target_binding_hash,
        ) = identity
        self._claim_pre_continuity_id = claim_pre_continuity_id
        self._claim_post_continuity_id = claim_post_continuity_id
        self._lease_pre_continuity_id = lease_pre_continuity_id
        self._lease_post_continuity_id = lease_post_continuity_id
        self._integrity_nonce = integrity_nonce
        self._execution_authorization_integrity_binding_id = (
            execution_authorization_integrity_binding_id
        )
        self._arguments = dict(arguments)
        self._consumed = False
        self._state_lock = threading.Lock()

    @property
    def consumed(self) -> bool:
        with self._state_lock:
            return self._consumed

    @property
    def live(self) -> bool:
        with self._state_lock:
            if self._consumed:
                return False

            try:
                with claims._locked_write_claim_validation_scope(
                    self._write_claim
                ) as scope:
                    identity, claim_pre, claim_post = _scope_identity(
                        scope
                    )

                    return (
                        self._consumed is False
                        and identity
                        == (
                            self._handoff_id,
                            self._target_path,
                            self._target_major_minor,
                            self._target_binding_hash,
                        )
                        and claim_pre == self._claim_pre_continuity_id
                        and claim_post == self._claim_post_continuity_id
                    )
            except Exception:
                return False

    @property
    def handoff_id(self) -> str:
        return self._handoff_id

    @property
    def target_path(self) -> str:
        return self._target_path

    @property
    def target_major_minor(self) -> str:
        return self._target_major_minor

    @property
    def target_binding_hash(self) -> str:
        return self._target_binding_hash

    @property
    def execution_authorization_integrity_binding_id(self) -> str:
        return self._execution_authorization_integrity_binding_id

    @property
    def internal_integrity_binding_only(self) -> bool:
        return True

    @property
    def external_authorization_proven(self) -> bool:
        return False

    @property
    def kernel_exclusive_claim_acquired(self) -> bool:
        return True

    @property
    def absolute_write_exclusion_guaranteed(self) -> bool:
        return False

    @property
    def ordinary_raw_writers_excluded(self) -> bool:
        return False

    @property
    def execution_supported(self) -> bool:
        return False

    @property
    def executor_eligible(self) -> bool:
        return False

    @property
    def execution_authorized(self) -> bool:
        return False

    @property
    def requires_trusted_executor_consumption(self) -> bool:
        return True

    def consume(self) -> None:
        """Atomically consume once after fresh synchronized safety checks."""

        with self._state_lock:
            if self._consumed:
                raise ExecutionLeaseError(
                    "execution lease has already been consumed"
                )

            expected_identity = (
                self._handoff_id,
                self._target_path,
                self._target_major_minor,
                self._target_binding_hash,
            )

            if not _internal_integrity_binding_valid(self):
                raise ExecutionLeaseError(
                    "internal execution-integrity binding failed"
                )

            try:
                scope_manager = (
                    claims
                    ._locked_write_claim_validation_scope(
                        self._write_claim
                    )
                )
                with scope_manager as scope:
                    identity, claim_pre, claim_post = _scope_identity(
                        scope
                    )

                    if (
                        identity != expected_identity
                        or claim_pre != self._claim_pre_continuity_id
                        or claim_post != self._claim_post_continuity_id
                    ):
                        raise ExecutionLeaseError(
                            "B3E-F claim changed before lease consumption"
                        )

                    _fresh_safety_cycle(
                        scope=scope,
                        expected_identity=expected_identity,
                        arguments=self._arguments,
                    )

                    identity_after, claim_pre_after, claim_post_after = (
                        _scope_identity(scope)
                    )

                    if (
                        identity_after != expected_identity
                        or claim_pre_after != self._claim_pre_continuity_id
                        or claim_post_after != self._claim_post_continuity_id
                    ):
                        raise ExecutionLeaseError(
                            "B3E-F claim changed during lease consumption"
                        )

                    if not _internal_integrity_binding_valid(self):
                        raise ExecutionLeaseError(
                            "internal execution-integrity binding changed "
                            "during consumption"
                        )

                    self._consumed = True

            except ExecutionLeaseError:
                raise

            except BaseException as exc:
                if isinstance(
                    exc,
                    (KeyboardInterrupt, SystemExit),
                ):
                    raise

                raise ExecutionLeaseError(
                    "synchronized execution-lease consumption failed"
                ) from exc

    def __copy__(self) -> Any:
        raise ExecutionLeaseError(
            "execution leases cannot be copied"
        )

    def __deepcopy__(
        self,
        memo: Any,
    ) -> Any:
        raise ExecutionLeaseError(
            "execution leases cannot be deep-copied"
        )

    def __reduce__(self) -> Any:
        raise ExecutionLeaseError(
            "execution leases cannot be serialized"
        )

    def __reduce_ex__(
        self,
        protocol: int,
    ) -> Any:
        raise ExecutionLeaseError(
            "execution leases cannot be serialized"
        )


def _internal_integrity_binding_valid(
    lease: Any,
) -> bool:
    try:
        if type(lease) is not ExecutionLease:
            return False

        expected = "xeli_" + _canonical_hash(
            _binding_payload(
                nonce=lease._integrity_nonce,
                identity=(
                    lease._handoff_id,
                    lease._target_path,
                    lease._target_major_minor,
                    lease._target_binding_hash,
                ),
                claim_pre_continuity_id=(
                    lease._claim_pre_continuity_id
                ),
                claim_post_continuity_id=(
                    lease._claim_post_continuity_id
                ),
                lease_pre_continuity_id=(
                    lease._lease_pre_continuity_id
                ),
                lease_post_continuity_id=(
                    lease._lease_post_continuity_id
                ),
            )
        )

        return (
            lease._execution_authorization_integrity_binding_id
            == expected
        )
    except Exception:
        return False


def create_execution_lease(
    *,
    write_claim: Any,
    registry: Any,
    approval_id: Any,
    request: Any,
    record: Any,
    journal: Any,
    gate: Any,
) -> ExecutionLease:
    """Create one opaque non-executing lease for one exact live B3E-F claim."""

    if type(write_claim) is not claims.HeldKernelWriteClaim:
        raise ExecutionLeaseError(
            "write_claim must be an exact published B3E-F held write claim"
        )

    arguments = {
        "registry": registry,
        "approval_id": approval_id,
        "request": request,
        "record": record,
        "journal": journal,
        "gate": gate,
    }

    try:
        scope_manager = (
            claims
            ._locked_write_claim_validation_scope(
                write_claim
            )
        )

        with scope_manager as scope:
            identity, claim_pre, claim_post = _scope_identity(
                scope
            )

            (
                lease_pre,
                lease_post,
            ) = _fresh_safety_cycle(
                scope=scope,
                expected_identity=identity,
                arguments=arguments,
            )

            claim_key = id(write_claim)

            with _ISSUANCE_LOCK:
                existing = _ISSUED_CLAIMS.get(
                    claim_key
                )
                if existing is not None:
                    raise ExecutionLeaseError(
                        "this B3E-F write claim already has an issued "
                        "execution lease"
                    )

                (
                    integrity_nonce,
                    integrity_binding_id,
                ) = _new_internal_integrity_binding(
                    identity=identity,
                    claim_pre_continuity_id=claim_pre,
                    claim_post_continuity_id=claim_post,
                    lease_pre_continuity_id=lease_pre,
                    lease_post_continuity_id=lease_post,
                )

                lease = ExecutionLease(
                    _CONSTRUCTION_TOKEN,
                    write_claim=write_claim,
                    identity=identity,
                    claim_pre_continuity_id=claim_pre,
                    claim_post_continuity_id=claim_post,
                    lease_pre_continuity_id=lease_pre,
                    lease_post_continuity_id=lease_post,
                    integrity_nonce=integrity_nonce,
                    execution_authorization_integrity_binding_id=(
                        integrity_binding_id
                    ),
                    arguments=arguments,
                )

                if not _internal_integrity_binding_valid(
                    lease
                ):
                    raise ExecutionLeaseError(
                        "fresh internal execution-integrity binding is invalid"
                    )

                _ISSUED_CLAIMS[claim_key] = write_claim
                return lease

    except ExecutionLeaseError:
        raise

    except BaseException as exc:
        if isinstance(
            exc,
            (KeyboardInterrupt, SystemExit),
        ):
            raise

        raise ExecutionLeaseError(
            "synchronized execution-lease establishment failed"
        ) from exc


class _LockedExecutionLeaseValidationScope:
    """Private single-use live-lease pin for trusted B3F-B consumers."""

    __slots__ = (
        "_lease",
        "_entry_lock",
        "_used",
        "_entered",
        "_claim_scope",
    )

    def __init__(self, execution_lease: ExecutionLease) -> None:
        if type(execution_lease) is not ExecutionLease:
            raise ExecutionLeaseError(
                "lease validation scope requires an exact B3F-A lease"
            )
        self._lease = execution_lease
        self._entry_lock = threading.Lock()
        self._used = False
        self._entered = False
        self._claim_scope = None

    def _require_entered(self) -> None:
        if self._entered is not True:
            raise ExecutionLeaseError(
                "execution-lease validation scope is not active"
            )

    def _state_locked(self) -> tuple[tuple[str, str, str, str], str]:
        self._require_entered()
        execution_lease = self._lease
        claim_scope = self._claim_scope

        if (
            execution_lease._consumed is not False
            or claim_scope is None
            or not _internal_integrity_binding_valid(execution_lease)
        ):
            raise ExecutionLeaseError(
                "execution lease is not live and integrity-valid"
            )

        identity, claim_pre, claim_post = _scope_identity(claim_scope)
        expected_identity = (
            execution_lease._handoff_id,
            execution_lease._target_path,
            execution_lease._target_major_minor,
            execution_lease._target_binding_hash,
        )

        if (
            identity != expected_identity
            or claim_pre != execution_lease._claim_pre_continuity_id
            or claim_post != execution_lease._claim_post_continuity_id
        ):
            raise ExecutionLeaseError(
                "execution lease differs from its pinned B3E-F claim"
            )

        binding_id = (
            execution_lease
            ._execution_authorization_integrity_binding_id
        )
        if (
            not isinstance(binding_id, str)
            or not binding_id.startswith("xeli_")
            or len(binding_id) != len("xeli_") + 64
            or any(
                character not in "0123456789abcdef"
                for character in binding_id[len("xeli_"):]
            )
        ):
            raise ExecutionLeaseError(
                "execution lease internal-integrity binding is malformed"
            )

        return expected_identity, binding_id

    def __enter__(self) -> "_LockedExecutionLeaseValidationScope":
        with self._entry_lock:
            if self._used:
                raise ExecutionLeaseError(
                    "execution-lease validation scope is single-use"
                )
            self._used = True

        self._lease._state_lock.acquire()
        claim_scope = None
        claim_entered = False

        try:
            if (
                self._lease._consumed is not False
                or not _internal_integrity_binding_valid(self._lease)
            ):
                raise ExecutionLeaseError(
                    "execution lease is consumed or integrity-invalid"
                )

            claim_scope = (
                claims
                ._locked_write_claim_validation_scope(
                    self._lease._write_claim
                )
            )
            claim_scope.__enter__()
            claim_entered = True
            self._claim_scope = claim_scope
            self._entered = True

            identity, _ = self._state_locked()
            _fresh_safety_cycle(
                scope=claim_scope,
                expected_identity=identity,
                arguments=self._lease._arguments,
            )
            self._state_locked()
            return self

        except BaseException as exc:
            self._entered = False
            self._claim_scope = None
            try:
                if claim_entered and claim_scope is not None:
                    claim_scope.__exit__(
                        type(exc), exc, exc.__traceback__
                    )
            finally:
                self._lease._state_lock.release()
            raise

    def __exit__(
        self,
        exc_type: Any,
        exc: BaseException | None,
        traceback: Any,
    ) -> bool:
        if self._entered is not True:
            raise ExecutionLeaseError(
                "execution-lease validation scope exit without active entry"
            )

        claim_scope = self._claim_scope
        self._entered = False
        self._claim_scope = None

        try:
            if claim_scope is None:
                raise ExecutionLeaseError(
                    "execution-lease validation scope lost B3E-F pin"
                )
            claim_scope.__exit__(exc_type, exc, traceback)
        finally:
            self._lease._state_lock.release()

        return False

    @property
    def identity(self) -> tuple[str, str, str, str]:
        identity, _ = self._state_locked()
        return identity

    @property
    def execution_authorization_integrity_binding_id(self) -> str:
        _, binding_id = self._state_locked()
        return binding_id


    def _consume_locked_for_executor_ready(
        self,
    ) -> tuple[tuple[str, str, str, str], str]:
        """Consume once while the B3F-C live lock chain is already held.

        The caller must already hold this exact validation scope. This method
        deliberately never reacquires the non-reentrant lease state lock.
        """

        self._require_entered()

        execution_lease = self._lease
        claim_scope = self._claim_scope

        if (
            execution_lease._consumed is not False
            or claim_scope is None
        ):
            raise ExecutionLeaseError(
                "execution lease is unavailable for final locked consumption"
            )

        identity, binding_id = self._state_locked()

        try:
            observed = claim_scope.revalidate_descriptor()
            if observed != identity[2]:
                raise ExecutionLeaseError(
                    "final locked descriptor identity differs from lease target"
                )

            _fresh_safety_cycle(
                scope=claim_scope,
                expected_identity=identity,
                arguments=execution_lease._arguments,
            )

            observed_after = claim_scope.revalidate_descriptor()
            if observed_after != identity[2]:
                raise ExecutionLeaseError(
                    "descriptor identity changed during final safety validation"
                )

            identity_after, binding_after = self._state_locked()
            if (
                identity_after != identity
                or binding_after != binding_id
                or not _internal_integrity_binding_valid(execution_lease)
            ):
                raise ExecutionLeaseError(
                    "execution lease changed during final locked consumption"
                )

            execution_lease._consumed = True
            return identity_after, binding_after

        except ExecutionLeaseError:
            raise

        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise

            raise ExecutionLeaseError(
                "final locked executor-ready lease consumption failed"
            ) from exc


def _locked_execution_lease_validation_scope(
    execution_lease: Any,
) -> _LockedExecutionLeaseValidationScope:
    """Return one private B3F-A live-capability validation scope."""
    return _LockedExecutionLeaseValidationScope(execution_lease)


__all__ = [
    "EXECUTION_LEASE_POLICY_VERSION",
    "ExecutionLease",
    "ExecutionLeaseError",
    "create_execution_lease",
]
