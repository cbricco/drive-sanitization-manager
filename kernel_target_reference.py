"""Process-local held kernel-target reference foundation.

This module does not open block devices and does not grant execution authority.

It only adopts an already-open descriptor, validates that the descriptor is a
non-inheritable read-only block-device reference whose kernel major:minor
matches one current integrity-valid Phase 6E-A decision, and owns deterministic
descriptor closure.

The caller remains responsible for obtaining the supplied 6E-A decision from
the trusted registry-controlled pipeline.  Object integrity alone is not proof
of caller provenance and must never be treated as destructive authority.
"""

from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import os
import stat
from typing import Any

import sanitization_authorization as auth


HELD_KERNEL_TARGET_REFERENCE_POLICY_VERSION = (
    "phase6e-b3a-held-kernel-reference-v1"
)


class HeldKernelTargetReferenceError(RuntimeError):
    """A supplied descriptor could not be adopted or managed safely."""


_CONSTRUCTION_TOKEN = object()


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


def _current_revalidation_is_usable(
    decision: Any,
) -> bool:
    if type(decision) is not (
        auth.FreshPhysicalTargetRevalidationDecision
    ):
        return False

    if not (
        auth._fresh_physical_target_revalidation_integrity_valid(
            decision
        )
    ):
        return False

    if (
        decision.policy_version
        != auth.FRESH_TARGET_REVALIDATION_POLICY_VERSION
        or type(decision.schema_version) is not int
        or decision.schema_version
        != auth.FRESH_TARGET_REVALIDATION_SCHEMA_VERSION
        or decision.status
        != auth.FRESH_TARGET_REVALIDATION_STATUS_SATISFIED
    ):
        return False

    if (
        type(decision.execution_supported) is not bool
        or decision.execution_supported is not False
        or type(decision.executor_eligible) is not bool
        or decision.executor_eligible is not False
        or type(
            decision.requires_separate_executor_authorization
        )
        is not bool
        or decision.requires_separate_executor_authorization
        is not True
    ):
        return False

    if any((
        decision.target_read_only,
        decision.target_mounted,
        decision.target_protected,
        decision.target_system_protected,
        decision.target_review_required,
        decision.target_ambiguous,
    )):
        return False

    if not auth._kernel_major_minor_valid(
        decision.target_major_minor
    ):
        return False

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
        return False

    now = now.astimezone(timezone.utc)

    return (
        evaluated_at
        <= now
        <= valid_until
    )


def _descriptor_major_minor(
    info: Any,
) -> str:
    try:
        mode = info.st_mode
        represented_device = info.st_rdev
    except AttributeError as exc:
        raise HeldKernelTargetReferenceError(
            "descriptor stat metadata is incomplete"
        ) from exc

    if not stat.S_ISBLK(mode):
        raise HeldKernelTargetReferenceError(
            "descriptor does not reference a block-special device"
        )

    try:
        major = os.major(represented_device)
        minor = os.minor(represented_device)
    except (TypeError, ValueError, OSError) as exc:
        raise HeldKernelTargetReferenceError(
            "descriptor kernel device number is invalid"
        ) from exc

    return f"{major}:{minor}"


class HeldKernelTargetReference:
    """Own one validated, already-open, non-authorizing block-device FD."""

    __slots__ = (
        "_fd",
        "_closed",
        "_target_path",
        "_target_major_minor",
        "_revalidation_id",
        "_handoff_id",
        "_target_binding_hash",
    )

    def __init__(
        self,
        token: object,
        *,
        fd: int,
        decision: auth.FreshPhysicalTargetRevalidationDecision,
        observed_major_minor: str,
    ) -> None:
        if token is not _CONSTRUCTION_TOKEN:
            raise TypeError(
                "HeldKernelTargetReference must be created by "
                "adopt_held_kernel_target_reference()"
            )

        self._fd = fd
        self._closed = False
        self._target_path = decision.target_path
        self._target_major_minor = (
            observed_major_minor
        )
        self._revalidation_id = (
            decision.revalidation_id
        )
        self._handoff_id = decision.handoff_id
        self._target_binding_hash = (
            decision.fresh_target_binding_hash
        )

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def target_path(self) -> str:
        return self._target_path

    @property
    def target_major_minor(self) -> str:
        return self._target_major_minor

    @property
    def revalidation_id(self) -> str:
        return self._revalidation_id

    @property
    def handoff_id(self) -> str:
        return self._handoff_id

    @property
    def target_binding_hash(self) -> str:
        return self._target_binding_hash

    def close(self) -> None:
        if self._closed:
            return

        fd = self._fd

        # Mark the capability unusable before close().  Retrying a descriptor
        # integer after a reported close error could act on a later-reused FD.
        self._fd = -1
        self._closed = True

        try:
            os.close(fd)
        except OSError as exc:
            raise HeldKernelTargetReferenceError(
                "held kernel target descriptor close failed; "
                "the reference must not be reused"
            ) from exc

    def __enter__(
        self,
    ) -> "HeldKernelTargetReference":
        if self._closed:
            raise HeldKernelTargetReferenceError(
                "held kernel target reference is already closed"
            )

        return self

    def __exit__(
        self,
        exc_type: Any,
        exc: BaseException | None,
        traceback: Any,
    ) -> bool:
        try:
            self.close()
        except HeldKernelTargetReferenceError as close_exc:
            if exc is None:
                raise

            if hasattr(exc, "add_note"):
                exc.add_note(
                    "held kernel target close also failed: "
                    + str(close_exc)
                )

        return False

    def __copy__(self) -> Any:
        raise HeldKernelTargetReferenceError(
            "held kernel target references cannot be copied"
        )

    def __deepcopy__(
        self,
        memo: Any,
    ) -> Any:
        raise HeldKernelTargetReferenceError(
            "held kernel target references cannot be deep-copied"
        )

    def __reduce__(self) -> Any:
        raise HeldKernelTargetReferenceError(
            "held kernel target references cannot be serialized"
        )

    def __reduce_ex__(
        self,
        protocol: int,
    ) -> Any:
        raise HeldKernelTargetReferenceError(
            "held kernel target references cannot be serialized"
        )


def adopt_held_kernel_target_reference(
    fd: Any,
    decision: Any,
) -> HeldKernelTargetReference:
    """Adopt an already-open descriptor after fail-closed validation.

    Ownership transfers only after ``fd`` is verified to be a non-negative
    exact integer.  From that point, every validation failure closes the
    supplied descriptor.

    This function never opens a device path, exposes a public FD capability,
    or grants destructive execution authority.
    """

    if type(fd) is not int or fd < 0:
        raise HeldKernelTargetReferenceError(
            "fd must be a non-negative exact integer"
        )

    try:
        if not _current_revalidation_is_usable(
            decision
        ):
            raise HeldKernelTargetReferenceError(
                "fresh target revalidation is not current "
                "and integrity-valid"
            )

        try:
            info = os.fstat(fd)
        except OSError as exc:
            raise HeldKernelTargetReferenceError(
                "supplied descriptor could not be inspected"
            ) from exc

        observed_major_minor = (
            _descriptor_major_minor(info)
        )

        if (
            observed_major_minor
            != decision.target_major_minor
        ):
            raise HeldKernelTargetReferenceError(
                "descriptor kernel device number differs "
                "from fresh target revalidation"
            )

        try:
            flags = fcntl.fcntl(
                fd,
                fcntl.F_GETFL,
            )
        except OSError as exc:
            raise HeldKernelTargetReferenceError(
                "supplied descriptor status flags are unavailable"
            ) from exc

        if type(flags) is not int:
            raise HeldKernelTargetReferenceError(
                "supplied descriptor status flags are invalid"
            )

        if (
            flags & os.O_ACCMODE
        ) != os.O_RDONLY:
            raise HeldKernelTargetReferenceError(
                "supplied descriptor is not read-only"
            )

        if (
            hasattr(os, "O_PATH")
            and bool(flags & os.O_PATH)
        ):
            raise HeldKernelTargetReferenceError(
                "O_PATH descriptors are not held target references"
            )

        try:
            inheritable = os.get_inheritable(
                fd
            )
        except OSError as exc:
            raise HeldKernelTargetReferenceError(
                "descriptor inheritance state is unavailable"
            ) from exc

        if inheritable is not False:
            raise HeldKernelTargetReferenceError(
                "supplied descriptor must be non-inheritable"
            )

        return HeldKernelTargetReference(
            _CONSTRUCTION_TOKEN,
            fd=fd,
            decision=decision,
            observed_major_minor=(
                observed_major_minor
            ),
        )

    except BaseException as exc:
        try:
            os.close(fd)
        except OSError as close_exc:
            raise HeldKernelTargetReferenceError(
                "descriptor validation failed and the owned descriptor "
                "could not be closed safely"
            ) from close_exc

        if isinstance(
            exc,
            (KeyboardInterrupt, SystemExit),
        ):
            raise

        if isinstance(
            exc,
            HeldKernelTargetReferenceError,
        ):
            raise

        raise HeldKernelTargetReferenceError(
            "descriptor validation failed"
        ) from exc


__all__ = [
    "HELD_KERNEL_TARGET_REFERENCE_POLICY_VERSION",
    "HeldKernelTargetReference",
    "HeldKernelTargetReferenceError",
    "adopt_held_kernel_target_reference",
]
