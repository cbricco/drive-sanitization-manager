"""Phase 6E-B3C read-only physical-target acquisition boundary.

This module opens only the target path returned by the existing trusted
Phase 6E-A revalidation pipeline.  It validates the resulting read-only
block-device descriptor, repeats Phase 6E-A while that same descriptor is
held, and transfers ownership exactly once into the Phase 6E-B3A held
kernel-target reference.

The returned reference is non-authorizing.  This module does not expose a
public FD, construct commands, grant executor authority, or mutate a device.
"""

from __future__ import annotations

import fcntl
import os
import stat
from typing import Any

import kernel_target_reference as held_ref
import sanitization_authorization as auth


KERNEL_TARGET_ACQUISITION_POLICY_VERSION = (
    "phase6e-b3c-mocked-read-only-acquisition-v1"
)


class KernelTargetAcquisitionError(RuntimeError):
    """A read-only physical-target descriptor could not be acquired safely."""


def _required_open_flags() -> int:
    missing = [
        name
        for name in ("O_NOFOLLOW", "O_CLOEXEC")
        if not hasattr(os, name)
    ]
    if missing:
        raise KernelTargetAcquisitionError(
            "required safe open flags are unavailable: "
            + ", ".join(missing)
        )
    return os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC


def _fresh_decision_is_safe(decision: Any) -> bool:
    if type(decision) is not auth.FreshPhysicalTargetRevalidationDecision:
        return False
    if not auth._fresh_physical_target_revalidation_integrity_valid(decision):
        return False
    if (
        decision.status
        != auth.FRESH_TARGET_REVALIDATION_STATUS_SATISFIED
        or decision.execution_supported is not False
        or decision.executor_eligible is not False
        or decision.requires_separate_executor_authorization is not True
    ):
        return False
    return not any((
        decision.target_read_only,
        decision.target_mounted,
        decision.target_protected,
        decision.target_system_protected,
        decision.target_review_required,
        decision.target_ambiguous,
    ))


def _descriptor_major_minor(info: Any) -> str:
    try:
        mode = info.st_mode
        represented_device = info.st_rdev
    except AttributeError as exc:
        raise KernelTargetAcquisitionError(
            "descriptor stat metadata is incomplete"
        ) from exc
    if not stat.S_ISBLK(mode):
        raise KernelTargetAcquisitionError(
            "acquired descriptor is not a block-special device"
        )
    try:
        return f"{os.major(represented_device)}:{os.minor(represented_device)}"
    except (TypeError, ValueError, OSError) as exc:
        raise KernelTargetAcquisitionError(
            "acquired descriptor kernel device number is invalid"
        ) from exc


def _validate_acquired_descriptor(fd: int, expected_major_minor: str) -> str:
    try:
        info = os.fstat(fd)
    except OSError as exc:
        raise KernelTargetAcquisitionError(
            "acquired descriptor could not be inspected"
        ) from exc

    observed = _descriptor_major_minor(info)
    if observed != expected_major_minor:
        raise KernelTargetAcquisitionError(
            "acquired descriptor kernel device number differs "
            "from the trusted pre-acquisition target"
        )

    try:
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    except OSError as exc:
        raise KernelTargetAcquisitionError(
            "acquired descriptor status flags are unavailable"
        ) from exc
    if type(flags) is not int or (flags & os.O_ACCMODE) != os.O_RDONLY:
        raise KernelTargetAcquisitionError(
            "acquired descriptor is not read-only"
        )
    if hasattr(os, "O_PATH") and bool(flags & os.O_PATH):
        raise KernelTargetAcquisitionError(
            "O_PATH descriptors are not physical target references"
        )

    try:
        inheritable = os.get_inheritable(fd)
    except OSError as exc:
        raise KernelTargetAcquisitionError(
            "acquired descriptor inheritance state is unavailable"
        ) from exc
    if inheritable is not False:
        raise KernelTargetAcquisitionError(
            "acquired descriptor must be non-inheritable"
        )
    return observed


def _same_held_target(before: Any, after: Any, observed: str) -> bool:
    return (
        _fresh_decision_is_safe(before)
        and _fresh_decision_is_safe(after)
        and after.handoff_id == before.handoff_id
        and after.target_path == before.target_path
        and before.target_major_minor == observed
        and after.target_major_minor == observed
        and after.fresh_target_binding_hash
        == before.fresh_target_binding_hash
    )


def acquire_held_kernel_target_reference(
    *,
    registry: Any,
    approval_id: Any,
    request: Any,
    record: Any,
    journal: Any,
    gate: Any,
) -> held_ref.HeldKernelTargetReference:
    """Acquire one read-only held target without granting execution authority."""

    arguments = {
        "registry": registry,
        "approval_id": approval_id,
        "request": request,
        "record": record,
        "journal": journal,
        "gate": gate,
    }

    try:
        before = auth.revalidate_physical_target_for_execution_handoff(
            **arguments
        )
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise KernelTargetAcquisitionError(
            "trusted pre-acquisition target revalidation failed"
        ) from exc

    if not _fresh_decision_is_safe(before):
        raise KernelTargetAcquisitionError(
            "trusted pre-acquisition target is not safe and integrity-valid"
        )

    try:
        fd = os.open(before.target_path, _required_open_flags())
    except OSError as exc:
        raise KernelTargetAcquisitionError(
            "read-only physical target acquisition failed"
        ) from exc

    owned_here = True
    try:
        observed = _validate_acquired_descriptor(
            fd,
            before.target_major_minor,
        )
        after = auth.revalidate_physical_target_for_execution_handoff(
            **arguments
        )
        if not _same_held_target(before, after, observed):
            raise KernelTargetAcquisitionError(
                "fresh target identity changed while descriptor was held"
            )

        # B3A takes ownership for this known-valid integer FD immediately.
        # It closes on adoption failure, so this layer must not double-close.
        owned_here = False
        return held_ref.adopt_held_kernel_target_reference(fd, after)

    except BaseException as exc:
        if owned_here:
            owned_here = False
            try:
                os.close(fd)
            except OSError as close_exc:
                raise KernelTargetAcquisitionError(
                    "acquisition failed and the descriptor could not be "
                    "closed safely; the descriptor integer must not be reused"
                ) from close_exc

        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        if isinstance(exc, KernelTargetAcquisitionError):
            raise
        if isinstance(exc, held_ref.HeldKernelTargetReferenceError):
            raise KernelTargetAcquisitionError(
                "held kernel target reference adoption failed"
            ) from exc
        raise KernelTargetAcquisitionError(
            "read-only physical target acquisition failed"
        ) from exc


__all__ = [
    "KERNEL_TARGET_ACQUISITION_POLICY_VERSION",
    "KernelTargetAcquisitionError",
    "acquire_held_kernel_target_reference",
]
