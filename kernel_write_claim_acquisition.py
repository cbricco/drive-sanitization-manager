"""Phase 6E-B3E-F production non-executing write-capable acquisition boundary.

This module performs only the final write-capable kernel descriptor acquisition
needed to establish an opaque held claim. It does not read, write, seek, issue
commands, or grant executor authority.

The target path comes only from the exact live Phase 6E-B3A held reference after
fresh trusted Phase 6E-B3D continuity. Acquisition uses fixed
O_RDWR|O_EXCL|O_NOFOLLOW|O_CLOEXEC flags, validates the new descriptor against
the still-held B3A kernel identity, and obtains fresh B3D continuity again while
both handles remain held.

O_EXCL is a kernel coordination signal, not an absolute writer lock. Ordinary
privileged non-exclusive raw writers are not excluded by this contract.
"""

from __future__ import annotations

from datetime import datetime, timezone
import errno
import fcntl
import os
import stat
from typing import Any

import held_target_safety_continuity as continuity
import kernel_target_reference as held_ref


KERNEL_WRITE_CLAIM_ACQUISITION_POLICY_VERSION = (
    "phase6e-b3e-f-kernel-write-claim-acquisition-v1"
)


class KernelWriteClaimAcquisitionError(RuntimeError):
    """A production non-executing write-capable claim could not be established."""


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


def _required_open_flags() -> int:
    missing = [
        name
        for name in (
            "O_EXCL",
            "O_NOFOLLOW",
            "O_CLOEXEC",
        )
        if not hasattr(os, name)
    ]

    if missing:
        raise KernelWriteClaimAcquisitionError(
            "required production acquisition flags are unavailable: "
            + ", ".join(missing)
        )

    return (
        os.O_RDWR
        | os.O_EXCL
        | os.O_NOFOLLOW
        | os.O_CLOEXEC
    )


def _held_identity(
    reference: Any,
) -> tuple[str, str, str, str]:
    try:
        if (
            type(reference)
            is not held_ref.HeldKernelTargetReference
        ):
            raise KernelWriteClaimAcquisitionError(
                "held_reference must be an exact B3A held target reference"
            )

        if reference.closed is not False:
            raise KernelWriteClaimAcquisitionError(
                "held target reference must still be open"
            )

        identity = (
            reference.handoff_id,
            reference.target_path,
            reference.target_major_minor,
            reference.target_binding_hash,
        )

        if not all(
            isinstance(value, str) and bool(value)
            for value in identity
        ):
            raise KernelWriteClaimAcquisitionError(
                "held target reference identity is malformed"
            )

        return identity

    except KernelWriteClaimAcquisitionError:
        raise

    except Exception as exc:
        raise KernelWriteClaimAcquisitionError(
            "held target reference could not be inspected safely"
        ) from exc


def _continuity_identity(
    decision: Any,
) -> tuple[str, str, str, str]:
    try:
        if (
            type(decision)
            is not continuity.HeldTargetSafetyContinuityDecision
        ):
            raise KernelWriteClaimAcquisitionError(
                "trusted continuity result has the wrong type"
            )

        if (
            continuity
            ._held_target_safety_continuity_integrity_valid(
                decision
            )
            is not True
        ):
            raise KernelWriteClaimAcquisitionError(
                "trusted continuity result failed B3D-B integrity"
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
            raise KernelWriteClaimAcquisitionError(
                "trusted continuity freshness metadata is invalid"
            )

        now = now.astimezone(timezone.utc)

        if not (
            evaluated_at
            <= now
            <= valid_until
        ):
            raise KernelWriteClaimAcquisitionError(
                "trusted continuity result is not current"
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
            raise KernelWriteClaimAcquisitionError(
                "trusted continuity result is not non-authorizing"
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
            raise KernelWriteClaimAcquisitionError(
                "trusted continuity identity is malformed"
            )

        return identity

    except KernelWriteClaimAcquisitionError:
        raise

    except Exception as exc:
        raise KernelWriteClaimAcquisitionError(
            "trusted continuity result could not be inspected safely"
        ) from exc


def _trusted_continuity(
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

        raise KernelWriteClaimAcquisitionError(
            "trusted held-target safety continuity failed"
        ) from exc

    if held_reference.closed is not False:
        raise KernelWriteClaimAcquisitionError(
            "held target reference closed during safety continuity"
        )

    identity = _continuity_identity(
        decision
    )

    if held_reference.closed is not False:
        raise KernelWriteClaimAcquisitionError(
            "held target reference closed after safety continuity"
        )

    return decision, identity


def _descriptor_major_minor(
    info: Any,
) -> str:
    try:
        mode = info.st_mode
        represented_device = info.st_rdev
    except AttributeError as exc:
        raise KernelWriteClaimAcquisitionError(
            "acquired descriptor stat metadata is incomplete"
        ) from exc

    if not stat.S_ISBLK(mode):
        raise KernelWriteClaimAcquisitionError(
            "acquired descriptor is not a block-special device"
        )

    try:
        major = os.major(
            represented_device
        )
        minor = os.minor(
            represented_device
        )
    except (TypeError, ValueError, OSError) as exc:
        raise KernelWriteClaimAcquisitionError(
            "acquired descriptor kernel device number is invalid"
        ) from exc

    return f"{major}:{minor}"


def _validate_acquired_descriptor(
    fd: int,
    expected_major_minor: str,
) -> str:
    try:
        info = os.fstat(fd)
    except OSError as exc:
        raise KernelWriteClaimAcquisitionError(
            "acquired descriptor could not be inspected"
        ) from exc

    observed = _descriptor_major_minor(
        info
    )

    if observed != expected_major_minor:
        raise KernelWriteClaimAcquisitionError(
            "acquired descriptor kernel device number differs "
            "from the still-held B3A target"
        )

    try:
        flags = fcntl.fcntl(
            fd,
            fcntl.F_GETFL,
        )
    except OSError as exc:
        raise KernelWriteClaimAcquisitionError(
            "acquired descriptor status flags are unavailable"
        ) from exc

    if (
        type(flags) is not int
        or (
            flags & os.O_ACCMODE
        )
        != os.O_RDWR
    ):
        raise KernelWriteClaimAcquisitionError(
            "acquired descriptor is not read-write"
        )

    if (
        hasattr(os, "O_PATH")
        and bool(flags & os.O_PATH)
    ):
        raise KernelWriteClaimAcquisitionError(
            "O_PATH descriptors are not write-capable target claims"
        )

    try:
        inheritable = os.get_inheritable(
            fd
        )
    except OSError as exc:
        raise KernelWriteClaimAcquisitionError(
            "acquired descriptor inheritance state is unavailable"
        ) from exc

    if inheritable is not False:
        raise KernelWriteClaimAcquisitionError(
            "acquired descriptor must be non-inheritable"
        )

    return observed


class HeldKernelWriteClaim:
    """Own one validated write-capable kernel claim without executor authority."""

    __slots__ = (
        "_fd",
        "_closed",
        "_held_reference",
        "_handoff_id",
        "_target_path",
        "_target_major_minor",
        "_target_binding_hash",
        "_pre_continuity_id",
        "_post_continuity_id",
    )

    def __init__(
        self,
        token: object,
        *,
        fd: int,
        held_reference: held_ref.HeldKernelTargetReference,
        identity: tuple[str, str, str, str],
        pre_continuity_id: str,
        post_continuity_id: str,
    ) -> None:
        if token is not _CONSTRUCTION_TOKEN:
            raise TypeError(
                "HeldKernelWriteClaim must be created by "
                "acquire_kernel_write_claim()"
            )

        (
            self._handoff_id,
            self._target_path,
            self._target_major_minor,
            self._target_binding_hash,
        ) = identity

        self._fd = fd
        self._closed = False
        self._held_reference = held_reference
        self._pre_continuity_id = pre_continuity_id
        self._post_continuity_id = post_continuity_id

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def live(self) -> bool:
        if self._closed:
            return False

        try:
            return self._held_reference.closed is False
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
    def pre_continuity_id(self) -> str:
        return self._pre_continuity_id

    @property
    def post_continuity_id(self) -> str:
        return self._post_continuity_id

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
    def requires_separate_executor_authorization(self) -> bool:
        return True

    def close(self) -> None:
        if self._closed:
            return

        fd = self._fd

        # Invalidate first. A reported close failure must never cause this
        # integer to be retried after the kernel could have recycled it.
        self._fd = -1
        self._closed = True

        try:
            os.close(fd)
        except OSError as exc:
            raise KernelWriteClaimAcquisitionError(
                "write-claim descriptor close failed; "
                "the claim must not be reused"
            ) from exc

    def __enter__(self) -> "HeldKernelWriteClaim":
        if not self.live:
            raise KernelWriteClaimAcquisitionError(
                "write-claim is not live"
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
        except KernelWriteClaimAcquisitionError as close_exc:
            if exc is None:
                raise

            if hasattr(exc, "add_note"):
                exc.add_note(
                    "write-claim close also failed: "
                    + str(close_exc)
                )

        return False

    def __copy__(self) -> Any:
        raise KernelWriteClaimAcquisitionError(
            "write claims cannot be copied"
        )

    def __deepcopy__(
        self,
        memo: Any,
    ) -> Any:
        raise KernelWriteClaimAcquisitionError(
            "write claims cannot be deep-copied"
        )

    def __reduce__(self) -> Any:
        raise KernelWriteClaimAcquisitionError(
            "write claims cannot be serialized"
        )

    def __reduce_ex__(
        self,
        protocol: int,
    ) -> Any:
        raise KernelWriteClaimAcquisitionError(
            "write claims cannot be serialized"
        )


def acquire_kernel_write_claim(
    *,
    held_reference: Any,
    registry: Any,
    approval_id: Any,
    request: Any,
    record: Any,
    journal: Any,
    gate: Any,
) -> HeldKernelWriteClaim:
    """Acquire one opaque non-executing write-capable kernel claim."""

    held_identity = _held_identity(
        held_reference
    )

    arguments = {
        "registry": registry,
        "approval_id": approval_id,
        "request": request,
        "record": record,
        "journal": journal,
        "gate": gate,
    }

    (
        pre,
        pre_identity,
    ) = _trusted_continuity(
        held_reference=held_reference,
        arguments=arguments,
    )

    if pre_identity != held_identity:
        raise KernelWriteClaimAcquisitionError(
            "pre-acquisition safety continuity differs "
            "from the held B3A target"
        )

    if _held_identity(
        held_reference
    ) != held_identity:
        raise KernelWriteClaimAcquisitionError(
            "held B3A target changed before write-capable acquisition"
        )

    flags = _required_open_flags()

    try:
        fd = os.open(
            pre.target_path,
            flags,
        )

    except BaseException as exc:
        if isinstance(
            exc,
            (KeyboardInterrupt, SystemExit),
        ):
            raise

        if (
            isinstance(exc, OSError)
            and exc.errno == errno.EBUSY
        ):
            raise KernelWriteClaimAcquisitionError(
                "kernel exclusive claim was refused as busy"
            ) from exc

        raise KernelWriteClaimAcquisitionError(
            "production write-capable acquisition failed"
        ) from exc

    if type(fd) is not int or fd < 0:
        raise KernelWriteClaimAcquisitionError(
            "production acquisition did not return "
            "a non-negative exact integer descriptor"
        )

    owned_here = True

    try:
        observed = _validate_acquired_descriptor(
            fd,
            held_identity[2],
        )

        if observed != held_identity[2]:
            raise KernelWriteClaimAcquisitionError(
                "acquired descriptor identity is inconsistent"
            )

        if _held_identity(
            held_reference
        ) != held_identity:
            raise KernelWriteClaimAcquisitionError(
                "held B3A target changed while the write-capable descriptor was held"
            )

        (
            post,
            post_identity,
        ) = _trusted_continuity(
            held_reference=held_reference,
            arguments=arguments,
        )

        if (
            post_identity != held_identity
            or post_identity != pre_identity
        ):
            raise KernelWriteClaimAcquisitionError(
                "post-acquisition safety continuity differs "
                "from the held target"
            )

        if _held_identity(
            held_reference
        ) != held_identity:
            raise KernelWriteClaimAcquisitionError(
                "held B3A target changed before claim construction"
            )

        claim = HeldKernelWriteClaim(
            _CONSTRUCTION_TOKEN,
            fd=fd,
            held_reference=held_reference,
            identity=held_identity,
            pre_continuity_id=pre.continuity_id,
            post_continuity_id=post.continuity_id,
        )

        owned_here = False
        return claim

    except BaseException as exc:
        if owned_here:
            owned_here = False

            try:
                os.close(fd)
            except OSError as close_exc:
                raise KernelWriteClaimAcquisitionError(
                    "claim establishment failed and the owned descriptor "
                    "could not be closed safely; "
                    "the descriptor integer must not be reused"
                ) from close_exc

        if isinstance(
            exc,
            (KeyboardInterrupt, SystemExit),
        ):
            raise

        if isinstance(
            exc,
            KernelWriteClaimAcquisitionError,
        ):
            raise

        raise KernelWriteClaimAcquisitionError(
            "production write-capable claim acquisition failed"
        ) from exc


__all__ = [
    "KERNEL_WRITE_CLAIM_ACQUISITION_POLICY_VERSION",
    "HeldKernelWriteClaim",
    "KernelWriteClaimAcquisitionError",
    "acquire_kernel_write_claim",
]
