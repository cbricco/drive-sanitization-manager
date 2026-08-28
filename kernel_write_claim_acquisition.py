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
import threading
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
        "_lifecycle_lock",
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
        self._lifecycle_lock = threading.RLock()

    @property
    def closed(self) -> bool:
        with self._lifecycle_lock:
            return self._closed

    @property
    def live(self) -> bool:
        with self._lifecycle_lock:
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
        with self._lifecycle_lock:
            if self._closed:
                return

            fd = self._fd

            # Invalidate first. A reported close failure must never cause
            # this integer to be retried after kernel descriptor reuse.
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



class _LockedWriteClaimValidationScope:
    """Private single-use B3E-F validation scope with a transitive B3A pin."""

    __slots__ = (
        "_claim",
        "_entry_lock",
        "_used",
        "_entered",
        "_b3a_scope",
    )

    def __init__(
        self,
        write_claim: HeldKernelWriteClaim,
    ) -> None:
        if type(write_claim) is not HeldKernelWriteClaim:
            raise KernelWriteClaimAcquisitionError(
                "validation scope requires an exact B3E-F write claim"
            )

        self._claim = write_claim
        self._entry_lock = threading.Lock()
        self._used = False
        self._entered = False
        self._b3a_scope = None

    def _require_entered(self) -> None:
        if self._entered is not True:
            raise KernelWriteClaimAcquisitionError(
                "write-claim validation scope is not active"
            )

    def _state_locked(
        self,
    ) -> tuple[
        held_ref.HeldKernelTargetReference,
        tuple[str, str, str, str],
        str,
        str,
        int,
    ]:
        self._require_entered()

        write_claim = self._claim

        if (
            write_claim._closed is not False
            or type(write_claim._fd) is not int
            or write_claim._fd < 0
        ):
            raise KernelWriteClaimAcquisitionError(
                "write claim is not live inside validation scope"
            )

        held_reference = write_claim._held_reference
        b3a_scope = self._b3a_scope

        if (
            type(held_reference)
            is not held_ref.HeldKernelTargetReference
            or b3a_scope is None
        ):
            raise KernelWriteClaimAcquisitionError(
                "write claim no longer owns the exact pinned B3A reference"
            )

        identity = (
            write_claim._handoff_id,
            write_claim._target_path,
            write_claim._target_major_minor,
            write_claim._target_binding_hash,
        )

        try:
            held_identity = b3a_scope.identity
        except Exception as exc:
            raise KernelWriteClaimAcquisitionError(
                "pinned B3A identity is unavailable"
            ) from exc

        if (
            not all(
                isinstance(value, str) and bool(value)
                for value in identity
            )
            or identity != held_identity
        ):
            raise KernelWriteClaimAcquisitionError(
                "write claim identity differs from its pinned B3A target"
            )

        if (
            not isinstance(write_claim._pre_continuity_id, str)
            or not write_claim._pre_continuity_id
            or not isinstance(write_claim._post_continuity_id, str)
            or not write_claim._post_continuity_id
        ):
            raise KernelWriteClaimAcquisitionError(
                "write-claim continuity identity is malformed"
            )

        return (
            held_reference,
            identity,
            write_claim._pre_continuity_id,
            write_claim._post_continuity_id,
            write_claim._fd,
        )

    def __enter__(
        self,
    ) -> "_LockedWriteClaimValidationScope":
        with self._entry_lock:
            if self._used:
                raise KernelWriteClaimAcquisitionError(
                    "write-claim validation scope is single-use"
                )
            self._used = True

        self._claim._lifecycle_lock.acquire()
        b3a_scope = None
        b3a_entered = False

        try:
            if (
                self._claim._closed is not False
                or type(self._claim._fd) is not int
                or self._claim._fd < 0
            ):
                raise KernelWriteClaimAcquisitionError(
                    "write claim is not live before B3A pin acquisition"
                )

            held_reference = self._claim._held_reference

            if (
                type(held_reference)
                is not held_ref.HeldKernelTargetReference
            ):
                raise KernelWriteClaimAcquisitionError(
                    "write claim no longer owns an exact B3A reference"
                )

            b3a_scope = (
                held_ref
                ._locked_kernel_target_reference_scope(
                    held_reference
                )
            )
            b3a_scope.__enter__()
            b3a_entered = True
            self._b3a_scope = b3a_scope
            self._entered = True
            self._state_locked()
            return self

        except BaseException as exc:
            self._entered = False
            self._b3a_scope = None

            try:
                if b3a_entered and b3a_scope is not None:
                    b3a_scope.__exit__(
                        type(exc),
                        exc,
                        exc.__traceback__,
                    )
            finally:
                self._claim._lifecycle_lock.release()

            raise

    def __exit__(
        self,
        exc_type: Any,
        exc: BaseException | None,
        traceback: Any,
    ) -> bool:
        if self._entered is not True:
            raise KernelWriteClaimAcquisitionError(
                "write-claim validation scope exit without active entry"
            )

        b3a_scope = self._b3a_scope
        self._entered = False
        self._b3a_scope = None

        try:
            if b3a_scope is None:
                raise KernelWriteClaimAcquisitionError(
                    "write-claim validation scope lost its B3A pin"
                )

            b3a_scope.__exit__(
                exc_type,
                exc,
                traceback,
            )
        finally:
            self._claim._lifecycle_lock.release()

        return False

    @property
    def held_reference(
        self,
    ) -> held_ref.HeldKernelTargetReference:
        held_reference, _, _, _, _ = self._state_locked()
        return held_reference

    @property
    def identity(
        self,
    ) -> tuple[str, str, str, str]:
        _, identity, _, _, _ = self._state_locked()
        return identity

    @property
    def claim_pre_continuity_id(self) -> str:
        _, _, value, _, _ = self._state_locked()
        return value

    @property
    def claim_post_continuity_id(self) -> str:
        _, _, _, value, _ = self._state_locked()
        return value

    def revalidate_descriptor(self) -> str:
        (
            held_reference,
            identity,
            pre_continuity_id,
            post_continuity_id,
            fd,
        ) = self._state_locked()

        observed = _validate_acquired_descriptor(
            fd,
            identity[2],
        )

        if observed != identity[2]:
            raise KernelWriteClaimAcquisitionError(
                "locked descriptor identity is inconsistent"
            )

        (
            held_reference_after,
            identity_after,
            pre_after,
            post_after,
            fd_after,
        ) = self._state_locked()

        if (
            held_reference_after is not held_reference
            or identity_after != identity
            or pre_after != pre_continuity_id
            or post_after != post_continuity_id
            or fd_after != fd
        ):
            raise KernelWriteClaimAcquisitionError(
                "write claim changed during locked descriptor validation"
            )

        return observed


def _locked_write_claim_validation_scope(
    write_claim: Any,
) -> _LockedWriteClaimValidationScope:
    """Return the private lifecycle-locked B3F validation scope."""

    return _LockedWriteClaimValidationScope(
        write_claim
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
