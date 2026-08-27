"""Phase 6E-B3E-D mocked write-capable exclusive-acquisition candidate.

This module models the final execution-adjacent acquisition seam without
providing a real production block-device opener or any executor capability.
It requires the exact live Phase 6E-B3A held target reference, directly obtains
trusted B3D-A continuity before and after the modeled acquisition, validates
B3D-B internal integrity and freshness, and verifies that a synthetic acquired
descriptor is the same block device while both handles remain held.

The default acquisition seam always fails closed. Tests may replace that private
seam with a synthetic descriptor. A successful candidate therefore represents
only the contract proven by this mocked boundary. It does not authorize
execution, expose a descriptor, or claim absolute exclusion of ordinary raw
writers.
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


KERNEL_WRITE_CLAIM_CANDIDATE_POLICY_VERSION = (
    "phase6e-b3e-d-mocked-write-claim-candidate-v1"
)


class KernelWriteClaimCandidateError(RuntimeError):
    """The mocked write-capable claim candidate could not be established."""


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
        raise KernelWriteClaimCandidateError(
            "required modeled acquisition flags are unavailable: "
            + ", ".join(missing)
        )

    return (
        os.O_RDWR
        | os.O_EXCL
        | os.O_NOFOLLOW
        | os.O_CLOEXEC
    )


def _acquire_mocked_write_descriptor(
    target_path: str,
    flags: int,
) -> int:
    """Private test seam; production behavior is deliberately fail-closed."""

    raise KernelWriteClaimCandidateError(
        "mocked write-capable acquisition has no production opener"
    )


def _held_identity(
    reference: Any,
) -> tuple[str, str, str, str]:
    try:
        if (
            type(reference)
            is not held_ref.HeldKernelTargetReference
        ):
            raise KernelWriteClaimCandidateError(
                "held_reference must be an exact B3A held target reference"
            )

        if reference.closed is not False:
            raise KernelWriteClaimCandidateError(
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
            raise KernelWriteClaimCandidateError(
                "held target reference identity is malformed"
            )

        return identity

    except KernelWriteClaimCandidateError:
        raise

    except Exception as exc:
        raise KernelWriteClaimCandidateError(
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
            raise KernelWriteClaimCandidateError(
                "trusted continuity result has the wrong type"
            )

        if (
            continuity
            ._held_target_safety_continuity_integrity_valid(
                decision
            )
            is not True
        ):
            raise KernelWriteClaimCandidateError(
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
            raise KernelWriteClaimCandidateError(
                "trusted continuity freshness metadata is invalid"
            )

        now = now.astimezone(timezone.utc)

        if not (
            evaluated_at
            <= now
            <= valid_until
        ):
            raise KernelWriteClaimCandidateError(
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
            raise KernelWriteClaimCandidateError(
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
            raise KernelWriteClaimCandidateError(
                "trusted continuity identity is malformed"
            )

        return identity

    except KernelWriteClaimCandidateError:
        raise

    except Exception as exc:
        raise KernelWriteClaimCandidateError(
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

        raise KernelWriteClaimCandidateError(
            "trusted held-target safety continuity failed"
        ) from exc

    if held_reference.closed is not False:
        raise KernelWriteClaimCandidateError(
            "held target reference closed during safety continuity"
        )

    identity = _continuity_identity(
        decision
    )

    if held_reference.closed is not False:
        raise KernelWriteClaimCandidateError(
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
        raise KernelWriteClaimCandidateError(
            "acquired descriptor stat metadata is incomplete"
        ) from exc

    if not stat.S_ISBLK(mode):
        raise KernelWriteClaimCandidateError(
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
        raise KernelWriteClaimCandidateError(
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
        raise KernelWriteClaimCandidateError(
            "acquired descriptor could not be inspected"
        ) from exc

    observed = _descriptor_major_minor(
        info
    )

    if observed != expected_major_minor:
        raise KernelWriteClaimCandidateError(
            "acquired descriptor kernel device number differs "
            "from the still-held B3A target"
        )

    try:
        flags = fcntl.fcntl(
            fd,
            fcntl.F_GETFL,
        )
    except OSError as exc:
        raise KernelWriteClaimCandidateError(
            "acquired descriptor status flags are unavailable"
        ) from exc

    if (
        type(flags) is not int
        or (
            flags & os.O_ACCMODE
        )
        != os.O_RDWR
    ):
        raise KernelWriteClaimCandidateError(
            "acquired descriptor is not read-write"
        )

    if (
        hasattr(os, "O_PATH")
        and bool(flags & os.O_PATH)
    ):
        raise KernelWriteClaimCandidateError(
            "O_PATH descriptors are not write-capable target claims"
        )

    try:
        inheritable = os.get_inheritable(
            fd
        )
    except OSError as exc:
        raise KernelWriteClaimCandidateError(
            "acquired descriptor inheritance state is unavailable"
        ) from exc

    if inheritable is not False:
        raise KernelWriteClaimCandidateError(
            "acquired descriptor must be non-inheritable"
        )

    return observed


class HeldKernelWriteClaimCandidate:
    """Own one validated synthetic write-capable claim without executor use."""

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
                "HeldKernelWriteClaimCandidate must be created by "
                "acquire_mocked_kernel_write_claim_candidate()"
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
        self._pre_continuity_id = (
            pre_continuity_id
        )
        self._post_continuity_id = (
            post_continuity_id
        )

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def live(self) -> bool:
        if self._closed:
            return False

        try:
            return (
                self._held_reference.closed
                is False
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
    def pre_continuity_id(self) -> str:
        return self._pre_continuity_id

    @property
    def post_continuity_id(self) -> str:
        return self._post_continuity_id

    @property
    def kernel_exclusive_claim_acquired(
        self,
    ) -> bool:
        return True

    @property
    def absolute_write_exclusion_guaranteed(
        self,
    ) -> bool:
        return False

    @property
    def ordinary_raw_writers_excluded(
        self,
    ) -> bool:
        return False

    @property
    def execution_supported(self) -> bool:
        return False

    @property
    def executor_eligible(self) -> bool:
        return False

    @property
    def requires_separate_executor_authorization(
        self,
    ) -> bool:
        return True

    def close(self) -> None:
        if self._closed:
            return

        fd = self._fd

        # Invalidate first. Retrying an integer after a reported close failure
        # could act on a kernel-recycled descriptor.
        self._fd = -1
        self._closed = True

        try:
            os.close(fd)
        except OSError as exc:
            raise KernelWriteClaimCandidateError(
                "write-claim descriptor close failed; "
                "the candidate must not be reused"
            ) from exc

    def __enter__(
        self,
    ) -> "HeldKernelWriteClaimCandidate":
        if not self.live:
            raise KernelWriteClaimCandidateError(
                "write-claim candidate is not live"
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
        except KernelWriteClaimCandidateError as close_exc:
            if exc is None:
                raise

            if hasattr(exc, "add_note"):
                exc.add_note(
                    "write-claim candidate close also failed: "
                    + str(close_exc)
                )

        return False

    def __copy__(self) -> Any:
        raise KernelWriteClaimCandidateError(
            "write-claim candidates cannot be copied"
        )

    def __deepcopy__(
        self,
        memo: Any,
    ) -> Any:
        raise KernelWriteClaimCandidateError(
            "write-claim candidates cannot be deep-copied"
        )

    def __reduce__(self) -> Any:
        raise KernelWriteClaimCandidateError(
            "write-claim candidates cannot be serialized"
        )

    def __reduce_ex__(
        self,
        protocol: int,
    ) -> Any:
        raise KernelWriteClaimCandidateError(
            "write-claim candidates cannot be serialized"
        )


def acquire_mocked_kernel_write_claim_candidate(
    *,
    held_reference: Any,
    registry: Any,
    approval_id: Any,
    request: Any,
    record: Any,
    journal: Any,
    gate: Any,
) -> HeldKernelWriteClaimCandidate:
    """Model a write-capable exclusive claim without granting execution."""

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
        raise KernelWriteClaimCandidateError(
            "pre-acquisition safety continuity differs "
            "from the held B3A target"
        )

    if _held_identity(
        held_reference
    ) != held_identity:
        raise KernelWriteClaimCandidateError(
            "held B3A target changed before modeled acquisition"
        )

    flags = _required_open_flags()

    try:
        fd = _acquire_mocked_write_descriptor(
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
            raise KernelWriteClaimCandidateError(
                "kernel exclusive claim was refused as busy"
            ) from exc

        if isinstance(
            exc,
            KernelWriteClaimCandidateError,
        ):
            raise

        raise KernelWriteClaimCandidateError(
            "mocked write-capable exclusive acquisition failed"
        ) from exc

    if type(fd) is not int or fd < 0:
        raise KernelWriteClaimCandidateError(
            "mocked acquisition did not return "
            "a non-negative exact integer descriptor"
        )

    owned_here = True

    try:
        observed = _validate_acquired_descriptor(
            fd,
            held_identity[2],
        )

        if observed != held_identity[2]:
            raise KernelWriteClaimCandidateError(
                "acquired descriptor identity is inconsistent"
            )

        if _held_identity(
            held_reference
        ) != held_identity:
            raise KernelWriteClaimCandidateError(
                "held B3A target changed while the new descriptor was held"
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
            raise KernelWriteClaimCandidateError(
                "post-acquisition safety continuity differs "
                "from the held target"
            )

        if _held_identity(
            held_reference
        ) != held_identity:
            raise KernelWriteClaimCandidateError(
                "held B3A target changed before candidate construction"
            )

        owned_here = False

        return HeldKernelWriteClaimCandidate(
            _CONSTRUCTION_TOKEN,
            fd=fd,
            held_reference=held_reference,
            identity=held_identity,
            pre_continuity_id=(
                pre.continuity_id
            ),
            post_continuity_id=(
                post.continuity_id
            ),
        )

    except BaseException as exc:
        if owned_here:
            owned_here = False

            try:
                os.close(fd)
            except OSError as close_exc:
                raise KernelWriteClaimCandidateError(
                    "candidate establishment failed and the owned descriptor "
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
            KernelWriteClaimCandidateError,
        ):
            raise

        raise KernelWriteClaimCandidateError(
            "mocked write-capable claim candidate failed"
        ) from exc


__all__ = [
    "KERNEL_WRITE_CLAIM_CANDIDATE_POLICY_VERSION",
    "HeldKernelWriteClaimCandidate",
    "KernelWriteClaimCandidateError",
    "acquire_mocked_kernel_write_claim_candidate",
]
