"""Phase 6E-B3D-A non-authorizing held-target safety continuity.

This module never opens or closes a block device and never exposes a raw file
descriptor. It requires one already-open Phase 6E-B3A held target reference,
reruns the existing trusted Phase 6E-A fresh physical-target revalidation, and
returns an immutable short-lived continuity decision only when the newly
observed safe target still exactly matches the held reference.

A satisfied continuity decision is not executor authorization and does not
grant or perform destructive execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Any

import kernel_target_reference as held_ref
import sanitization_authorization as auth


HELD_TARGET_SAFETY_CONTINUITY_POLICY_VERSION = (
    "phase6e-b3d-a-held-safety-continuity-v1"
)
HELD_TARGET_SAFETY_CONTINUITY_SCHEMA_VERSION = 1
HELD_TARGET_SAFETY_CONTINUITY_STATUS_SATISFIED = (
    "held_target_safety_continuity_satisfied"
)


class HeldTargetSafetyContinuityError(RuntimeError):
    """Fresh held-target safety continuity could not be established."""


@dataclass(frozen=True)
class HeldTargetSafetyContinuityDecision:
    """Immutable, short-lived, non-authorizing held-target safety result."""

    continuity_id: str
    policy_version: str
    schema_version: int
    status: str

    handoff_id: str
    revalidation_id: str
    target_path: str
    target_major_minor: str
    target_binding_hash: str

    evaluated_at_utc: str
    valid_until_utc: str

    execution_supported: bool
    executor_eligible: bool
    requires_separate_executor_authorization: bool


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


def _iso_utc(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _prefixed_hex_id(
    value: Any,
    prefix: str,
) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(prefix)
        and len(value) == len(prefix) + 64
        and all(
            character in "0123456789abcdef"
            for character in value[len(prefix):]
        )
    )


def _exact_text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and not any(
            ord(character) < 32
            or ord(character) == 127
            for character in value
        )
    )


def _canonical_major_minor(value: Any) -> bool:
    if not isinstance(value, str):
        return False

    parts = value.split(":")
    return (
        len(parts) == 2
        and all(
            part
            and all(
                "0" <= character <= "9"
                for character in part
            )
            and (
                len(part) == 1
                or not part.startswith("0")
            )
            for part in parts
        )
    )


def _canonical_sha256(value: Any) -> bool:
    if (
        not isinstance(value, str)
        or not value.startswith("sha256:")
    ):
        return False

    digest = value.split(":", 1)[1]

    return (
        len(digest) == 64
        and all(
            character in "0123456789abcdef"
            for character in digest
        )
    )


def _held_identity(
    reference: Any,
) -> tuple[str, str, str, str]:
    try:
        if (
            type(reference)
            is not held_ref.HeldKernelTargetReference
        ):
            raise HeldTargetSafetyContinuityError(
                "held_reference must be an exact B3A held target reference"
            )

        if reference.closed is not False:
            raise HeldTargetSafetyContinuityError(
                "held target reference must still be open"
            )

        handoff_id = reference.handoff_id
        target_path = reference.target_path
        target_major_minor = (
            reference.target_major_minor
        )
        target_binding_hash = (
            reference.target_binding_hash
        )

        if (
            not _exact_text(handoff_id)
            or not _exact_text(target_path)
            or not _canonical_major_minor(
                target_major_minor
            )
            or not _canonical_sha256(
                target_binding_hash
            )
        ):
            raise HeldTargetSafetyContinuityError(
                "held target reference identity is malformed"
            )

        return (
            handoff_id,
            target_path,
            target_major_minor,
            target_binding_hash,
        )

    except HeldTargetSafetyContinuityError:
        raise

    except Exception as exc:
        raise HeldTargetSafetyContinuityError(
            "held target reference could not be inspected safely"
        ) from exc


def _fresh_decision_is_current_and_safe(
    decision: Any,
) -> bool:
    try:
        if (
            type(decision)
            is not auth.FreshPhysicalTargetRevalidationDecision
        ):
            return False

        integrity_valid = (
            auth._fresh_physical_target_revalidation_integrity_valid(
                decision
            )
        )

        if integrity_valid is not True:
            return False

        if (
            decision.status
            != auth.FRESH_TARGET_REVALIDATION_STATUS_SATISFIED
            or decision.execution_supported is not False
            or decision.executor_eligible is not False
            or (
                decision
                .requires_separate_executor_authorization
                is not True
            )
        ):
            return False

        safety_flags = (
            decision.target_read_only,
            decision.target_mounted,
            decision.target_protected,
            decision.target_system_protected,
            decision.target_review_required,
            decision.target_ambiguous,
        )

        if any(
            type(value) is not bool
            for value in safety_flags
        ):
            return False

        if any(safety_flags):
            return False

        if (
            not _exact_text(decision.handoff_id)
            or not _exact_text(
                decision.revalidation_id
            )
            or not _exact_text(
                decision.target_path
            )
            or not _canonical_major_minor(
                decision.target_major_minor
            )
            or not _canonical_sha256(
                decision.fresh_target_binding_hash
            )
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

    except Exception:
        return False


def _continuity_payload(
    *,
    handoff_id: str,
    revalidation_id: str,
    target_path: str,
    target_major_minor: str,
    target_binding_hash: str,
    evaluated_at_utc: str,
    valid_until_utc: str,
) -> dict[str, Any]:
    return {
        "policy_version":
            HELD_TARGET_SAFETY_CONTINUITY_POLICY_VERSION,
        "schema_version":
            HELD_TARGET_SAFETY_CONTINUITY_SCHEMA_VERSION,
        "status":
            HELD_TARGET_SAFETY_CONTINUITY_STATUS_SATISFIED,
        "handoff_id": handoff_id,
        "revalidation_id": revalidation_id,
        "target_path": target_path,
        "target_major_minor": target_major_minor,
        "target_binding_hash": target_binding_hash,
        "evaluated_at_utc": evaluated_at_utc,
        "valid_until_utc": valid_until_utc,
        "execution_supported": False,
        "executor_eligible": False,
        "requires_separate_executor_authorization":
            True,
    }


def _continuity_id(
    payload: dict[str, Any],
) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return (
        "hsc_"
        + hashlib.sha256(encoded).hexdigest()
    )


def _held_target_safety_continuity_integrity_valid(
    decision: Any,
) -> bool:
    """Check deterministic continuity-object internal consistency only.

    This is not a signature, not a provenance proof, and not executor
    authorization. A caller able to construct arbitrary objects can also
    recompute an unkeyed deterministic hash. Future authority consumers
    must obtain continuity through a separately trusted path.
    """

    try:
        if (
            type(decision)
            is not HeldTargetSafetyContinuityDecision
        ):
            return False

        if (
            decision.policy_version
            != HELD_TARGET_SAFETY_CONTINUITY_POLICY_VERSION
            or type(decision.schema_version)
            is not int
            or decision.schema_version
            != HELD_TARGET_SAFETY_CONTINUITY_SCHEMA_VERSION
            or decision.status
            != HELD_TARGET_SAFETY_CONTINUITY_STATUS_SATISFIED
        ):
            return False

        if not _prefixed_hex_id(
            decision.continuity_id,
            "hsc_",
        ):
            return False

        if not _prefixed_hex_id(
            decision.handoff_id,
            "xhnd_",
        ):
            return False

        if not _prefixed_hex_id(
            decision.revalidation_id,
            "ptrv_",
        ):
            return False

        if (
            not _exact_text(
                decision.target_path
            )
            or not _canonical_major_minor(
                decision.target_major_minor
            )
            or not _canonical_sha256(
                decision.target_binding_hash
            )
        ):
            return False

        if (
            type(decision.execution_supported)
            is not bool
            or decision.execution_supported
            is not False
            or type(decision.executor_eligible)
            is not bool
            or decision.executor_eligible
            is not False
            or type(
                decision
                .requires_separate_executor_authorization
            )
            is not bool
            or (
                decision
                .requires_separate_executor_authorization
                is not True
            )
        ):
            return False

        evaluated_at = _parse_utc(
            decision.evaluated_at_utc
        )
        valid_until = _parse_utc(
            decision.valid_until_utc
        )

        if (
            evaluated_at is None
            or valid_until is None
        ):
            return False

        if (
            _iso_utc(evaluated_at)
            != decision.evaluated_at_utc
            or _iso_utc(valid_until)
            != decision.valid_until_utc
        ):
            return False

        lifetime_seconds = getattr(
            auth,
            "PREREQUISITE_LIFETIME_SECONDS",
            None,
        )

        if (
            type(lifetime_seconds)
            is not int
            or lifetime_seconds <= 0
        ):
            return False

        if (
            evaluated_at > valid_until
            or valid_until
            != evaluated_at
            + timedelta(
                seconds=lifetime_seconds
            )
        ):
            return False

        payload = _continuity_payload(
            handoff_id=decision.handoff_id,
            revalidation_id=(
                decision.revalidation_id
            ),
            target_path=decision.target_path,
            target_major_minor=(
                decision.target_major_minor
            ),
            target_binding_hash=(
                decision.target_binding_hash
            ),
            evaluated_at_utc=(
                decision.evaluated_at_utc
            ),
            valid_until_utc=(
                decision.valid_until_utc
            ),
        )

        return (
            decision.continuity_id
            == _continuity_id(payload)
        )

    except Exception:
        return False


def revalidate_held_target_safety_continuity(
    *,
    held_reference: Any,
    registry: Any,
    approval_id: Any,
    request: Any,
    record: Any,
    journal: Any,
    gate: Any,
) -> HeldTargetSafetyContinuityDecision:
    """Recheck fresh host safety while the exact B3A target remains held."""

    (
        held_handoff_id,
        held_target_path,
        held_target_major_minor,
        held_target_binding_hash,
    ) = _held_identity(
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

    try:
        fresh = (
            auth
            .revalidate_physical_target_for_execution_handoff(
                **arguments
            )
        )

    except BaseException as exc:
        if isinstance(
            exc,
            (KeyboardInterrupt, SystemExit),
        ):
            raise

        raise HeldTargetSafetyContinuityError(
            "fresh held-target safety revalidation failed"
        ) from exc

    if held_reference.closed is not False:
        raise HeldTargetSafetyContinuityError(
            "held target reference closed during safety revalidation"
        )

    if not _fresh_decision_is_current_and_safe(
        fresh
    ):
        raise HeldTargetSafetyContinuityError(
            "fresh target safety decision is not current, safe, and integrity-valid"
        )

    if (
        fresh.handoff_id
        != held_handoff_id
        or fresh.target_path
        != held_target_path
        or fresh.target_major_minor
        != held_target_major_minor
        or fresh.fresh_target_binding_hash
        != held_target_binding_hash
    ):
        raise HeldTargetSafetyContinuityError(
            "fresh target identity differs from the held target reference"
        )

    payload = _continuity_payload(
        handoff_id=held_handoff_id,
        revalidation_id=fresh.revalidation_id,
        target_path=held_target_path,
        target_major_minor=(
            held_target_major_minor
        ),
        target_binding_hash=(
            held_target_binding_hash
        ),
        evaluated_at_utc=(
            fresh.evaluated_at_utc
        ),
        valid_until_utc=(
            fresh.valid_until_utc
        ),
    )

    if held_reference.closed is not False:
        raise HeldTargetSafetyContinuityError(
            "held target reference closed before continuity decision"
        )

    decision = HeldTargetSafetyContinuityDecision(
        continuity_id=_continuity_id(
            payload
        ),
        policy_version=payload[
            "policy_version"
        ],
        schema_version=payload[
            "schema_version"
        ],
        status=payload["status"],
        handoff_id=payload[
            "handoff_id"
        ],
        revalidation_id=payload[
            "revalidation_id"
        ],
        target_path=payload[
            "target_path"
        ],
        target_major_minor=payload[
            "target_major_minor"
        ],
        target_binding_hash=payload[
            "target_binding_hash"
        ],
        evaluated_at_utc=payload[
            "evaluated_at_utc"
        ],
        valid_until_utc=payload[
            "valid_until_utc"
        ],
        execution_supported=False,
        executor_eligible=False,
        requires_separate_executor_authorization=True,
    )

    if not (
        _held_target_safety_continuity_integrity_valid(
            decision
        )
    ):
        raise HeldTargetSafetyContinuityError(
            "constructed held-target safety continuity decision failed integrity validation"
        )

    return decision


__all__ = [
    "HELD_TARGET_SAFETY_CONTINUITY_POLICY_VERSION",
    "HELD_TARGET_SAFETY_CONTINUITY_SCHEMA_VERSION",
    "HELD_TARGET_SAFETY_CONTINUITY_STATUS_SATISFIED",
    "HeldTargetSafetyContinuityDecision",
    "HeldTargetSafetyContinuityError",
    "revalidate_held_target_safety_continuity",
]
