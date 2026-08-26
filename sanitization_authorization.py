"""Fail-closed Phase 5 sanitization prerequisite evaluation.

The public positive path obtains current evidence through the fixed Phase 4
collector and timestamps that collection internally.

A positive result means only that deterministic prerequisites were met for one
exact request and one exact observed target.  It is not human approval and it
does not grant or perform destructive execution.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any, Optional

from drive_discovery import (
    DiscoveryError,
    PhysicalDrive,
    parse_lsblk_json,
)
from drive_discovery_adapter import (
    DiscoveryCollectionError,
    DiscoverySnapshot,
    collect_current_drive_discovery,
)
from drive_sanitization_manager import (
    DriveRecord,
    RecordError,
)


POLICY_VERSION = "phase5-auth-v4"
SCHEMA_VERSION = 1

EVIDENCE_ORIGIN = "phase4-current-collector-v1"

MAX_DISCOVERY_AGE_SECONDS = 60
MAX_FUTURE_SKEW_SECONDS = 5
MAX_REQUEST_AGE_SECONDS = 300
PREREQUISITE_LIFETIME_SECONDS = 300
APPROVAL_POLICY_VERSION = "phase6a2-approval-v1"
APPROVAL_CHALLENGE_LIFETIME_SECONDS = 180
APPROVAL_REVALIDATION_WINDOW_SECONDS = 30

APPROVAL_STATUS_REVALIDATED = "approval_revalidated"
APPROVAL_STATUS_REVALIDATION_FAILED = "approval_revalidation_failed"

STATUS_PREREQUISITES_MET = "prerequisites_met"
STATUS_REFUSED = "refused"
STATUS_REVIEW_REQUIRED = "review_required"
STATUS_EVALUATION_FAILED = "evaluation_failed"

SUPPORTED_OPERATIONS = frozenset({"sanitize"})

@dataclass(frozen=True)
class SanitizationMethodPolicy:
    """Static sanitization method metadata.

    This model carries policy metadata only.  It contains no command,
    executable, callback, device handle, or execution authority.
    """

    method_profile_id: str
    operation: str
    policy_only: bool
    execution_supported: bool


# Private deterministic registry.  The tuple and its frozen records contain
# policy metadata only; they do not contain execution implementations.
_SANITIZATION_METHOD_POLICIES = (
    SanitizationMethodPolicy(
        method_profile_id="phase5-policy-only",
        operation="sanitize",
        policy_only=True,
        execution_supported=False,
    ),
)


# Compatibility view retained for existing Phase 5 policy checks/tests.
# The authoritative Phase 6B lookup is get_sanitization_method_policy().
NON_EXECUTABLE_METHOD_PROFILES = frozenset(
    policy.method_profile_id
    for policy in _SANITIZATION_METHOD_POLICIES
    if (
        policy.policy_only
        and not policy.execution_supported
    )
)


def get_sanitization_method_policy(
    method_profile_id: Any,
) -> Optional[SanitizationMethodPolicy]:
    """Return trusted static metadata for one exact method-profile ID."""

    if (
        not isinstance(method_profile_id, str)
        or not method_profile_id
        or method_profile_id != method_profile_id.strip()
        or any(
            ord(character) < 32
            or ord(character) == 127
            for character in method_profile_id
        )
    ):
        return None

    for policy in _SANITIZATION_METHOD_POLICIES:
        if policy.method_profile_id == method_profile_id:
            return policy

    return None

@dataclass(frozen=True)
class SanitizationMethodCapabilityMetadata:
    """Non-executable capability and safety-constraint metadata."""

    method_profile_id: str
    capability_class: str
    requires_strong_identity: bool
    requires_unmounted: bool
    requires_writable: bool
    requires_unprotected: bool
    requires_non_system_target: bool
    requires_unambiguous_target: bool
    requires_no_review_required: bool
    verification_expectation: str


_METHOD_CAPABILITY_CLASSES = frozenset({
    "policy_only",
})

_METHOD_VERIFICATION_EXPECTATIONS = frozenset({
    "not_applicable",
})


_SANITIZATION_METHOD_CAPABILITIES = (
    SanitizationMethodCapabilityMetadata(
        method_profile_id="phase5-policy-only",
        capability_class="policy_only",
        requires_strong_identity=True,
        requires_unmounted=True,
        requires_writable=True,
        requires_unprotected=True,
        requires_non_system_target=True,
        requires_unambiguous_target=True,
        requires_no_review_required=True,
        verification_expectation="not_applicable",
    ),
)


def _method_capability_text(value: Any) -> bool:
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


def _sanitization_method_capability_metadata_valid(
    metadata: Any,
) -> bool:
    if not isinstance(
        metadata,
        SanitizationMethodCapabilityMetadata,
    ):
        return False

    if not _method_capability_text(
        metadata.method_profile_id
    ):
        return False

    if (
        metadata.capability_class
        not in _METHOD_CAPABILITY_CLASSES
    ):
        return False

    if (
        metadata.verification_expectation
        not in _METHOD_VERIFICATION_EXPECTATIONS
    ):
        return False

    constraint_values = (
        metadata.requires_strong_identity,
        metadata.requires_unmounted,
        metadata.requires_writable,
        metadata.requires_unprotected,
        metadata.requires_non_system_target,
        metadata.requires_unambiguous_target,
        metadata.requires_no_review_required,
    )

    if any(
        type(value) is not bool
        for value in constraint_values
    ):
        return False

    if metadata.capability_class == "policy_only":
        return (
            all(constraint_values)
            and metadata.verification_expectation
            == "not_applicable"
        )

    return False


def _sanitization_method_capability_registry_valid() -> bool:
    if (
        not isinstance(
            _SANITIZATION_METHOD_POLICIES,
            tuple,
        )
        or not _SANITIZATION_METHOD_POLICIES
        or not isinstance(
            _SANITIZATION_METHOD_CAPABILITIES,
            tuple,
        )
        or not _SANITIZATION_METHOD_CAPABILITIES
    ):
        return False

    policy_ids = []

    for policy in _SANITIZATION_METHOD_POLICIES:
        if not isinstance(
            policy,
            SanitizationMethodPolicy,
        ):
            return False

        if not _method_capability_text(
            policy.method_profile_id
        ):
            return False

        if policy.method_profile_id in policy_ids:
            return False

        if (
            policy.operation not in SUPPORTED_OPERATIONS
            or type(policy.policy_only) is not bool
            or type(policy.execution_supported) is not bool
            or policy.policy_only is not True
            or policy.execution_supported is not False
        ):
            return False

        policy_ids.append(
            policy.method_profile_id
        )

    capability_ids = []

    for metadata in _SANITIZATION_METHOD_CAPABILITIES:
        if not _sanitization_method_capability_metadata_valid(
            metadata
        ):
            return False

        if metadata.method_profile_id in capability_ids:
            return False

        capability_ids.append(
            metadata.method_profile_id
        )

    return (
        set(policy_ids) == set(capability_ids)
        and len(policy_ids) == len(capability_ids)
    )


def get_sanitization_method_capability_metadata(
    method_profile_id: Any,
) -> Optional[SanitizationMethodCapabilityMetadata]:
    """Return metadata for one exact trusted method-profile identifier."""

    if not _method_capability_text(
        method_profile_id
    ):
        return None

    if not _sanitization_method_capability_registry_valid():
        return None

    for metadata in _SANITIZATION_METHOD_CAPABILITIES:
        if metadata.method_profile_id == method_profile_id:
            return metadata

    return None


class AuthorizationError(ValueError):
    """Authorization request or evidence could not be safely interpreted."""


@dataclass(frozen=True)
class AuthorizationRequest:
    request_id: str
    batch_job_id: str
    internal_record_id: str
    operation: str
    method_profile_id: str
    record_snapshot_hash: str
    created_at_utc: str
    schema_version: int = SCHEMA_VERSION


@dataclass(frozen=True)
class TargetIdentityBinding:
    path: str
    serial: Optional[str]
    wwn: Optional[str]
    size_bytes: int
    model: Optional[str]
    transport: Optional[str]
    read_only: bool
    mounted: bool
    protected: bool
    system_protected: bool
    review_required: bool
    ambiguous: bool
    major_minor: Optional[str] = None


@dataclass(frozen=True)
class AuthorizationDecision:
    decision_id: str
    policy_version: str
    schema_version: int
    evidence_origin: str
    request_id: str
    request_hash: Optional[str]
    record_snapshot_hash: Optional[str]
    discovery_snapshot_hash: Optional[str]
    target_binding_hash: Optional[str]
    status: str
    reason_codes: tuple[str, ...]
    evaluated_at_utc: str
    discovery_captured_at_utc: str
    prerequisite_valid_until_utc: Optional[str]
    target_binding: Optional[TargetIdentityBinding]


_REASON_CLASS = {
    # Evidence / authority-context failures.
    "REQUEST_SCHEMA_INVALID": STATUS_EVALUATION_FAILED,
    "REQUEST_TIMESTAMP_INVALID": STATUS_EVALUATION_FAILED,
    "REQUEST_STALE": STATUS_EVALUATION_FAILED,
    "INTERNAL_CLOCK_INVALID": STATUS_EVALUATION_FAILED,
    "DISCOVERY_COLLECTION_FAILED": STATUS_EVALUATION_FAILED,
    "DISCOVERY_EVIDENCE_INVALID": STATUS_EVALUATION_FAILED,
    "DISCOVERY_EVIDENCE_MISMATCH": STATUS_EVALUATION_FAILED,
    "DISCOVERY_STALE": STATUS_EVALUATION_FAILED,
    "RECORD_INVALID": STATUS_EVALUATION_FAILED,
    "RECORD_SNAPSHOT_MISMATCH": STATUS_EVALUATION_FAILED,
    "STRONG_IDENTITY_MISSING": STATUS_EVALUATION_FAILED,
    "MALFORMED_RECORD_SERIAL": STATUS_EVALUATION_FAILED,
    "MALFORMED_RECORD_STABLE_IDENTIFIER": STATUS_EVALUATION_FAILED,
    "MALFORMED_DISCOVERED_SERIAL": STATUS_EVALUATION_FAILED,
    "MALFORMED_DISCOVERED_WWN": STATUS_EVALUATION_FAILED,
    "TARGET_NOT_PRESENT": STATUS_EVALUATION_FAILED,
    "MULTIPLE_TARGET_MATCHES": STATUS_EVALUATION_FAILED,
    "DUPLICATE_SERIAL": STATUS_EVALUATION_FAILED,
    "DUPLICATE_STABLE_IDENTIFIER": STATUS_EVALUATION_FAILED,
    "IDENTITY_COMPONENTS_DIVERGE": STATUS_EVALUATION_FAILED,
    "CAPACITY_UNKNOWN": STATUS_EVALUATION_FAILED,
    "CAPACITY_INVALID": STATUS_EVALUATION_FAILED,
    "READ_ONLY_STATE_UNKNOWN": STATUS_EVALUATION_FAILED,
    "TARGET_PATH_INVALID": STATUS_EVALUATION_FAILED,
    "KERNEL_DEVICE_NUMBER_MISSING": STATUS_EVALUATION_FAILED,
    "KERNEL_DEVICE_NUMBER_INVALID": STATUS_EVALUATION_FAILED,

    # Hard policy refusals.
    "BATCH_ID_MISMATCH": STATUS_REFUSED,
    "RECORD_ID_MISMATCH": STATUS_REFUSED,
    "OPERATION_MISSING": STATUS_REFUSED,
    "OPERATION_UNSUPPORTED": STATUS_REFUSED,
    "METHOD_PROFILE_MISSING": STATUS_REFUSED,
    "METHOD_PROFILE_UNSUPPORTED": STATUS_REFUSED,
    "METHOD_PROFILE_UNKNOWN": STATUS_REFUSED,
    "METHOD_PROFILE_OPERATION_MISMATCH": STATUS_REFUSED,
    "INTENDED_ACTION_MISSING": STATUS_REFUSED,
    "INTENDED_ACTION_MISMATCH": STATUS_REFUSED,
    "RECORDED_SYSTEM_PROTECTED": STATUS_REFUSED,
    "RECORD_MARKED_INELIGIBLE": STATUS_REFUSED,
    "RECORD_SANITIZATION_STATE_NOT_READY": STATUS_REFUSED,
    "TARGET_IDENTITY_CHANGED": STATUS_REFUSED,
    "SERIAL_MISMATCH": STATUS_REFUSED,
    "STABLE_IDENTIFIER_MISMATCH": STATUS_REFUSED,
    "DEVICE_PATH_CHANGED": STATUS_REFUSED,
    "CAPACITY_MISMATCH": STATUS_REFUSED,
    "SYSTEM_STORAGE": STATUS_REFUSED,
    "PROTECTED_STORAGE": STATUS_REFUSED,
    "TARGET_MOUNTED": STATUS_REFUSED,
    "TARGET_READ_ONLY": STATUS_REFUSED,

    # Evidence requiring operator investigation.
    "RECORD_REVIEW_REQUIRED": STATUS_REVIEW_REQUIRED,
    "RECORD_ELIGIBILITY_UNKNOWN": STATUS_REVIEW_REQUIRED,
    "RECORD_INTAKE_INCOMPLETE": STATUS_REVIEW_REQUIRED,
    "RECORDED_SYSTEM_STATE_UNKNOWN": STATUS_REVIEW_REQUIRED,
    "RECORDED_MOUNTED_REVIEW_REQUIRED": STATUS_REVIEW_REQUIRED,
    "RECORDED_MOUNT_STATE_UNKNOWN": STATUS_REVIEW_REQUIRED,
    "TARGET_AMBIGUOUS": STATUS_REVIEW_REQUIRED,
    "TARGET_REVIEW_REQUIRED": STATUS_REVIEW_REQUIRED,
    "MODEL_MISMATCH_REVIEW_REQUIRED": STATUS_REVIEW_REQUIRED,
}

_STATUS_PRECEDENCE = {
    STATUS_PREREQUISITES_MET: 0,
    STATUS_REVIEW_REQUIRED: 1,
    STATUS_REFUSED: 2,
    STATUS_EVALUATION_FAILED: 3,
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _aware_utc(value: Any) -> Optional[datetime]:
    if not isinstance(value, datetime):
        return None

    if value.tzinfo is None or value.utcoffset() is None:
        return None

    return value.astimezone(timezone.utc)


def _iso_utc(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _require_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AuthorizationError(
            f"{name} must be a non-empty string"
        )

    return value.strip()


def _parse_utc(value: Any, name: str) -> datetime:
    text = _require_text(value, name)

    try:
        parsed = datetime.fromisoformat(
            text[:-1] + "+00:00"
            if text.endswith("Z")
            else text
        )
    except ValueError as exc:
        raise AuthorizationError(
            f"{name} must be an ISO-8601 timestamp"
        ) from exc

    parsed = _aware_utc(parsed)

    if parsed is None:
        raise AuthorizationError(
            f"{name} must include a timezone"
        )

    return parsed


def _canonical_hash(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return "sha256:" + hashlib.sha256(encoded).hexdigest()

METHOD_CONSTRAINT_STATUS_SATISFIED = (
    "method_constraints_satisfied"
)
METHOD_CONSTRAINT_STATUS_REVIEW_REQUIRED = (
    "method_constraints_review_required"
)
METHOD_CONSTRAINT_STATUS_REFUSED = (
    "method_constraints_refused"
)
METHOD_CONSTRAINT_STATUS_EVALUATION_FAILED = (
    "method_constraints_evaluation_failed"
)


@dataclass(frozen=True)
class SanitizationMethodConstraintEvaluation:
    """Deterministic non-authorizing method-constraint result.

    A satisfied result means only that the supplied target binding
    satisfies the frozen capability metadata.  It is not human approval,
    execution authorization, method selection, or evidence of sanitization.
    """

    method_profile_id: str
    target_binding_hash: Optional[str]
    status: str
    reason_codes: tuple[str, ...]


_METHOD_CONSTRAINT_REASON_CLASS = {
    "METHOD_CONSTRAINT_METADATA_UNAVAILABLE":
        METHOD_CONSTRAINT_STATUS_EVALUATION_FAILED,
    "METHOD_CONSTRAINT_TARGET_BINDING_INVALID":
        METHOD_CONSTRAINT_STATUS_EVALUATION_FAILED,
    "METHOD_CONSTRAINT_STRONG_IDENTITY_REQUIRED":
        METHOD_CONSTRAINT_STATUS_EVALUATION_FAILED,

    "METHOD_CONSTRAINT_SYSTEM_TARGET":
        METHOD_CONSTRAINT_STATUS_REFUSED,
    "METHOD_CONSTRAINT_TARGET_PROTECTED":
        METHOD_CONSTRAINT_STATUS_REFUSED,
    "METHOD_CONSTRAINT_TARGET_MOUNTED":
        METHOD_CONSTRAINT_STATUS_REFUSED,
    "METHOD_CONSTRAINT_TARGET_READ_ONLY":
        METHOD_CONSTRAINT_STATUS_REFUSED,

    "METHOD_CONSTRAINT_TARGET_AMBIGUOUS":
        METHOD_CONSTRAINT_STATUS_REVIEW_REQUIRED,
    "METHOD_CONSTRAINT_TARGET_REVIEW_REQUIRED":
        METHOD_CONSTRAINT_STATUS_REVIEW_REQUIRED,
}


_METHOD_CONSTRAINT_STATUS_PRECEDENCE = {
    METHOD_CONSTRAINT_STATUS_SATISFIED: 0,
    METHOD_CONSTRAINT_STATUS_REVIEW_REQUIRED: 1,
    METHOD_CONSTRAINT_STATUS_REFUSED: 2,
    METHOD_CONSTRAINT_STATUS_EVALUATION_FAILED: 3,
}


def _method_constraint_optional_text_valid(
    value: Any,
) -> bool:
    if value is None:
        return True

    if not isinstance(value, str):
        return False

    return not any(
        ord(character) < 32
        or ord(character) == 127
        for character in value
    )


def _method_constraint_identity_present(
    value: Any,
) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and not any(
            ord(character) < 32
            or ord(character) == 127
            for character in value
        )
    )


def _sanitization_method_constraint_target_binding_valid(
    target_binding: Any,
) -> bool:
    if not isinstance(
        target_binding,
        TargetIdentityBinding,
    ):
        return False

    if (
        not isinstance(target_binding.path, str)
        or not target_binding.path.strip()
        or any(
            ord(character) < 32
            or ord(character) == 127
            for character in target_binding.path
        )
    ):
        return False

    if (
        target_binding.major_minor is not None
        and not _kernel_major_minor_valid(
            target_binding.major_minor
        )
    ):
        return False

    if (
        type(target_binding.size_bytes) is not int
        or target_binding.size_bytes <= 0
    ):
        return False

    for value in (
        target_binding.serial,
        target_binding.wwn,
        target_binding.model,
        target_binding.transport,
    ):
        if not _method_constraint_optional_text_valid(
            value
        ):
            return False

    bool_values = (
        target_binding.read_only,
        target_binding.mounted,
        target_binding.protected,
        target_binding.system_protected,
        target_binding.review_required,
        target_binding.ambiguous,
    )

    return all(
        type(value) is bool
        for value in bool_values
    )


def _sanitization_method_constraint_status(
    reason_codes: tuple[str, ...],
) -> str:
    if not reason_codes:
        return METHOD_CONSTRAINT_STATUS_SATISFIED

    return max(
        (
            _METHOD_CONSTRAINT_REASON_CLASS.get(
                reason,
                METHOD_CONSTRAINT_STATUS_EVALUATION_FAILED,
            )
            for reason in reason_codes
        ),
        key=_METHOD_CONSTRAINT_STATUS_PRECEDENCE.__getitem__,
    )


def evaluate_sanitization_method_constraints(
    method_profile_id: Any,
    target_binding: Any,
) -> SanitizationMethodConstraintEvaluation:
    """Evaluate frozen method constraints against one supplied binding.

    This function performs no discovery, approval, execution, device access,
    method auto-selection, or mutation.
    """

    reasons: list[str] = []

    raw_method_profile_id = (
        method_profile_id
        if isinstance(method_profile_id, str)
        else ""
    )

    metadata = (
        get_sanitization_method_capability_metadata(
            method_profile_id
        )
    )

    if metadata is None:
        reasons.append(
            "METHOD_CONSTRAINT_METADATA_UNAVAILABLE"
        )

    binding_valid = (
        _sanitization_method_constraint_target_binding_valid(
            target_binding
        )
    )

    target_binding_hash = None

    if not binding_valid:
        reasons.append(
            "METHOD_CONSTRAINT_TARGET_BINDING_INVALID"
        )
    else:
        target_binding_hash = _canonical_hash(
            asdict(target_binding)
        )

    if metadata is not None and binding_valid:
        strong_identity_present = (
            _method_constraint_identity_present(
                target_binding.serial
            )
            or _method_constraint_identity_present(
                target_binding.wwn
            )
        )

        if (
            metadata.requires_strong_identity
            and not strong_identity_present
        ):
            reasons.append(
                "METHOD_CONSTRAINT_STRONG_IDENTITY_REQUIRED"
            )

        if (
            metadata.requires_non_system_target
            and target_binding.system_protected
        ):
            reasons.append(
                "METHOD_CONSTRAINT_SYSTEM_TARGET"
            )

        if (
            metadata.requires_unprotected
            and target_binding.protected
        ):
            reasons.append(
                "METHOD_CONSTRAINT_TARGET_PROTECTED"
            )

        if (
            metadata.requires_unmounted
            and target_binding.mounted
        ):
            reasons.append(
                "METHOD_CONSTRAINT_TARGET_MOUNTED"
            )

        if (
            metadata.requires_writable
            and target_binding.read_only
        ):
            reasons.append(
                "METHOD_CONSTRAINT_TARGET_READ_ONLY"
            )

        if (
            metadata.requires_unambiguous_target
            and target_binding.ambiguous
        ):
            reasons.append(
                "METHOD_CONSTRAINT_TARGET_AMBIGUOUS"
            )

        if (
            metadata.requires_no_review_required
            and target_binding.review_required
        ):
            reasons.append(
                "METHOD_CONSTRAINT_TARGET_REVIEW_REQUIRED"
            )

    reason_codes = tuple(
        dict.fromkeys(reasons)
    )

    return SanitizationMethodConstraintEvaluation(
        method_profile_id=raw_method_profile_id,
        target_binding_hash=target_binding_hash,
        status=_sanitization_method_constraint_status(
            reason_codes
        ),
        reason_codes=reason_codes,
    )

SYNTHETIC_SANITIZATION_PLAN_SCHEMA_VERSION = 1
SYNTHETIC_SANITIZATION_PLAN_MODE = "synthetic_only"


class SyntheticSanitizationPlanError(AuthorizationError):
    """Synthetic plan input could not be bound safely."""


@dataclass(frozen=True)
class SyntheticSanitizationPlan:
    """Inert, deterministic synthetic sanitization plan.

    This object contains no command, executable, callback, device handle,
    approval authority, or execution authority.  It cannot target a real
    operating-system device path.
    """

    plan_id: str
    schema_version: int
    plan_mode: str
    method_profile_id: str
    operation: str
    synthetic_target_id: str
    target_binding_hash: str
    constraint_evaluation_hash: str
    plan_hash: str


def _synthetic_plan_exact_text(
    value: Any,
) -> bool:
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


def _synthetic_target_id_valid(
    value: Any,
) -> bool:
    if not _synthetic_plan_exact_text(value):
        return False

    prefix = "synthetic://"

    if not value.startswith(prefix):
        return False

    identifier = value[len(prefix):]

    return (
        bool(identifier)
        and identifier not in {".", ".."}
        and all(
            character.isalnum()
            or character in "-_."
            for character in identifier
        )
    )


def _synthetic_plan_hash_value(
    value: Any,
) -> bool:
    if (
        not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != len("sha256:") + 64
    ):
        return False

    suffix = value[len("sha256:"):]

    return all(
        character in "0123456789abcdef"
        for character in suffix
    )


def _synthetic_sanitization_plan_payload(
    *,
    schema_version: int,
    plan_mode: str,
    method_profile_id: str,
    operation: str,
    synthetic_target_id: str,
    target_binding_hash: str,
    constraint_evaluation_hash: str,
) -> dict[str, Any]:
    return {
        "schema_version": schema_version,
        "plan_mode": plan_mode,
        "method_profile_id": method_profile_id,
        "operation": operation,
        "synthetic_target_id": synthetic_target_id,
        "target_binding_hash": target_binding_hash,
        "constraint_evaluation_hash": (
            constraint_evaluation_hash
        ),
    }


def _synthetic_sanitization_plan_integrity_valid(
    plan: Any,
) -> bool:
    try:
        if not isinstance(
            plan,
            SyntheticSanitizationPlan,
        ):
            return False

        if (
            type(plan.schema_version) is not int
            or plan.schema_version
            != SYNTHETIC_SANITIZATION_PLAN_SCHEMA_VERSION
            or plan.plan_mode
            != SYNTHETIC_SANITIZATION_PLAN_MODE
        ):
            return False

        if not _synthetic_plan_exact_text(
            plan.method_profile_id
        ):
            return False

        if not _synthetic_plan_exact_text(
            plan.operation
        ):
            return False

        if not _synthetic_target_id_valid(
            plan.synthetic_target_id
        ):
            return False

        if not _synthetic_plan_hash_value(
            plan.target_binding_hash
        ):
            return False

        if not _synthetic_plan_hash_value(
            plan.constraint_evaluation_hash
        ):
            return False

        if not _synthetic_plan_hash_value(
            plan.plan_hash
        ):
            return False

        payload = (
            _synthetic_sanitization_plan_payload(
                schema_version=plan.schema_version,
                plan_mode=plan.plan_mode,
                method_profile_id=plan.method_profile_id,
                operation=plan.operation,
                synthetic_target_id=(
                    plan.synthetic_target_id
                ),
                target_binding_hash=(
                    plan.target_binding_hash
                ),
                constraint_evaluation_hash=(
                    plan.constraint_evaluation_hash
                ),
            )
        )

        expected_hash = _canonical_hash(payload)

        expected_id = (
            "splan_"
            + expected_hash.split(":", 1)[1]
        )

        return (
            plan.plan_hash == expected_hash
            and plan.plan_id == expected_id
        )
    except Exception:
        return False


def build_synthetic_sanitization_plan(
    *,
    method_profile_id: Any,
    operation: Any,
    synthetic_target_id: Any,
    target_binding: Any,
    constraint_evaluation: Any,
) -> SyntheticSanitizationPlan:
    """Build one inert synthetic-only plan.

    The supplied constraint result is independently recomputed and must
    match exactly.  This function performs no discovery, approval,
    execution, command construction, filesystem access, or device access.
    """

    if not _synthetic_plan_exact_text(
        method_profile_id
    ):
        raise SyntheticSanitizationPlanError(
            "method_profile_id is invalid"
        )

    if not _synthetic_plan_exact_text(
        operation
    ):
        raise SyntheticSanitizationPlanError(
            "operation is invalid"
        )

    policy = get_sanitization_method_policy(
        method_profile_id
    )

    metadata = (
        get_sanitization_method_capability_metadata(
            method_profile_id
        )
    )

    if policy is None or metadata is None:
        raise SyntheticSanitizationPlanError(
            "trusted method metadata is unavailable"
        )

    if (
        policy.method_profile_id
        != method_profile_id
        or metadata.method_profile_id
        != method_profile_id
        or policy.operation != operation
    ):
        raise SyntheticSanitizationPlanError(
            "method policy binding mismatch"
        )

    if (
        policy.policy_only is not True
        or policy.execution_supported is not False
        or metadata.capability_class != "policy_only"
    ):
        raise SyntheticSanitizationPlanError(
            "method is outside synthetic-plan policy"
        )

    if not _synthetic_target_id_valid(
        synthetic_target_id
    ):
        raise SyntheticSanitizationPlanError(
            "synthetic_target_id is invalid"
        )

    if not (
        _sanitization_method_constraint_target_binding_valid(
            target_binding
        )
    ):
        raise SyntheticSanitizationPlanError(
            "target binding is invalid"
        )

    if target_binding.path != synthetic_target_id:
        raise SyntheticSanitizationPlanError(
            "target binding is not the exact synthetic target"
        )

    if not isinstance(
        constraint_evaluation,
        SanitizationMethodConstraintEvaluation,
    ):
        raise SyntheticSanitizationPlanError(
            "constraint evaluation is invalid"
        )

    recomputed = (
        evaluate_sanitization_method_constraints(
            method_profile_id,
            target_binding,
        )
    )

    if constraint_evaluation != recomputed:
        raise SyntheticSanitizationPlanError(
            "constraint evaluation does not match recomputation"
        )

    if (
        constraint_evaluation.method_profile_id
        != method_profile_id
        or constraint_evaluation.status
        != METHOD_CONSTRAINT_STATUS_SATISFIED
        or constraint_evaluation.reason_codes != ()
        or constraint_evaluation.target_binding_hash
        is None
    ):
        raise SyntheticSanitizationPlanError(
            "method constraints are not satisfied"
        )

    target_binding_hash = _canonical_hash(
        asdict(target_binding)
    )

    if (
        constraint_evaluation.target_binding_hash
        != target_binding_hash
    ):
        raise SyntheticSanitizationPlanError(
            "constraint target binding hash mismatch"
        )

    constraint_evaluation_hash = _canonical_hash(
        asdict(constraint_evaluation)
    )

    payload = (
        _synthetic_sanitization_plan_payload(
            schema_version=(
                SYNTHETIC_SANITIZATION_PLAN_SCHEMA_VERSION
            ),
            plan_mode=SYNTHETIC_SANITIZATION_PLAN_MODE,
            method_profile_id=method_profile_id,
            operation=operation,
            synthetic_target_id=synthetic_target_id,
            target_binding_hash=target_binding_hash,
            constraint_evaluation_hash=(
                constraint_evaluation_hash
            ),
        )
    )

    plan_hash = _canonical_hash(payload)

    plan = SyntheticSanitizationPlan(
        plan_id=(
            "splan_"
            + plan_hash.split(":", 1)[1]
        ),
        schema_version=(
            SYNTHETIC_SANITIZATION_PLAN_SCHEMA_VERSION
        ),
        plan_mode=SYNTHETIC_SANITIZATION_PLAN_MODE,
        method_profile_id=method_profile_id,
        operation=operation,
        synthetic_target_id=synthetic_target_id,
        target_binding_hash=target_binding_hash,
        constraint_evaluation_hash=(
            constraint_evaluation_hash
        ),
        plan_hash=plan_hash,
    )

    if not _synthetic_sanitization_plan_integrity_valid(
        plan
    ):
        raise SyntheticSanitizationPlanError(
            "constructed synthetic plan failed integrity validation"
        )

    return plan

SYNTHETIC_SANITIZATION_RUN_SCHEMA_VERSION = 1
SYNTHETIC_SANITIZATION_RUN_MODE = "synthetic_memory_only"
SYNTHETIC_SANITIZATION_RUN_STATUS_COMPLETED = "synthetic_completed"
SYNTHETIC_SANITIZATION_MAX_PAYLOAD_BYTES = 1_048_576


class SyntheticSanitizationRunError(AuthorizationError):
    """Synthetic in-memory run could not be performed safely."""


@dataclass(frozen=True)
class SyntheticSanitizationMemoryTarget:
    """Immutable synthetic target backed only by in-memory bytes."""

    synthetic_target_id: str
    target_binding_hash: str
    payload: bytes


@dataclass(frozen=True)
class SyntheticSanitizationRunResult:
    """Frozen deterministic evidence from one synthetic-only memory run.

    Integrity here proves internal consistency only.  This result is not
    evidence that any physical storage device was sanitized.
    """

    run_id: str
    schema_version: int
    run_mode: str
    status: str
    plan_id: str
    plan_hash: str
    method_profile_id: str
    operation: str
    synthetic_target_id: str
    target_binding_hash: str
    constraint_evaluation_hash: str
    input_payload_hash: str
    output_payload_hash: str
    bytes_processed: int
    result_hash: str


def _synthetic_memory_payload_hash(
    payload: bytes,
) -> str:
    return (
        "sha256:"
        + hashlib.sha256(payload).hexdigest()
    )


def _synthetic_run_id_value(
    value: Any,
) -> bool:
    if (
        not isinstance(value, str)
        or not value.startswith("srun_")
        or len(value) != len("srun_") + 64
    ):
        return False

    suffix = value[len("srun_"):]

    return all(
        character in "0123456789abcdef"
        for character in suffix
    )


def _synthetic_memory_target_valid(
    target: Any,
) -> bool:
    if not isinstance(
        target,
        SyntheticSanitizationMemoryTarget,
    ):
        return False

    if not _synthetic_target_id_valid(
        target.synthetic_target_id
    ):
        return False

    if not _synthetic_plan_hash_value(
        target.target_binding_hash
    ):
        return False

    if type(target.payload) is not bytes:
        return False

    return (
        0 < len(target.payload)
        <= SYNTHETIC_SANITIZATION_MAX_PAYLOAD_BYTES
    )


def _synthetic_sanitization_run_payload(
    *,
    schema_version: int,
    run_mode: str,
    status: str,
    plan_id: str,
    plan_hash: str,
    method_profile_id: str,
    operation: str,
    synthetic_target_id: str,
    target_binding_hash: str,
    constraint_evaluation_hash: str,
    input_payload_hash: str,
    output_payload_hash: str,
    bytes_processed: int,
) -> dict[str, Any]:
    return {
        "schema_version": schema_version,
        "run_mode": run_mode,
        "status": status,
        "plan_id": plan_id,
        "plan_hash": plan_hash,
        "method_profile_id": method_profile_id,
        "operation": operation,
        "synthetic_target_id": synthetic_target_id,
        "target_binding_hash": target_binding_hash,
        "constraint_evaluation_hash": (
            constraint_evaluation_hash
        ),
        "input_payload_hash": input_payload_hash,
        "output_payload_hash": output_payload_hash,
        "bytes_processed": bytes_processed,
    }


def _synthetic_sanitization_run_result_integrity_valid(
    result: Any,
) -> bool:
    try:
        if not isinstance(
            result,
            SyntheticSanitizationRunResult,
        ):
            return False

        if (
            type(result.schema_version) is not int
            or result.schema_version
            != SYNTHETIC_SANITIZATION_RUN_SCHEMA_VERSION
            or result.run_mode
            != SYNTHETIC_SANITIZATION_RUN_MODE
            or result.status
            != SYNTHETIC_SANITIZATION_RUN_STATUS_COMPLETED
        ):
            return False

        if not _synthetic_run_id_value(
            result.run_id
        ):
            return False

        if (
            not isinstance(result.plan_id, str)
            or not result.plan_id.startswith("splan_")
            or len(result.plan_id)
            != len("splan_") + 64
            or not all(
                character in "0123456789abcdef"
                for character
                in result.plan_id[len("splan_"):]
            )
        ):
            return False

        if not _synthetic_plan_hash_value(
            result.plan_hash
        ):
            return False

        if not _synthetic_plan_exact_text(
            result.method_profile_id
        ):
            return False

        if not _synthetic_plan_exact_text(
            result.operation
        ):
            return False

        if not _synthetic_target_id_valid(
            result.synthetic_target_id
        ):
            return False

        for hash_value in (
            result.target_binding_hash,
            result.constraint_evaluation_hash,
            result.input_payload_hash,
            result.output_payload_hash,
            result.result_hash,
        ):
            if not _synthetic_plan_hash_value(
                hash_value
            ):
                return False

        if (
            type(result.bytes_processed) is not int
            or result.bytes_processed <= 0
            or result.bytes_processed
            > SYNTHETIC_SANITIZATION_MAX_PAYLOAD_BYTES
        ):
            return False

        expected_output_hash = (
            _synthetic_memory_payload_hash(
                bytes(result.bytes_processed)
            )
        )

        if (
            result.output_payload_hash
            != expected_output_hash
        ):
            return False

        payload = (
            _synthetic_sanitization_run_payload(
                schema_version=result.schema_version,
                run_mode=result.run_mode,
                status=result.status,
                plan_id=result.plan_id,
                plan_hash=result.plan_hash,
                method_profile_id=(
                    result.method_profile_id
                ),
                operation=result.operation,
                synthetic_target_id=(
                    result.synthetic_target_id
                ),
                target_binding_hash=(
                    result.target_binding_hash
                ),
                constraint_evaluation_hash=(
                    result.constraint_evaluation_hash
                ),
                input_payload_hash=(
                    result.input_payload_hash
                ),
                output_payload_hash=(
                    result.output_payload_hash
                ),
                bytes_processed=(
                    result.bytes_processed
                ),
            )
        )

        expected_result_hash = _canonical_hash(
            payload
        )

        expected_run_id = (
            "srun_"
            + expected_result_hash.split(":", 1)[1]
        )

        return (
            result.result_hash
            == expected_result_hash
            and result.run_id == expected_run_id
        )
    except Exception:
        return False


def run_synthetic_sanitization_plan(
    *,
    plan: Any,
    target: Any,
) -> SyntheticSanitizationRunResult:
    """Run one bounded sanitization simulation entirely in memory.

    The input bytes are immutable.  A zero-filled bytes object is created
    only in memory to model the synthetic result.  Nothing is written to
    external state.
    """

    if not isinstance(
        plan,
        SyntheticSanitizationPlan,
    ):
        raise SyntheticSanitizationRunError(
            "plan is invalid"
        )

    if not _synthetic_sanitization_plan_integrity_valid(
        plan
    ):
        raise SyntheticSanitizationRunError(
            "plan integrity is invalid"
        )

    policy = get_sanitization_method_policy(
        plan.method_profile_id
    )

    metadata = (
        get_sanitization_method_capability_metadata(
            plan.method_profile_id
        )
    )

    if policy is None or metadata is None:
        raise SyntheticSanitizationRunError(
            "trusted method metadata is unavailable"
        )

    if (
        policy.method_profile_id
        != plan.method_profile_id
        or metadata.method_profile_id
        != plan.method_profile_id
        or policy.operation != plan.operation
        or policy.policy_only is not True
        or policy.execution_supported is not False
        or metadata.capability_class != "policy_only"
    ):
        raise SyntheticSanitizationRunError(
            "plan is outside synthetic-only policy"
        )

    if not _synthetic_memory_target_valid(
        target
    ):
        raise SyntheticSanitizationRunError(
            "synthetic memory target is invalid"
        )

    if (
        target.synthetic_target_id
        != plan.synthetic_target_id
        or target.target_binding_hash
        != plan.target_binding_hash
    ):
        raise SyntheticSanitizationRunError(
            "synthetic target does not match plan"
        )

    input_payload_hash = (
        _synthetic_memory_payload_hash(
            target.payload
        )
    )

    output_payload = bytes(
        len(target.payload)
    )

    output_payload_hash = (
        _synthetic_memory_payload_hash(
            output_payload
        )
    )

    payload = (
        _synthetic_sanitization_run_payload(
            schema_version=(
                SYNTHETIC_SANITIZATION_RUN_SCHEMA_VERSION
            ),
            run_mode=(
                SYNTHETIC_SANITIZATION_RUN_MODE
            ),
            status=(
                SYNTHETIC_SANITIZATION_RUN_STATUS_COMPLETED
            ),
            plan_id=plan.plan_id,
            plan_hash=plan.plan_hash,
            method_profile_id=(
                plan.method_profile_id
            ),
            operation=plan.operation,
            synthetic_target_id=(
                plan.synthetic_target_id
            ),
            target_binding_hash=(
                plan.target_binding_hash
            ),
            constraint_evaluation_hash=(
                plan.constraint_evaluation_hash
            ),
            input_payload_hash=input_payload_hash,
            output_payload_hash=output_payload_hash,
            bytes_processed=len(target.payload),
        )
    )

    result_hash = _canonical_hash(
        payload
    )

    result = SyntheticSanitizationRunResult(
        run_id=(
            "srun_"
            + result_hash.split(":", 1)[1]
        ),
        schema_version=(
            SYNTHETIC_SANITIZATION_RUN_SCHEMA_VERSION
        ),
        run_mode=(
            SYNTHETIC_SANITIZATION_RUN_MODE
        ),
        status=(
            SYNTHETIC_SANITIZATION_RUN_STATUS_COMPLETED
        ),
        plan_id=plan.plan_id,
        plan_hash=plan.plan_hash,
        method_profile_id=(
            plan.method_profile_id
        ),
        operation=plan.operation,
        synthetic_target_id=(
            plan.synthetic_target_id
        ),
        target_binding_hash=(
            plan.target_binding_hash
        ),
        constraint_evaluation_hash=(
            plan.constraint_evaluation_hash
        ),
        input_payload_hash=input_payload_hash,
        output_payload_hash=output_payload_hash,
        bytes_processed=len(target.payload),
        result_hash=result_hash,
    )

    if not (
        _synthetic_sanitization_run_result_integrity_valid(
            result
        )
    ):
        raise SyntheticSanitizationRunError(
            "synthetic run result failed integrity validation"
        )

    return result

SYNTHETIC_RUN_EVIDENCE_ORIGIN = (
    "phase6c-b-synthetic-memory-v1"
)


_SYNTHETIC_RUN_MEASUREMENT_KEYS = (
    "synthetic_evidence_origin",
    "synthetic_run_mode",
    "synthetic_run_status",
    "synthetic_plan_id",
    "synthetic_run_id",
    "synthetic_method_profile_id",
    "synthetic_operation",
    "synthetic_target_id",
    "synthetic_bytes_processed",
)


_SYNTHETIC_RUN_EVIDENCE_HASH_KEYS = (
    "synthetic_plan_hash",
    "synthetic_constraint_evaluation_hash",
    "synthetic_target_binding_hash",
    "synthetic_input_payload_hash",
    "synthetic_output_payload_hash",
    "synthetic_run_result_hash",
)


class SyntheticRunEvidenceIntegrationError(
    AuthorizationError
):
    """Synthetic evidence could not be bound to a record safely."""


def build_drive_record_with_synthetic_run_evidence(
    *,
    record: Any,
    plan: Any,
    result: Any,
) -> DriveRecord:
    """Return a copied DriveRecord containing synthetic-run evidence.

    This function does not mutate the supplied record and does not mark
    sanitization, verification, or final disposition as successful.
    It performs no discovery, execution, approval, filesystem, or device
    operation.
    """

    if not isinstance(record, DriveRecord):
        raise SyntheticRunEvidenceIntegrationError(
            "record is invalid"
        )

    try:
        record.validate()
    except RecordError as exc:
        raise SyntheticRunEvidenceIntegrationError(
            "record validation failed"
        ) from exc

    if (
        record.sanitization_status != "not_started"
        or record.sanitization_result is not None
        or record.verification_result != "not_performed"
        or record.final_status != "pending"
    ):
        raise SyntheticRunEvidenceIntegrationError(
            "record already carries outcome state"
        )

    if not isinstance(
        plan,
        SyntheticSanitizationPlan,
    ):
        raise SyntheticRunEvidenceIntegrationError(
            "plan is invalid"
        )

    if not _synthetic_sanitization_plan_integrity_valid(
        plan
    ):
        raise SyntheticRunEvidenceIntegrationError(
            "plan integrity is invalid"
        )

    if not isinstance(
        result,
        SyntheticSanitizationRunResult,
    ):
        raise SyntheticRunEvidenceIntegrationError(
            "synthetic run result is invalid"
        )

    if not (
        _synthetic_sanitization_run_result_integrity_valid(
            result
        )
    ):
        raise SyntheticRunEvidenceIntegrationError(
            "synthetic run result integrity is invalid"
        )

    policy = get_sanitization_method_policy(
        plan.method_profile_id
    )

    metadata = (
        get_sanitization_method_capability_metadata(
            plan.method_profile_id
        )
    )

    if policy is None or metadata is None:
        raise SyntheticRunEvidenceIntegrationError(
            "trusted method metadata is unavailable"
        )

    if (
        policy.method_profile_id
        != plan.method_profile_id
        or metadata.method_profile_id
        != plan.method_profile_id
        or policy.operation != plan.operation
        or policy.policy_only is not True
        or policy.execution_supported is not False
        or metadata.capability_class != "policy_only"
    ):
        raise SyntheticRunEvidenceIntegrationError(
            "plan is outside synthetic evidence policy"
        )

    if (
        result.plan_id != plan.plan_id
        or result.plan_hash != plan.plan_hash
        or result.method_profile_id
        != plan.method_profile_id
        or result.operation != plan.operation
        or result.synthetic_target_id
        != plan.synthetic_target_id
        or result.target_binding_hash
        != plan.target_binding_hash
        or result.constraint_evaluation_hash
        != plan.constraint_evaluation_hash
    ):
        raise SyntheticRunEvidenceIntegrationError(
            "synthetic run result does not match plan"
        )

    if (
        not _synthetic_target_id_valid(
            record.linux_device_path
        )
        or record.linux_device_path
        != plan.synthetic_target_id
    ):
        raise SyntheticRunEvidenceIntegrationError(
            "drive record does not match synthetic target"
        )

    if any(
        key in record.sanitization_measurements
        for key in _SYNTHETIC_RUN_MEASUREMENT_KEYS
    ):
        raise SyntheticRunEvidenceIntegrationError(
            "synthetic measurement evidence already exists"
        )

    if any(
        key in record.evidence_hashes
        for key in _SYNTHETIC_RUN_EVIDENCE_HASH_KEYS
    ):
        raise SyntheticRunEvidenceIntegrationError(
            "synthetic hash evidence already exists"
        )

    values = asdict(record)

    measurements = dict(
        record.sanitization_measurements
    )

    measurements.update({
        "synthetic_evidence_origin":
            SYNTHETIC_RUN_EVIDENCE_ORIGIN,
        "synthetic_run_mode":
            result.run_mode,
        "synthetic_run_status":
            result.status,
        "synthetic_plan_id":
            result.plan_id,
        "synthetic_run_id":
            result.run_id,
        "synthetic_method_profile_id":
            result.method_profile_id,
        "synthetic_operation":
            result.operation,
        "synthetic_target_id":
            result.synthetic_target_id,
        "synthetic_bytes_processed":
            result.bytes_processed,
    })

    hashes = dict(
        record.evidence_hashes
    )

    hashes.update({
        "synthetic_plan_hash":
            result.plan_hash,
        "synthetic_constraint_evaluation_hash":
            result.constraint_evaluation_hash,
        "synthetic_target_binding_hash":
            result.target_binding_hash,
        "synthetic_input_payload_hash":
            result.input_payload_hash,
        "synthetic_output_payload_hash":
            result.output_payload_hash,
        "synthetic_run_result_hash":
            result.result_hash,
    })

    values["sanitization_measurements"] = (
        measurements
    )

    values["evidence_hashes"] = hashes

    integrated = DriveRecord.from_dict(
        values
    )

    if (
        integrated.sanitization_status
        != record.sanitization_status
        or integrated.sanitization_result
        != record.sanitization_result
        or integrated.verification_result
        != record.verification_result
        or integrated.final_status
        != record.final_status
    ):
        raise SyntheticRunEvidenceIntegrationError(
            "synthetic evidence changed outcome state"
        )

    return integrated


def _contains_forbidden_control(value: str) -> bool:
    return any(
        ord(character) < 32 or ord(character) == 127
        for character in value
    )


def _identity(
    value: Any,
    malformed_reason: str,
    reasons: list[str],
) -> Optional[str]:
    if value is None:
        return None

    if not isinstance(value, str):
        reasons.append(malformed_reason)
        return None

    stripped = value.strip()

    if not stripped:
        return None

    if _contains_forbidden_control(stripped):
        reasons.append(malformed_reason)
        return None

    return stripped


def _candidate_identity(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None

    stripped = value.strip()

    if not stripped:
        return None

    if _contains_forbidden_control(stripped):
        return None

    return stripped


def _path_is_valid(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and not _contains_forbidden_control(value.strip())
    )


def _kernel_major_minor_valid(value: Any) -> bool:
    """Validate exact canonical decimal Linux major:minor observation."""

    if not isinstance(value, str):
        return False

    components = value.split(":")

    return (
        len(components) == 2
        and all(
            component
            and all(
                "0" <= character <= "9"
                for character in component
            )
            and (
                len(component) == 1
                or not component.startswith("0")
            )
            for component in components
        )
    )


def record_snapshot_hash(record: DriveRecord) -> str:
    """Hash every record field that can affect this Phase 5 policy."""

    record.validate()

    payload = {
        "schema_version": SCHEMA_VERSION,
        "internal_record_id": record.internal_record_id,
        "batch_job_id": record.batch_job_id,
        "model": record.model,
        "serial_number": record.serial_number,
        "capacity_bytes": record.capacity_bytes,
        "linux_device_path": record.linux_device_path,
        "stable_device_identifier":
            record.stable_device_identifier,
        "mounted": record.mounted,
        "system_protected": record.system_protected,
        "intended_action": record.intended_action,
        "sanitization_eligibility_status":
            record.sanitization_eligibility_status,
        "sanitization_status": record.sanitization_status,
        "intake_status": record.intake_status,
    }

    return _canonical_hash(payload)


def _snapshot_shape_valid(
    snapshot: Any,
) -> bool:
    if not isinstance(snapshot, DiscoverySnapshot):
        return False

    byte_fields = (
        "captured_lsblk_json",
        "captured_findmnt_root_json",
        "captured_findmnt_real_json",
        "captured_swapon_output",
        "captured_findmnt_fstab_json",
    )

    if any(
        not isinstance(getattr(snapshot, name), bytes)
        for name in byte_fields
    ):
        return False

    if (
        not isinstance(snapshot.protected_sources, tuple)
        or any(
            not isinstance(source, str)
            or not source.strip()
            for source in snapshot.protected_sources
        )
    ):
        return False

    if (
        not isinstance(snapshot.drives, tuple)
        or any(
            not isinstance(drive, PhysicalDrive)
            for drive in snapshot.drives
        )
    ):
        return False

    return True


def discovery_snapshot_hash(
    snapshot: DiscoverySnapshot,
) -> str:
    if not _snapshot_shape_valid(snapshot):
        raise AuthorizationError(
            "discovery snapshot shape is invalid"
        )

    payload = {
        "schema_version": SCHEMA_VERSION,
        "captured_lsblk_json":
            snapshot.captured_lsblk_json.hex(),
        "protected_sources":
            list(snapshot.protected_sources),
        "captured_findmnt_root_json":
            snapshot.captured_findmnt_root_json.hex(),
        "captured_findmnt_real_json":
            snapshot.captured_findmnt_real_json.hex(),
        "captured_swapon_output":
            snapshot.captured_swapon_output.hex(),
        "captured_findmnt_fstab_json":
            snapshot.captured_findmnt_fstab_json.hex(),
    }

    return _canonical_hash(payload)


def build_authorization_request(
    record: DriveRecord,
    *,
    request_id: str,
    operation: str,
    method_profile_id: str,
) -> AuthorizationRequest:
    """Create a request with an internally obtained creation timestamp."""

    if not isinstance(record, DriveRecord):
        raise AuthorizationError(
            "record must be a DriveRecord"
        )

    try:
        record.validate()
    except RecordError as exc:
        raise AuthorizationError(
            "record is invalid"
        ) from exc

    _require_text(request_id, "request_id")
    _require_text(operation, "operation")
    _require_text(method_profile_id, "method_profile_id")

    now = _aware_utc(_utc_now())

    if now is None:
        raise AuthorizationError(
            "internal clock did not return an aware timestamp"
        )

    return AuthorizationRequest(
        request_id=request_id,
        batch_job_id=record.batch_job_id,
        internal_record_id=record.internal_record_id,
        operation=operation,
        method_profile_id=method_profile_id,
        record_snapshot_hash=record_snapshot_hash(record),
        created_at_utc=_iso_utc(now),
    )


def request_hash(
    request: AuthorizationRequest,
) -> str:
    return _canonical_hash(asdict(request))


def _derived_drives(
    snapshot: DiscoverySnapshot,
    reasons: list[str],
) -> Optional[tuple[PhysicalDrive, ...]]:
    if not _snapshot_shape_valid(snapshot):
        reasons.append("DISCOVERY_EVIDENCE_INVALID")
        return None

    try:
        independently_derived = parse_lsblk_json(
            snapshot.captured_lsblk_json,
            protected_sources=snapshot.protected_sources,
        )
    except DiscoveryError:
        reasons.append("DISCOVERY_EVIDENCE_INVALID")
        return None

    if independently_derived != snapshot.drives:
        reasons.append("DISCOVERY_EVIDENCE_MISMATCH")
        return None

    return independently_derived


def _matching_target(
    record: DriveRecord,
    drives: tuple[PhysicalDrive, ...],
    reasons: list[str],
) -> Optional[PhysicalDrive]:
    serial = _identity(
        record.serial_number,
        "MALFORMED_RECORD_SERIAL",
        reasons,
    )

    stable = _identity(
        record.stable_device_identifier,
        "MALFORMED_RECORD_STABLE_IDENTIFIER",
        reasons,
    )

    if serial is None and stable is None:
        reasons.append("STRONG_IDENTITY_MISSING")
        return None

    serial_matches: list[PhysicalDrive] = []
    stable_matches: list[PhysicalDrive] = []

    for drive in drives:
        fresh_serial = _candidate_identity(drive.serial)
        fresh_wwn = _candidate_identity(drive.wwn)

        if (
            serial is not None
            and fresh_serial == serial
        ):
            serial_matches.append(drive)

        if (
            stable is not None
            and stable in {fresh_serial, fresh_wwn}
        ):
            stable_matches.append(drive)

    if len(serial_matches) > 1:
        reasons.append("DUPLICATE_SERIAL")

    if len(stable_matches) > 1:
        reasons.append("DUPLICATE_STABLE_IDENTIFIER")

    if (
        len(serial_matches) > 1
        or len(stable_matches) > 1
    ):
        return None

    if serial is not None and stable is not None:
        if serial_matches and stable_matches:
            if serial_matches[0] is not stable_matches[0]:
                reasons.append(
                    "IDENTITY_COMPONENTS_DIVERGE"
                )
                return None

            return serial_matches[0]

        if serial_matches:
            reasons.append(
                "STABLE_IDENTIFIER_MISMATCH"
            )
            return serial_matches[0]

        if stable_matches:
            reasons.append("SERIAL_MISMATCH")
            return stable_matches[0]

        same_path = [
            drive
            for drive in drives
            if (
                isinstance(record.linux_device_path, str)
                and drive.path
                == record.linux_device_path
            )
        ]

        if len(same_path) == 1:
            reasons.append("TARGET_IDENTITY_CHANGED")
            return same_path[0]

        if len(same_path) > 1:
            reasons.append("MULTIPLE_TARGET_MATCHES")
            return None

        reasons.append("TARGET_NOT_PRESENT")
        return None

    matches = (
        serial_matches
        if serial is not None
        else stable_matches
    )

    if matches:
        return matches[0]

    same_path = [
        drive
        for drive in drives
        if (
            isinstance(record.linux_device_path, str)
            and drive.path == record.linux_device_path
        )
    ]

    if len(same_path) == 1:
        reasons.append("TARGET_IDENTITY_CHANGED")
        return same_path[0]

    if len(same_path) > 1:
        reasons.append("MULTIPLE_TARGET_MATCHES")
        return None

    reasons.append("TARGET_NOT_PRESENT")
    return None


def _target_binding(
    drive: PhysicalDrive,
) -> Optional[TargetIdentityBinding]:
    if not _path_is_valid(drive.path):
        return None

    if not _kernel_major_minor_valid(
        drive.major_minor
    ):
        return None

    if type(drive.size) is not int or drive.size <= 0:
        return None

    if type(drive.read_only) is not bool:
        return None

    return TargetIdentityBinding(
        path=drive.path,
        serial=drive.serial,
        wwn=drive.wwn,
        size_bytes=drive.size,
        model=drive.model,
        transport=drive.transport,
        read_only=drive.read_only,
        mounted=drive.mounted,
        protected=drive.protected,
        system_protected=drive.system_protected,
        review_required=drive.review_required,
        ambiguous=drive.ambiguous,
        major_minor=drive.major_minor,
    )


def _decision_status(
    reasons: tuple[str, ...],
) -> str:
    if not reasons:
        return STATUS_PREREQUISITES_MET

    return max(
        (
            _REASON_CLASS.get(
                reason,
                STATUS_EVALUATION_FAILED,
            )
            for reason in reasons
        ),
        key=_STATUS_PRECEDENCE.__getitem__,
    )


def _safe_request_hash(
    request: Any,
) -> Optional[str]:
    try:
        return request_hash(request)
    except (TypeError, ValueError):
        return None


def _safe_record_hash(
    record: Any,
) -> Optional[str]:
    try:
        return record_snapshot_hash(record)
    except (
        RecordError,
        TypeError,
        AttributeError,
    ):
        return None


def _make_decision(
    request: Any,
    *,
    record_hash: Optional[str],
    snapshot_hash: Optional[str],
    binding: Optional[TargetIdentityBinding],
    reasons: list[str],
    captured_at: datetime,
    evaluated_at: datetime,
) -> AuthorizationDecision:
    reason_codes = tuple(dict.fromkeys(reasons))
    status = _decision_status(reason_codes)

    binding_hash = (
        _canonical_hash(asdict(binding))
        if binding is not None
        else None
    )

    req_hash = _safe_request_hash(request)

    valid_until = None

    if status == STATUS_PREREQUISITES_MET:
        valid_until = _iso_utc(
            evaluated_at
            + timedelta(
                seconds=PREREQUISITE_LIFETIME_SECONDS
            )
        )

    raw_request_id = getattr(
        request,
        "request_id",
        "",
    )

    request_id = (
        raw_request_id
        if isinstance(raw_request_id, str)
        else ""
    )

    payload = {
        "policy_version": POLICY_VERSION,
        "schema_version": SCHEMA_VERSION,
        "evidence_origin": EVIDENCE_ORIGIN,
        "request_id": request_id,
        "request_hash": req_hash,
        "record_snapshot_hash": record_hash,
        "discovery_snapshot_hash": snapshot_hash,
        "target_binding_hash": binding_hash,
        "status": status,
        "reason_codes": reason_codes,
        "evaluated_at_utc": _iso_utc(evaluated_at),
        "discovery_captured_at_utc":
            _iso_utc(captured_at),
        "prerequisite_valid_until_utc": valid_until,
    }

    return AuthorizationDecision(
        decision_id=_canonical_hash(payload),
        policy_version=POLICY_VERSION,
        schema_version=SCHEMA_VERSION,
        evidence_origin=EVIDENCE_ORIGIN,
        request_id=request_id,
        request_hash=req_hash,
        record_snapshot_hash=record_hash,
        discovery_snapshot_hash=snapshot_hash,
        target_binding_hash=binding_hash,
        status=status,
        reason_codes=reason_codes,
        evaluated_at_utc=_iso_utc(evaluated_at),
        discovery_captured_at_utc=_iso_utc(captured_at),
        prerequisite_valid_until_utc=valid_until,
        target_binding=binding,
    )


def _evaluate_collected_evidence(
    request: AuthorizationRequest,
    record: DriveRecord,
    snapshot: DiscoverySnapshot,
    *,
    captured_at: datetime,
    evaluated_at: datetime,
) -> AuthorizationDecision:
    """Private deterministic evaluator for internally collected evidence."""

    reasons: list[str] = []

    request_created: Optional[datetime]

    try:
        _require_text(request.request_id, "request_id")
        _require_text(request.batch_job_id, "batch_job_id")
        _require_text(
            request.internal_record_id,
            "internal_record_id",
        )
        request_created = _parse_utc(
            request.created_at_utc,
            "created_at_utc",
        )
    except (
        AuthorizationError,
        AttributeError,
    ):
        request_created = None
        reasons.append("REQUEST_SCHEMA_INVALID")

    if (
        not isinstance(request, AuthorizationRequest)
        or request.schema_version != SCHEMA_VERSION
    ):
        reasons.append("REQUEST_SCHEMA_INVALID")

    if request_created is not None:
        request_age = evaluated_at - request_created

        if request_age < -timedelta(
            seconds=MAX_FUTURE_SKEW_SECONDS
        ):
            reasons.append("REQUEST_TIMESTAMP_INVALID")
        elif request_age > timedelta(
            seconds=MAX_REQUEST_AGE_SECONDS
        ):
            reasons.append("REQUEST_STALE")

    if request.batch_job_id != record.batch_job_id:
        reasons.append("BATCH_ID_MISMATCH")

    if (
        request.internal_record_id
        != record.internal_record_id
    ):
        reasons.append("RECORD_ID_MISMATCH")

    operation_value = (
        request.operation
        if isinstance(request.operation, str)
        else ""
    )

    operation = operation_value.strip()

    method_profile_id = (
        request.method_profile_id
        if isinstance(request.method_profile_id, str)
        else ""
    )

    method = method_profile_id.strip()

    if not operation:
        reasons.append("OPERATION_MISSING")
    elif operation_value not in SUPPORTED_OPERATIONS:
        reasons.append("OPERATION_UNSUPPORTED")

    method_policy = None

    if not method:
        reasons.append("METHOD_PROFILE_MISSING")
    else:
        method_policy = get_sanitization_method_policy(
            method_profile_id
        )

        if method_policy is None:
            # Preserve the established Phase 5 reason while adding the
            # more precise Phase 6B registry result.
            reasons.append("METHOD_PROFILE_UNSUPPORTED")
            reasons.append("METHOD_PROFILE_UNKNOWN")
        elif (
            operation
            and method_policy.operation != operation_value
        ):
            reasons.append(
                "METHOD_PROFILE_OPERATION_MISMATCH"
            )

    record_hash = _safe_record_hash(record)

    if record_hash is None:
        reasons.append("RECORD_INVALID")
    elif request.record_snapshot_hash != record_hash:
        reasons.append("RECORD_SNAPSHOT_MISMATCH")

    if (
        not isinstance(record.intended_action, str)
        or not record.intended_action.strip()
    ):
        reasons.append("INTENDED_ACTION_MISSING")
    elif (
        record.intended_action.strip()
        != operation
    ):
        reasons.append("INTENDED_ACTION_MISMATCH")

    if record.system_protected is True:
        reasons.append("RECORDED_SYSTEM_PROTECTED")
    elif record.system_protected is None:
        reasons.append("RECORDED_SYSTEM_STATE_UNKNOWN")

    if record.mounted is True:
        reasons.append(
            "RECORDED_MOUNTED_REVIEW_REQUIRED"
        )
    elif record.mounted is None:
        reasons.append(
            "RECORDED_MOUNT_STATE_UNKNOWN"
        )

    if record.sanitization_status != "not_started":
        reasons.append(
            "RECORD_SANITIZATION_STATE_NOT_READY"
        )

    if (
        record.sanitization_eligibility_status
        == "ineligible"
    ):
        reasons.append("RECORD_MARKED_INELIGIBLE")
    elif (
        record.sanitization_eligibility_status
        == "review_needed"
    ):
        reasons.append("RECORD_REVIEW_REQUIRED")
    elif (
        record.sanitization_eligibility_status
        == "unknown"
    ):
        reasons.append("RECORD_ELIGIBILITY_UNKNOWN")

    if record.intake_status != "complete":
        reasons.append("RECORD_INTAKE_INCOMPLETE")

    discovery_age = evaluated_at - captured_at

    if discovery_age < -timedelta(
        seconds=MAX_FUTURE_SKEW_SECONDS
    ):
        reasons.append("INTERNAL_CLOCK_INVALID")
    elif discovery_age > timedelta(
        seconds=MAX_DISCOVERY_AGE_SECONDS
    ):
        reasons.append("DISCOVERY_STALE")

    snapshot_hash: Optional[str]

    try:
        snapshot_hash = discovery_snapshot_hash(snapshot)
    except AuthorizationError:
        snapshot_hash = None
        reasons.append("DISCOVERY_EVIDENCE_INVALID")

    drives = _derived_drives(snapshot, reasons)

    target = None
    binding = None

    if drives is not None:
        target = _matching_target(
            record,
            drives,
            reasons,
        )

    if target is not None:
        fresh_serial = _identity(
            target.serial,
            "MALFORMED_DISCOVERED_SERIAL",
            reasons,
        )

        fresh_wwn = _identity(
            target.wwn,
            "MALFORMED_DISCOVERED_WWN",
            reasons,
        )

        record_serial = _candidate_identity(
            record.serial_number
        )

        stable = _candidate_identity(
            record.stable_device_identifier
        )

        if (
            record_serial is not None
            and fresh_serial != record_serial
        ):
            reasons.append("SERIAL_MISMATCH")

        if (
            stable is not None
            and stable not in {fresh_serial, fresh_wwn}
        ):
            reasons.append(
                "STABLE_IDENTIFIER_MISMATCH"
            )

        if target.major_minor is None:
            reasons.append(
                "KERNEL_DEVICE_NUMBER_MISSING"
            )
        elif not _kernel_major_minor_valid(
            target.major_minor
        ):
            reasons.append(
                "KERNEL_DEVICE_NUMBER_INVALID"
            )

        if not _path_is_valid(target.path):
            reasons.append("TARGET_PATH_INVALID")
        elif (
            not isinstance(record.linux_device_path, str)
            or not record.linux_device_path.strip()
            or target.path != record.linux_device_path
        ):
            reasons.append("DEVICE_PATH_CHANGED")

        if record.capacity_bytes is None:
            reasons.append("CAPACITY_UNKNOWN")
        elif (
            type(record.capacity_bytes) is not int
            or record.capacity_bytes <= 0
        ):
            reasons.append("CAPACITY_INVALID")
        elif (
            type(target.size) is not int
            or target.size <= 0
        ):
            reasons.append("CAPACITY_INVALID")
        elif target.size != record.capacity_bytes:
            reasons.append("CAPACITY_MISMATCH")

        if target.system_protected:
            reasons.append("SYSTEM_STORAGE")

        if target.protected:
            reasons.append("PROTECTED_STORAGE")

        if target.mounted:
            reasons.append("TARGET_MOUNTED")

        if target.ambiguous:
            reasons.append("TARGET_AMBIGUOUS")

        if target.review_required:
            reasons.append("TARGET_REVIEW_REQUIRED")

        if target.read_only is None:
            reasons.append("READ_ONLY_STATE_UNKNOWN")
        elif target.read_only:
            reasons.append("TARGET_READ_ONLY")

        if (
            isinstance(record.model, str)
            and record.model.strip()
            and isinstance(target.model, str)
            and target.model.strip()
            and (
                record.model.strip().casefold()
                != target.model.strip().casefold()
            )
        ):
            reasons.append(
                "MODEL_MISMATCH_REVIEW_REQUIRED"
            )

        binding = _target_binding(target)

        if binding is None:
            if not _path_is_valid(target.path):
                reasons.append("TARGET_PATH_INVALID")

            if (
                type(target.size) is not int
                or target.size <= 0
            ):
                reasons.append("CAPACITY_INVALID")

            if type(target.read_only) is not bool:
                reasons.append(
                    "READ_ONLY_STATE_UNKNOWN"
                )

    return _make_decision(
        request,
        record_hash=record_hash,
        snapshot_hash=snapshot_hash,
        binding=binding,
        reasons=reasons,
        captured_at=captured_at,
        evaluated_at=evaluated_at,
    )


def evaluate_current_authorization_prerequisites(
    request: AuthorizationRequest,
    record: DriveRecord,
) -> AuthorizationDecision:
    """Collect current Phase 4 evidence and evaluate it.

    The caller cannot substitute a snapshot, capture time, evaluation time,
    command, executable, or collection path through this public API.
    """

    captured_at = _aware_utc(_utc_now())

    if captured_at is None:
        epoch = datetime(
            1970,
            1,
            1,
            tzinfo=timezone.utc,
        )

        return _make_decision(
            request,
            record_hash=_safe_record_hash(record),
            snapshot_hash=None,
            binding=None,
            reasons=["INTERNAL_CLOCK_INVALID"],
            captured_at=epoch,
            evaluated_at=epoch,
        )

    if not isinstance(request, AuthorizationRequest):
        return _make_decision(
            request,
            record_hash=_safe_record_hash(record),
            snapshot_hash=None,
            binding=None,
            reasons=["REQUEST_SCHEMA_INVALID"],
            captured_at=captured_at,
            evaluated_at=captured_at,
        )

    record_hash = _safe_record_hash(record)

    if (
        not isinstance(record, DriveRecord)
        or record_hash is None
    ):
        return _make_decision(
            request,
            record_hash=None,
            snapshot_hash=None,
            binding=None,
            reasons=["RECORD_INVALID"],
            captured_at=captured_at,
            evaluated_at=captured_at,
        )

    try:
        snapshot = collect_current_drive_discovery()
    except (
        DiscoveryCollectionError,
        DiscoveryError,
    ):
        evaluated_at = _aware_utc(_utc_now())

        if evaluated_at is None:
            evaluated_at = captured_at

        return _make_decision(
            request,
            record_hash=_safe_record_hash(record),
            snapshot_hash=None,
            binding=None,
            reasons=["DISCOVERY_COLLECTION_FAILED"],
            captured_at=captured_at,
            evaluated_at=evaluated_at,
        )

    evaluated_at = _aware_utc(_utc_now())

    if evaluated_at is None:
        return _make_decision(
            request,
            record_hash=_safe_record_hash(record),
            snapshot_hash=None,
            binding=None,
            reasons=["INTERNAL_CLOCK_INVALID"],
            captured_at=captured_at,
            evaluated_at=captured_at,
        )

    return _evaluate_collected_evidence(
        request,
        record,
        snapshot,
        captured_at=captured_at,
        evaluated_at=evaluated_at,
    )


def _canonical_hash_value(value: Any) -> bool:
    """Return whether value has the canonical SHA-256 representation."""

    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
    ):
        return False

    return all(
        character in "0123456789abcdef"
        for character in value[7:]
    )


def _positive_binding_integrity_valid(
    binding: TargetIdentityBinding,
) -> bool:
    """Validate all strict target facts required by a positive decision."""

    if not isinstance(binding, TargetIdentityBinding):
        return False

    if not _path_is_valid(binding.path):
        return False

    if not _kernel_major_minor_valid(
        binding.major_minor
    ):
        return False

    serial = _candidate_identity(binding.serial)
    wwn = _candidate_identity(binding.wwn)

    if (
        binding.serial is not None
        and serial != binding.serial
    ):
        return False

    if (
        binding.wwn is not None
        and wwn != binding.wwn
    ):
        return False

    if serial is None and wwn is None:
        return False

    if (
        type(binding.size_bytes) is not int
        or binding.size_bytes <= 0
    ):
        return False

    for optional_text in (
        binding.model,
        binding.transport,
    ):
        if optional_text is None:
            continue

        if (
            not isinstance(optional_text, str)
            or not optional_text.strip()
            or optional_text != optional_text.strip()
            or _contains_forbidden_control(optional_text)
        ):
            return False

    safety_flags = (
        binding.read_only,
        binding.mounted,
        binding.protected,
        binding.system_protected,
        binding.review_required,
        binding.ambiguous,
    )

    if any(
        type(value) is not bool
        for value in safety_flags
    ):
        return False

    # A positive prerequisite decision requires every safety blocker
    # to be explicitly false. Merely being a boolean is insufficient.
    if any(safety_flags):
        return False

    return True


def _decision_integrity_valid_impl(
    decision: AuthorizationDecision,
) -> bool:
    """Internal implementation for fail-closed decision validation."""

    if not isinstance(decision, AuthorizationDecision):
        return False

    if (
        decision.policy_version != POLICY_VERSION
        or type(decision.schema_version) is not int
        or decision.schema_version != SCHEMA_VERSION
        or decision.evidence_origin != EVIDENCE_ORIGIN
    ):
        return False

    if (
        not isinstance(decision.request_id, str)
        or _contains_forbidden_control(decision.request_id)
    ):
        return False

    if not _canonical_hash_value(decision.decision_id):
        return False

    for hash_value in (
        decision.request_hash,
        decision.record_snapshot_hash,
        decision.discovery_snapshot_hash,
        decision.target_binding_hash,
    ):
        if (
            hash_value is not None
            and not _canonical_hash_value(hash_value)
        ):
            return False

    if (
        not isinstance(decision.status, str)
        or decision.status not in _STATUS_PRECEDENCE
    ):
        return False

    if not isinstance(decision.reason_codes, tuple):
        return False

    if any(
        not isinstance(reason, str)
        or reason not in _REASON_CLASS
        for reason in decision.reason_codes
    ):
        return False

    if (
        len(set(decision.reason_codes))
        != len(decision.reason_codes)
    ):
        return False

    expected_status = _decision_status(
        list(decision.reason_codes)
    )

    if expected_status != decision.status:
        return False

    evaluated_at = _parse_utc(
        decision.evaluated_at_utc,
        "evaluated_at_utc",
    )

    captured_at = _parse_utc(
        decision.discovery_captured_at_utc,
        "discovery_captured_at_utc",
    )

    if (
        _iso_utc(evaluated_at)
        != decision.evaluated_at_utc
        or _iso_utc(captured_at)
        != decision.discovery_captured_at_utc
    ):
        return False

    binding = decision.target_binding

    if binding is None:
        if decision.target_binding_hash is not None:
            return False
    else:
        if not isinstance(binding, TargetIdentityBinding):
            return False

        expected_binding_hash = _canonical_hash(
            asdict(binding)
        )

        if (
            decision.target_binding_hash
            != expected_binding_hash
        ):
            return False

    if decision.status == STATUS_PREREQUISITES_MET:
        if (
            not decision.request_id.strip()
            or decision.request_id
            != decision.request_id.strip()
        ):
            return False

        if any(
            value is None
            for value in (
                decision.request_hash,
                decision.record_snapshot_hash,
                decision.discovery_snapshot_hash,
                decision.target_binding_hash,
                binding,
            )
        ):
            return False

        if decision.reason_codes:
            return False

        if not _positive_binding_integrity_valid(binding):
            return False

        if (
            captured_at
            > evaluated_at
            + timedelta(
                seconds=MAX_FUTURE_SKEW_SECONDS
            )
        ):
            return False

        if (
            evaluated_at - captured_at
            > timedelta(
                seconds=MAX_DISCOVERY_AGE_SECONDS
            )
        ):
            return False

        if decision.prerequisite_valid_until_utc is None:
            return False

        expires = _parse_utc(
            decision.prerequisite_valid_until_utc,
            "prerequisite_valid_until_utc",
        )

        if (
            _iso_utc(expires)
            != decision.prerequisite_valid_until_utc
        ):
            return False

        if (
            expires
            != evaluated_at
            + timedelta(
                seconds=PREREQUISITE_LIFETIME_SECONDS
            )
        ):
            return False

    else:
        if decision.prerequisite_valid_until_utc is not None:
            return False

    payload = {
        "policy_version": decision.policy_version,
        "schema_version": decision.schema_version,
        "evidence_origin": decision.evidence_origin,
        "request_id": decision.request_id,
        "request_hash": decision.request_hash,
        "record_snapshot_hash":
            decision.record_snapshot_hash,
        "discovery_snapshot_hash":
            decision.discovery_snapshot_hash,
        "target_binding_hash":
            decision.target_binding_hash,
        "status": decision.status,
        "reason_codes": decision.reason_codes,
        "evaluated_at_utc": decision.evaluated_at_utc,
        "discovery_captured_at_utc":
            decision.discovery_captured_at_utc,
        "prerequisite_valid_until_utc":
            decision.prerequisite_valid_until_utc,
    }

    return (
        decision.decision_id
        == _canonical_hash(payload)
    )


def decision_integrity_valid(
    decision: Any,
) -> bool:
    """Verify deterministic decision internal consistency.

    This is deliberately not a signature, provenance proof, human
    approval, or execution authority. Any malformed input fails closed.
    """

    try:
        return _decision_integrity_valid_impl(
            decision
        )
    except Exception:
        return False


def decision_is_current(
    decision: AuthorizationDecision,
) -> bool:
    """Check the prerequisite window using the internal clock.

    True still does not represent human approval or execution authority.
    """

    if not decision_integrity_valid(decision):
        return False

    if (
        decision.status
        != STATUS_PREREQUISITES_MET
    ):
        return False

    if (
        decision.prerequisite_valid_until_utc
        is None
    ):
        return False

    now = _aware_utc(_utc_now())

    if now is None:
        return False

    try:
        expires = _parse_utc(
            decision.prerequisite_valid_until_utc,
            "prerequisite_valid_until_utc",
        )
    except AuthorizationError:
        return False

    try:
        evaluated_at = _parse_utc(
            decision.evaluated_at_utc,
            "evaluated_at_utc",
        )
        captured_at = _parse_utc(
            decision.discovery_captured_at_utc,
            "discovery_captured_at_utc",
        )
    except AuthorizationError:
        return False

    # Currentness must fail closed if the local clock is more than the
    # configured skew behind either trusted decision timestamp.
    lower_reference = max(
        evaluated_at,
        captured_at,
    )

    if (
        now
        < lower_reference
        - timedelta(
            seconds=MAX_FUTURE_SKEW_SECONDS
        )
    ):
        return False

    return now <= expires



class ApprovalError(AuthorizationError):
    """Raised when the ephemeral approval boundary fails closed."""


@dataclass(frozen=True)
class ApprovalChallenge:
    challenge_id: str
    policy_version: str
    schema_version: int
    request_id: str
    request_hash: str
    record_snapshot_hash: str
    prerequisite_decision_id: str
    target_binding_hash: str
    created_at_utc: str
    valid_until_utc: str
    challenge_hash: str


@dataclass(frozen=True)
class HumanApprovalEvidence:
    approval_id: str
    challenge_id: str
    policy_version: str
    schema_version: int
    request_id: str
    request_hash: str
    record_snapshot_hash: str
    prerequisite_decision_id: str
    target_binding_hash: str
    approved_at_utc: str
    revalidation_valid_until_utc: str
    evidence_hash: str


@dataclass(frozen=True)
class ApprovalRevalidationDecision:
    revalidation_id: str
    policy_version: str
    schema_version: int
    approval_id: str
    challenge_id: Optional[str]
    request_id: Optional[str]
    original_prerequisite_decision_id: Optional[str]
    fresh_prerequisite_decision_id: Optional[str]
    original_target_binding_hash: Optional[str]
    fresh_target_binding_hash: Optional[str]
    status: str
    reason_codes: tuple[str, ...]
    evaluated_at_utc: str


def _approval_text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and value == value.strip()
        and not _contains_forbidden_control(value)
    )


def _new_approval_token(prefix: str) -> str:
    import secrets

    return f"{prefix}_{secrets.token_urlsafe(24)}"


def _challenge_payload(
    *,
    challenge_id: str,
    request_id: str,
    request_hash: str,
    record_snapshot_hash: str,
    prerequisite_decision_id: str,
    target_binding_hash: str,
    created_at_utc: str,
    valid_until_utc: str,
) -> dict[str, Any]:
    return {
        "challenge_id": challenge_id,
        "policy_version": APPROVAL_POLICY_VERSION,
        "schema_version": SCHEMA_VERSION,
        "request_id": request_id,
        "request_hash": request_hash,
        "record_snapshot_hash": record_snapshot_hash,
        "prerequisite_decision_id": prerequisite_decision_id,
        "target_binding_hash": target_binding_hash,
        "created_at_utc": created_at_utc,
        "valid_until_utc": valid_until_utc,
    }


def _approval_evidence_payload(
    *,
    approval_id: str,
    challenge_id: str,
    request_id: str,
    request_hash: str,
    record_snapshot_hash: str,
    prerequisite_decision_id: str,
    target_binding_hash: str,
    approved_at_utc: str,
    revalidation_valid_until_utc: str,
) -> dict[str, Any]:
    return {
        "approval_id": approval_id,
        "challenge_id": challenge_id,
        "policy_version": APPROVAL_POLICY_VERSION,
        "schema_version": SCHEMA_VERSION,
        "request_id": request_id,
        "request_hash": request_hash,
        "record_snapshot_hash": record_snapshot_hash,
        "prerequisite_decision_id": prerequisite_decision_id,
        "target_binding_hash": target_binding_hash,
        "approved_at_utc": approved_at_utc,
        "revalidation_valid_until_utc": (
            revalidation_valid_until_utc
        ),
    }


def _approval_challenge_integrity_valid(
    challenge: Any,
) -> bool:
    try:
        if not isinstance(
            challenge,
            ApprovalChallenge,
        ):
            return False

        if (
            challenge.policy_version
            != APPROVAL_POLICY_VERSION
            or type(challenge.schema_version) is not int
            or challenge.schema_version != SCHEMA_VERSION
        ):
            return False

        for text_value in (
            challenge.challenge_id,
            challenge.request_id,
        ):
            if not _approval_text(text_value):
                return False

        for hash_value in (
            challenge.request_hash,
            challenge.record_snapshot_hash,
            challenge.prerequisite_decision_id,
            challenge.target_binding_hash,
            challenge.challenge_hash,
        ):
            if not _canonical_hash_value(hash_value):
                return False

        created_at = _parse_utc(
            challenge.created_at_utc,
            "challenge.created_at_utc",
        )

        valid_until = _parse_utc(
            challenge.valid_until_utc,
            "challenge.valid_until_utc",
        )

        if (
            _iso_utc(created_at)
            != challenge.created_at_utc
            or _iso_utc(valid_until)
            != challenge.valid_until_utc
            or valid_until
            != created_at
            + timedelta(
                seconds=(
                    APPROVAL_CHALLENGE_LIFETIME_SECONDS
                )
            )
        ):
            return False

        payload = _challenge_payload(
            challenge_id=challenge.challenge_id,
            request_id=challenge.request_id,
            request_hash=challenge.request_hash,
            record_snapshot_hash=(
                challenge.record_snapshot_hash
            ),
            prerequisite_decision_id=(
                challenge.prerequisite_decision_id
            ),
            target_binding_hash=(
                challenge.target_binding_hash
            ),
            created_at_utc=challenge.created_at_utc,
            valid_until_utc=challenge.valid_until_utc,
        )

        return (
            challenge.challenge_hash
            == _canonical_hash(payload)
        )
    except Exception:
        return False


def _approval_evidence_integrity_valid(
    evidence: Any,
) -> bool:
    try:
        if not isinstance(
            evidence,
            HumanApprovalEvidence,
        ):
            return False

        if (
            evidence.policy_version
            != APPROVAL_POLICY_VERSION
            or type(evidence.schema_version) is not int
            or evidence.schema_version != SCHEMA_VERSION
        ):
            return False

        for text_value in (
            evidence.approval_id,
            evidence.challenge_id,
            evidence.request_id,
        ):
            if not _approval_text(text_value):
                return False

        for hash_value in (
            evidence.request_hash,
            evidence.record_snapshot_hash,
            evidence.prerequisite_decision_id,
            evidence.target_binding_hash,
            evidence.evidence_hash,
        ):
            if not _canonical_hash_value(hash_value):
                return False

        approved_at = _parse_utc(
            evidence.approved_at_utc,
            "evidence.approved_at_utc",
        )

        valid_until = _parse_utc(
            evidence.revalidation_valid_until_utc,
            "evidence.revalidation_valid_until_utc",
        )

        if (
            _iso_utc(approved_at)
            != evidence.approved_at_utc
            or _iso_utc(valid_until)
            != evidence.revalidation_valid_until_utc
            or valid_until
            != approved_at
            + timedelta(
                seconds=(
                    APPROVAL_REVALIDATION_WINDOW_SECONDS
                )
            )
        ):
            return False

        payload = _approval_evidence_payload(
            approval_id=evidence.approval_id,
            challenge_id=evidence.challenge_id,
            request_id=evidence.request_id,
            request_hash=evidence.request_hash,
            record_snapshot_hash=(
                evidence.record_snapshot_hash
            ),
            prerequisite_decision_id=(
                evidence.prerequisite_decision_id
            ),
            target_binding_hash=(
                evidence.target_binding_hash
            ),
            approved_at_utc=evidence.approved_at_utc,
            revalidation_valid_until_utc=(
                evidence.revalidation_valid_until_utc
            ),
        )

        return (
            evidence.evidence_hash
            == _canonical_hash(payload)
        )
    except Exception:
        return False


def _approval_revalidation_result(
    *,
    approval_id: Any,
    evidence: Optional[HumanApprovalEvidence],
    fresh_decision: Optional[AuthorizationDecision],
    status: str,
    reason_codes: tuple[str, ...],
    evaluated_at: datetime,
) -> ApprovalRevalidationDecision:
    safe_approval_id = (
        approval_id
        if isinstance(approval_id, str)
        else ""
    )

    challenge_id = (
        evidence.challenge_id
        if isinstance(
            evidence,
            HumanApprovalEvidence,
        )
        else None
    )

    request_id = (
        evidence.request_id
        if isinstance(
            evidence,
            HumanApprovalEvidence,
        )
        else None
    )

    original_decision_id = (
        evidence.prerequisite_decision_id
        if isinstance(
            evidence,
            HumanApprovalEvidence,
        )
        else None
    )

    original_binding_hash = (
        evidence.target_binding_hash
        if isinstance(
            evidence,
            HumanApprovalEvidence,
        )
        else None
    )

    fresh_decision_id = (
        fresh_decision.decision_id
        if isinstance(
            fresh_decision,
            AuthorizationDecision,
        )
        else None
    )

    fresh_binding_hash = (
        fresh_decision.target_binding_hash
        if isinstance(
            fresh_decision,
            AuthorizationDecision,
        )
        else None
    )

    evaluated_text = _iso_utc(evaluated_at)

    payload = {
        "policy_version": APPROVAL_POLICY_VERSION,
        "schema_version": SCHEMA_VERSION,
        "approval_id": safe_approval_id,
        "challenge_id": challenge_id,
        "request_id": request_id,
        "original_prerequisite_decision_id": (
            original_decision_id
        ),
        "fresh_prerequisite_decision_id": (
            fresh_decision_id
        ),
        "original_target_binding_hash": (
            original_binding_hash
        ),
        "fresh_target_binding_hash": (
            fresh_binding_hash
        ),
        "status": status,
        "reason_codes": reason_codes,
        "evaluated_at_utc": evaluated_text,
    }

    return ApprovalRevalidationDecision(
        revalidation_id=_canonical_hash(payload),
        policy_version=APPROVAL_POLICY_VERSION,
        schema_version=SCHEMA_VERSION,
        approval_id=safe_approval_id,
        challenge_id=challenge_id,
        request_id=request_id,
        original_prerequisite_decision_id=(
            original_decision_id
        ),
        fresh_prerequisite_decision_id=(
            fresh_decision_id
        ),
        original_target_binding_hash=(
            original_binding_hash
        ),
        fresh_target_binding_hash=(
            fresh_binding_hash
        ),
        status=status,
        reason_codes=reason_codes,
        evaluated_at_utc=evaluated_text,
    )


_APPROVAL_TOKEN_ALLOCATION_MAX_ATTEMPTS = 32

class ApprovalRegistry:
    """Process-local Phase 6A2 approval registry.

    Challenge creation obtains its prerequisite
    decision internally.

    record_human_approval() is a trusted core
    boundary intended for a future trusted
    UI/event adapter after a real human gesture.
    This Python core cannot itself prove that a
    physical human clicked anything.

    Revalidation consumes an approval before
    performing fresh discovery/evaluation.

    Nothing here executes sanitization.
    """

    def __init__(self) -> None:
        import threading

        self._state_lock = threading.Lock()

        self._challenges: dict[
            str,
            ApprovalChallenge,
        ] = {}

        self._approvals: dict[
            str,
            HumanApprovalEvidence,
        ] = {}

        self._approved_challenges: set[str] = set()
        self._consumed_approvals: set[str] = set()

        # Phase 6D-A: retain only registry-produced successful
        # revalidation evidence.  This is process-local state,
        # not persistence and not execution authority.
        self._successful_revalidations: dict[
            str,
            tuple[
                ApprovalRevalidationDecision,
                AuthorizationDecision,
            ],
        ] = {}

        # Phase 6D-B: successful currentness gates consume
        # one exact trusted 6D-A binding ID once per process.
        # This grants no device or command authority.
        self._consumed_execution_bindings: set[str] = set()

    def create_challenge(
        self,
        request: AuthorizationRequest,
        record: DriveRecord,
    ) -> ApprovalChallenge:
        decision = (
            evaluate_current_authorization_prerequisites(
                request,
                record,
            )
        )

        if (
            not decision_integrity_valid(decision)
            or not decision_is_current(decision)
            or decision.status
            != STATUS_PREREQUISITES_MET
            or decision.request_hash is None
            or decision.record_snapshot_hash is None
            or decision.target_binding_hash is None
        ):
            raise ApprovalError(
                "fresh authorization prerequisites "
                "are not met"
            )

        now = _aware_utc(_utc_now())

        if now is None:
            raise ApprovalError(
                "internal clock did not return "
                "an aware timestamp"
            )

        try:
            evaluated_at = _parse_utc(
                decision.evaluated_at_utc,
                "decision.evaluated_at_utc",
            )

            captured_at = _parse_utc(
                decision.discovery_captured_at_utc,
                "decision.discovery_captured_at_utc",
            )

            prerequisite_valid_until = _parse_utc(
                decision.prerequisite_valid_until_utc,
                "decision.prerequisite_valid_until_utc",
            )
        except AuthorizationError as exc:
            raise ApprovalError(
                "fresh prerequisite timestamps "
                "are invalid"
            ) from exc

        lower_reference = max(
            evaluated_at,
            captured_at,
        )

        if (
            now
            < lower_reference
            - timedelta(
                seconds=MAX_FUTURE_SKEW_SECONDS
            )
        ):
            raise ApprovalError(
                "internal clock rolled back after "
                "prerequisite evaluation"
            )

        if now > prerequisite_valid_until:
            raise ApprovalError(
                "fresh prerequisite decision "
                "expired before challenge creation"
            )

        with self._state_lock:
            locked_now = _aware_utc(_utc_now())

            if locked_now is None:
                raise ApprovalError(
                    "internal clock did not return "
                    "an aware timestamp"
                )

            if (
                locked_now
                < lower_reference
                - timedelta(
                    seconds=MAX_FUTURE_SKEW_SECONDS
                )
            ):
                raise ApprovalError(
                    "internal clock rolled back while "
                    "waiting to create challenge"
                )

            if locked_now > prerequisite_valid_until:
                raise ApprovalError(
                    "fresh prerequisite decision "
                    "expired before challenge allocation"
                )

            challenge_id = None

            for _allocation_attempt in range(
                _APPROVAL_TOKEN_ALLOCATION_MAX_ATTEMPTS
            ):
                candidate_challenge_id = (
                    _new_approval_token("apch")
                )

                if (
                    _approval_text(candidate_challenge_id)
                    and candidate_challenge_id.startswith("apch_")
                    and len(candidate_challenge_id) > len("apch_")
                    and candidate_challenge_id
                    not in self._challenges
                ):
                    challenge_id = candidate_challenge_id
                    break

            if challenge_id is None:
                raise ApprovalError(
                    "could not allocate unique challenge_id"
                )

            created_at_utc = _iso_utc(locked_now)

            valid_until_utc = _iso_utc(
                locked_now
                + timedelta(
                    seconds=(
                        APPROVAL_CHALLENGE_LIFETIME_SECONDS
                    )
                )
            )

            payload = _challenge_payload(
                challenge_id=challenge_id,
                request_id=decision.request_id,
                request_hash=decision.request_hash,
                record_snapshot_hash=(
                    decision.record_snapshot_hash
                ),
                prerequisite_decision_id=(
                    decision.decision_id
                ),
                target_binding_hash=(
                    decision.target_binding_hash
                ),
                created_at_utc=created_at_utc,
                valid_until_utc=valid_until_utc,
            )

            challenge = ApprovalChallenge(
                challenge_id=challenge_id,
                policy_version=APPROVAL_POLICY_VERSION,
                schema_version=SCHEMA_VERSION,
                request_id=decision.request_id,
                request_hash=decision.request_hash,
                record_snapshot_hash=(
                    decision.record_snapshot_hash
                ),
                prerequisite_decision_id=(
                    decision.decision_id
                ),
                target_binding_hash=(
                    decision.target_binding_hash
                ),
                created_at_utc=created_at_utc,
                valid_until_utc=valid_until_utc,
                challenge_hash=_canonical_hash(payload),
            )

            self._challenges[
                challenge_id
            ] = challenge

            return challenge

    def record_human_approval(
        self,
        challenge_id: str,
    ) -> HumanApprovalEvidence:
        """Record a trusted external approval event.

        No approved boolean, caller timestamp,
        caller nonce, AuthorizationDecision, or
        caller-created evidence is accepted.
        """

        if not _approval_text(challenge_id):
            raise ApprovalError(
                "challenge_id is invalid"
            )

        with self._state_lock:
            challenge = self._challenges.get(
                challenge_id
            )

            if (
                challenge is None
                or not _approval_challenge_integrity_valid(
                    challenge
                )
            ):
                raise ApprovalError(
                    "challenge is unknown or invalid"
                )

            if (
                challenge_id
                in self._approved_challenges
            ):
                raise ApprovalError(
                    "challenge has already been approved"
                )

            now = _aware_utc(_utc_now())

            if now is None:
                raise ApprovalError(
                    "internal clock did not return "
                    "an aware timestamp"
                )

            try:
                created_at = _parse_utc(
                    challenge.created_at_utc,
                    "challenge.created_at_utc",
                )

                valid_until = _parse_utc(
                    challenge.valid_until_utc,
                    "challenge.valid_until_utc",
                )
            except AuthorizationError as exc:
                raise ApprovalError(
                    "challenge timestamps are invalid"
                ) from exc

            if (
                now
                < created_at
                - timedelta(
                    seconds=MAX_FUTURE_SKEW_SECONDS
                )
            ):
                raise ApprovalError(
                    "internal clock is behind "
                    "challenge creation"
                )

            if now > valid_until:
                raise ApprovalError(
                    "challenge has expired"
                )

            approval_id = None

            for _allocation_attempt in range(
                _APPROVAL_TOKEN_ALLOCATION_MAX_ATTEMPTS
            ):
                candidate_approval_id = (
                    _new_approval_token("appr")
                )

                if (
                    _approval_text(candidate_approval_id)
                    and candidate_approval_id.startswith("appr_")
                    and len(candidate_approval_id) > len("appr_")
                    and candidate_approval_id
                    not in self._approvals
                ):
                    approval_id = candidate_approval_id
                    break

            if approval_id is None:
                raise ApprovalError(
                    "could not allocate unique approval_id"
                )

            approved_at_utc = _iso_utc(now)

            revalidation_valid_until_utc = _iso_utc(
                now
                + timedelta(
                    seconds=(
                        APPROVAL_REVALIDATION_WINDOW_SECONDS
                    )
                )
            )

            payload = _approval_evidence_payload(
                approval_id=approval_id,
                challenge_id=challenge.challenge_id,
                request_id=challenge.request_id,
                request_hash=challenge.request_hash,
                record_snapshot_hash=(
                    challenge.record_snapshot_hash
                ),
                prerequisite_decision_id=(
                    challenge.prerequisite_decision_id
                ),
                target_binding_hash=(
                    challenge.target_binding_hash
                ),
                approved_at_utc=approved_at_utc,
                revalidation_valid_until_utc=(
                    revalidation_valid_until_utc
                ),
            )

            evidence = HumanApprovalEvidence(
                approval_id=approval_id,
                challenge_id=challenge.challenge_id,
                policy_version=APPROVAL_POLICY_VERSION,
                schema_version=SCHEMA_VERSION,
                request_id=challenge.request_id,
                request_hash=challenge.request_hash,
                record_snapshot_hash=(
                    challenge.record_snapshot_hash
                ),
                prerequisite_decision_id=(
                    challenge.prerequisite_decision_id
                ),
                target_binding_hash=(
                    challenge.target_binding_hash
                ),
                approved_at_utc=approved_at_utc,
                revalidation_valid_until_utc=(
                    revalidation_valid_until_utc
                ),
                evidence_hash=_canonical_hash(payload),
            )

            self._approvals[
                approval_id
            ] = evidence

            self._approved_challenges.add(
                challenge_id
            )

            return evidence

    def revalidate_approval(
        self,
        approval_id: Any,
        request: Any,
        record: Any,
    ) -> ApprovalRevalidationDecision:
        """Consume one approval and collect fresh evidence.

        approval_revalidated means only that one
        registry-recorded approval matched one
        fresh positive prerequisite evaluation.

        It is not execution authority.
        """

        now = _aware_utc(_utc_now())

        if now is None:
            now = datetime(
                1970,
                1,
                1,
                tzinfo=timezone.utc,
            )

        if not _approval_text(approval_id):
            return _approval_revalidation_result(
                approval_id=approval_id,
                evidence=None,
                fresh_decision=None,
                status=(
                    APPROVAL_STATUS_REVALIDATION_FAILED
                ),
                reason_codes=(
                    "APPROVAL_ID_INVALID",
                ),
                evaluated_at=now,
            )

        with self._state_lock:
            evidence = self._approvals.get(
                approval_id
            )

            if evidence is None:
                return _approval_revalidation_result(
                    approval_id=approval_id,
                    evidence=None,
                    fresh_decision=None,
                    status=(
                        APPROVAL_STATUS_REVALIDATION_FAILED
                    ),
                    reason_codes=(
                        "APPROVAL_UNKNOWN",
                    ),
                    evaluated_at=now,
                )

            if (
                approval_id
                in self._consumed_approvals
            ):
                return _approval_revalidation_result(
                    approval_id=approval_id,
                    evidence=evidence,
                    fresh_decision=None,
                    status=(
                        APPROVAL_STATUS_REVALIDATION_FAILED
                    ),
                    reason_codes=(
                        "APPROVAL_ALREADY_CONSUMED",
                    ),
                    evaluated_at=now,
                )

            # One known approval gets exactly one
            # revalidation attempt, success or failure.
            self._consumed_approvals.add(
                approval_id
            )

        if not _approval_evidence_integrity_valid(
            evidence
        ):
            return _approval_revalidation_result(
                approval_id=approval_id,
                evidence=evidence,
                fresh_decision=None,
                status=(
                    APPROVAL_STATUS_REVALIDATION_FAILED
                ),
                reason_codes=(
                    "APPROVAL_EVIDENCE_INVALID",
                ),
                evaluated_at=now,
            )

        challenge = self._challenges.get(
            evidence.challenge_id
        )

        if (
            challenge is None
            or not _approval_challenge_integrity_valid(
                challenge
            )
            or evidence.challenge_id
            not in self._approved_challenges
            or challenge.request_id
            != evidence.request_id
            or challenge.request_hash
            != evidence.request_hash
            or challenge.record_snapshot_hash
            != evidence.record_snapshot_hash
            or challenge.prerequisite_decision_id
            != evidence.prerequisite_decision_id
            or challenge.target_binding_hash
            != evidence.target_binding_hash
        ):
            return _approval_revalidation_result(
                approval_id=approval_id,
                evidence=evidence,
                fresh_decision=None,
                status=(
                    APPROVAL_STATUS_REVALIDATION_FAILED
                ),
                reason_codes=(
                    "APPROVAL_PROVENANCE_INVALID",
                ),
                evaluated_at=now,
            )

        try:
            approved_at = _parse_utc(
                evidence.approved_at_utc,
                "evidence.approved_at_utc",
            )

            valid_until = _parse_utc(
                evidence.revalidation_valid_until_utc,
                (
                    "evidence."
                    "revalidation_valid_until_utc"
                ),
            )
        except AuthorizationError:
            return _approval_revalidation_result(
                approval_id=approval_id,
                evidence=evidence,
                fresh_decision=None,
                status=(
                    APPROVAL_STATUS_REVALIDATION_FAILED
                ),
                reason_codes=(
                    "APPROVAL_EVIDENCE_INVALID",
                ),
                evaluated_at=now,
            )

        if (
            now
            < approved_at
            - timedelta(
                seconds=MAX_FUTURE_SKEW_SECONDS
            )
        ):
            return _approval_revalidation_result(
                approval_id=approval_id,
                evidence=evidence,
                fresh_decision=None,
                status=(
                    APPROVAL_STATUS_REVALIDATION_FAILED
                ),
                reason_codes=(
                    "APPROVAL_CLOCK_INVALID",
                ),
                evaluated_at=now,
            )

        if now > valid_until:
            return _approval_revalidation_result(
                approval_id=approval_id,
                evidence=evidence,
                fresh_decision=None,
                status=(
                    APPROVAL_STATUS_REVALIDATION_FAILED
                ),
                reason_codes=(
                    "APPROVAL_EXPIRED",
                ),
                evaluated_at=now,
            )

        fresh = (
            evaluate_current_authorization_prerequisites(
                request,
                record,
            )
        )

        try:
            fresh_captured_at = _parse_utc(
                fresh.discovery_captured_at_utc,
                "fresh.discovery_captured_at_utc",
            )

            fresh_evaluated_at = _parse_utc(
                fresh.evaluated_at_utc,
                "fresh.evaluated_at_utc",
            )
        except Exception:
            return _approval_revalidation_result(
                approval_id=approval_id,
                evidence=evidence,
                fresh_decision=fresh,
                status=(
                    APPROVAL_STATUS_REVALIDATION_FAILED
                ),
                reason_codes=(
                    "FRESH_DECISION_INVALID",
                ),
                evaluated_at=now,
            )

        fresh_lower_reference = max(
            approved_at,
            now,
        )

        if (
            fresh_captured_at
            < fresh_lower_reference
            - timedelta(
                seconds=MAX_FUTURE_SKEW_SECONDS
            )
            or fresh_evaluated_at
            < fresh_lower_reference
            - timedelta(
                seconds=MAX_FUTURE_SKEW_SECONDS
            )
        ):
            return _approval_revalidation_result(
                approval_id=approval_id,
                evidence=evidence,
                fresh_decision=fresh,
                status=(
                    APPROVAL_STATUS_REVALIDATION_FAILED
                ),
                reason_codes=(
                    "FRESH_CLOCK_INVALID",
                ),
                evaluated_at=now,
            )

        if fresh_evaluated_at > valid_until:
            return _approval_revalidation_result(
                approval_id=approval_id,
                evidence=evidence,
                fresh_decision=fresh,
                status=(
                    APPROVAL_STATUS_REVALIDATION_FAILED
                ),
                reason_codes=(
                    "REVALIDATION_WINDOW_EXPIRED",
                ),
                evaluated_at=fresh_evaluated_at,
            )

        if not decision_integrity_valid(fresh):
            return _approval_revalidation_result(
                approval_id=approval_id,
                evidence=evidence,
                fresh_decision=fresh,
                status=(
                    APPROVAL_STATUS_REVALIDATION_FAILED
                ),
                reason_codes=(
                    "FRESH_DECISION_INVALID",
                ),
                evaluated_at=fresh_evaluated_at,
            )

        if (
            fresh.status
            != STATUS_PREREQUISITES_MET
        ):
            return _approval_revalidation_result(
                approval_id=approval_id,
                evidence=evidence,
                fresh_decision=fresh,
                status=(
                    APPROVAL_STATUS_REVALIDATION_FAILED
                ),
                reason_codes=(
                    "FRESH_PREREQUISITES_NOT_MET",
                ),
                evaluated_at=fresh_evaluated_at,
            )

        if not decision_is_current(fresh):
            return _approval_revalidation_result(
                approval_id=approval_id,
                evidence=evidence,
                fresh_decision=fresh,
                status=(
                    APPROVAL_STATUS_REVALIDATION_FAILED
                ),
                reason_codes=(
                    "FRESH_DECISION_NOT_CURRENT",
                ),
                evaluated_at=fresh_evaluated_at,
            )

        if (
            fresh.request_id
            != evidence.request_id
            or fresh.request_hash
            != evidence.request_hash
        ):
            return _approval_revalidation_result(
                approval_id=approval_id,
                evidence=evidence,
                fresh_decision=fresh,
                status=(
                    APPROVAL_STATUS_REVALIDATION_FAILED
                ),
                reason_codes=(
                    "REQUEST_CHANGED",
                ),
                evaluated_at=fresh_evaluated_at,
            )

        if (
            fresh.record_snapshot_hash
            != evidence.record_snapshot_hash
        ):
            return _approval_revalidation_result(
                approval_id=approval_id,
                evidence=evidence,
                fresh_decision=fresh,
                status=(
                    APPROVAL_STATUS_REVALIDATION_FAILED
                ),
                reason_codes=(
                    "RECORD_CHANGED",
                ),
                evaluated_at=fresh_evaluated_at,
            )

        if (
            fresh.target_binding_hash
            != evidence.target_binding_hash
        ):
            return _approval_revalidation_result(
                approval_id=approval_id,
                evidence=evidence,
                fresh_decision=fresh,
                status=(
                    APPROVAL_STATUS_REVALIDATION_FAILED
                ),
                reason_codes=(
                    "TARGET_BINDING_CHANGED",
                ),
                evaluated_at=fresh_evaluated_at,
            )

        result = _approval_revalidation_result(
            approval_id=approval_id,
            evidence=evidence,
            fresh_decision=fresh,
            status=APPROVAL_STATUS_REVALIDATED,
            reason_codes=(),
            evaluated_at=fresh_evaluated_at,
        )

        with self._state_lock:
            if approval_id in self._successful_revalidations:
                raise ApprovalError(
                    "successful revalidation was already retained"
                )

            self._successful_revalidations[
                approval_id
            ] = (
                result,
                fresh,
            )

        return result


EXECUTION_BINDING_POLICY_VERSION = (
    "phase6d-a-execution-binding-v2"
)
EXECUTION_BINDING_SCHEMA_VERSION = 1
EXECUTION_BINDING_STATUS_SATISFIED = (
    "execution_binding_satisfied"
)


class TrustedExecutionBindingError(
    AuthorizationError
):
    """Trusted execution-binding inputs failed closed."""


@dataclass(frozen=True)
class TrustedExecutionBindingDecision:
    """Deterministic process-local execution-binding foundation.

    A satisfied binding means exact registry-produced approval/revalidation
    provenance, request identity, record snapshot, target binding, method
    policy, and method constraints all agree.

    It is not execution authorization, does not prove currentness at a later
    time, and contains no command, executor, callback, or mutation authority.
    """

    binding_id: str
    policy_version: str
    schema_version: int
    status: str
    approval_id: str
    challenge_id: str
    approval_evidence_hash: str
    revalidation_id: str
    request_id: str
    request_hash: str
    record_snapshot_hash: str
    original_prerequisite_decision_id: str
    fresh_prerequisite_decision_id: str
    method_profile_id: str
    operation: str
    target_binding_hash: str
    constraint_evaluation_hash: str
    revalidated_at_utc: str
    prerequisite_valid_until_utc: str


def _trusted_execution_binding_payload(
    *,
    policy_version: str,
    schema_version: int,
    status: str,
    approval_id: str,
    challenge_id: str,
    approval_evidence_hash: str,
    revalidation_id: str,
    request_id: str,
    request_hash: str,
    record_snapshot_hash: str,
    original_prerequisite_decision_id: str,
    fresh_prerequisite_decision_id: str,
    method_profile_id: str,
    operation: str,
    target_binding_hash: str,
    constraint_evaluation_hash: str,
    revalidated_at_utc: str,
    prerequisite_valid_until_utc: str,
) -> dict[str, Any]:
    return {
        "policy_version": policy_version,
        "schema_version": schema_version,
        "status": status,
        "approval_id": approval_id,
        "challenge_id": challenge_id,
        "approval_evidence_hash": approval_evidence_hash,
        "revalidation_id": revalidation_id,
        "request_id": request_id,
        "request_hash": request_hash,
        "record_snapshot_hash": record_snapshot_hash,
        "original_prerequisite_decision_id":
            original_prerequisite_decision_id,
        "fresh_prerequisite_decision_id":
            fresh_prerequisite_decision_id,
        "method_profile_id": method_profile_id,
        "operation": operation,
        "target_binding_hash": target_binding_hash,
        "constraint_evaluation_hash":
            constraint_evaluation_hash,
        "revalidated_at_utc": revalidated_at_utc,
        "prerequisite_valid_until_utc":
            prerequisite_valid_until_utc,
    }


def _trusted_execution_binding_integrity_valid(
    binding: Any,
) -> bool:
    """Check binding-object internal consistency only.

    This helper does not prove registry provenance by itself.
    """

    try:
        if not isinstance(
            binding,
            TrustedExecutionBindingDecision,
        ):
            return False

        if (
            binding.policy_version
            != EXECUTION_BINDING_POLICY_VERSION
            or type(binding.schema_version) is not int
            or binding.schema_version
            != EXECUTION_BINDING_SCHEMA_VERSION
            or binding.status
            != EXECUTION_BINDING_STATUS_SATISFIED
        ):
            return False

        for value in (
            binding.approval_id,
            binding.challenge_id,
            binding.request_id,
        ):
            if not _approval_text(value):
                return False

        for value in (
            binding.method_profile_id,
            binding.operation,
        ):
            if not _synthetic_plan_exact_text(value):
                return False

        for hash_value in (
            binding.approval_evidence_hash,
            binding.revalidation_id,
            binding.request_hash,
            binding.record_snapshot_hash,
            binding.original_prerequisite_decision_id,
            binding.fresh_prerequisite_decision_id,
            binding.target_binding_hash,
            binding.constraint_evaluation_hash,
        ):
            if not _synthetic_plan_hash_value(
                hash_value
            ):
                return False

        if (
            not isinstance(binding.binding_id, str)
            or not binding.binding_id.startswith("xeb_")
            or len(binding.binding_id)
            != len("xeb_") + 64
            or not all(
                character in "0123456789abcdef"
                for character
                in binding.binding_id[len("xeb_"):]
            )
        ):
            return False

        revalidated_at = _parse_utc(
            binding.revalidated_at_utc,
            "binding.revalidated_at_utc",
        )

        valid_until = _parse_utc(
            binding.prerequisite_valid_until_utc,
            "binding.prerequisite_valid_until_utc",
        )

        if (
            _iso_utc(revalidated_at)
            != binding.revalidated_at_utc
            or _iso_utc(valid_until)
            != binding.prerequisite_valid_until_utc
            or revalidated_at > valid_until
        ):
            return False

        payload = _trusted_execution_binding_payload(
            policy_version=binding.policy_version,
            schema_version=binding.schema_version,
            status=binding.status,
            approval_id=binding.approval_id,
            challenge_id=binding.challenge_id,
            approval_evidence_hash=(
                binding.approval_evidence_hash
            ),
            revalidation_id=binding.revalidation_id,
            request_id=binding.request_id,
            request_hash=binding.request_hash,
            record_snapshot_hash=(
                binding.record_snapshot_hash
            ),
            original_prerequisite_decision_id=(
                binding.original_prerequisite_decision_id
            ),
            fresh_prerequisite_decision_id=(
                binding.fresh_prerequisite_decision_id
            ),
            method_profile_id=binding.method_profile_id,
            operation=binding.operation,
            target_binding_hash=(
                binding.target_binding_hash
            ),
            constraint_evaluation_hash=(
                binding.constraint_evaluation_hash
            ),
            revalidated_at_utc=(
                binding.revalidated_at_utc
            ),
            prerequisite_valid_until_utc=(
                binding.prerequisite_valid_until_utc
            ),
        )

        expected_hash = _canonical_hash(payload)

        return (
            binding.binding_id
            == (
                "xeb_"
                + expected_hash.split(":", 1)[1]
            )
        )

    except Exception:
        return False


def build_trusted_execution_binding(
    *,
    registry: Any,
    approval_id: Any,
    request: Any,
    record: Any,
) -> TrustedExecutionBindingDecision:
    """Build a non-executing binding from registry-held success evidence.

    Caller-created approval evidence, revalidation decisions, fresh
    prerequisite decisions, and constraint decisions are not accepted.
    The function performs no discovery, approval event, external I/O,
    command construction, or mutation.
    """

    if not isinstance(
        registry,
        ApprovalRegistry,
    ):
        raise TrustedExecutionBindingError(
            "registry is invalid"
        )

    if not _approval_text(approval_id):
        raise TrustedExecutionBindingError(
            "approval_id is invalid"
        )

    if not isinstance(
        request,
        AuthorizationRequest,
    ):
        raise TrustedExecutionBindingError(
            "request is invalid"
        )

    if not isinstance(record, DriveRecord):
        raise TrustedExecutionBindingError(
            "record is invalid"
        )

    try:
        record.validate()
        current_record_hash = (
            record_snapshot_hash(record)
        )
        current_request_hash = (
            request_hash(request)
        )
    except Exception as exc:
        raise TrustedExecutionBindingError(
            "request or record validation failed"
        ) from exc

    with registry._state_lock:
        evidence = registry._approvals.get(
            approval_id
        )

        retained = (
            registry._successful_revalidations.get(
                approval_id
            )
        )

        if isinstance(
            evidence,
            HumanApprovalEvidence,
        ):
            challenge = registry._challenges.get(
                evidence.challenge_id
            )
        else:
            challenge = None

        challenge_approved = (
            isinstance(
                evidence,
                HumanApprovalEvidence,
            )
            and evidence.challenge_id
            in registry._approved_challenges
        )

        approval_consumed = (
            approval_id
            in registry._consumed_approvals
        )

    if (
        evidence is None
        or challenge is None
        or retained is None
        or not challenge_approved
        or not approval_consumed
    ):
        raise TrustedExecutionBindingError(
            "successful registry provenance is unavailable"
        )

    if (
        not isinstance(retained, tuple)
        or len(retained) != 2
    ):
        raise TrustedExecutionBindingError(
            "retained success evidence is malformed"
        )

    revalidation, fresh = retained

    if not _approval_evidence_integrity_valid(
        evidence
    ):
        raise TrustedExecutionBindingError(
            "approval evidence integrity is invalid"
        )

    if not _approval_challenge_integrity_valid(
        challenge
    ):
        raise TrustedExecutionBindingError(
            "approval challenge integrity is invalid"
        )

    if (
        challenge.challenge_id
        != evidence.challenge_id
        or challenge.request_id
        != evidence.request_id
        or challenge.request_hash
        != evidence.request_hash
        or challenge.record_snapshot_hash
        != evidence.record_snapshot_hash
        or challenge.prerequisite_decision_id
        != evidence.prerequisite_decision_id
        or challenge.target_binding_hash
        != evidence.target_binding_hash
    ):
        raise TrustedExecutionBindingError(
            "approval challenge/evidence binding is invalid"
        )

    if not isinstance(
        revalidation,
        ApprovalRevalidationDecision,
    ):
        raise TrustedExecutionBindingError(
            "retained revalidation is invalid"
        )

    if not isinstance(
        fresh,
        AuthorizationDecision,
    ):
        raise TrustedExecutionBindingError(
            "retained fresh prerequisite decision is invalid"
        )

    if (
        revalidation.status
        != APPROVAL_STATUS_REVALIDATED
        or revalidation.reason_codes != ()
    ):
        raise TrustedExecutionBindingError(
            "retained revalidation was not successful"
        )

    try:
        revalidated_at = _parse_utc(
            revalidation.evaluated_at_utc,
            "revalidation.evaluated_at_utc",
        )
    except AuthorizationError as exc:
        raise TrustedExecutionBindingError(
            "retained revalidation timestamp is invalid"
        ) from exc

    expected_revalidation = (
        _approval_revalidation_result(
            approval_id=approval_id,
            evidence=evidence,
            fresh_decision=fresh,
            status=APPROVAL_STATUS_REVALIDATED,
            reason_codes=(),
            evaluated_at=revalidated_at,
        )
    )

    if revalidation != expected_revalidation:
        raise TrustedExecutionBindingError(
            "retained revalidation integrity is invalid"
        )

    if (
        revalidation.approval_id
        != evidence.approval_id
        or revalidation.challenge_id
        != evidence.challenge_id
        or revalidation.request_id
        != evidence.request_id
        or revalidation.original_prerequisite_decision_id
        != evidence.prerequisite_decision_id
        or revalidation.original_target_binding_hash
        != evidence.target_binding_hash
    ):
        raise TrustedExecutionBindingError(
            "retained revalidation provenance mismatch"
        )

    if not decision_integrity_valid(fresh):
        raise TrustedExecutionBindingError(
            "fresh prerequisite decision integrity is invalid"
        )

    if (
        fresh.status != STATUS_PREREQUISITES_MET
        or fresh.reason_codes != ()
        or fresh.request_hash is None
        or fresh.record_snapshot_hash is None
        or fresh.target_binding_hash is None
        or fresh.target_binding is None
        or fresh.prerequisite_valid_until_utc is None
    ):
        raise TrustedExecutionBindingError(
            "fresh prerequisite decision is not positive and complete"
        )

    if (
        revalidation.fresh_prerequisite_decision_id
        != fresh.decision_id
        or revalidation.fresh_target_binding_hash
        != fresh.target_binding_hash
    ):
        raise TrustedExecutionBindingError(
            "fresh prerequisite/revalidation binding mismatch"
        )

    if (
        request.schema_version != SCHEMA_VERSION
        or request.request_id != evidence.request_id
        or current_request_hash
        != evidence.request_hash
        or fresh.request_id != request.request_id
        or fresh.request_hash
        != current_request_hash
    ):
        raise TrustedExecutionBindingError(
            "authorization request binding mismatch"
        )

    if (
        request.batch_job_id
        != record.batch_job_id
        or request.internal_record_id
        != record.internal_record_id
        or request.record_snapshot_hash
        != current_record_hash
        or evidence.record_snapshot_hash
        != current_record_hash
        or fresh.record_snapshot_hash
        != current_record_hash
    ):
        raise TrustedExecutionBindingError(
            "drive record snapshot binding mismatch"
        )

    policy = get_sanitization_method_policy(
        request.method_profile_id
    )

    metadata = (
        get_sanitization_method_capability_metadata(
            request.method_profile_id
        )
    )

    if policy is None or metadata is None:
        raise TrustedExecutionBindingError(
            "trusted method metadata is unavailable"
        )

    if (
        policy.method_profile_id
        != request.method_profile_id
        or metadata.method_profile_id
        != request.method_profile_id
        or policy.operation != request.operation
        or policy.policy_only is not True
        or policy.execution_supported is not False
        or metadata.capability_class != "policy_only"
    ):
        raise TrustedExecutionBindingError(
            "trusted method binding mismatch"
        )

    target_binding_hash = _canonical_hash(
        asdict(fresh.target_binding)
    )

    if (
        target_binding_hash
        != fresh.target_binding_hash
        or target_binding_hash
        != evidence.target_binding_hash
        or target_binding_hash
        != revalidation.original_target_binding_hash
        or target_binding_hash
        != revalidation.fresh_target_binding_hash
    ):
        raise TrustedExecutionBindingError(
            "target binding provenance mismatch"
        )

    constraints = (
        evaluate_sanitization_method_constraints(
            request.method_profile_id,
            fresh.target_binding,
        )
    )

    if (
        constraints.method_profile_id
        != request.method_profile_id
        or constraints.status
        != METHOD_CONSTRAINT_STATUS_SATISFIED
        or constraints.reason_codes != ()
        or constraints.target_binding_hash
        != target_binding_hash
    ):
        raise TrustedExecutionBindingError(
            "method constraints are not satisfied"
        )

    constraint_hash = _canonical_hash(
        asdict(constraints)
    )

    try:
        prerequisite_valid_until = _parse_utc(
            fresh.prerequisite_valid_until_utc,
            "fresh.prerequisite_valid_until_utc",
        )
    except AuthorizationError as exc:
        raise TrustedExecutionBindingError(
            "fresh prerequisite expiry is invalid"
        ) from exc

    if revalidated_at > prerequisite_valid_until:
        raise TrustedExecutionBindingError(
            "revalidation occurred after prerequisite expiry"
        )

    payload = _trusted_execution_binding_payload(
        policy_version=EXECUTION_BINDING_POLICY_VERSION,
        schema_version=EXECUTION_BINDING_SCHEMA_VERSION,
        status=EXECUTION_BINDING_STATUS_SATISFIED,
        approval_id=approval_id,
        challenge_id=evidence.challenge_id,
        approval_evidence_hash=evidence.evidence_hash,
        revalidation_id=revalidation.revalidation_id,
        request_id=request.request_id,
        request_hash=current_request_hash,
        record_snapshot_hash=current_record_hash,
        original_prerequisite_decision_id=(
            evidence.prerequisite_decision_id
        ),
        fresh_prerequisite_decision_id=(
            fresh.decision_id
        ),
        method_profile_id=request.method_profile_id,
        operation=request.operation,
        target_binding_hash=target_binding_hash,
        constraint_evaluation_hash=constraint_hash,
        revalidated_at_utc=(
            revalidation.evaluated_at_utc
        ),
        prerequisite_valid_until_utc=(
            fresh.prerequisite_valid_until_utc
        ),
    )

    payload_hash = _canonical_hash(payload)

    binding = TrustedExecutionBindingDecision(
        binding_id=(
            "xeb_"
            + payload_hash.split(":", 1)[1]
        ),
        policy_version=EXECUTION_BINDING_POLICY_VERSION,
        schema_version=EXECUTION_BINDING_SCHEMA_VERSION,
        status=EXECUTION_BINDING_STATUS_SATISFIED,
        approval_id=approval_id,
        challenge_id=evidence.challenge_id,
        approval_evidence_hash=evidence.evidence_hash,
        revalidation_id=revalidation.revalidation_id,
        request_id=request.request_id,
        request_hash=current_request_hash,
        record_snapshot_hash=current_record_hash,
        original_prerequisite_decision_id=(
            evidence.prerequisite_decision_id
        ),
        fresh_prerequisite_decision_id=(
            fresh.decision_id
        ),
        method_profile_id=request.method_profile_id,
        operation=request.operation,
        target_binding_hash=target_binding_hash,
        constraint_evaluation_hash=constraint_hash,
        revalidated_at_utc=(
            revalidation.evaluated_at_utc
        ),
        prerequisite_valid_until_utc=(
            fresh.prerequisite_valid_until_utc
        ),
    )

    if not _trusted_execution_binding_integrity_valid(
        binding
    ):
        raise TrustedExecutionBindingError(
            "constructed execution binding failed integrity validation"
        )

    return binding

EXECUTION_GATE_POLICY_VERSION = (
    "phase6d-b-one-shot-currentness-v1"
)
EXECUTION_GATE_SCHEMA_VERSION = 1
EXECUTION_GATE_STATUS_SATISFIED = (
    "execution_gate_satisfied"
)


class OneShotExecutionGateError(
    AuthorizationError
):
    """One-shot execution-gate conditions failed closed."""


@dataclass(frozen=True)
class OneShotExecutionGateDecision:
    """Frozen evidence that one trusted binding passed a time gate.

    A satisfied gate proves only that the exact 6D-A binding was current
    when this process atomically consumed that binding ID.

    It is not an executor, command, device capability, sanitization result,
    verification result, or physical-device success claim.
    """

    gate_id: str
    policy_version: str
    schema_version: int
    status: str
    binding_id: str
    approval_id: str
    challenge_id: str
    approval_evidence_hash: str
    revalidation_id: str
    request_id: str
    request_hash: str
    record_snapshot_hash: str
    fresh_prerequisite_decision_id: str
    method_profile_id: str
    operation: str
    target_binding_hash: str
    constraint_evaluation_hash: str
    evaluated_at_utc: str
    prerequisite_valid_until_utc: str


def _one_shot_execution_gate_payload(
    *,
    policy_version: str,
    schema_version: int,
    status: str,
    binding_id: str,
    approval_id: str,
    challenge_id: str,
    approval_evidence_hash: str,
    revalidation_id: str,
    request_id: str,
    request_hash: str,
    record_snapshot_hash: str,
    fresh_prerequisite_decision_id: str,
    method_profile_id: str,
    operation: str,
    target_binding_hash: str,
    constraint_evaluation_hash: str,
    evaluated_at_utc: str,
    prerequisite_valid_until_utc: str,
) -> dict[str, Any]:
    return {
        "policy_version": policy_version,
        "schema_version": schema_version,
        "status": status,
        "binding_id": binding_id,
        "approval_id": approval_id,
        "challenge_id": challenge_id,
        "approval_evidence_hash":
            approval_evidence_hash,
        "revalidation_id": revalidation_id,
        "request_id": request_id,
        "request_hash": request_hash,
        "record_snapshot_hash":
            record_snapshot_hash,
        "fresh_prerequisite_decision_id":
            fresh_prerequisite_decision_id,
        "method_profile_id": method_profile_id,
        "operation": operation,
        "target_binding_hash":
            target_binding_hash,
        "constraint_evaluation_hash":
            constraint_evaluation_hash,
        "evaluated_at_utc": evaluated_at_utc,
        "prerequisite_valid_until_utc":
            prerequisite_valid_until_utc,
    }


def _one_shot_execution_gate_integrity_valid(
    gate: Any,
) -> bool:
    """Check gate-object internal consistency only."""

    try:
        if not isinstance(
            gate,
            OneShotExecutionGateDecision,
        ):
            return False

        if (
            gate.policy_version
            != EXECUTION_GATE_POLICY_VERSION
            or type(gate.schema_version) is not int
            or gate.schema_version
            != EXECUTION_GATE_SCHEMA_VERSION
            or gate.status
            != EXECUTION_GATE_STATUS_SATISFIED
        ):
            return False

        if (
            not isinstance(gate.binding_id, str)
            or not gate.binding_id.startswith("xeb_")
            or len(gate.binding_id)
            != len("xeb_") + 64
            or not all(
                character in "0123456789abcdef"
                for character
                in gate.binding_id[len("xeb_"):]
            )
        ):
            return False

        if (
            not isinstance(gate.gate_id, str)
            or not gate.gate_id.startswith("xgate_")
            or len(gate.gate_id)
            != len("xgate_") + 64
            or not all(
                character in "0123456789abcdef"
                for character
                in gate.gate_id[len("xgate_"):]
            )
        ):
            return False

        for value in (
            gate.approval_id,
            gate.challenge_id,
            gate.request_id,
        ):
            if not _approval_text(value):
                return False

        for value in (
            gate.method_profile_id,
            gate.operation,
        ):
            if not _synthetic_plan_exact_text(value):
                return False

        for hash_value in (
            gate.approval_evidence_hash,
            gate.revalidation_id,
            gate.request_hash,
            gate.record_snapshot_hash,
            gate.fresh_prerequisite_decision_id,
            gate.target_binding_hash,
            gate.constraint_evaluation_hash,
        ):
            if not _synthetic_plan_hash_value(
                hash_value
            ):
                return False

        evaluated_at = _parse_utc(
            gate.evaluated_at_utc,
            "gate.evaluated_at_utc",
        )

        valid_until = _parse_utc(
            gate.prerequisite_valid_until_utc,
            "gate.prerequisite_valid_until_utc",
        )

        if (
            _iso_utc(evaluated_at)
            != gate.evaluated_at_utc
            or _iso_utc(valid_until)
            != gate.prerequisite_valid_until_utc
            or evaluated_at > valid_until
        ):
            return False

        payload = _one_shot_execution_gate_payload(
            policy_version=gate.policy_version,
            schema_version=gate.schema_version,
            status=gate.status,
            binding_id=gate.binding_id,
            approval_id=gate.approval_id,
            challenge_id=gate.challenge_id,
            approval_evidence_hash=(
                gate.approval_evidence_hash
            ),
            revalidation_id=gate.revalidation_id,
            request_id=gate.request_id,
            request_hash=gate.request_hash,
            record_snapshot_hash=(
                gate.record_snapshot_hash
            ),
            fresh_prerequisite_decision_id=(
                gate.fresh_prerequisite_decision_id
            ),
            method_profile_id=gate.method_profile_id,
            operation=gate.operation,
            target_binding_hash=(
                gate.target_binding_hash
            ),
            constraint_evaluation_hash=(
                gate.constraint_evaluation_hash
            ),
            evaluated_at_utc=gate.evaluated_at_utc,
            prerequisite_valid_until_utc=(
                gate.prerequisite_valid_until_utc
            ),
        )

        expected_hash = _canonical_hash(payload)

        return (
            gate.gate_id
            == (
                "xgate_"
                + expected_hash.split(":", 1)[1]
            )
        )

    except Exception:
        return False


def satisfy_one_shot_execution_gate(
    *,
    registry: Any,
    approval_id: Any,
    request: Any,
    record: Any,
) -> OneShotExecutionGateDecision:
    """Atomically consume one current registry-backed 6D-A binding."""

    if not isinstance(
        registry,
        ApprovalRegistry,
    ):
        raise OneShotExecutionGateError(
            "registry is invalid"
        )

    try:
        binding = build_trusted_execution_binding(
            registry=registry,
            approval_id=approval_id,
            request=request,
            record=record,
        )
    except TrustedExecutionBindingError as exc:
        raise OneShotExecutionGateError(
            "trusted execution binding is unavailable"
        ) from exc

    if not _trusted_execution_binding_integrity_valid(
        binding
    ):
        raise OneShotExecutionGateError(
            "trusted execution binding integrity is invalid"
        )

    try:
        revalidated_at = _parse_utc(
            binding.revalidated_at_utc,
            "binding.revalidated_at_utc",
        )

        valid_until = _parse_utc(
            binding.prerequisite_valid_until_utc,
            "binding.prerequisite_valid_until_utc",
        )
    except AuthorizationError as exc:
        raise OneShotExecutionGateError(
            "execution binding timestamps are invalid"
        ) from exc

    first_now = _aware_utc(_utc_now())

    if first_now is None:
        raise OneShotExecutionGateError(
            "internal clock is invalid"
        )

    if (
        first_now
        < revalidated_at
        - timedelta(
            seconds=MAX_FUTURE_SKEW_SECONDS
        )
    ):
        raise OneShotExecutionGateError(
            "internal clock rolled back before gate evaluation"
        )

    if first_now > valid_until:
        raise OneShotExecutionGateError(
            "execution binding is stale"
        )

    with registry._state_lock:
        evidence = registry._approvals.get(
            approval_id
        )

        retained = (
            registry._successful_revalidations.get(
                approval_id
            )
        )

        challenge = registry._challenges.get(
            binding.challenge_id
        )

        if (
            not isinstance(
                evidence,
                HumanApprovalEvidence,
            )
            or not isinstance(
                challenge,
                ApprovalChallenge,
            )
            or not isinstance(retained, tuple)
            or len(retained) != 2
            or approval_id
            not in registry._consumed_approvals
            or challenge.challenge_id
            not in registry._approved_challenges
        ):
            raise OneShotExecutionGateError(
                "registry provenance changed before gate consumption"
            )

        revalidation, fresh = retained

        if (
            not isinstance(
                revalidation,
                ApprovalRevalidationDecision,
            )
            or not isinstance(
                fresh,
                AuthorizationDecision,
            )
            or evidence.approval_id
            != binding.approval_id
            or evidence.challenge_id
            != binding.challenge_id
            or evidence.evidence_hash
            != binding.approval_evidence_hash
            or revalidation.revalidation_id
            != binding.revalidation_id
            or revalidation.request_id
            != binding.request_id
            or revalidation.evaluated_at_utc
            != binding.revalidated_at_utc
            or fresh.decision_id
            != binding.fresh_prerequisite_decision_id
            or fresh.request_hash
            != binding.request_hash
            or fresh.record_snapshot_hash
            != binding.record_snapshot_hash
            or fresh.target_binding_hash
            != binding.target_binding_hash
            or fresh.prerequisite_valid_until_utc
            != binding.prerequisite_valid_until_utc
        ):
            raise OneShotExecutionGateError(
                "registry evidence changed before gate consumption"
            )

        if (
            binding.binding_id
            in registry._consumed_execution_bindings
        ):
            raise OneShotExecutionGateError(
                "execution binding has already been consumed"
            )

        locked_now = _aware_utc(_utc_now())

        if locked_now is None:
            raise OneShotExecutionGateError(
                "internal clock is invalid under gate lock"
            )

        locked_lower_reference = max(
            revalidated_at,
            first_now,
        )

        if (
            locked_now
            < locked_lower_reference
            - timedelta(
                seconds=MAX_FUTURE_SKEW_SECONDS
            )
        ):
            raise OneShotExecutionGateError(
                "internal clock rolled back while waiting for gate lock"
            )

        if locked_now > valid_until:
            raise OneShotExecutionGateError(
                "execution binding expired before atomic consumption"
            )

        evaluated_at_utc = _iso_utc(
            locked_now
        )

        payload = _one_shot_execution_gate_payload(
            policy_version=(
                EXECUTION_GATE_POLICY_VERSION
            ),
            schema_version=(
                EXECUTION_GATE_SCHEMA_VERSION
            ),
            status=(
                EXECUTION_GATE_STATUS_SATISFIED
            ),
            binding_id=binding.binding_id,
            approval_id=binding.approval_id,
            challenge_id=binding.challenge_id,
            approval_evidence_hash=(
                binding.approval_evidence_hash
            ),
            revalidation_id=binding.revalidation_id,
            request_id=binding.request_id,
            request_hash=binding.request_hash,
            record_snapshot_hash=(
                binding.record_snapshot_hash
            ),
            fresh_prerequisite_decision_id=(
                binding.fresh_prerequisite_decision_id
            ),
            method_profile_id=(
                binding.method_profile_id
            ),
            operation=binding.operation,
            target_binding_hash=(
                binding.target_binding_hash
            ),
            constraint_evaluation_hash=(
                binding.constraint_evaluation_hash
            ),
            evaluated_at_utc=evaluated_at_utc,
            prerequisite_valid_until_utc=(
                binding.prerequisite_valid_until_utc
            ),
        )

        payload_hash = _canonical_hash(
            payload
        )

        gate = OneShotExecutionGateDecision(
            gate_id=(
                "xgate_"
                + payload_hash.split(":", 1)[1]
            ),
            policy_version=(
                EXECUTION_GATE_POLICY_VERSION
            ),
            schema_version=(
                EXECUTION_GATE_SCHEMA_VERSION
            ),
            status=(
                EXECUTION_GATE_STATUS_SATISFIED
            ),
            binding_id=binding.binding_id,
            approval_id=binding.approval_id,
            challenge_id=binding.challenge_id,
            approval_evidence_hash=(
                binding.approval_evidence_hash
            ),
            revalidation_id=binding.revalidation_id,
            request_id=binding.request_id,
            request_hash=binding.request_hash,
            record_snapshot_hash=(
                binding.record_snapshot_hash
            ),
            fresh_prerequisite_decision_id=(
                binding.fresh_prerequisite_decision_id
            ),
            method_profile_id=(
                binding.method_profile_id
            ),
            operation=binding.operation,
            target_binding_hash=(
                binding.target_binding_hash
            ),
            constraint_evaluation_hash=(
                binding.constraint_evaluation_hash
            ),
            evaluated_at_utc=evaluated_at_utc,
            prerequisite_valid_until_utc=(
                binding.prerequisite_valid_until_utc
            ),
        )

        if not _one_shot_execution_gate_integrity_valid(
            gate
        ):
            raise OneShotExecutionGateError(
                "constructed execution gate failed integrity validation"
            )

        registry._consumed_execution_bindings.add(
            binding.binding_id
        )

        return gate

DURABLE_GATE_JOURNAL_POLICY_VERSION = (
    "phase6d-c-durable-consumption-v1"
)
DURABLE_GATE_JOURNAL_SCHEMA_VERSION = 1
DURABLE_GATE_JOURNAL_MAX_BYTES = 1_048_576

DURABLE_GATE_JOURNAL_STATE_RESERVED = "reserved"
DURABLE_GATE_JOURNAL_STATE_COMPLETED = "completed"


class DurableExecutionGateJournalError(
    AuthorizationError
):
    """Durable execution-gate journal failed closed."""


class DurableOneShotExecutionGateError(
    AuthorizationError
):
    """Durable one-shot gate could not complete safely."""


@dataclass(frozen=True)
class DurableExecutionGateJournalEntry:
    binding_id: str
    state: str
    request_hash: str
    record_snapshot_hash: str
    target_binding_hash: str
    reserved_at_utc: str
    gate_id: Optional[str]
    completed_at_utc: Optional[str]
    entry_hash: str


def _durable_prefixed_hex_id(
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


def _durable_gate_journal_entry_payload(
    *,
    binding_id: str,
    state: str,
    request_hash: str,
    record_snapshot_hash: str,
    target_binding_hash: str,
    reserved_at_utc: str,
    gate_id: Optional[str],
    completed_at_utc: Optional[str],
) -> dict[str, Any]:
    return {
        "binding_id": binding_id,
        "state": state,
        "request_hash": request_hash,
        "record_snapshot_hash":
            record_snapshot_hash,
        "target_binding_hash":
            target_binding_hash,
        "reserved_at_utc": reserved_at_utc,
        "gate_id": gate_id,
        "completed_at_utc": completed_at_utc,
    }


def _durable_gate_journal_entry_integrity_valid(
    entry: Any,
) -> bool:
    try:
        if not isinstance(
            entry,
            DurableExecutionGateJournalEntry,
        ):
            return False

        if not _durable_prefixed_hex_id(
            entry.binding_id,
            "xeb_",
        ):
            return False

        if entry.state not in (
            DURABLE_GATE_JOURNAL_STATE_RESERVED,
            DURABLE_GATE_JOURNAL_STATE_COMPLETED,
        ):
            return False

        for hash_value in (
            entry.request_hash,
            entry.record_snapshot_hash,
            entry.target_binding_hash,
            entry.entry_hash,
        ):
            if not _synthetic_plan_hash_value(
                hash_value
            ):
                return False

        reserved_at = _parse_utc(
            entry.reserved_at_utc,
            "entry.reserved_at_utc",
        )

        if (
            _iso_utc(reserved_at)
            != entry.reserved_at_utc
        ):
            return False

        if (
            entry.state
            == DURABLE_GATE_JOURNAL_STATE_RESERVED
        ):
            if (
                entry.gate_id is not None
                or entry.completed_at_utc is not None
            ):
                return False

        else:
            if not _durable_prefixed_hex_id(
                entry.gate_id,
                "xgate_",
            ):
                return False

            if entry.completed_at_utc is None:
                return False

            completed_at = _parse_utc(
                entry.completed_at_utc,
                "entry.completed_at_utc",
            )

            if (
                _iso_utc(completed_at)
                != entry.completed_at_utc
                or completed_at < reserved_at
            ):
                return False

        payload = _durable_gate_journal_entry_payload(
            binding_id=entry.binding_id,
            state=entry.state,
            request_hash=entry.request_hash,
            record_snapshot_hash=(
                entry.record_snapshot_hash
            ),
            target_binding_hash=(
                entry.target_binding_hash
            ),
            reserved_at_utc=entry.reserved_at_utc,
            gate_id=entry.gate_id,
            completed_at_utc=(
                entry.completed_at_utc
            ),
        )

        return (
            entry.entry_hash
            == _canonical_hash(payload)
        )

    except Exception:
        return False


class DurableExecutionGateConsumptionJournal:
    """Private restart-safe consumption journal.

    Both reserved and completed entries block automatic replay.
    A reserved entry after a crash is intentionally ambiguous and
    requires review rather than automatic retry.
    """

    def __init__(
        self,
        path: Any,
    ) -> None:
        try:
            self._path = Path(
                os.fspath(path)
            )
        except (TypeError, ValueError) as exc:
            raise DurableExecutionGateJournalError(
                "journal path is invalid"
            ) from exc

        if (
            not self._path.is_absolute()
            or not self._path.name
        ):
            raise DurableExecutionGateJournalError(
                "journal path must be an absolute file path"
            )

        self._lock_path = self._path.with_name(
            self._path.name + ".lock"
        )

    @property
    def path(self) -> Path:
        return self._path

    def _validate_parent(self) -> None:
        parent = self._path.parent

        try:
            info = os.lstat(parent)
        except OSError as exc:
            raise DurableExecutionGateJournalError(
                "journal parent is unavailable"
            ) from exc

        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise DurableExecutionGateJournalError(
                "journal parent is not private and trusted"
            )

    def _open_lock(self) -> int:
        self._validate_parent()

        if not hasattr(os, "O_NOFOLLOW"):
            raise DurableExecutionGateJournalError(
                "platform lacks no-follow file support"
            )

        flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_NOFOLLOW
        )

        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC

        try:
            fd = os.open(
                self._lock_path,
                flags,
                0o600,
            )
        except OSError as exc:
            raise DurableExecutionGateJournalError(
                "journal lock file could not be opened safely"
            ) from exc

        try:
            info = os.fstat(fd)

            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode)
                != 0o600
            ):
                raise DurableExecutionGateJournalError(
                    "journal lock file is not private and trusted"
                )

            fcntl.flock(
                fd,
                fcntl.LOCK_EX,
            )

            return fd

        except Exception:
            os.close(fd)
            raise

    @staticmethod
    def _close_lock(fd: int) -> None:
        try:
            fcntl.flock(
                fd,
                fcntl.LOCK_UN,
            )
        finally:
            os.close(fd)

    def _validate_existing_journal_file(
        self,
        info: os.stat_result,
    ) -> None:
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode)
            != 0o600
            or info.st_size
            > DURABLE_GATE_JOURNAL_MAX_BYTES
        ):
            raise DurableExecutionGateJournalError(
                "journal file is not private and trusted"
            )

    def _read_entries_locked(
        self,
    ) -> list[DurableExecutionGateJournalEntry]:
        if not os.path.lexists(self._path):
            return []

        flags = (
            os.O_RDONLY
            | os.O_NOFOLLOW
        )

        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC

        try:
            fd = os.open(
                self._path,
                flags,
            )
        except OSError as exc:
            raise DurableExecutionGateJournalError(
                "journal file could not be opened safely"
            ) from exc

        try:
            info = os.fstat(fd)

            self._validate_existing_journal_file(
                info
            )

            chunks: list[bytes] = []
            total = 0

            while True:
                chunk = os.read(
                    fd,
                    65_536,
                )

                if not chunk:
                    break

                total += len(chunk)

                if (
                    total
                    > DURABLE_GATE_JOURNAL_MAX_BYTES
                ):
                    raise DurableExecutionGateJournalError(
                        "journal file exceeds size limit"
                    )

                chunks.append(chunk)

        finally:
            os.close(fd)

        raw = b"".join(chunks)

        if not raw:
            raise DurableExecutionGateJournalError(
                "journal file is empty"
            )

        try:
            document = json.loads(
                raw.decode("utf-8")
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise DurableExecutionGateJournalError(
                "journal file is malformed"
            ) from exc

        if (
            not isinstance(document, dict)
            or set(document)
            != {
                "policy_version",
                "schema_version",
                "entries",
                "journal_hash",
            }
            or document["policy_version"]
            != DURABLE_GATE_JOURNAL_POLICY_VERSION
            or type(document["schema_version"])
            is not int
            or document["schema_version"]
            != DURABLE_GATE_JOURNAL_SCHEMA_VERSION
            or not isinstance(
                document["entries"],
                list,
            )
            or not _synthetic_plan_hash_value(
                document["journal_hash"]
            )
        ):
            raise DurableExecutionGateJournalError(
                "journal document is invalid"
            )

        expected_keys = {
            "binding_id",
            "state",
            "request_hash",
            "record_snapshot_hash",
            "target_binding_hash",
            "reserved_at_utc",
            "gate_id",
            "completed_at_utc",
            "entry_hash",
        }

        entries = []

        for raw_entry in document["entries"]:
            if (
                not isinstance(raw_entry, dict)
                or set(raw_entry)
                != expected_keys
            ):
                raise DurableExecutionGateJournalError(
                    "journal entry shape is invalid"
                )

            try:
                entry = (
                    DurableExecutionGateJournalEntry(
                        **raw_entry
                    )
                )
            except TypeError as exc:
                raise DurableExecutionGateJournalError(
                    "journal entry could not be decoded"
                ) from exc

            if not (
                _durable_gate_journal_entry_integrity_valid(
                    entry
                )
            ):
                raise DurableExecutionGateJournalError(
                    "journal entry integrity is invalid"
                )

            entries.append(entry)

        binding_ids = [
            entry.binding_id
            for entry in entries
        ]

        if (
            binding_ids
            != sorted(binding_ids)
            or len(binding_ids)
            != len(set(binding_ids))
        ):
            raise DurableExecutionGateJournalError(
                "journal binding IDs are duplicated or unsorted"
            )

        gate_ids = [
            entry.gate_id
            for entry in entries
            if entry.gate_id is not None
        ]

        if len(gate_ids) != len(set(gate_ids)):
            raise DurableExecutionGateJournalError(
                "journal gate IDs are duplicated"
            )

        payload = {
            "policy_version":
                DURABLE_GATE_JOURNAL_POLICY_VERSION,
            "schema_version":
                DURABLE_GATE_JOURNAL_SCHEMA_VERSION,
            "entries": [
                asdict(entry)
                for entry in entries
            ],
        }

        if (
            document["journal_hash"]
            != _canonical_hash(payload)
        ):
            raise DurableExecutionGateJournalError(
                "journal document hash is invalid"
            )

        return entries

    def _write_entries_locked(
        self,
        entries: list[
            DurableExecutionGateJournalEntry
        ],
    ) -> None:
        ordered = sorted(
            entries,
            key=lambda entry: entry.binding_id,
        )

        if (
            len({
                entry.binding_id
                for entry in ordered
            })
            != len(ordered)
        ):
            raise DurableExecutionGateJournalError(
                "journal contains duplicate bindings"
            )

        for entry in ordered:
            if not (
                _durable_gate_journal_entry_integrity_valid(
                    entry
                )
            ):
                raise DurableExecutionGateJournalError(
                    "refusing to write invalid journal entry"
                )

        payload = {
            "policy_version":
                DURABLE_GATE_JOURNAL_POLICY_VERSION,
            "schema_version":
                DURABLE_GATE_JOURNAL_SCHEMA_VERSION,
            "entries": [
                asdict(entry)
                for entry in ordered
            ],
        }

        document = dict(payload)
        document["journal_hash"] = (
            _canonical_hash(payload)
        )

        try:
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
        except (TypeError, ValueError) as exc:
            raise DurableExecutionGateJournalError(
                "journal state is not serializable"
            ) from exc

        if (
            len(encoded)
            > DURABLE_GATE_JOURNAL_MAX_BYTES
        ):
            raise DurableExecutionGateJournalError(
                "journal state exceeds size limit"
            )

        if os.path.lexists(self._path):
            try:
                current = os.lstat(
                    self._path
                )
            except OSError as exc:
                raise DurableExecutionGateJournalError(
                    "existing journal could not be inspected"
                ) from exc

            self._validate_existing_journal_file(
                current
            )

        temp_fd = None
        temp_name = None

        try:
            temp_fd, temp_name = tempfile.mkstemp(
                prefix=(
                    "."
                    + self._path.name
                    + ".tmp."
                ),
                dir=str(self._path.parent),
            )

            os.fchmod(
                temp_fd,
                0o600,
            )

            offset = 0

            while offset < len(encoded):
                written = os.write(
                    temp_fd,
                    encoded[offset:],
                )

                if written <= 0:
                    raise DurableExecutionGateJournalError(
                        "journal temporary write did not progress"
                    )

                offset += written

            os.fsync(temp_fd)
            os.close(temp_fd)
            temp_fd = None

            os.replace(
                temp_name,
                self._path,
            )
            temp_name = None

            final_info = os.lstat(
                self._path
            )

            self._validate_existing_journal_file(
                final_info
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

        except DurableExecutionGateJournalError:
            raise

        except OSError as exc:
            raise DurableExecutionGateJournalError(
                "journal atomic persistence failed"
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

    def _reserve(
        self,
        binding: Any,
    ) -> DurableExecutionGateJournalEntry:
        if (
            not isinstance(
                binding,
                TrustedExecutionBindingDecision,
            )
            or not (
                _trusted_execution_binding_integrity_valid(
                    binding
                )
            )
        ):
            raise DurableExecutionGateJournalError(
                "trusted binding is invalid"
            )

        now = _aware_utc(
            _utc_now()
        )

        if now is None:
            raise DurableExecutionGateJournalError(
                "internal journal clock is invalid"
            )

        reserved_at_utc = _iso_utc(now)

        payload = (
            _durable_gate_journal_entry_payload(
                binding_id=binding.binding_id,
                state=(
                    DURABLE_GATE_JOURNAL_STATE_RESERVED
                ),
                request_hash=binding.request_hash,
                record_snapshot_hash=(
                    binding.record_snapshot_hash
                ),
                target_binding_hash=(
                    binding.target_binding_hash
                ),
                reserved_at_utc=reserved_at_utc,
                gate_id=None,
                completed_at_utc=None,
            )
        )

        entry = DurableExecutionGateJournalEntry(
            binding_id=binding.binding_id,
            state=(
                DURABLE_GATE_JOURNAL_STATE_RESERVED
            ),
            request_hash=binding.request_hash,
            record_snapshot_hash=(
                binding.record_snapshot_hash
            ),
            target_binding_hash=(
                binding.target_binding_hash
            ),
            reserved_at_utc=reserved_at_utc,
            gate_id=None,
            completed_at_utc=None,
            entry_hash=_canonical_hash(payload),
        )

        lock_fd = self._open_lock()

        try:
            entries = self._read_entries_locked()

            if any(
                existing.binding_id
                == binding.binding_id
                for existing in entries
            ):
                raise DurableExecutionGateJournalError(
                    "execution binding is already durably reserved or consumed"
                )

            self._write_entries_locked(
                entries + [entry]
            )

            return entry

        finally:
            self._close_lock(lock_fd)

    def _rollback_reservation(
        self,
        binding_id: Any,
    ) -> None:
        lock_fd = self._open_lock()

        try:
            entries = self._read_entries_locked()

            matches = [
                entry
                for entry in entries
                if entry.binding_id == binding_id
            ]

            if (
                len(matches) != 1
                or matches[0].state
                != DURABLE_GATE_JOURNAL_STATE_RESERVED
            ):
                raise DurableExecutionGateJournalError(
                    "durable reservation cannot be rolled back safely"
                )

            self._write_entries_locked([
                entry
                for entry in entries
                if entry.binding_id != binding_id
            ])

        finally:
            self._close_lock(lock_fd)

    def _complete(
        self,
        binding_id: Any,
        gate: Any,
    ) -> DurableExecutionGateJournalEntry:
        if not (
            isinstance(
                gate,
                OneShotExecutionGateDecision,
            )
            and _one_shot_execution_gate_integrity_valid(
                gate
            )
            and gate.binding_id == binding_id
        ):
            raise DurableExecutionGateJournalError(
                "completed gate is invalid"
            )

        lock_fd = self._open_lock()

        try:
            entries = self._read_entries_locked()

            matches = [
                entry
                for entry in entries
                if entry.binding_id == binding_id
            ]

            if (
                len(matches) != 1
                or matches[0].state
                != DURABLE_GATE_JOURNAL_STATE_RESERVED
            ):
                raise DurableExecutionGateJournalError(
                    "durable reservation is unavailable"
                )

            reserved = matches[0]

            if (
                reserved.request_hash
                != gate.request_hash
                or reserved.record_snapshot_hash
                != gate.record_snapshot_hash
                or reserved.target_binding_hash
                != gate.target_binding_hash
            ):
                raise DurableExecutionGateJournalError(
                    "gate does not match durable reservation"
                )

            payload = (
                _durable_gate_journal_entry_payload(
                    binding_id=reserved.binding_id,
                    state=(
                        DURABLE_GATE_JOURNAL_STATE_COMPLETED
                    ),
                    request_hash=(
                        reserved.request_hash
                    ),
                    record_snapshot_hash=(
                        reserved.record_snapshot_hash
                    ),
                    target_binding_hash=(
                        reserved.target_binding_hash
                    ),
                    reserved_at_utc=(
                        reserved.reserved_at_utc
                    ),
                    gate_id=gate.gate_id,
                    completed_at_utc=(
                        gate.evaluated_at_utc
                    ),
                )
            )

            completed = (
                DurableExecutionGateJournalEntry(
                    binding_id=reserved.binding_id,
                    state=(
                        DURABLE_GATE_JOURNAL_STATE_COMPLETED
                    ),
                    request_hash=(
                        reserved.request_hash
                    ),
                    record_snapshot_hash=(
                        reserved.record_snapshot_hash
                    ),
                    target_binding_hash=(
                        reserved.target_binding_hash
                    ),
                    reserved_at_utc=(
                        reserved.reserved_at_utc
                    ),
                    gate_id=gate.gate_id,
                    completed_at_utc=(
                        gate.evaluated_at_utc
                    ),
                    entry_hash=(
                        _canonical_hash(payload)
                    ),
                )
            )

            if not (
                _durable_gate_journal_entry_integrity_valid(
                    completed
                )
            ):
                raise DurableExecutionGateJournalError(
                    "completed journal entry failed integrity"
                )

            self._write_entries_locked([
                completed
                if entry.binding_id == binding_id
                else entry
                for entry in entries
            ])

            return completed

        finally:
            self._close_lock(lock_fd)

    def entry_for_binding(
        self,
        binding_id: Any,
    ) -> Optional[
        DurableExecutionGateJournalEntry
    ]:
        if not _durable_prefixed_hex_id(
            binding_id,
            "xeb_",
        ):
            raise DurableExecutionGateJournalError(
                "binding ID is invalid"
            )

        lock_fd = self._open_lock()

        try:
            entries = self._read_entries_locked()

            matches = [
                entry
                for entry in entries
                if entry.binding_id == binding_id
            ]

            if len(matches) > 1:
                raise DurableExecutionGateJournalError(
                    "journal contains duplicate binding IDs"
                )

            return (
                matches[0]
                if matches
                else None
            )

        finally:
            self._close_lock(lock_fd)


def satisfy_durable_one_shot_execution_gate(
    *,
    registry: Any,
    approval_id: Any,
    request: Any,
    record: Any,
    journal: Any,
) -> OneShotExecutionGateDecision:
    """Wrap the verified 6D-B gate with restart-safe consumption state.

    A crash after durable reservation is intentionally fail-closed:
    the reserved entry blocks automatic replay and requires review.
    """

    if not isinstance(
        journal,
        DurableExecutionGateConsumptionJournal,
    ):
        raise DurableOneShotExecutionGateError(
            "journal is invalid"
        )

    try:
        binding = build_trusted_execution_binding(
            registry=registry,
            approval_id=approval_id,
            request=request,
            record=record,
        )
    except TrustedExecutionBindingError as exc:
        raise DurableOneShotExecutionGateError(
            "trusted execution binding is unavailable"
        ) from exc

    try:
        journal._reserve(binding)
    except DurableExecutionGateJournalError as exc:
        raise DurableOneShotExecutionGateError(
            "durable reservation failed"
        ) from exc

    try:
        gate = satisfy_one_shot_execution_gate(
            registry=registry,
            approval_id=approval_id,
            request=request,
            record=record,
        )

    except OneShotExecutionGateError as gate_exc:
        try:
            journal._rollback_reservation(
                binding.binding_id
            )
        except DurableExecutionGateJournalError as rollback_exc:
            raise DurableOneShotExecutionGateError(
                "gate failed and durable reservation rollback failed; "
                "manual recovery is required"
            ) from rollback_exc

        raise DurableOneShotExecutionGateError(
            "one-shot gate failed; durable reservation was rolled back"
        ) from gate_exc

    try:
        journal._complete(
            binding.binding_id,
            gate,
        )
    except DurableExecutionGateJournalError as exc:
        raise DurableOneShotExecutionGateError(
            "gate was consumed but durable completion failed; "
            "reserved state must be treated as consumed"
        ) from exc

    return gate

EXECUTION_HANDOFF_POLICY_VERSION = (
    "phase6d-d-immutable-handoff-v2"
)
EXECUTION_HANDOFF_SCHEMA_VERSION = 2
EXECUTION_HANDOFF_STATUS_CONTRACT_BUILT = (
    "execution_handoff_contract_built"
)


class ExecutionHandoffContractError(
    AuthorizationError
):
    """Execution-handoff contract inputs failed closed."""


@dataclass(frozen=True)
class ImmutableExecutionHandoffContract:
    """Immutable non-executing description of one completed gate handoff.

    This record carries no command, executable location, callback,
    open device resource, or mutation capability.

    The current policy-only method is explicitly not executor eligible.
    A future destructive boundary must perform fresh target revalidation
    and establish separate execution authority.
    """

    handoff_id: str
    policy_version: str
    schema_version: int
    status: str

    gate_id: str
    binding_id: str

    journal_policy_version: str
    journal_schema_version: int
    journal_state: str
    journal_entry_hash: str

    approval_id: str
    challenge_id: str
    approval_evidence_hash: str
    revalidation_id: str
    fresh_prerequisite_decision_id: str

    request_id: str
    request_hash: str
    record_snapshot_hash: str
    batch_job_id: str
    internal_record_id: str

    method_profile_id: str
    operation: str
    policy_only: bool
    execution_supported: bool
    executor_eligible: bool
    requires_fresh_target_revalidation: bool

    target_path: str
    target_major_minor: str
    target_serial: Optional[str]
    target_wwn: Optional[str]
    target_size_bytes: int
    target_model: Optional[str]
    target_transport: Optional[str]
    target_binding_hash: str
    constraint_evaluation_hash: str

    gate_evaluated_at_utc: str
    prerequisite_valid_until_utc: str


def _execution_handoff_payload(
    *,
    policy_version: str,
    schema_version: int,
    status: str,
    gate_id: str,
    binding_id: str,
    journal_policy_version: str,
    journal_schema_version: int,
    journal_state: str,
    journal_entry_hash: str,
    approval_id: str,
    challenge_id: str,
    approval_evidence_hash: str,
    revalidation_id: str,
    fresh_prerequisite_decision_id: str,
    request_id: str,
    request_hash: str,
    record_snapshot_hash: str,
    batch_job_id: str,
    internal_record_id: str,
    method_profile_id: str,
    operation: str,
    policy_only: bool,
    execution_supported: bool,
    executor_eligible: bool,
    requires_fresh_target_revalidation: bool,
    target_path: str,
    target_major_minor: str,
    target_serial: Optional[str],
    target_wwn: Optional[str],
    target_size_bytes: int,
    target_model: Optional[str],
    target_transport: Optional[str],
    target_binding_hash: str,
    constraint_evaluation_hash: str,
    gate_evaluated_at_utc: str,
    prerequisite_valid_until_utc: str,
) -> dict[str, Any]:
    return {
        "policy_version": policy_version,
        "schema_version": schema_version,
        "status": status,
        "gate_id": gate_id,
        "binding_id": binding_id,
        "journal_policy_version":
            journal_policy_version,
        "journal_schema_version":
            journal_schema_version,
        "journal_state": journal_state,
        "journal_entry_hash":
            journal_entry_hash,
        "approval_id": approval_id,
        "challenge_id": challenge_id,
        "approval_evidence_hash":
            approval_evidence_hash,
        "revalidation_id": revalidation_id,
        "fresh_prerequisite_decision_id":
            fresh_prerequisite_decision_id,
        "request_id": request_id,
        "request_hash": request_hash,
        "record_snapshot_hash":
            record_snapshot_hash,
        "batch_job_id": batch_job_id,
        "internal_record_id":
            internal_record_id,
        "method_profile_id":
            method_profile_id,
        "operation": operation,
        "policy_only": policy_only,
        "execution_supported":
            execution_supported,
        "executor_eligible":
            executor_eligible,
        "requires_fresh_target_revalidation":
            requires_fresh_target_revalidation,
        "target_path": target_path,
        "target_major_minor":
            target_major_minor,
        "target_serial": target_serial,
        "target_wwn": target_wwn,
        "target_size_bytes":
            target_size_bytes,
        "target_model": target_model,
        "target_transport":
            target_transport,
        "target_binding_hash":
            target_binding_hash,
        "constraint_evaluation_hash":
            constraint_evaluation_hash,
        "gate_evaluated_at_utc":
            gate_evaluated_at_utc,
        "prerequisite_valid_until_utc":
            prerequisite_valid_until_utc,
    }


def _immutable_execution_handoff_integrity_valid(
    handoff: Any,
) -> bool:
    """Check handoff-object internal consistency only."""

    try:
        if not isinstance(
            handoff,
            ImmutableExecutionHandoffContract,
        ):
            return False

        if (
            handoff.policy_version
            != EXECUTION_HANDOFF_POLICY_VERSION
            or type(handoff.schema_version)
            is not int
            or handoff.schema_version
            != EXECUTION_HANDOFF_SCHEMA_VERSION
            or handoff.status
            != EXECUTION_HANDOFF_STATUS_CONTRACT_BUILT
        ):
            return False

        if not _durable_prefixed_hex_id(
            handoff.gate_id,
            "xgate_",
        ):
            return False

        if not _durable_prefixed_hex_id(
            handoff.binding_id,
            "xeb_",
        ):
            return False

        if (
            not isinstance(
                handoff.handoff_id,
                str,
            )
            or not handoff.handoff_id.startswith(
                "xhnd_"
            )
            or len(handoff.handoff_id)
            != len("xhnd_") + 64
            or not all(
                character
                in "0123456789abcdef"
                for character
                in handoff.handoff_id[
                    len("xhnd_"):
                ]
            )
        ):
            return False

        if (
            handoff.journal_policy_version
            != DURABLE_GATE_JOURNAL_POLICY_VERSION
            or type(
                handoff.journal_schema_version
            )
            is not int
            or handoff.journal_schema_version
            != DURABLE_GATE_JOURNAL_SCHEMA_VERSION
            or handoff.journal_state
            != DURABLE_GATE_JOURNAL_STATE_COMPLETED
        ):
            return False

        for value in (
            handoff.approval_id,
            handoff.challenge_id,
            handoff.request_id,
            handoff.batch_job_id,
            handoff.internal_record_id,
            handoff.method_profile_id,
            handoff.operation,
            handoff.target_path,
        ):
            if not _approval_text(value):
                return False

        for value in (
            handoff.method_profile_id,
            handoff.operation,
        ):
            if not _synthetic_plan_exact_text(
                value
            ):
                return False

        for hash_value in (
            handoff.journal_entry_hash,
            handoff.approval_evidence_hash,
            handoff.revalidation_id,
            handoff.fresh_prerequisite_decision_id,
            handoff.request_hash,
            handoff.record_snapshot_hash,
            handoff.target_binding_hash,
            handoff.constraint_evaluation_hash,
        ):
            if not _synthetic_plan_hash_value(
                hash_value
            ):
                return False

        if (
            type(handoff.policy_only)
            is not bool
            or handoff.policy_only is not True
            or type(
                handoff.execution_supported
            )
            is not bool
            or handoff.execution_supported
            is not False
            or type(
                handoff.executor_eligible
            )
            is not bool
            or handoff.executor_eligible
            is not False
            or type(
                handoff.requires_fresh_target_revalidation
            )
            is not bool
            or handoff.requires_fresh_target_revalidation
            is not True
        ):
            return False

        if (
            type(handoff.target_size_bytes)
            is not int
            or handoff.target_size_bytes <= 0
        ):
            return False

        if not _kernel_major_minor_valid(
            handoff.target_major_minor
        ):
            return False

        for optional_value in (
            handoff.target_serial,
            handoff.target_wwn,
            handoff.target_model,
            handoff.target_transport,
        ):
            if not _method_constraint_optional_text_valid(
                optional_value
            ):
                return False

        if not (
            _method_constraint_identity_present(
                handoff.target_serial
            )
            or _method_constraint_identity_present(
                handoff.target_wwn
            )
        ):
            return False

        evaluated_at = _parse_utc(
            handoff.gate_evaluated_at_utc,
            "handoff.gate_evaluated_at_utc",
        )

        valid_until = _parse_utc(
            handoff.prerequisite_valid_until_utc,
            "handoff.prerequisite_valid_until_utc",
        )

        if (
            _iso_utc(evaluated_at)
            != handoff.gate_evaluated_at_utc
            or _iso_utc(valid_until)
            != handoff.prerequisite_valid_until_utc
            or evaluated_at > valid_until
        ):
            return False

        payload = _execution_handoff_payload(
            policy_version=handoff.policy_version,
            schema_version=handoff.schema_version,
            status=handoff.status,
            gate_id=handoff.gate_id,
            binding_id=handoff.binding_id,
            journal_policy_version=(
                handoff.journal_policy_version
            ),
            journal_schema_version=(
                handoff.journal_schema_version
            ),
            journal_state=handoff.journal_state,
            journal_entry_hash=(
                handoff.journal_entry_hash
            ),
            approval_id=handoff.approval_id,
            challenge_id=handoff.challenge_id,
            approval_evidence_hash=(
                handoff.approval_evidence_hash
            ),
            revalidation_id=(
                handoff.revalidation_id
            ),
            fresh_prerequisite_decision_id=(
                handoff.fresh_prerequisite_decision_id
            ),
            request_id=handoff.request_id,
            request_hash=handoff.request_hash,
            record_snapshot_hash=(
                handoff.record_snapshot_hash
            ),
            batch_job_id=handoff.batch_job_id,
            internal_record_id=(
                handoff.internal_record_id
            ),
            method_profile_id=(
                handoff.method_profile_id
            ),
            operation=handoff.operation,
            policy_only=handoff.policy_only,
            execution_supported=(
                handoff.execution_supported
            ),
            executor_eligible=(
                handoff.executor_eligible
            ),
            requires_fresh_target_revalidation=(
                handoff.requires_fresh_target_revalidation
            ),
            target_path=handoff.target_path,
            target_major_minor=(
                handoff.target_major_minor
            ),
            target_serial=handoff.target_serial,
            target_wwn=handoff.target_wwn,
            target_size_bytes=(
                handoff.target_size_bytes
            ),
            target_model=handoff.target_model,
            target_transport=(
                handoff.target_transport
            ),
            target_binding_hash=(
                handoff.target_binding_hash
            ),
            constraint_evaluation_hash=(
                handoff.constraint_evaluation_hash
            ),
            gate_evaluated_at_utc=(
                handoff.gate_evaluated_at_utc
            ),
            prerequisite_valid_until_utc=(
                handoff.prerequisite_valid_until_utc
            ),
        )

        payload_hash = _canonical_hash(
            payload
        )

        return (
            handoff.handoff_id
            == (
                "xhnd_"
                + payload_hash.split(":", 1)[1]
            )
        )

    except Exception:
        return False


def build_immutable_execution_handoff_contract(
    *,
    registry: Any,
    approval_id: Any,
    request: Any,
    record: Any,
    journal: Any,
    gate: Any,
) -> ImmutableExecutionHandoffContract:
    """Build a deterministic non-executing handoff contract.

    The function reads already-completed journal evidence and registry-held
    provenance.  It does not run discovery, approval, gate consumption,
    command construction, or device mutation.
    """

    if not isinstance(
        journal,
        DurableExecutionGateConsumptionJournal,
    ):
        raise ExecutionHandoffContractError(
            "journal is invalid"
        )

    if not isinstance(
        gate,
        OneShotExecutionGateDecision,
    ):
        raise ExecutionHandoffContractError(
            "gate is invalid"
        )

    if not _one_shot_execution_gate_integrity_valid(
        gate
    ):
        raise ExecutionHandoffContractError(
            "gate integrity is invalid"
        )

    try:
        binding = build_trusted_execution_binding(
            registry=registry,
            approval_id=approval_id,
            request=request,
            record=record,
        )
    except TrustedExecutionBindingError as exc:
        raise ExecutionHandoffContractError(
            "trusted binding is unavailable"
        ) from exc

    if (
        gate.status
        != EXECUTION_GATE_STATUS_SATISFIED
        or gate.binding_id
        != binding.binding_id
        or gate.approval_id
        != binding.approval_id
        or gate.challenge_id
        != binding.challenge_id
        or gate.approval_evidence_hash
        != binding.approval_evidence_hash
        or gate.revalidation_id
        != binding.revalidation_id
        or gate.request_id
        != binding.request_id
        or gate.request_hash
        != binding.request_hash
        or gate.record_snapshot_hash
        != binding.record_snapshot_hash
        or gate.fresh_prerequisite_decision_id
        != binding.fresh_prerequisite_decision_id
        or gate.method_profile_id
        != binding.method_profile_id
        or gate.operation
        != binding.operation
        or gate.target_binding_hash
        != binding.target_binding_hash
        or gate.constraint_evaluation_hash
        != binding.constraint_evaluation_hash
        or gate.prerequisite_valid_until_utc
        != binding.prerequisite_valid_until_utc
    ):
        raise ExecutionHandoffContractError(
            "gate does not match trusted binding"
        )

    try:
        entry = journal.entry_for_binding(
            binding.binding_id
        )
    except DurableExecutionGateJournalError as exc:
        raise ExecutionHandoffContractError(
            "durable journal evidence is unavailable"
        ) from exc

    if (
        entry is None
        or entry.state
        != DURABLE_GATE_JOURNAL_STATE_COMPLETED
        or not (
            _durable_gate_journal_entry_integrity_valid(
                entry
            )
        )
        or entry.binding_id
        != binding.binding_id
        or entry.gate_id != gate.gate_id
        or entry.request_hash
        != gate.request_hash
        or entry.record_snapshot_hash
        != gate.record_snapshot_hash
        or entry.target_binding_hash
        != gate.target_binding_hash
        or entry.completed_at_utc
        != gate.evaluated_at_utc
    ):
        raise ExecutionHandoffContractError(
            "completed durable journal evidence does not match gate"
        )

    with registry._state_lock:
        retained = (
            registry._successful_revalidations.get(
                approval_id
            )
        )

    if (
        not isinstance(retained, tuple)
        or len(retained) != 2
    ):
        raise ExecutionHandoffContractError(
            "fresh prerequisite provenance is unavailable"
        )

    retained_revalidation, fresh = retained

    if (
        not isinstance(
            retained_revalidation,
            ApprovalRevalidationDecision,
        )
        or not isinstance(
            fresh,
            AuthorizationDecision,
        )
        or not decision_integrity_valid(fresh)
        or fresh.status
        != STATUS_PREREQUISITES_MET
        or fresh.reason_codes != ()
        or fresh.target_binding is None
        or fresh.decision_id
        != binding.fresh_prerequisite_decision_id
        or fresh.target_binding_hash
        != binding.target_binding_hash
        or fresh.request_hash
        != binding.request_hash
        or fresh.record_snapshot_hash
        != binding.record_snapshot_hash
    ):
        raise ExecutionHandoffContractError(
            "fresh prerequisite provenance is invalid"
        )

    target = fresh.target_binding

    if not (
        _sanitization_method_constraint_target_binding_valid(
            target
        )
    ):
        raise ExecutionHandoffContractError(
            "fresh target identity is invalid"
        )

    target_hash = _canonical_hash(
        asdict(target)
    )

    if (
        target_hash
        != binding.target_binding_hash
        or target_hash
        != gate.target_binding_hash
        or target_hash
        != entry.target_binding_hash
        or target.path
        != record.linux_device_path
    ):
        raise ExecutionHandoffContractError(
            "fresh target identity binding mismatch"
        )

    policy = get_sanitization_method_policy(
        request.method_profile_id
    )

    metadata = (
        get_sanitization_method_capability_metadata(
            request.method_profile_id
        )
    )

    if (
        policy is None
        or metadata is None
        or policy.method_profile_id
        != request.method_profile_id
        or metadata.method_profile_id
        != request.method_profile_id
        or policy.operation
        != request.operation
        or policy.policy_only is not True
        or policy.execution_supported is not False
        or metadata.capability_class
        != "policy_only"
    ):
        raise ExecutionHandoffContractError(
            "current trusted method policy is not the expected non-executable profile"
        )

    constraints = (
        evaluate_sanitization_method_constraints(
            request.method_profile_id,
            target,
        )
    )

    constraint_hash = _canonical_hash(
        asdict(constraints)
    )

    if (
        constraints.status
        != METHOD_CONSTRAINT_STATUS_SATISFIED
        or constraints.reason_codes != ()
        or constraints.method_profile_id
        != request.method_profile_id
        or constraints.target_binding_hash
        != target_hash
        or constraint_hash
        != binding.constraint_evaluation_hash
        or constraint_hash
        != gate.constraint_evaluation_hash
    ):
        raise ExecutionHandoffContractError(
            "current method constraints do not match gate provenance"
        )

    if (
        request.batch_job_id
        != record.batch_job_id
        or request.internal_record_id
        != record.internal_record_id
    ):
        raise ExecutionHandoffContractError(
            "request/record identity mismatch"
        )

    payload = _execution_handoff_payload(
        policy_version=(
            EXECUTION_HANDOFF_POLICY_VERSION
        ),
        schema_version=(
            EXECUTION_HANDOFF_SCHEMA_VERSION
        ),
        status=(
            EXECUTION_HANDOFF_STATUS_CONTRACT_BUILT
        ),
        gate_id=gate.gate_id,
        binding_id=binding.binding_id,
        journal_policy_version=(
            DURABLE_GATE_JOURNAL_POLICY_VERSION
        ),
        journal_schema_version=(
            DURABLE_GATE_JOURNAL_SCHEMA_VERSION
        ),
        journal_state=entry.state,
        journal_entry_hash=entry.entry_hash,
        approval_id=binding.approval_id,
        challenge_id=binding.challenge_id,
        approval_evidence_hash=(
            binding.approval_evidence_hash
        ),
        revalidation_id=(
            binding.revalidation_id
        ),
        fresh_prerequisite_decision_id=(
            binding.fresh_prerequisite_decision_id
        ),
        request_id=request.request_id,
        request_hash=binding.request_hash,
        record_snapshot_hash=(
            binding.record_snapshot_hash
        ),
        batch_job_id=request.batch_job_id,
        internal_record_id=(
            request.internal_record_id
        ),
        method_profile_id=(
            request.method_profile_id
        ),
        operation=request.operation,
        policy_only=policy.policy_only,
        execution_supported=(
            policy.execution_supported
        ),
        executor_eligible=False,
        requires_fresh_target_revalidation=True,
        target_path=target.path,
        target_major_minor=target.major_minor,
        target_serial=target.serial,
        target_wwn=target.wwn,
        target_size_bytes=target.size_bytes,
        target_model=target.model,
        target_transport=target.transport,
        target_binding_hash=target_hash,
        constraint_evaluation_hash=(
            constraint_hash
        ),
        gate_evaluated_at_utc=(
            gate.evaluated_at_utc
        ),
        prerequisite_valid_until_utc=(
            gate.prerequisite_valid_until_utc
        ),
    )

    payload_hash = _canonical_hash(
        payload
    )

    handoff = ImmutableExecutionHandoffContract(
        handoff_id=(
            "xhnd_"
            + payload_hash.split(":", 1)[1]
        ),
        policy_version=(
            EXECUTION_HANDOFF_POLICY_VERSION
        ),
        schema_version=(
            EXECUTION_HANDOFF_SCHEMA_VERSION
        ),
        status=(
            EXECUTION_HANDOFF_STATUS_CONTRACT_BUILT
        ),
        gate_id=gate.gate_id,
        binding_id=binding.binding_id,
        journal_policy_version=(
            DURABLE_GATE_JOURNAL_POLICY_VERSION
        ),
        journal_schema_version=(
            DURABLE_GATE_JOURNAL_SCHEMA_VERSION
        ),
        journal_state=entry.state,
        journal_entry_hash=entry.entry_hash,
        approval_id=binding.approval_id,
        challenge_id=binding.challenge_id,
        approval_evidence_hash=(
            binding.approval_evidence_hash
        ),
        revalidation_id=(
            binding.revalidation_id
        ),
        fresh_prerequisite_decision_id=(
            binding.fresh_prerequisite_decision_id
        ),
        request_id=request.request_id,
        request_hash=binding.request_hash,
        record_snapshot_hash=(
            binding.record_snapshot_hash
        ),
        batch_job_id=request.batch_job_id,
        internal_record_id=(
            request.internal_record_id
        ),
        method_profile_id=(
            request.method_profile_id
        ),
        operation=request.operation,
        policy_only=policy.policy_only,
        execution_supported=(
            policy.execution_supported
        ),
        executor_eligible=False,
        requires_fresh_target_revalidation=True,
        target_path=target.path,
        target_major_minor=target.major_minor,
        target_serial=target.serial,
        target_wwn=target.wwn,
        target_size_bytes=target.size_bytes,
        target_model=target.model,
        target_transport=target.transport,
        target_binding_hash=target_hash,
        constraint_evaluation_hash=(
            constraint_hash
        ),
        gate_evaluated_at_utc=(
            gate.evaluated_at_utc
        ),
        prerequisite_valid_until_utc=(
            gate.prerequisite_valid_until_utc
        ),
    )

    if not _immutable_execution_handoff_integrity_valid(
        handoff
    ):
        raise ExecutionHandoffContractError(
            "constructed handoff failed integrity validation"
        )

    return handoff

FRESH_TARGET_REVALIDATION_POLICY_VERSION = (
    "phase6e-a-fresh-physical-target-v2"
)
FRESH_TARGET_REVALIDATION_SCHEMA_VERSION = 2
FRESH_TARGET_REVALIDATION_STATUS_SATISFIED = (
    "target_revalidation_satisfied"
)


class FreshPhysicalTargetRevalidationError(
    AuthorizationError
):
    """Fresh physical-target revalidation failed closed."""


@dataclass(frozen=True)
class FreshPhysicalTargetRevalidationDecision:
    """Immutable read-only revalidation result for one 6D-D handoff.

    A satisfied result means the existing Phase-4/Phase-5 read-only
    discovery/evaluation path freshly observed the same exact target and
    found the same safe constraint state.

    It is not execution authorization, executor readiness, a command,
    a device handle, sanitization, verification, or proof that the target
    cannot change after this observation.
    """

    revalidation_id: str
    policy_version: str
    schema_version: int
    status: str

    handoff_id: str
    gate_id: str
    binding_id: str
    journal_entry_hash: str

    fresh_prerequisite_decision_id: str
    fresh_discovery_snapshot_hash: str

    request_id: str
    request_hash: str
    record_snapshot_hash: str

    method_profile_id: str
    operation: str

    prior_target_binding_hash: str
    fresh_target_binding_hash: str
    constraint_evaluation_hash: str

    target_path: str
    target_major_minor: str
    target_serial: Optional[str]
    target_wwn: Optional[str]
    target_size_bytes: int
    target_model: Optional[str]
    target_transport: Optional[str]

    target_read_only: bool
    target_mounted: bool
    target_protected: bool
    target_system_protected: bool
    target_review_required: bool
    target_ambiguous: bool

    discovery_captured_at_utc: str
    evaluated_at_utc: str
    valid_until_utc: str

    execution_supported: bool
    executor_eligible: bool
    requires_separate_executor_authorization: bool


def _fresh_target_revalidation_payload(
    *,
    policy_version: str,
    schema_version: int,
    status: str,
    handoff_id: str,
    gate_id: str,
    binding_id: str,
    journal_entry_hash: str,
    fresh_prerequisite_decision_id: str,
    fresh_discovery_snapshot_hash: str,
    request_id: str,
    request_hash: str,
    record_snapshot_hash: str,
    method_profile_id: str,
    operation: str,
    prior_target_binding_hash: str,
    fresh_target_binding_hash: str,
    constraint_evaluation_hash: str,
    target_path: str,
    target_major_minor: str,
    target_serial: Optional[str],
    target_wwn: Optional[str],
    target_size_bytes: int,
    target_model: Optional[str],
    target_transport: Optional[str],
    target_read_only: bool,
    target_mounted: bool,
    target_protected: bool,
    target_system_protected: bool,
    target_review_required: bool,
    target_ambiguous: bool,
    discovery_captured_at_utc: str,
    evaluated_at_utc: str,
    valid_until_utc: str,
    execution_supported: bool,
    executor_eligible: bool,
    requires_separate_executor_authorization: bool,
) -> dict[str, Any]:
    return {
        "policy_version": policy_version,
        "schema_version": schema_version,
        "status": status,
        "handoff_id": handoff_id,
        "gate_id": gate_id,
        "binding_id": binding_id,
        "journal_entry_hash":
            journal_entry_hash,
        "fresh_prerequisite_decision_id":
            fresh_prerequisite_decision_id,
        "fresh_discovery_snapshot_hash":
            fresh_discovery_snapshot_hash,
        "request_id": request_id,
        "request_hash": request_hash,
        "record_snapshot_hash":
            record_snapshot_hash,
        "method_profile_id":
            method_profile_id,
        "operation": operation,
        "prior_target_binding_hash":
            prior_target_binding_hash,
        "fresh_target_binding_hash":
            fresh_target_binding_hash,
        "constraint_evaluation_hash":
            constraint_evaluation_hash,
        "target_path": target_path,
        "target_major_minor":
            target_major_minor,
        "target_serial": target_serial,
        "target_wwn": target_wwn,
        "target_size_bytes":
            target_size_bytes,
        "target_model": target_model,
        "target_transport":
            target_transport,
        "target_read_only":
            target_read_only,
        "target_mounted":
            target_mounted,
        "target_protected":
            target_protected,
        "target_system_protected":
            target_system_protected,
        "target_review_required":
            target_review_required,
        "target_ambiguous":
            target_ambiguous,
        "discovery_captured_at_utc":
            discovery_captured_at_utc,
        "evaluated_at_utc":
            evaluated_at_utc,
        "valid_until_utc":
            valid_until_utc,
        "execution_supported":
            execution_supported,
        "executor_eligible":
            executor_eligible,
        "requires_separate_executor_authorization":
            requires_separate_executor_authorization,
    }


def _fresh_physical_target_revalidation_integrity_valid(
    decision: Any,
) -> bool:
    """Check result internal consistency only."""

    try:
        if not isinstance(
            decision,
            FreshPhysicalTargetRevalidationDecision,
        ):
            return False

        if (
            decision.policy_version
            != FRESH_TARGET_REVALIDATION_POLICY_VERSION
            or type(decision.schema_version)
            is not int
            or decision.schema_version
            != FRESH_TARGET_REVALIDATION_SCHEMA_VERSION
            or decision.status
            != FRESH_TARGET_REVALIDATION_STATUS_SATISFIED
        ):
            return False

        if (
            not isinstance(
                decision.revalidation_id,
                str,
            )
            or not decision.revalidation_id.startswith(
                "ptrv_"
            )
            or len(decision.revalidation_id)
            != len("ptrv_") + 64
            or not all(
                character
                in "0123456789abcdef"
                for character
                in decision.revalidation_id[
                    len("ptrv_"):
                ]
            )
        ):
            return False

        if not _durable_prefixed_hex_id(
            decision.handoff_id,
            "xhnd_",
        ):
            return False

        if not _durable_prefixed_hex_id(
            decision.gate_id,
            "xgate_",
        ):
            return False

        if not _durable_prefixed_hex_id(
            decision.binding_id,
            "xeb_",
        ):
            return False

        for text_value in (
            decision.request_id,
            decision.method_profile_id,
            decision.operation,
            decision.target_path,
        ):
            if not _approval_text(
                text_value
            ):
                return False

        for hash_value in (
            decision.journal_entry_hash,
            decision.fresh_prerequisite_decision_id,
            decision.fresh_discovery_snapshot_hash,
            decision.request_hash,
            decision.record_snapshot_hash,
            decision.prior_target_binding_hash,
            decision.fresh_target_binding_hash,
            decision.constraint_evaluation_hash,
        ):
            if not _canonical_hash_value(
                hash_value
            ):
                return False

        if (
            decision.prior_target_binding_hash
            != decision.fresh_target_binding_hash
        ):
            return False

        serial = _candidate_identity(
            decision.target_serial
        )

        wwn = _candidate_identity(
            decision.target_wwn
        )

        if (
            decision.target_serial is not None
            and serial
            != decision.target_serial
        ):
            return False

        if (
            decision.target_wwn is not None
            and wwn
            != decision.target_wwn
        ):
            return False

        if serial is None and wwn is None:
            return False

        if (
            type(decision.target_size_bytes)
            is not int
            or decision.target_size_bytes <= 0
        ):
            return False

        if not _kernel_major_minor_valid(
            decision.target_major_minor
        ):
            return False

        for optional_value in (
            decision.target_model,
            decision.target_transport,
        ):
            if optional_value is None:
                continue

            if (
                not isinstance(
                    optional_value,
                    str,
                )
                or not optional_value.strip()
                or optional_value
                != optional_value.strip()
                or _contains_forbidden_control(
                    optional_value
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
            type(decision.execution_supported)
            is not bool
            or decision.execution_supported
            is not False
            or type(
                decision.executor_eligible
            )
            is not bool
            or decision.executor_eligible
            is not False
            or type(
                decision.requires_separate_executor_authorization
            )
            is not bool
            or decision.requires_separate_executor_authorization
            is not True
        ):
            return False

        captured_at = _parse_utc(
            decision.discovery_captured_at_utc,
            "decision.discovery_captured_at_utc",
        )

        evaluated_at = _parse_utc(
            decision.evaluated_at_utc,
            "decision.evaluated_at_utc",
        )

        valid_until = _parse_utc(
            decision.valid_until_utc,
            "decision.valid_until_utc",
        )

        if (
            _iso_utc(captured_at)
            != decision.discovery_captured_at_utc
            or _iso_utc(evaluated_at)
            != decision.evaluated_at_utc
            or _iso_utc(valid_until)
            != decision.valid_until_utc
        ):
            return False

        if (
            captured_at
            > evaluated_at
            + timedelta(
                seconds=MAX_FUTURE_SKEW_SECONDS
            )
        ):
            return False

        if (
            evaluated_at - captured_at
            > timedelta(
                seconds=MAX_DISCOVERY_AGE_SECONDS
            )
        ):
            return False

        if (
            valid_until
            != evaluated_at
            + timedelta(
                seconds=PREREQUISITE_LIFETIME_SECONDS
            )
        ):
            return False

        payload = _fresh_target_revalidation_payload(
            policy_version=(
                decision.policy_version
            ),
            schema_version=(
                decision.schema_version
            ),
            status=decision.status,
            handoff_id=decision.handoff_id,
            gate_id=decision.gate_id,
            binding_id=decision.binding_id,
            journal_entry_hash=(
                decision.journal_entry_hash
            ),
            fresh_prerequisite_decision_id=(
                decision.fresh_prerequisite_decision_id
            ),
            fresh_discovery_snapshot_hash=(
                decision.fresh_discovery_snapshot_hash
            ),
            request_id=decision.request_id,
            request_hash=decision.request_hash,
            record_snapshot_hash=(
                decision.record_snapshot_hash
            ),
            method_profile_id=(
                decision.method_profile_id
            ),
            operation=decision.operation,
            prior_target_binding_hash=(
                decision.prior_target_binding_hash
            ),
            fresh_target_binding_hash=(
                decision.fresh_target_binding_hash
            ),
            constraint_evaluation_hash=(
                decision.constraint_evaluation_hash
            ),
            target_path=decision.target_path,
            target_major_minor=(
                decision.target_major_minor
            ),
            target_serial=decision.target_serial,
            target_wwn=decision.target_wwn,
            target_size_bytes=(
                decision.target_size_bytes
            ),
            target_model=decision.target_model,
            target_transport=(
                decision.target_transport
            ),
            target_read_only=(
                decision.target_read_only
            ),
            target_mounted=(
                decision.target_mounted
            ),
            target_protected=(
                decision.target_protected
            ),
            target_system_protected=(
                decision.target_system_protected
            ),
            target_review_required=(
                decision.target_review_required
            ),
            target_ambiguous=(
                decision.target_ambiguous
            ),
            discovery_captured_at_utc=(
                decision.discovery_captured_at_utc
            ),
            evaluated_at_utc=(
                decision.evaluated_at_utc
            ),
            valid_until_utc=(
                decision.valid_until_utc
            ),
            execution_supported=(
                decision.execution_supported
            ),
            executor_eligible=(
                decision.executor_eligible
            ),
            requires_separate_executor_authorization=(
                decision.requires_separate_executor_authorization
            ),
        )

        payload_hash = _canonical_hash(
            payload
        )

        return (
            decision.revalidation_id
            == (
                "ptrv_"
                + payload_hash.split(":", 1)[1]
            )
        )

    except Exception:
        return False


def revalidate_physical_target_for_execution_handoff(
    *,
    registry: Any,
    approval_id: Any,
    request: Any,
    record: Any,
    journal: Any,
    gate: Any,
) -> FreshPhysicalTargetRevalidationDecision:
    """Freshly revalidate one 6D-D handoff using established discovery.

    The exact immutable handoff is rebuilt internally from registry, gate,
    request, record, and completed journal evidence.

    Fresh physical state is then obtained only through
    evaluate_current_authorization_prerequisites(), which owns the fixed
    Phase-4 read-only collector.

    No command, executor, approval event, or destructive mutation occurs.
    """

    try:
        handoff = (
            build_immutable_execution_handoff_contract(
                registry=registry,
                approval_id=approval_id,
                request=request,
                record=record,
                journal=journal,
                gate=gate,
            )
        )
    except ExecutionHandoffContractError as exc:
        raise FreshPhysicalTargetRevalidationError(
            "trusted execution handoff is unavailable"
        ) from exc

    if not _immutable_execution_handoff_integrity_valid(
        handoff
    ):
        raise FreshPhysicalTargetRevalidationError(
            "execution handoff integrity is invalid"
        )

    if (
        handoff.execution_supported
        is not False
        or handoff.executor_eligible
        is not False
        or handoff.requires_fresh_target_revalidation
        is not True
    ):
        raise FreshPhysicalTargetRevalidationError(
            "handoff execution boundary is invalid"
        )

    fresh = (
        evaluate_current_authorization_prerequisites(
            request,
            record,
        )
    )

    if (
        not decision_integrity_valid(fresh)
        or not decision_is_current(fresh)
        or fresh.status
        != STATUS_PREREQUISITES_MET
        or fresh.reason_codes != ()
        or fresh.request_hash is None
        or fresh.record_snapshot_hash is None
        or fresh.discovery_snapshot_hash is None
        or fresh.target_binding_hash is None
        or fresh.target_binding is None
        or fresh.prerequisite_valid_until_utc
        is None
    ):
        raise FreshPhysicalTargetRevalidationError(
            "fresh physical-target prerequisites are not positive and current"
        )

    if (
        fresh.request_id
        != handoff.request_id
        or fresh.request_hash
        != handoff.request_hash
        or fresh.record_snapshot_hash
        != handoff.record_snapshot_hash
        or request.request_id
        != handoff.request_id
        or request_hash(request)
        != handoff.request_hash
        or record_snapshot_hash(record)
        != handoff.record_snapshot_hash
    ):
        raise FreshPhysicalTargetRevalidationError(
            "fresh request or record identity differs from handoff"
        )

    target = fresh.target_binding

    if not _positive_binding_integrity_valid(
        target
    ):
        raise FreshPhysicalTargetRevalidationError(
            "fresh physical target binding is not strictly safe"
        )

    fresh_target_hash = _canonical_hash(
        asdict(target)
    )

    if (
        fresh_target_hash
        != fresh.target_binding_hash
        or fresh_target_hash
        != handoff.target_binding_hash
    ):
        raise FreshPhysicalTargetRevalidationError(
            "fresh physical target binding differs from handoff"
        )

    if (
        target.path
        != handoff.target_path
        or target.major_minor
        != handoff.target_major_minor
        or target.serial
        != handoff.target_serial
        or target.wwn
        != handoff.target_wwn
        or target.size_bytes
        != handoff.target_size_bytes
        or target.model
        != handoff.target_model
        or target.transport
        != handoff.target_transport
    ):
        raise FreshPhysicalTargetRevalidationError(
            "fresh physical target identity facts differ from handoff"
        )

    if any((
        target.read_only,
        target.mounted,
        target.protected,
        target.system_protected,
        target.review_required,
        target.ambiguous,
    )):
        raise FreshPhysicalTargetRevalidationError(
            "fresh physical target has a safety blocker"
        )

    policy = get_sanitization_method_policy(
        request.method_profile_id
    )

    metadata = (
        get_sanitization_method_capability_metadata(
            request.method_profile_id
        )
    )

    if (
        policy is None
        or metadata is None
        or policy.method_profile_id
        != handoff.method_profile_id
        or metadata.method_profile_id
        != handoff.method_profile_id
        or policy.operation
        != handoff.operation
        or policy.policy_only is not True
        or policy.execution_supported is not False
        or metadata.capability_class
        != "policy_only"
    ):
        raise FreshPhysicalTargetRevalidationError(
            "trusted method remains outside executable policy"
        )

    constraints = (
        evaluate_sanitization_method_constraints(
            request.method_profile_id,
            target,
        )
    )

    constraint_hash = _canonical_hash(
        asdict(constraints)
    )

    if (
        constraints.status
        != METHOD_CONSTRAINT_STATUS_SATISFIED
        or constraints.reason_codes != ()
        or constraints.method_profile_id
        != handoff.method_profile_id
        or constraints.target_binding_hash
        != fresh_target_hash
        or constraint_hash
        != handoff.constraint_evaluation_hash
    ):
        raise FreshPhysicalTargetRevalidationError(
            "fresh method constraints differ from handoff"
        )

    payload = _fresh_target_revalidation_payload(
        policy_version=(
            FRESH_TARGET_REVALIDATION_POLICY_VERSION
        ),
        schema_version=(
            FRESH_TARGET_REVALIDATION_SCHEMA_VERSION
        ),
        status=(
            FRESH_TARGET_REVALIDATION_STATUS_SATISFIED
        ),
        handoff_id=handoff.handoff_id,
        gate_id=handoff.gate_id,
        binding_id=handoff.binding_id,
        journal_entry_hash=(
            handoff.journal_entry_hash
        ),
        fresh_prerequisite_decision_id=(
            fresh.decision_id
        ),
        fresh_discovery_snapshot_hash=(
            fresh.discovery_snapshot_hash
        ),
        request_id=fresh.request_id,
        request_hash=fresh.request_hash,
        record_snapshot_hash=(
            fresh.record_snapshot_hash
        ),
        method_profile_id=(
            handoff.method_profile_id
        ),
        operation=handoff.operation,
        prior_target_binding_hash=(
            handoff.target_binding_hash
        ),
        fresh_target_binding_hash=(
            fresh_target_hash
        ),
        constraint_evaluation_hash=(
            constraint_hash
        ),
        target_path=target.path,
        target_major_minor=target.major_minor,
        target_serial=target.serial,
        target_wwn=target.wwn,
        target_size_bytes=target.size_bytes,
        target_model=target.model,
        target_transport=target.transport,
        target_read_only=target.read_only,
        target_mounted=target.mounted,
        target_protected=target.protected,
        target_system_protected=(
            target.system_protected
        ),
        target_review_required=(
            target.review_required
        ),
        target_ambiguous=(
            target.ambiguous
        ),
        discovery_captured_at_utc=(
            fresh.discovery_captured_at_utc
        ),
        evaluated_at_utc=(
            fresh.evaluated_at_utc
        ),
        valid_until_utc=(
            fresh.prerequisite_valid_until_utc
        ),
        execution_supported=False,
        executor_eligible=False,
        requires_separate_executor_authorization=True,
    )

    payload_hash = _canonical_hash(
        payload
    )

    decision = (
        FreshPhysicalTargetRevalidationDecision(
            revalidation_id=(
                "ptrv_"
                + payload_hash.split(":", 1)[1]
            ),
            policy_version=(
                FRESH_TARGET_REVALIDATION_POLICY_VERSION
            ),
            schema_version=(
                FRESH_TARGET_REVALIDATION_SCHEMA_VERSION
            ),
            status=(
                FRESH_TARGET_REVALIDATION_STATUS_SATISFIED
            ),
            handoff_id=handoff.handoff_id,
            gate_id=handoff.gate_id,
            binding_id=handoff.binding_id,
            journal_entry_hash=(
                handoff.journal_entry_hash
            ),
            fresh_prerequisite_decision_id=(
                fresh.decision_id
            ),
            fresh_discovery_snapshot_hash=(
                fresh.discovery_snapshot_hash
            ),
            request_id=fresh.request_id,
            request_hash=fresh.request_hash,
            record_snapshot_hash=(
                fresh.record_snapshot_hash
            ),
            method_profile_id=(
                handoff.method_profile_id
            ),
            operation=handoff.operation,
            prior_target_binding_hash=(
                handoff.target_binding_hash
            ),
            fresh_target_binding_hash=(
                fresh_target_hash
            ),
            constraint_evaluation_hash=(
                constraint_hash
            ),
            target_path=target.path,
            target_major_minor=target.major_minor,
            target_serial=target.serial,
            target_wwn=target.wwn,
            target_size_bytes=target.size_bytes,
            target_model=target.model,
            target_transport=(
                target.transport
            ),
            target_read_only=(
                target.read_only
            ),
            target_mounted=target.mounted,
            target_protected=(
                target.protected
            ),
            target_system_protected=(
                target.system_protected
            ),
            target_review_required=(
                target.review_required
            ),
            target_ambiguous=(
                target.ambiguous
            ),
            discovery_captured_at_utc=(
                fresh.discovery_captured_at_utc
            ),
            evaluated_at_utc=(
                fresh.evaluated_at_utc
            ),
            valid_until_utc=(
                fresh.prerequisite_valid_until_utc
            ),
            execution_supported=False,
            executor_eligible=False,
            requires_separate_executor_authorization=True,
        )
    )

    if not (
        _fresh_physical_target_revalidation_integrity_valid(
            decision
        )
    ):
        raise FreshPhysicalTargetRevalidationError(
            "constructed fresh target revalidation failed integrity validation"
        )

    return decision
__all__ = [
    "APPROVAL_POLICY_VERSION",
    "APPROVAL_CHALLENGE_LIFETIME_SECONDS",
    "APPROVAL_REVALIDATION_WINDOW_SECONDS",
    "APPROVAL_STATUS_REVALIDATED",
    "APPROVAL_STATUS_REVALIDATION_FAILED",
    "ApprovalError",
    "ApprovalChallenge",
    "HumanApprovalEvidence",
    "ApprovalRevalidationDecision",
    "ApprovalRegistry",
    "TrustedExecutionBindingDecision",
    "TrustedExecutionBindingError",
    "EXECUTION_BINDING_POLICY_VERSION",
    "EXECUTION_BINDING_SCHEMA_VERSION",
    "EXECUTION_BINDING_STATUS_SATISFIED",
    "OneShotExecutionGateDecision",
    "OneShotExecutionGateError",
    "EXECUTION_GATE_POLICY_VERSION",
    "EXECUTION_GATE_SCHEMA_VERSION",
    "EXECUTION_GATE_STATUS_SATISFIED",
    "DurableExecutionGateJournalEntry",
    "DurableExecutionGateConsumptionJournal",
    "DurableExecutionGateJournalError",
    "DurableOneShotExecutionGateError",
    "DURABLE_GATE_JOURNAL_POLICY_VERSION",
    "DURABLE_GATE_JOURNAL_SCHEMA_VERSION",
    "DURABLE_GATE_JOURNAL_STATE_RESERVED",
    "DURABLE_GATE_JOURNAL_STATE_COMPLETED",
    "ImmutableExecutionHandoffContract",
    "ExecutionHandoffContractError",
    "EXECUTION_HANDOFF_POLICY_VERSION",
    "EXECUTION_HANDOFF_SCHEMA_VERSION",
    "EXECUTION_HANDOFF_STATUS_CONTRACT_BUILT",
    "FreshPhysicalTargetRevalidationDecision",
    "FreshPhysicalTargetRevalidationError",
    "FRESH_TARGET_REVALIDATION_POLICY_VERSION",
    "FRESH_TARGET_REVALIDATION_SCHEMA_VERSION",
    "FRESH_TARGET_REVALIDATION_STATUS_SATISFIED",
    "AuthorizationDecision",
    "AuthorizationError",
    "AuthorizationRequest",
    "TargetIdentityBinding",
    "SanitizationMethodPolicy",
    "SanitizationMethodCapabilityMetadata",
    "SanitizationMethodConstraintEvaluation",
    "SyntheticSanitizationPlan",
    "SyntheticSanitizationPlanError",
    "SYNTHETIC_SANITIZATION_PLAN_SCHEMA_VERSION",
    "SYNTHETIC_SANITIZATION_PLAN_MODE",
    "SyntheticSanitizationMemoryTarget",
    "SyntheticSanitizationRunResult",
    "SyntheticSanitizationRunError",
    "SyntheticRunEvidenceIntegrationError",
    "SYNTHETIC_RUN_EVIDENCE_ORIGIN",
    "SYNTHETIC_SANITIZATION_RUN_SCHEMA_VERSION",
    "SYNTHETIC_SANITIZATION_RUN_MODE",
    "SYNTHETIC_SANITIZATION_RUN_STATUS_COMPLETED",
    "SYNTHETIC_SANITIZATION_MAX_PAYLOAD_BYTES",
    "METHOD_CONSTRAINT_STATUS_SATISFIED",
    "METHOD_CONSTRAINT_STATUS_REVIEW_REQUIRED",
    "METHOD_CONSTRAINT_STATUS_REFUSED",
    "METHOD_CONSTRAINT_STATUS_EVALUATION_FAILED",
    "POLICY_VERSION",
    "SCHEMA_VERSION",
    "EVIDENCE_ORIGIN",
    "MAX_DISCOVERY_AGE_SECONDS",
    "MAX_FUTURE_SKEW_SECONDS",
    "MAX_REQUEST_AGE_SECONDS",
    "PREREQUISITE_LIFETIME_SECONDS",
    "STATUS_PREREQUISITES_MET",
    "STATUS_REFUSED",
    "STATUS_REVIEW_REQUIRED",
    "STATUS_EVALUATION_FAILED",
    "build_authorization_request",
    "decision_integrity_valid",
    "decision_is_current",
    "discovery_snapshot_hash",
    "evaluate_current_authorization_prerequisites",
    "get_sanitization_method_policy",
    "get_sanitization_method_capability_metadata",
    "evaluate_sanitization_method_constraints",
    "build_synthetic_sanitization_plan",
    "run_synthetic_sanitization_plan",
    "build_drive_record_with_synthetic_run_evidence",
    "build_trusted_execution_binding",
    "satisfy_one_shot_execution_gate",
    "satisfy_durable_one_shot_execution_gate",
    "build_immutable_execution_handoff_contract",
    "revalidate_physical_target_for_execution_handoff",
    "record_snapshot_hash",
    "request_hash",
]
