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
import hashlib
import json
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


POLICY_VERSION = "phase5-auth-v3"
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

        return _approval_revalidation_result(
            approval_id=approval_id,
            evidence=evidence,
            fresh_decision=fresh,
            status=APPROVAL_STATUS_REVALIDATED,
            reason_codes=(),
            evaluated_at=fresh_evaluated_at,
        )

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
    "record_snapshot_hash",
    "request_hash",
]
