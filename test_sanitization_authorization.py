from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
import inspect
import json
import unittest
import sanitization_authorization as auth
from unittest.mock import patch

from drive_discovery import (
    BlockDevice,
    PhysicalDrive,
    parse_lsblk_json,
)
from drive_discovery_adapter import (
    DiscoveryCollectionError,
    DiscoverySnapshot,
)
from drive_sanitization_manager import DriveRecord
from sanitization_authorization import (
    AuthorizationDecision,
    STATUS_EVALUATION_FAILED,
    STATUS_PREREQUISITES_MET,
    STATUS_REFUSED,
    STATUS_REVIEW_REQUIRED,
    build_authorization_request,
    decision_integrity_valid,
    decision_is_current,
    discovery_snapshot_hash,
    evaluate_current_authorization_prerequisites,
    record_snapshot_hash,
    request_hash,
)


UTC = timezone.utc


class Phase5AuthorizationR2Tests(unittest.TestCase):
    REQUEST_TIME = datetime(
        2026, 8, 23, 9, 59, 0, tzinfo=UTC
    )
    CAPTURE_TIME = datetime(
        2026, 8, 23, 10, 0, 0, tzinfo=UTC
    )
    EVALUATION_TIME = datetime(
        2026, 8, 23, 10, 0, 30, tzinfo=UTC
    )

    def device(
        self,
        *,
        path="/dev/syn-a",
        size=1_000_000,
        model="Synthetic Model",
        serial="SERIAL-A",
        wwn="WWN-A",
        transport="usb",
        read_only=False,
        mountpoints=None,
    ):
        name = path.rsplit("/", 1)[-1]

        return {
            "name": name,
            "kname": name,
            "path": path,
            "type": "disk",
            "size": size,
            "model": model,
            "serial": serial,
            "tran": transport,
            "rota": 0,
            "rm": 1,
            "ro": read_only,
            "wwn": wwn,
            "pkname": None,
            "fstype": None,
            "mountpoints": (
                []
                if mountpoints is None
                else mountpoints
            ),
        }

    def snapshot(
        self,
        devices=None,
        *,
        protected_sources=(),
    ):
        if devices is None:
            devices = [self.device()]

        raw = json.dumps(
            {"blockdevices": devices},
            separators=(",", ":"),
        ).encode("utf-8")

        protected = tuple(protected_sources)

        drives = parse_lsblk_json(
            raw,
            protected_sources=protected,
        )

        return DiscoverySnapshot(
            raw,
            protected,
            drives,
            b'{"synthetic":"root"}',
            b'{"synthetic":"real"}',
            b"",
            b'{"synthetic":"fstab"}',
        )

    def record(self, **changes):
        values = dict(
            internal_record_id="REC-A",
            batch_job_id="BATCH-A",
            model="Synthetic Model",
            serial_number="SERIAL-A",
            capacity_bytes=1_000_000,
            linux_device_path="/dev/syn-a",
            stable_device_identifier="WWN-A",
            mounted=False,
            system_protected=False,
            intended_action="sanitize",
            sanitization_eligibility_status="eligible",
            sanitization_status="not_started",
            intake_status="complete",
        )

        values.update(changes)

        record = DriveRecord(**values)
        record.validate()
        return record

    def request(
        self,
        record=None,
        *,
        created=None,
        **changes,
    ):
        if record is None:
            record = self.record()

        if created is None:
            created = self.REQUEST_TIME

        with patch(
            "sanitization_authorization._utc_now",
            return_value=created,
        ):
            request = build_authorization_request(
                record,
                request_id="REQ-A",
                operation="sanitize",
                method_profile_id=
                    "phase5-policy-only",
            )

        return (
            replace(request, **changes)
            if changes
            else request
        )

    def evaluate(
        self,
        *,
        record=None,
        request=None,
        snapshot=None,
        captured=None,
        evaluated=None,
    ):
        if record is None:
            record = self.record()

        if request is None:
            request = self.request(record)

        if snapshot is None:
            snapshot = self.snapshot()

        if captured is None:
            captured = self.CAPTURE_TIME

        if evaluated is None:
            evaluated = self.EVALUATION_TIME

        with (
            patch(
                "sanitization_authorization."
                "collect_current_drive_discovery",
                return_value=snapshot,
            ),
            patch(
                "sanitization_authorization._utc_now",
                side_effect=[captured, evaluated],
            ),
        ):
            return (
                evaluate_current_authorization_prerequisites(
                    request,
                    record,
                )
            )

    def assertReason(self, decision, reason):
        self.assertIn(
            reason,
            decision.reason_codes,
        )

    def test_exact_current_unique_target_meets_prerequisites(self):
        decision = self.evaluate()

        self.assertEqual(
            decision.status,
            STATUS_PREREQUISITES_MET,
        )
        self.assertEqual(decision.reason_codes, ())
        self.assertIsNotNone(
            decision.target_binding
        )

    def test_eligible_never_overrides_system_storage(self):
        snapshot = self.snapshot(
            protected_sources=("/dev/syn-a",)
        )

        decision = self.evaluate(
            snapshot=snapshot
        )

        self.assertEqual(
            decision.status,
            STATUS_REFUSED,
        )
        self.assertReason(
            decision,
            "SYSTEM_STORAGE",
        )
        self.assertReason(
            decision,
            "PROTECTED_STORAGE",
        )

    def test_eligible_never_overrides_current_mount(self):
        snapshot = self.snapshot([
            self.device(
                mountpoints=["/media/synthetic"]
            )
        ])

        decision = self.evaluate(
            snapshot=snapshot
        )

        self.assertEqual(
            decision.status,
            STATUS_REFUSED,
        )
        self.assertReason(
            decision,
            "TARGET_MOUNTED",
        )

    def test_read_only_target_refuses(self):
        snapshot = self.snapshot([
            self.device(read_only=True)
        ])

        decision = self.evaluate(
            snapshot=snapshot
        )

        self.assertEqual(
            decision.status,
            STATUS_REFUSED,
        )
        self.assertReason(
            decision,
            "TARGET_READ_ONLY",
        )

    def test_ineligible_record_refuses(self):
        record = self.record(
            sanitization_eligibility_status=
                "ineligible"
        )

        decision = self.evaluate(
            record=record,
            request=self.request(record),
        )

        self.assertEqual(
            decision.status,
            STATUS_REFUSED,
        )
        self.assertReason(
            decision,
            "RECORD_MARKED_INELIGIBLE",
        )

    def test_review_record_never_becomes_positive(self):
        record = self.record(
            sanitization_eligibility_status=
                "review_needed"
        )

        decision = self.evaluate(
            record=record,
            request=self.request(record),
        )

        self.assertEqual(
            decision.status,
            STATUS_REVIEW_REQUIRED,
        )
        self.assertReason(
            decision,
            "RECORD_REVIEW_REQUIRED",
        )

    def test_unknown_record_never_becomes_positive(self):
        record = self.record(
            sanitization_eligibility_status=
                "unknown"
        )

        decision = self.evaluate(
            record=record,
            request=self.request(record),
        )

        self.assertEqual(
            decision.status,
            STATUS_REVIEW_REQUIRED,
        )
        self.assertReason(
            decision,
            "RECORD_ELIGIBILITY_UNKNOWN",
        )

    def test_existing_sanitization_state_refuses(self):
        record = self.record(
            sanitization_status="succeeded"
        )

        decision = self.evaluate(
            record=record,
            request=self.request(record),
        )

        self.assertEqual(
            decision.status,
            STATUS_REFUSED,
        )
        self.assertReason(
            decision,
            "RECORD_SANITIZATION_STATE_NOT_READY",
        )

    def test_missing_strong_identity_fails_closed(self):
        record = self.record(
            serial_number=None,
            stable_device_identifier=None,
        )

        decision = self.evaluate(
            record=record,
            request=self.request(record),
        )

        self.assertEqual(
            decision.status,
            STATUS_EVALUATION_FAILED,
        )
        self.assertReason(
            decision,
            "STRONG_IDENTITY_MISSING",
        )

    def test_serial_only_can_bind_unique_target(self):
        record = self.record(
            stable_device_identifier=None
        )

        decision = self.evaluate(
            record=record,
            request=self.request(record),
        )

        self.assertEqual(
            decision.status,
            STATUS_PREREQUISITES_MET,
        )

    def test_stable_identifier_only_can_bind_unique_target(self):
        record = self.record(
            serial_number=None
        )

        decision = self.evaluate(
            record=record,
            request=self.request(record),
        )

        self.assertEqual(
            decision.status,
            STATUS_PREREQUISITES_MET,
        )

    def test_serial_mismatch_refuses(self):
        record = self.record(
            serial_number="OTHER-SERIAL"
        )

        decision = self.evaluate(
            record=record,
            request=self.request(record),
        )

        self.assertEqual(
            decision.status,
            STATUS_REFUSED,
        )
        self.assertReason(
            decision,
            "SERIAL_MISMATCH",
        )

    def test_stable_identifier_mismatch_refuses(self):
        record = self.record(
            stable_device_identifier="OTHER-WWN"
        )

        decision = self.evaluate(
            record=record,
            request=self.request(record),
        )

        self.assertEqual(
            decision.status,
            STATUS_REFUSED,
        )
        self.assertReason(
            decision,
            "STABLE_IDENTIFIER_MISMATCH",
        )

    def test_identity_components_diverging_fail_closed(self):
        snapshot = self.snapshot([
            self.device(
                path="/dev/syn-a",
                serial="SERIAL-A",
                wwn="WWN-X",
            ),
            self.device(
                path="/dev/syn-b",
                serial="SERIAL-B",
                wwn="WWN-A",
            ),
        ])

        decision = self.evaluate(
            snapshot=snapshot
        )

        self.assertEqual(
            decision.status,
            STATUS_EVALUATION_FAILED,
        )
        self.assertReason(
            decision,
            "IDENTITY_COMPONENTS_DIVERGE",
        )

    def test_duplicate_serial_fails_closed(self):
        snapshot = self.snapshot([
            self.device(),
            self.device(
                path="/dev/syn-b",
                serial="SERIAL-A",
                wwn="WWN-B",
            ),
        ])

        decision = self.evaluate(
            snapshot=snapshot
        )

        self.assertEqual(
            decision.status,
            STATUS_EVALUATION_FAILED,
        )
        self.assertReason(
            decision,
            "DUPLICATE_SERIAL",
        )

    def test_duplicate_stable_identifier_fails_closed(self):
        snapshot = self.snapshot([
            self.device(),
            self.device(
                path="/dev/syn-b",
                serial="SERIAL-B",
                wwn="WWN-A",
            ),
        ])

        decision = self.evaluate(
            snapshot=snapshot
        )

        self.assertEqual(
            decision.status,
            STATUS_EVALUATION_FAILED,
        )
        self.assertReason(
            decision,
            "DUPLICATE_STABLE_IDENTIFIER",
        )

    def test_same_path_with_changed_identity_refuses(self):
        snapshot = self.snapshot([
            self.device(
                serial="OTHER",
                wwn="OTHER-WWN",
            )
        ])

        decision = self.evaluate(
            snapshot=snapshot
        )

        self.assertEqual(
            decision.status,
            STATUS_REFUSED,
        )
        self.assertReason(
            decision,
            "TARGET_IDENTITY_CHANGED",
        )

    def test_target_not_present_fails_closed(self):
        snapshot = self.snapshot([
            self.device(
                path="/dev/syn-b",
                serial="OTHER",
                wwn="OTHER-WWN",
            )
        ])

        decision = self.evaluate(
            snapshot=snapshot
        )

        self.assertEqual(
            decision.status,
            STATUS_EVALUATION_FAILED,
        )
        self.assertReason(
            decision,
            "TARGET_NOT_PRESENT",
        )

    def test_changed_path_refuses_even_with_strong_identity(self):
        snapshot = self.snapshot([
            self.device(path="/dev/syn-z")
        ])

        decision = self.evaluate(
            snapshot=snapshot
        )

        self.assertEqual(
            decision.status,
            STATUS_REFUSED,
        )
        self.assertReason(
            decision,
            "DEVICE_PATH_CHANGED",
        )

    def test_capacity_mismatch_refuses(self):
        snapshot = self.snapshot([
            self.device(size=999_999)
        ])

        decision = self.evaluate(
            snapshot=snapshot
        )

        self.assertEqual(
            decision.status,
            STATUS_REFUSED,
        )
        self.assertReason(
            decision,
            "CAPACITY_MISMATCH",
        )

    def test_missing_record_capacity_fails_closed(self):
        record = self.record(
            capacity_bytes=None
        )

        decision = self.evaluate(
            record=record,
            request=self.request(record),
        )

        self.assertEqual(
            decision.status,
            STATUS_EVALUATION_FAILED,
        )
        self.assertReason(
            decision,
            "CAPACITY_UNKNOWN",
        )

    def test_zero_fresh_capacity_fails_closed(self):
        snapshot = self.snapshot([
            self.device(size=0)
        ])

        decision = self.evaluate(
            snapshot=snapshot
        )

        self.assertEqual(
            decision.status,
            STATUS_EVALUATION_FAILED,
        )
        self.assertReason(
            decision,
            "CAPACITY_INVALID",
        )

    def test_model_mismatch_requires_review(self):
        snapshot = self.snapshot([
            self.device(model="Other Model")
        ])

        decision = self.evaluate(
            snapshot=snapshot
        )

        self.assertEqual(
            decision.status,
            STATUS_REVIEW_REQUIRED,
        )
        self.assertReason(
            decision,
            "MODEL_MISMATCH_REVIEW_REQUIRED",
        )

    def test_collection_longer_than_sixty_seconds_is_stale(self):
        evaluated = datetime(
            2026, 8, 23, 10, 1, 1,
            tzinfo=UTC,
        )

        decision = self.evaluate(
            evaluated=evaluated
        )

        self.assertEqual(
            decision.status,
            STATUS_EVALUATION_FAILED,
        )
        self.assertReason(
            decision,
            "DISCOVERY_STALE",
        )

    def test_exact_sixty_second_collection_window_is_accepted(self):
        evaluated = datetime(
            2026, 8, 23, 10, 1, 0,
            tzinfo=UTC,
        )

        decision = self.evaluate(
            evaluated=evaluated
        )

        self.assertEqual(
            decision.status,
            STATUS_PREREQUISITES_MET,
        )

    def test_internal_clock_reversal_fails_closed(self):
        evaluated = datetime(
            2026, 8, 23, 9, 59, 54,
            tzinfo=UTC,
        )

        decision = self.evaluate(
            evaluated=evaluated
        )

        self.assertEqual(
            decision.status,
            STATUS_EVALUATION_FAILED,
        )
        self.assertReason(
            decision,
            "INTERNAL_CLOCK_INVALID",
        )

    def test_stale_request_fails_closed(self):
        old = datetime(
            2026, 8, 23, 9, 50, 0,
            tzinfo=UTC,
        )

        record = self.record()
        request = self.request(
            record,
            created=old,
        )

        decision = self.evaluate(
            record=record,
            request=request,
        )

        self.assertEqual(
            decision.status,
            STATUS_EVALUATION_FAILED,
        )
        self.assertReason(
            decision,
            "REQUEST_STALE",
        )

    def test_future_request_timestamp_fails_closed(self):
        future = datetime(
            2026, 8, 23, 10, 0, 40,
            tzinfo=UTC,
        )

        record = self.record()
        request = self.request(
            record,
            created=future,
        )

        decision = self.evaluate(
            record=record,
            request=request,
        )

        self.assertEqual(
            decision.status,
            STATUS_EVALUATION_FAILED,
        )
        self.assertReason(
            decision,
            "REQUEST_TIMESTAMP_INVALID",
        )

    def test_malformed_captured_lsblk_cannot_be_overridden_by_safe_drive_tuple(self):
        valid = self.snapshot()

        forged = DiscoverySnapshot(
            b'{"not":"lsblk"}',
            (),
            valid.drives,
            b"{}",
            b"{}",
            b"",
            b"{}",
        )

        decision = self.evaluate(
            snapshot=forged
        )

        self.assertEqual(
            decision.status,
            STATUS_EVALUATION_FAILED,
        )
        self.assertReason(
            decision,
            "DISCOVERY_EVIDENCE_INVALID",
        )

    def test_supplied_drive_tuple_must_equal_independent_reparse(self):
        protected = self.snapshot(
            protected_sources=("/dev/syn-a",)
        )

        actual = protected.drives[0]

        tampered = replace(
            actual,
            protected=False,
            system_protected=False,
            protection_reasons=(),
        )

        forged = replace(
            protected,
            drives=(tampered,),
        )

        decision = self.evaluate(
            snapshot=forged
        )

        self.assertEqual(
            decision.status,
            STATUS_EVALUATION_FAILED,
        )
        self.assertReason(
            decision,
            "DISCOVERY_EVIDENCE_MISMATCH",
        )

    def test_malformed_nonblank_record_serial_fails_closed(self):
        record = self.record(
            serial_number="BAD\x00SERIAL"
        )

        decision = self.evaluate(
            record=record,
            request=self.request(record),
        )

        self.assertEqual(
            decision.status,
            STATUS_EVALUATION_FAILED,
        )
        self.assertReason(
            decision,
            "MALFORMED_RECORD_SERIAL",
        )

    def test_malformed_nonblank_stable_identifier_fails_closed(self):
        record = self.record(
            stable_device_identifier="BAD\x00WWN"
        )

        decision = self.evaluate(
            record=record,
            request=self.request(record),
        )

        self.assertEqual(
            decision.status,
            STATUS_EVALUATION_FAILED,
        )
        self.assertReason(
            decision,
            "MALFORMED_RECORD_STABLE_IDENTIFIER",
        )

    def test_malformed_discovered_serial_fails_closed_even_when_wwn_matches(self):
        record = self.record(
            serial_number=None
        )

        snapshot = self.snapshot([
            self.device(
                serial="BAD\x00SERIAL",
                wwn="WWN-A",
            )
        ])

        decision = self.evaluate(
            record=record,
            request=self.request(record),
            snapshot=snapshot,
        )

        self.assertEqual(
            decision.status,
            STATUS_EVALUATION_FAILED,
        )
        self.assertReason(
            decision,
            "MALFORMED_DISCOVERED_SERIAL",
        )

    def test_record_mutation_after_request_breaks_hash_binding(self):
        record = self.record()
        request = self.request(record)

        record.model = "Changed Later"

        decision = self.evaluate(
            record=record,
            request=request,
        )

        self.assertEqual(
            decision.status,
            STATUS_EVALUATION_FAILED,
        )
        self.assertReason(
            decision,
            "RECORD_SNAPSHOT_MISMATCH",
        )

    def test_batch_and_record_ids_are_exactly_bound(self):
        record = self.record()
        request = self.request(record)

        wrong_batch = self.evaluate(
            record=record,
            request=replace(
                request,
                batch_job_id="OTHER-BATCH",
            ),
        )

        wrong_record = self.evaluate(
            record=record,
            request=replace(
                request,
                internal_record_id="OTHER-RECORD",
            ),
        )

        self.assertEqual(
            wrong_batch.status,
            STATUS_REFUSED,
        )
        self.assertReason(
            wrong_batch,
            "BATCH_ID_MISMATCH",
        )

        self.assertEqual(
            wrong_record.status,
            STATUS_REFUSED,
        )
        self.assertReason(
            wrong_record,
            "RECORD_ID_MISMATCH",
        )

    def test_operation_and_method_are_exactly_bound(self):
        record = self.record()
        request = self.request(record)

        wrong_operation = self.evaluate(
            record=record,
            request=replace(
                request,
                operation="other",
            ),
        )

        wrong_method = self.evaluate(
            record=record,
            request=replace(
                request,
                method_profile_id="other",
            ),
        )

        self.assertEqual(
            wrong_operation.status,
            STATUS_REFUSED,
        )
        self.assertReason(
            wrong_operation,
            "OPERATION_UNSUPPORTED",
        )

        self.assertEqual(
            wrong_method.status,
            STATUS_REFUSED,
        )
        self.assertReason(
            wrong_method,
            "METHOD_PROFILE_UNSUPPORTED",
        )

    def test_missing_intended_action_refuses(self):
        record = self.record(
            intended_action=None
        )

        decision = self.evaluate(
            record=record,
            request=self.request(record),
        )

        self.assertEqual(
            decision.status,
            STATUS_REFUSED,
        )
        self.assertReason(
            decision,
            "INTENDED_ACTION_MISSING",
        )

    def test_recorded_system_protection_cannot_be_relaxed_by_fresh_state(self):
        record = self.record(
            system_protected=True
        )

        decision = self.evaluate(
            record=record,
            request=self.request(record),
        )

        self.assertEqual(
            decision.status,
            STATUS_REFUSED,
        )
        self.assertReason(
            decision,
            "RECORDED_SYSTEM_PROTECTED",
        )

    def test_recorded_mount_and_unknown_states_require_review(self):
        mounted = self.record(
            mounted=True
        )

        mounted_decision = self.evaluate(
            record=mounted,
            request=self.request(mounted),
        )

        unknown = self.record(
            mounted=None,
            system_protected=None,
        )

        unknown_decision = self.evaluate(
            record=unknown,
            request=self.request(unknown),
        )

        self.assertEqual(
            mounted_decision.status,
            STATUS_REVIEW_REQUIRED,
        )
        self.assertReason(
            mounted_decision,
            "RECORDED_MOUNTED_REVIEW_REQUIRED",
        )

        self.assertEqual(
            unknown_decision.status,
            STATUS_REVIEW_REQUIRED,
        )
        self.assertReason(
            unknown_decision,
            "RECORDED_MOUNT_STATE_UNKNOWN",
        )
        self.assertReason(
            unknown_decision,
            "RECORDED_SYSTEM_STATE_UNKNOWN",
        )

    def test_incomplete_intake_requires_review(self):
        record = self.record(
            intake_status="in_progress"
        )

        decision = self.evaluate(
            record=record,
            request=self.request(record),
        )

        self.assertEqual(
            decision.status,
            STATUS_REVIEW_REQUIRED,
        )
        self.assertReason(
            decision,
            "RECORD_INTAKE_INCOMPLETE",
        )

    def test_collection_failure_returns_fail_closed_decision(self):
        record = self.record()
        request = self.request(record)

        with (
            patch(
                "sanitization_authorization."
                "collect_current_drive_discovery",
                side_effect=
                    DiscoveryCollectionError("synthetic"),
            ),
            patch(
                "sanitization_authorization._utc_now",
                side_effect=[
                    self.CAPTURE_TIME,
                    self.EVALUATION_TIME,
                ],
            ),
        ):
            decision = (
                evaluate_current_authorization_prerequisites(
                    request,
                    record,
                )
            )

        self.assertEqual(
            decision.status,
            STATUS_EVALUATION_FAILED,
        )
        self.assertReason(
            decision,
            "DISCOVERY_COLLECTION_FAILED",
        )
        self.assertIsNone(
            decision.discovery_snapshot_hash
        )

    def test_request_creation_time_is_internal_not_caller_supplied(self):
        record = self.record()

        with patch(
            "sanitization_authorization._utc_now",
            return_value=self.REQUEST_TIME,
        ):
            request = build_authorization_request(
                record,
                request_id="REQ-INTERNAL-TIME",
                operation="sanitize",
                method_profile_id=
                    "phase5-policy-only",
            )

        self.assertEqual(
            request.created_at_utc,
            "2026-08-23T09:59:00Z",
        )

    def test_decision_currentness_uses_internal_clock(self):
        decision = self.evaluate()

        current = datetime(
            2026, 8, 23, 10, 5, 30,
            tzinfo=UTC,
        )

        expired = datetime(
            2026, 8, 23, 10, 5, 31,
            tzinfo=UTC,
        )

        with patch(
            "sanitization_authorization._utc_now",
            return_value=current,
        ):
            self.assertTrue(
                decision_is_current(decision)
            )

        with patch(
            "sanitization_authorization._utc_now",
            return_value=expired,
        ):
            self.assertFalse(
                decision_is_current(decision)
            )

    def test_public_evaluator_cannot_accept_snapshot_or_time_substitution(self):
        parameters = inspect.signature(
            evaluate_current_authorization_prerequisites
        ).parameters

        self.assertEqual(
            list(parameters),
            ["request", "record"],
        )

    def test_request_builder_cannot_accept_creation_time_substitution(self):
        parameters = inspect.signature(
            build_authorization_request
        ).parameters

        self.assertNotIn(
            "created_at_utc",
            parameters,
        )

    def test_currentness_check_cannot_accept_time_substitution(self):
        parameters = inspect.signature(
            decision_is_current
        ).parameters

        self.assertEqual(
            list(parameters),
            ["decision"],
        )

    def test_request_decision_and_binding_are_frozen(self):
        record = self.record()
        request = self.request(record)
        decision = self.evaluate(
            record=record,
            request=request,
        )

        with self.assertRaises(
            FrozenInstanceError
        ):
            request.operation = "other"

        with self.assertRaises(
            FrozenInstanceError
        ):
            decision.status = STATUS_REFUSED

        with self.assertRaises(
            FrozenInstanceError
        ):
            decision.target_binding.path = "/dev/other"

    def test_hashes_are_deterministic(self):
        record = self.record()
        request = self.request(record)
        snapshot = self.snapshot()

        self.assertEqual(
            record_snapshot_hash(record),
            record_snapshot_hash(record),
        )

        self.assertEqual(
            request_hash(request),
            request_hash(request),
        )

        self.assertEqual(
            discovery_snapshot_hash(snapshot),
            discovery_snapshot_hash(snapshot),
        )

    def test_decisions_are_deterministic_for_same_trusted_inputs(self):
        first = self.evaluate()
        second = self.evaluate()

        self.assertEqual(first, second)

    def test_reason_order_is_deterministic(self):
        record = self.record(
            sanitization_eligibility_status=
                "ineligible",
            mounted=True,
            system_protected=True,
        )

        snapshot = self.snapshot(
            [self.device(
                read_only=True,
                mountpoints=["/media/x"],
            )],
            protected_sources=("/dev/syn-a",),
        )

        request = self.request(record)

        first = self.evaluate(
            record=record,
            request=request,
            snapshot=snapshot,
        )

        second = self.evaluate(
            record=record,
            request=request,
            snapshot=snapshot,
        )

        self.assertEqual(
            first.reason_codes,
            second.reason_codes,
        )

    def test_discovery_models_gain_no_destructive_authority(self):
        forbidden = {
            "approved",
            "approval_token",
            "authorization",
            "execute",
            "executor",
            "execution_authority",
            "safe_to_wipe",
        }

        physical_names = {
            item.name
            for item in fields(PhysicalDrive)
        }

        snapshot_names = {
            item.name
            for item in fields(DiscoverySnapshot)
        }

        self.assertTrue(
            forbidden.isdisjoint(
                physical_names
            )
        )

        self.assertTrue(
            forbidden.isdisjoint(
                snapshot_names
            )
        )

    def test_decision_has_no_human_approval_or_executor_surface(self):
        names = {
            item.name
            for item in fields(
                AuthorizationDecision
            )
        }

        for forbidden in (
            "approved",
            "approval_token",
            "executor",
            "command",
            "execution_authority",
            "safe_to_wipe",
        ):
            self.assertNotIn(
                forbidden,
                names,
            )

    def test_case_only_serial_difference_refuses_even_when_wwn_is_exact(self):
        record = self.record()

        snapshot = self.snapshot([
            self.device(
                serial="serial-a",
                wwn="WWN-A",
            )
        ])

        decision = self.evaluate(
            record=record,
            request=self.request(record),
            snapshot=snapshot,
        )

        self.assertEqual(
            decision.status,
            STATUS_REFUSED,
        )
        self.assertReason(
            decision,
            "SERIAL_MISMATCH",
        )

    def test_case_only_single_strong_identity_does_not_match(self):
        record = self.record(
            stable_device_identifier=None
        )

        snapshot = self.snapshot([
            self.device(
                serial="serial-a",
                wwn=None,
            )
        ])

        decision = self.evaluate(
            record=record,
            request=self.request(record),
            snapshot=snapshot,
        )

        self.assertNotEqual(
            decision.status,
            STATUS_PREREQUISITES_MET,
        )
        self.assertReason(
            decision,
            "TARGET_IDENTITY_CHANGED",
        )

    def test_intended_action_case_difference_refuses(self):
        record = self.record(
            intended_action="SANITIZE"
        )

        decision = self.evaluate(
            record=record,
            request=self.request(record),
        )

        self.assertEqual(
            decision.status,
            STATUS_REFUSED,
        )
        self.assertReason(
            decision,
            "INTENDED_ACTION_MISMATCH",
        )

    def test_malformed_request_object_returns_controlled_failure(self):
        record = self.record()

        class MalformedRequest:
            pass

        decision = self.evaluate(
            record=record,
            request=MalformedRequest(),
        )

        self.assertEqual(
            decision.status,
            STATUS_EVALUATION_FAILED,
        )
        self.assertReason(
            decision,
            "REQUEST_SCHEMA_INVALID",
        )

    def test_malformed_record_object_returns_controlled_failure(self):
        valid_record = self.record()
        request = self.request(valid_record)

        class MalformedRecord:
            pass

        decision = self.evaluate(
            record=MalformedRecord(),
            request=request,
        )

        self.assertEqual(
            decision.status,
            STATUS_EVALUATION_FAILED,
        )
        self.assertReason(
            decision,
            "RECORD_INVALID",
        )

    def test_mutated_invalid_drive_record_returns_controlled_failure(self):
        record = self.record()
        request = self.request(record)

        record.batch_job_id = ""

        decision = self.evaluate(
            record=record,
            request=request,
        )

        self.assertEqual(
            decision.status,
            STATUS_EVALUATION_FAILED,
        )
        self.assertReason(
            decision,
            "RECORD_INVALID",
        )

    def test_decision_integrity_accepts_genuine_positive_decision(self):
        decision = self.evaluate()

        self.assertEqual(
            decision.status,
            STATUS_PREREQUISITES_MET,
        )
        self.assertTrue(
            decision_integrity_valid(decision)
        )

    def test_decision_integrity_rejects_invented_decision_id(self):
        decision = self.evaluate()

        forged = replace(
            decision,
            decision_id="sha256:" + ("0" * 64),
        )

        self.assertFalse(
            decision_integrity_valid(forged)
        )
        self.assertFalse(
            decision_is_current(forged)
        )

    def test_decision_integrity_binds_request_id(self):
        decision = self.evaluate()

        tampered = replace(
            decision,
            request_id="REQ-TAMPERED",
        )

        self.assertFalse(
            decision_integrity_valid(tampered)
        )

    def test_decision_integrity_rejects_status_or_reason_tampering(self):
        decision = self.evaluate()

        self.assertFalse(
            decision_integrity_valid(
                replace(
                    decision,
                    status=STATUS_REFUSED,
                )
            )
        )

        self.assertFalse(
            decision_integrity_valid(
                replace(
                    decision,
                    reason_codes=("TARGET_MOUNTED",),
                )
            )
        )

    def test_decision_integrity_binds_target_binding(self):
        decision = self.evaluate()

        tampered_binding = replace(
            decision.target_binding,
            path="/dev/other-synthetic",
        )

        self.assertFalse(
            decision_integrity_valid(
                replace(
                    decision,
                    target_binding=tampered_binding,
                )
            )
        )

    def test_decision_integrity_rejects_extended_prerequisite_lifetime(self):
        decision = self.evaluate()

        expires = datetime.fromisoformat(
            decision.prerequisite_valid_until_utc
            .replace("Z", "+00:00")
        )

        extended = (
            expires
            + timedelta(seconds=1)
        ).isoformat().replace(
            "+00:00",
            "Z",
        )

        self.assertFalse(
            decision_integrity_valid(
                replace(
                    decision,
                    prerequisite_valid_until_utc=extended,
                )
            )
        )

    def test_decision_integrity_rejects_policy_schema_or_origin_tampering(self):
        decision = self.evaluate()

        values = (
            replace(
                decision,
                policy_version="phase5-auth-v2",
            ),
            replace(
                decision,
                schema_version=999,
            ),
            replace(
                decision,
                evidence_origin="fabricated-origin",
            ),
        )

        for value in values:
            with self.subTest(value=value):
                self.assertFalse(
                    decision_integrity_valid(value)
                )

    def test_decision_integrity_and_currentness_fail_closed_on_malformed_input(self):
        decision = self.evaluate()

        malformed_values = (
            object(),
            replace(
                decision,
                decision_id=object(),
            ),
            replace(
                decision,
                request_id=object(),
            ),
            replace(
                decision,
                evaluated_at_utc=object(),
            ),
            replace(
                decision,
                status=[],
            ),
            replace(
                decision,
                reason_codes=([],),
            ),
            replace(
                decision,
                target_binding=replace(
                    decision.target_binding,
                    path=object(),
                ),
            ),
            replace(
                decision,
                target_binding=replace(
                    decision.target_binding,
                    mounted=1,
                ),
            ),
        )

        for value in malformed_values:
            with self.subTest(value=type(value).__name__):
                self.assertFalse(
                    decision_integrity_valid(value)
                )
                self.assertFalse(
                    decision_is_current(value)
                )

    def test_decision_integrity_accepts_exact_five_second_future_skew(self):
        record = self.record()
        snapshot = self.snapshot()

        with patch(
            "sanitization_authorization._utc_now",
            return_value=datetime(
                2026, 8, 23, 9, 59, 0,
                tzinfo=UTC,
            ),
        ):
            request = build_authorization_request(
                record,
                request_id="SKEW-BOUNDARY-REQ",
                operation="sanitize",
                method_profile_id="phase5-policy-only",
            )

        with (
            patch(
                "sanitization_authorization."
                "collect_current_drive_discovery",
                return_value=snapshot,
            ),
            patch(
                "sanitization_authorization._utc_now",
                side_effect=[
                    datetime(
                        2026, 8, 23, 10, 0, 5,
                        tzinfo=UTC,
                    ),
                    datetime(
                        2026, 8, 23, 10, 0, 0,
                        tzinfo=UTC,
                    ),
                ],
            ),
        ):
            decision = (
                evaluate_current_authorization_prerequisites(
                    request,
                    record,
                )
            )

        self.assertEqual(
            decision.status,
            STATUS_PREREQUISITES_MET,
        )
        self.assertTrue(
            decision_integrity_valid(decision)
        )

    def test_decision_currentness_allows_exact_skew_but_rejects_excessive_rollback(self):
        decision = self.evaluate()

        evaluated = datetime.fromisoformat(
            decision.evaluated_at_utc.replace(
                "Z",
                "+00:00",
            )
        )

        exact_boundary = (
            evaluated
            - timedelta(seconds=5)
        )

        beyond_boundary = (
            exact_boundary
            - timedelta(seconds=1)
        )

        with patch(
            "sanitization_authorization._utc_now",
            return_value=exact_boundary,
        ):
            self.assertTrue(
                decision_is_current(decision)
            )

        with patch(
            "sanitization_authorization._utc_now",
            return_value=beyond_boundary,
        ):
            self.assertFalse(
                decision_is_current(decision)
            )

    def test_genuine_nonpositive_decisions_remain_integrity_valid(self):
        refused_record = self.record(
            intended_action="different-action"
        )

        refused = self.evaluate(
            record=refused_record,
            request=self.request(
                refused_record
            ),
        )

        review_record = self.record(
            sanitization_eligibility_status="review_needed"
        )

        review = self.evaluate(
            record=review_record,
            request=self.request(
                review_record
            ),
        )

        malformed_snapshot = self.snapshot([
            self.device(
                serial="BAD\x00SERIAL",
                wwn="WWN-A",
            )
        ])

        record = self.record()

        failed = self.evaluate(
            record=record,
            request=self.request(record),
            snapshot=malformed_snapshot,
        )

        for decision in (
            refused,
            review,
            failed,
        ):
            with self.subTest(status=decision.status):
                self.assertNotEqual(
                    decision.status,
                    STATUS_PREREQUISITES_MET,
                )
                self.assertTrue(
                    decision_integrity_valid(
                        decision
                    )
                )
                self.assertFalse(
                    decision_is_current(
                        decision
                    )
                )

    def test_positive_integrity_requires_complete_evidence_and_safe_binding(self):
        decision = self.evaluate()

        missing_hash = replace(
            decision,
            discovery_snapshot_hash=None,
        )

        unsafe_binding = replace(
            decision.target_binding,
            mounted=True,
        )

        unsafe = replace(
            decision,
            target_binding=unsafe_binding,
        )

        self.assertFalse(
            decision_integrity_valid(
                missing_hash
            )
        )
        self.assertFalse(
            decision_integrity_valid(
                unsafe
            )
        )

    def test_currentness_uses_later_of_evaluation_and_discovery_timestamp(self):
        record = self.record()
        snapshot = self.snapshot()

        with patch(
            "sanitization_authorization._utc_now",
            return_value=datetime(
                2026, 8, 23, 9, 59, 0,
                tzinfo=UTC,
            ),
        ):
            request = build_authorization_request(
                record,
                request_id="R3-CURRENTNESS-LATER-TIME",
                operation="sanitize",
                method_profile_id="phase5-policy-only",
            )

        with (
            patch(
                "sanitization_authorization."
                "collect_current_drive_discovery",
                return_value=snapshot,
            ),
            patch(
                "sanitization_authorization._utc_now",
                side_effect=[
                    datetime(
                        2026, 8, 23, 10, 0, 5,
                        tzinfo=UTC,
                    ),
                    datetime(
                        2026, 8, 23, 10, 0, 0,
                        tzinfo=UTC,
                    ),
                ],
            ),
        ):
            decision = (
                evaluate_current_authorization_prerequisites(
                    request,
                    record,
                )
            )

        with patch(
            "sanitization_authorization._utc_now",
            return_value=datetime(
                2026, 8, 23, 10, 0, 0,
                tzinfo=UTC,
            ),
        ):
            self.assertTrue(
                decision_is_current(decision)
            )

        with patch(
            "sanitization_authorization._utc_now",
            return_value=datetime(
                2026, 8, 23, 9, 59, 59,
                tzinfo=UTC,
            ),
        ):
            self.assertFalse(
                decision_is_current(decision)
            )

    def test_rehashed_positive_rejects_each_unsafe_safety_flag(self):
        from dataclasses import asdict
        import sanitization_authorization as auth

        decision = self.evaluate()

        flag_names = (
            "read_only",
            "mounted",
            "protected",
            "system_protected",
            "review_required",
            "ambiguous",
        )

        for flag_name in flag_names:
            with self.subTest(flag=flag_name):
                unsafe_binding = replace(
                    decision.target_binding,
                    **{flag_name: True},
                )

                unsafe_binding_hash = (
                    auth._canonical_hash(
                        asdict(unsafe_binding)
                    )
                )

                tampered = replace(
                    decision,
                    target_binding=unsafe_binding,
                    target_binding_hash=unsafe_binding_hash,
                )

                payload = {
                    "policy_version":
                        tampered.policy_version,
                    "schema_version":
                        tampered.schema_version,
                    "evidence_origin":
                        tampered.evidence_origin,
                    "request_id":
                        tampered.request_id,
                    "request_hash":
                        tampered.request_hash,
                    "record_snapshot_hash":
                        tampered.record_snapshot_hash,
                    "discovery_snapshot_hash":
                        tampered.discovery_snapshot_hash,
                    "target_binding_hash":
                        tampered.target_binding_hash,
                    "status":
                        tampered.status,
                    "reason_codes":
                        tampered.reason_codes,
                    "evaluated_at_utc":
                        tampered.evaluated_at_utc,
                    "discovery_captured_at_utc":
                        tampered.discovery_captured_at_utc,
                    "prerequisite_valid_until_utc":
                        tampered.prerequisite_valid_until_utc,
                }

                rehashed = replace(
                    tampered,
                    decision_id=auth._canonical_hash(
                        payload
                    ),
                )

                self.assertFalse(
                    decision_integrity_valid(
                        rehashed
                    )
                )
                self.assertFalse(
                    decision_is_current(
                        rehashed
                    )
                )


    def _phase6a2_request(
        self,
        record,
        *,
        request_id="PHASE6A2-REQ",
        at=None,
    ):
        if at is None:
            at = datetime(
                2026, 8, 23, 9, 59, 0,
                tzinfo=timezone.utc,
            )

        with patch(
            "sanitization_authorization._utc_now",
            return_value=at,
        ):
            return auth.build_authorization_request(
                record,
                request_id=request_id,
                operation="sanitize",
                method_profile_id="phase5-policy-only",
            )

    def _phase6a2_create_challenge(
        self,
        *,
        registry=None,
        record=None,
        snapshot=None,
        at=None,
        request_id="PHASE6A2-REQ",
    ):
        if registry is None:
            registry = auth.ApprovalRegistry()

        if record is None:
            record = self.record()

        if snapshot is None:
            snapshot = self.snapshot()

        if at is None:
            at = datetime(
                2026, 8, 23, 10, 0, 0,
                tzinfo=timezone.utc,
            )

        request = self._phase6a2_request(
            record,
            request_id=request_id,
            at=at - timedelta(seconds=60),
        )

        with (
            patch(
                "sanitization_authorization."
                "collect_current_drive_discovery",
                return_value=snapshot,
            ),
            patch(
                "sanitization_authorization._utc_now",
                return_value=at,
            ),
        ):
            challenge = registry.create_challenge(
                request,
                record,
            )

        return (
            registry,
            record,
            request,
            challenge,
            snapshot,
            at,
        )

    def _phase6a2_start_approval(
        self,
        *,
        registry=None,
        record=None,
        snapshot=None,
        at=None,
        request_id="PHASE6A2-REQ",
    ):
        (
            registry,
            record,
            request,
            challenge,
            snapshot,
            at,
        ) = self._phase6a2_create_challenge(
            registry=registry,
            record=record,
            snapshot=snapshot,
            at=at,
            request_id=request_id,
        )

        with patch(
            "sanitization_authorization._utc_now",
            return_value=at,
        ):
            evidence = (
                registry.record_human_approval(
                    challenge.challenge_id
                )
            )

        return (
            registry,
            record,
            request,
            challenge,
            evidence,
            snapshot,
            at,
        )

    def _phase6a2_revalidate(
        self,
        registry,
        evidence,
        request,
        record,
        snapshot,
        *,
        at,
    ):
        with (
            patch(
                "sanitization_authorization."
                "collect_current_drive_discovery",
                return_value=snapshot,
            ),
            patch(
                "sanitization_authorization._utc_now",
                return_value=at,
            ),
        ):
            return registry.revalidate_approval(
                evidence.approval_id,
                request,
                record,
            )

    def test_approval_registry_public_surface_has_no_decision_or_boolean_authority(
        self,
    ):
        create_params = inspect.signature(
            auth.ApprovalRegistry.create_challenge
        ).parameters

        approval_params = inspect.signature(
            auth.ApprovalRegistry.record_human_approval
        ).parameters

        revalidate_params = inspect.signature(
            auth.ApprovalRegistry.revalidate_approval
        ).parameters

        self.assertEqual(
            tuple(create_params),
            ("self", "request", "record"),
        )

        self.assertEqual(
            tuple(approval_params),
            ("self", "challenge_id"),
        )

        self.assertEqual(
            tuple(revalidate_params),
            (
                "self",
                "approval_id",
                "request",
                "record",
            ),
        )

        for params in (
            create_params,
            approval_params,
            revalidate_params,
        ):
            for forbidden in (
                "decision",
                "current_decision",
                "approved",
                "approval_evidence",
                "now",
                "nonce",
            ):
                self.assertNotIn(
                    forbidden,
                    params,
                )

    def test_create_challenge_uses_fresh_internal_positive_evaluation(
        self,
    ):
        record = self.record()
        snapshot = self.snapshot()

        at = datetime(
            2026, 8, 23, 10, 0, 0,
            tzinfo=timezone.utc,
        )

        request = self._phase6a2_request(
            record,
            at=at - timedelta(seconds=60),
        )

        registry = auth.ApprovalRegistry()

        original = (
            auth.evaluate_current_authorization_prerequisites
        )

        with (
            patch(
                "sanitization_authorization."
                "collect_current_drive_discovery",
                return_value=snapshot,
            ),
            patch(
                "sanitization_authorization._utc_now",
                return_value=at,
            ),
            patch(
                "sanitization_authorization."
                "evaluate_current_authorization_prerequisites",
                wraps=original,
            ) as evaluator,
        ):
            challenge = registry.create_challenge(
                request,
                record,
            )

        self.assertEqual(
            evaluator.call_count,
            1,
        )

        self.assertTrue(
            auth._approval_challenge_integrity_valid(
                challenge
            )
        )

    def test_create_challenge_rejects_nonpositive_target(
        self,
    ):
        mounted_snapshot = self.snapshot([
            self.device(
                mountpoints=[
                    "/mnt/phase6a2"
                ]
            )
        ])

        with self.assertRaises(
            auth.ApprovalError
        ):
            self._phase6a2_create_challenge(
                snapshot=mounted_snapshot
            )

    def test_challenge_creation_rejects_post_evaluation_clock_rollback(
        self,
    ):
        record = self.record()
        snapshot = self.snapshot()

        at = datetime(
            2026, 8, 23, 10, 0, 0,
            tzinfo=timezone.utc,
        )

        request = self._phase6a2_request(
            record,
            at=at - timedelta(seconds=60),
        )

        registry = auth.ApprovalRegistry()

        with (
            patch(
                "sanitization_authorization."
                "collect_current_drive_discovery",
                return_value=snapshot,
            ),
            patch(
                "sanitization_authorization._utc_now",
                side_effect=[
                    at,
                    at,
                    at,
                    at - timedelta(seconds=6),
                ],
            ),
            self.assertRaises(
                auth.ApprovalError
            ),
        ):
            registry.create_challenge(
                request,
                record,
            )

    def test_expired_challenge_cannot_be_approved(
        self,
    ):
        (
            registry,
            _record,
            _request,
            challenge,
            _snapshot,
            at,
        ) = self._phase6a2_create_challenge()

        with (
            patch(
                "sanitization_authorization._utc_now",
                return_value=(
                    at
                    + timedelta(
                        seconds=(
                            auth.APPROVAL_CHALLENGE_LIFETIME_SECONDS
                            + 1
                        )
                    )
                ),
            ),
            self.assertRaises(
                auth.ApprovalError
            ),
        ):
            registry.record_human_approval(
                challenge.challenge_id
            )

    def test_challenge_can_be_approved_only_once(
        self,
    ):
        (
            registry,
            _record,
            _request,
            challenge,
            _snapshot,
            at,
        ) = self._phase6a2_create_challenge()

        with patch(
            "sanitization_authorization._utc_now",
            return_value=at,
        ):
            evidence = (
                registry.record_human_approval(
                    challenge.challenge_id
                )
            )

        self.assertTrue(
            auth._approval_evidence_integrity_valid(
                evidence
            )
        )

        with (
            patch(
                "sanitization_authorization._utc_now",
                return_value=at,
            ),
            self.assertRaises(
                auth.ApprovalError
            ),
        ):
            registry.record_human_approval(
                challenge.challenge_id
            )

    def test_exact_approval_flow_revalidates_fresh_state(
        self,
    ):
        (
            registry,
            record,
            request,
            challenge,
            evidence,
            snapshot,
            at,
        ) = self._phase6a2_start_approval()

        result = self._phase6a2_revalidate(
            registry,
            evidence,
            request,
            record,
            snapshot,
            at=at + timedelta(seconds=1),
        )

        self.assertEqual(
            result.status,
            auth.APPROVAL_STATUS_REVALIDATED,
        )

        self.assertEqual(
            result.reason_codes,
            (),
        )

        self.assertEqual(
            result.approval_id,
            evidence.approval_id,
        )

        self.assertEqual(
            result.challenge_id,
            challenge.challenge_id,
        )

        self.assertEqual(
            result.original_target_binding_hash,
            result.fresh_target_binding_hash,
        )

        self.assertNotEqual(
            result.original_prerequisite_decision_id,
            result.fresh_prerequisite_decision_id,
        )

    def test_revalidation_can_be_attempted_only_once(
        self,
    ):
        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            snapshot,
            at,
        ) = self._phase6a2_start_approval()

        first = self._phase6a2_revalidate(
            registry,
            evidence,
            request,
            record,
            snapshot,
            at=at + timedelta(seconds=1),
        )

        second = self._phase6a2_revalidate(
            registry,
            evidence,
            request,
            record,
            snapshot,
            at=at + timedelta(seconds=2),
        )

        self.assertEqual(
            first.status,
            auth.APPROVAL_STATUS_REVALIDATED,
        )

        self.assertEqual(
            second.reason_codes,
            (
                "APPROVAL_ALREADY_CONSUMED",
            ),
        )

    def test_expired_approval_fails_closed_and_is_consumed(
        self,
    ):
        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            snapshot,
            at,
        ) = self._phase6a2_start_approval()

        expired = self._phase6a2_revalidate(
            registry,
            evidence,
            request,
            record,
            snapshot,
            at=(
                at
                + timedelta(
                    seconds=(
                        auth.APPROVAL_REVALIDATION_WINDOW_SECONDS
                        + 1
                    )
                )
            ),
        )

        self.assertEqual(
            expired.reason_codes,
            ("APPROVAL_EXPIRED",),
        )

        second = self._phase6a2_revalidate(
            registry,
            evidence,
            request,
            record,
            snapshot,
            at=at + timedelta(seconds=2),
        )

        self.assertEqual(
            second.reason_codes,
            (
                "APPROVAL_ALREADY_CONSUMED",
            ),
        )

    def test_failed_revalidation_is_consumed(
        self,
    ):
        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            _snapshot,
            at,
        ) = self._phase6a2_start_approval()

        unsafe_snapshot = self.snapshot([
            self.device(
                mountpoints=[
                    "/mnt/phase6a2"
                ]
            )
        ])

        failed = self._phase6a2_revalidate(
            registry,
            evidence,
            request,
            record,
            unsafe_snapshot,
            at=at + timedelta(seconds=1),
        )

        self.assertEqual(
            failed.status,
            auth.APPROVAL_STATUS_REVALIDATION_FAILED,
        )

        second = self._phase6a2_revalidate(
            registry,
            evidence,
            request,
            record,
            self.snapshot(),
            at=at + timedelta(seconds=2),
        )

        self.assertEqual(
            second.reason_codes,
            (
                "APPROVAL_ALREADY_CONSUMED",
            ),
        )

    def test_record_mutation_after_challenge_fails_revalidation(
        self,
    ):
        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            snapshot,
            at,
        ) = self._phase6a2_start_approval()

        changed_record = replace(
            record,
            intended_action="different-action",
        )

        result = self._phase6a2_revalidate(
            registry,
            evidence,
            request,
            changed_record,
            snapshot,
            at=at + timedelta(seconds=1),
        )

        self.assertEqual(
            result.status,
            auth.APPROVAL_STATUS_REVALIDATION_FAILED,
        )

    def test_path_change_with_same_identity_fails_revalidation(
        self,
    ):
        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            _snapshot,
            at,
        ) = self._phase6a2_start_approval()

        moved_snapshot = self.snapshot([
            self.device(
                path="/dev/phase6a2-other"
            )
        ])

        result = self._phase6a2_revalidate(
            registry,
            evidence,
            request,
            record,
            moved_snapshot,
            at=at + timedelta(seconds=1),
        )

        self.assertEqual(
            result.status,
            auth.APPROVAL_STATUS_REVALIDATION_FAILED,
        )

    def test_strong_identity_change_fails_revalidation(
        self,
    ):
        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            _snapshot,
            at,
        ) = self._phase6a2_start_approval()

        changed_snapshot = self.snapshot([
            self.device(
                serial=(
                    "PHASE6A2-OTHER-SERIAL"
                ),
                wwn=(
                    "PHASE6A2-OTHER-WWN"
                ),
            )
        ])

        result = self._phase6a2_revalidate(
            registry,
            evidence,
            request,
            record,
            changed_snapshot,
            at=at + timedelta(seconds=1),
        )

        self.assertEqual(
            result.status,
            auth.APPROVAL_STATUS_REVALIDATION_FAILED,
        )

    def test_raw_unsafe_discovery_states_fail_revalidation(
        self,
    ):
        def read_only_snapshot():
            return self.snapshot([
                self.device(
                    read_only=True
                )
            ])

        def mounted_snapshot():
            return self.snapshot([
                self.device(
                    mountpoints=[
                        "/mnt/phase6a2"
                    ]
                )
            ])

        def protected_snapshot():
            return self.snapshot(
                protected_sources=(
                    "/dev/syn-a",
                )
            )

        def duplicate_identity_snapshot():
            return self.snapshot([
                self.device(),
                self.device(
                    path="/dev/syn-b",
                    serial="SERIAL-A",
                    wwn="WWN-B",
                ),
            ])

        cases = (
            (
                "read_only",
                read_only_snapshot,
            ),
            (
                "mounted",
                mounted_snapshot,
            ),
            (
                "protected",
                protected_snapshot,
            ),
            (
                "duplicate_identity",
                duplicate_identity_snapshot,
            ),
        )

        for label, make_snapshot in cases:
            with self.subTest(label=label):
                (
                    registry,
                    record,
                    request,
                    _challenge,
                    evidence,
                    _snapshot,
                    at,
                ) = (
                    self._phase6a2_start_approval(
                        request_id=(
                            "PHASE6A2-RAW-"
                            + label.upper()
                        )
                    )
                )

                result = (
                    self._phase6a2_revalidate(
                        registry,
                        evidence,
                        request,
                        record,
                        make_snapshot(),
                        at=(
                            at
                            + timedelta(
                                seconds=1
                            )
                        ),
                    )
                )

                self.assertEqual(
                    result.status,
                    auth.APPROVAL_STATUS_REVALIDATION_FAILED,
                )

                self.assertTrue(
                    result.reason_codes
                )

    def test_discovery_collection_failure_fails_revalidation(
        self,
    ):
        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            _snapshot,
            at,
        ) = self._phase6a2_start_approval()

        with (
            patch(
                "sanitization_authorization."
                "collect_current_drive_discovery",
                side_effect=(
                    auth.DiscoveryCollectionError(
                        "synthetic collection failure"
                    )
                ),
            ),
            patch(
                "sanitization_authorization._utc_now",
                return_value=(
                    at + timedelta(seconds=1)
                ),
            ),
        ):
            result = registry.revalidate_approval(
                evidence.approval_id,
                request,
                record,
            )

        self.assertEqual(
            result.status,
            auth.APPROVAL_STATUS_REVALIDATION_FAILED,
        )

    def test_clock_rollback_fails_approval_and_revalidation(
        self,
    ):
        (
            registry,
            _record,
            _request,
            challenge,
            _snapshot,
            at,
        ) = self._phase6a2_create_challenge()

        with (
            patch(
                "sanitization_authorization._utc_now",
                return_value=(
                    at - timedelta(seconds=6)
                ),
            ),
            self.assertRaises(
                auth.ApprovalError
            ),
        ):
            registry.record_human_approval(
                challenge.challenge_id
            )

        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            snapshot,
            at,
        ) = self._phase6a2_start_approval(
            request_id=(
                "PHASE6A2-ROLLBACK-REVALIDATION"
            )
        )

        result = self._phase6a2_revalidate(
            registry,
            evidence,
            request,
            record,
            snapshot,
            at=at - timedelta(seconds=6),
        )

        self.assertEqual(
            result.reason_codes,
            ("APPROVAL_CLOCK_INVALID",),
        )

    def test_fresh_evaluation_clock_rollback_after_valid_revalidation_start_fails(
        self,
    ):
        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            snapshot,
            at,
        ) = self._phase6a2_start_approval(
            request_id="PHASE6A2-FRESH-ROLLBACK"
        )

        with (
            patch(
                "sanitization_authorization."
                "collect_current_drive_discovery",
                return_value=snapshot,
            ),
            patch(
                "sanitization_authorization._utc_now",
                side_effect=[
                    at + timedelta(seconds=1),
                    at - timedelta(seconds=10),
                    at - timedelta(seconds=10),
                ],
            ),
        ):
            result = registry.revalidate_approval(
                evidence.approval_id,
                request,
                record,
            )

        self.assertEqual(
            result.status,
            auth.APPROVAL_STATUS_REVALIDATION_FAILED,
        )

        self.assertEqual(
            result.reason_codes,
            ("FRESH_CLOCK_INVALID",),
        )

    def test_fabricated_approval_evidence_object_is_not_trusted(
        self,
    ):
        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            _snapshot,
            at,
        ) = self._phase6a2_start_approval()

        fabricated = replace(
            evidence,
            approval_id="appr_fabricated",
        )

        with patch(
            "sanitization_authorization._utc_now",
            return_value=at + timedelta(seconds=1),
        ):
            malformed = registry.revalidate_approval(
                fabricated,
                request,
                record,
            )

        self.assertEqual(
            malformed.reason_codes,
            ("APPROVAL_ID_INVALID",),
        )

        with patch(
            "sanitization_authorization._utc_now",
            return_value=at + timedelta(seconds=1),
        ):
            unknown = registry.revalidate_approval(
                fabricated.approval_id,
                request,
                record,
            )

        self.assertEqual(
            unknown.reason_codes,
            ("APPROVAL_UNKNOWN",),
        )

    def test_new_registry_has_no_old_approval_state(
        self,
    ):
        (
            _registry,
            record,
            request,
            _challenge,
            evidence,
            _snapshot,
            at,
        ) = self._phase6a2_start_approval()

        new_registry = auth.ApprovalRegistry()

        with patch(
            "sanitization_authorization._utc_now",
            return_value=at + timedelta(seconds=1),
        ):
            result = new_registry.revalidate_approval(
                evidence.approval_id,
                request,
                record,
            )

        self.assertEqual(
            result.reason_codes,
            ("APPROVAL_UNKNOWN",),
        )

    def test_approval_models_are_frozen(
        self,
    ):
        (
            registry,
            record,
            request,
            challenge,
            evidence,
            snapshot,
            at,
        ) = self._phase6a2_start_approval()

        result = self._phase6a2_revalidate(
            registry,
            evidence,
            request,
            record,
            snapshot,
            at=at + timedelta(seconds=1),
        )

        for value in (
            challenge,
            evidence,
            result,
        ):
            with self.subTest(
                model=type(value).__name__
            ):
                with self.assertRaises(
                    FrozenInstanceError
                ):
                    value.schema_version = 999

    def test_no_executor_or_destructive_authority_surface(
        self,
    ):
        registry_methods = {
            name
            for name, value
            in inspect.getmembers(
                auth.ApprovalRegistry,
                predicate=inspect.isfunction,
            )
            if not name.startswith("_")
        }

        self.assertEqual(
            registry_methods,
            {
                "create_challenge",
                "record_human_approval",
                "revalidate_approval",
            },
        )

        forbidden_fields = {
            "approved",
            "authorized",
            "execute",
            "executor",
            "ready_to_wipe",
            "safe_to_wipe",
        }

        for model in (
            auth.ApprovalChallenge,
            auth.HumanApprovalEvidence,
            auth.ApprovalRevalidationDecision,
        ):
            self.assertTrue(
                forbidden_fields.isdisjoint(
                    {
                        field.name
                        for field in fields(model)
                    }
                )
            )

    def test_stale_fresh_evaluation_fails_revalidation(
        self,
    ):
        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            snapshot,
            at,
        ) = self._phase6a2_start_approval(
            request_id="PHASE6A2-STALE-FRESH"
        )

        with (
            patch(
                "sanitization_authorization."
                "collect_current_drive_discovery",
                return_value=snapshot,
            ),
            patch(
                "sanitization_authorization._utc_now",
                side_effect=[
                    at + timedelta(seconds=1),
                    at + timedelta(seconds=1),
                    at + timedelta(seconds=62),
                ],
            ),
        ):
            result = registry.revalidate_approval(
                evidence.approval_id,
                request,
                record,
            )

        self.assertEqual(
            result.status,
            auth.APPROVAL_STATUS_REVALIDATION_FAILED,
        )

    def test_future_skew_fresh_evaluation_fails_revalidation(
        self,
    ):
        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            snapshot,
            at,
        ) = self._phase6a2_start_approval(
            request_id="PHASE6A2-FUTURE-FRESH"
        )

        with (
            patch(
                "sanitization_authorization."
                "collect_current_drive_discovery",
                return_value=snapshot,
            ),
            patch(
                "sanitization_authorization._utc_now",
                side_effect=[
                    at + timedelta(seconds=1),
                    at + timedelta(seconds=7),
                    at + timedelta(seconds=1),
                ],
            ),
        ):
            result = registry.revalidate_approval(
                evidence.approval_id,
                request,
                record,
            )

        self.assertEqual(
            result.status,
            auth.APPROVAL_STATUS_REVALIDATION_FAILED,
        )

    def test_approval_registry_lock_is_per_instance(
        self,
    ):
        first = auth.ApprovalRegistry()
        second = auth.ApprovalRegistry()

        self.assertIsNot(
            first._state_lock,
            second._state_lock,
        )

    def test_concurrent_challenge_approval_is_atomic(
        self,
    ):
        import threading

        (
            registry,
            _record,
            _request,
            challenge,
            _snapshot,
            at,
        ) = self._phase6a2_create_challenge(
            request_id=(
                "PHASE6A2-R5-CONCURRENT-APPROVAL"
            )
        )

        barrier = threading.Barrier(2)

        class RacingSet(set):
            def __contains__(
                self,
                value,
            ):
                present = super().__contains__(
                    value
                )

                if not present:
                    try:
                        barrier.wait(
                            timeout=0.2
                        )
                    except threading.BrokenBarrierError:
                        pass

                return present

        registry._approved_challenges = (
            RacingSet(
                registry._approved_challenges
            )
        )

        approvals = []
        errors = []

        def worker():
            try:
                evidence = (
                    registry.record_human_approval(
                        challenge.challenge_id
                    )
                )

                approvals.append(
                    evidence.approval_id
                )

            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(
                target=worker
            ),
            threading.Thread(
                target=worker
            ),
        ]

        with patch(
            "sanitization_authorization._utc_now",
            return_value=at,
        ):
            for thread in threads:
                thread.start()

            for thread in threads:
                thread.join(timeout=5)

        self.assertTrue(
            all(
                not thread.is_alive()
                for thread in threads
            )
        )

        self.assertEqual(
            len(approvals),
            1,
        )

        self.assertEqual(
            len(errors),
            1,
        )

        self.assertIsInstance(
            errors[0],
            auth.ApprovalError,
        )

        self.assertIn(
            "already been approved",
            str(errors[0]),
        )

    def test_concurrent_revalidation_consumption_is_atomic(
        self,
    ):
        import threading

        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            snapshot,
            at,
        ) = self._phase6a2_start_approval(
            request_id=(
                "PHASE6A2-R5-CONCURRENT-REVALIDATION"
            )
        )

        barrier = threading.Barrier(2)

        class RacingSet(set):
            def __contains__(
                self,
                value,
            ):
                present = super().__contains__(
                    value
                )

                if not present:
                    try:
                        barrier.wait(
                            timeout=0.2
                        )
                    except threading.BrokenBarrierError:
                        pass

                return present

        registry._consumed_approvals = (
            RacingSet(
                registry._consumed_approvals
            )
        )

        results = []
        errors = []

        def worker():
            try:
                result = (
                    registry.revalidate_approval(
                        evidence.approval_id,
                        request,
                        record,
                    )
                )

                results.append(result)

            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(
                target=worker
            ),
            threading.Thread(
                target=worker
            ),
        ]

        with (
            patch(
                "sanitization_authorization."
                "collect_current_drive_discovery",
                return_value=snapshot,
            ),
            patch(
                "sanitization_authorization._utc_now",
                return_value=(
                    at + timedelta(seconds=1)
                ),
            ),
        ):
            for thread in threads:
                thread.start()

            for thread in threads:
                thread.join(timeout=5)

        self.assertTrue(
            all(
                not thread.is_alive()
                for thread in threads
            )
        )

        self.assertEqual(
            errors,
            [],
        )

        self.assertEqual(
            len(results),
            2,
        )

        statuses = [
            result.status
            for result in results
        ]

        self.assertEqual(
            statuses.count(
                auth.APPROVAL_STATUS_REVALIDATED
            ),
            1,
        )

        consumed = [
            result
            for result in results
            if (
                result.status
                == auth.APPROVAL_STATUS_REVALIDATION_FAILED
                and result.reason_codes
                == (
                    "APPROVAL_ALREADY_CONSUMED",
                )
            )
        ]

        self.assertEqual(
            len(consumed),
            1,
        )

    def test_concurrent_challenge_token_collision_is_atomic(
        self,
    ):
        import threading

        (
            _seed_registry,
            record,
            _seed_request,
            _seed_challenge,
            snapshot,
            at,
        ) = self._phase6a2_create_challenge(
            request_id=(
                "PHASE6A2-R6-CONCURRENT-SEED"
            )
        )

        registry = auth.ApprovalRegistry()

        request_a = self._phase6a2_request(
            record,
            request_id=(
                "PHASE6A2-R6-CONCURRENT-A"
            ),
            at=at - timedelta(seconds=60),
        )

        request_b = self._phase6a2_request(
            record,
            request_id=(
                "PHASE6A2-R6-CONCURRENT-B"
            ),
            at=at - timedelta(seconds=60),
        )

        forced_id = (
            "apch_R6_FORCED_COLLISION_"
            "0123456789ABCDEF"
        )

        start = threading.Barrier(2)
        created = []
        errors = []

        def worker(request):
            try:
                start.wait(timeout=5)

                created.append(
                    registry.create_challenge(
                        request,
                        record,
                    )
                )
            except Exception as exc:
                errors.append(exc)

        with (
            patch(
                "sanitization_authorization."
                "collect_current_drive_discovery",
                return_value=snapshot,
            ),
            patch(
                "sanitization_authorization._utc_now",
                return_value=at,
            ),
            patch(
                "sanitization_authorization."
                "_new_approval_token",
                return_value=forced_id,
            ),
        ):
            threads = [
                threading.Thread(
                    target=worker,
                    args=(request_a,),
                ),
                threading.Thread(
                    target=worker,
                    args=(request_b,),
                ),
            ]

            for thread in threads:
                thread.start()

            for thread in threads:
                thread.join(timeout=5)

        self.assertTrue(
            all(
                not thread.is_alive()
                for thread in threads
            )
        )

        self.assertEqual(
            len(created),
            1,
        )

        self.assertEqual(
            len(errors),
            1,
        )

        self.assertIsInstance(
            errors[0],
            auth.ApprovalError,
        )

        self.assertIn(
            "could not allocate unique challenge_id",
            str(errors[0]),
        )

        self.assertEqual(
            len(registry._challenges),
            1,
        )

    def test_challenge_token_collision_retries_then_succeeds(
        self,
    ):
        (
            _seed_registry,
            record,
            _seed_request,
            _seed_challenge,
            snapshot,
            at,
        ) = self._phase6a2_create_challenge(
            request_id="PHASE6A2-R6-RETRY-SEED"
        )

        registry = auth.ApprovalRegistry()

        request_a = self._phase6a2_request(
            record,
            request_id="PHASE6A2-R6-RETRY-A",
            at=at - timedelta(seconds=60),
        )

        request_b = self._phase6a2_request(
            record,
            request_id="PHASE6A2-R6-RETRY-B",
            at=at - timedelta(seconds=60),
        )

        existing_id = (
            "apch_R6_EXISTING_0123456789ABCDEF"
        )

        unique_id = (
            "apch_R6_UNIQUE_0123456789ABCDEF"
        )

        with (
            patch(
                "sanitization_authorization."
                "collect_current_drive_discovery",
                return_value=snapshot,
            ),
            patch(
                "sanitization_authorization._utc_now",
                return_value=at,
            ),
            patch(
                "sanitization_authorization."
                "_new_approval_token",
                return_value=existing_id,
            ),
        ):
            first = registry.create_challenge(
                request_a,
                record,
            )

        with (
            patch(
                "sanitization_authorization."
                "collect_current_drive_discovery",
                return_value=snapshot,
            ),
            patch(
                "sanitization_authorization._utc_now",
                return_value=at,
            ),
            patch(
                "sanitization_authorization."
                "_new_approval_token",
                side_effect=(
                    existing_id,
                    unique_id,
                ),
            ),
        ):
            second = registry.create_challenge(
                request_b,
                record,
            )

        self.assertEqual(
            first.challenge_id,
            existing_id,
        )

        self.assertEqual(
            second.challenge_id,
            unique_id,
        )

        self.assertEqual(
            len(registry._challenges),
            2,
        )

    def test_repeated_challenge_token_collision_fails_bounded(
        self,
    ):
        (
            _seed_registry,
            record,
            _seed_request,
            _seed_challenge,
            snapshot,
            at,
        ) = self._phase6a2_create_challenge(
            request_id=(
                "PHASE6A2-R6-BOUNDED-CHAL-SEED"
            )
        )

        registry = auth.ApprovalRegistry()

        request_a = self._phase6a2_request(
            record,
            request_id=(
                "PHASE6A2-R6-BOUNDED-CHAL-A"
            ),
            at=at - timedelta(seconds=60),
        )

        request_b = self._phase6a2_request(
            record,
            request_id=(
                "PHASE6A2-R6-BOUNDED-CHAL-B"
            ),
            at=at - timedelta(seconds=60),
        )

        forced_id = (
            "apch_R6_BOUNDED_0123456789ABCDEF"
        )

        with (
            patch(
                "sanitization_authorization."
                "collect_current_drive_discovery",
                return_value=snapshot,
            ),
            patch(
                "sanitization_authorization._utc_now",
                return_value=at,
            ),
            patch(
                "sanitization_authorization."
                "_new_approval_token",
                return_value=forced_id,
            ),
        ):
            registry.create_challenge(
                request_a,
                record,
            )

        with (
            patch(
                "sanitization_authorization."
                "collect_current_drive_discovery",
                return_value=snapshot,
            ),
            patch(
                "sanitization_authorization._utc_now",
                return_value=at,
            ),
            patch(
                "sanitization_authorization."
                "_new_approval_token",
                return_value=forced_id,
            ) as token_mock,
        ):
            with self.assertRaises(
                auth.ApprovalError
            ):
                registry.create_challenge(
                    request_b,
                    record,
                )

        self.assertEqual(
            token_mock.call_count,
            auth._APPROVAL_TOKEN_ALLOCATION_MAX_ATTEMPTS,
        )

        self.assertEqual(
            len(registry._challenges),
            1,
        )

        acquired = (
            registry._state_lock.acquire(
                blocking=False
            )
        )

        self.assertTrue(acquired)

        if acquired:
            registry._state_lock.release()

    def test_repeated_approval_token_collision_fails_without_approving_challenge(
        self,
    ):
        (
            _seed_registry,
            record,
            _seed_request,
            _seed_challenge,
            snapshot,
            at,
        ) = self._phase6a2_create_challenge(
            request_id=(
                "PHASE6A2-R6-BOUNDED-APPR-SEED"
            )
        )

        registry = auth.ApprovalRegistry()

        request_a = self._phase6a2_request(
            record,
            request_id="PHASE6A2-R6-APPR-A",
            at=at - timedelta(seconds=60),
        )

        request_b = self._phase6a2_request(
            record,
            request_id="PHASE6A2-R6-APPR-B",
            at=at - timedelta(seconds=60),
        )

        with (
            patch(
                "sanitization_authorization."
                "collect_current_drive_discovery",
                return_value=snapshot,
            ),
            patch(
                "sanitization_authorization._utc_now",
                return_value=at,
            ),
            patch(
                "sanitization_authorization."
                "_new_approval_token",
                side_effect=(
                    "apch_R6_APPR_A_0123456789ABCDEF",
                    "apch_R6_APPR_B_0123456789ABCDEF",
                ),
            ),
        ):
            challenge_a = registry.create_challenge(
                request_a,
                record,
            )

            challenge_b = registry.create_challenge(
                request_b,
                record,
            )

        existing_approval_id = (
            "appr_R6_EXISTING_0123456789ABCDEF"
        )

        with (
            patch(
                "sanitization_authorization._utc_now",
                return_value=at,
            ),
            patch(
                "sanitization_authorization."
                "_new_approval_token",
                return_value=existing_approval_id,
            ),
        ):
            registry.record_human_approval(
                challenge_a.challenge_id
            )

        with (
            patch(
                "sanitization_authorization._utc_now",
                return_value=at,
            ),
            patch(
                "sanitization_authorization."
                "_new_approval_token",
                return_value=existing_approval_id,
            ) as token_mock,
        ):
            with self.assertRaises(
                auth.ApprovalError
            ):
                registry.record_human_approval(
                    challenge_b.challenge_id
                )

        self.assertEqual(
            token_mock.call_count,
            auth._APPROVAL_TOKEN_ALLOCATION_MAX_ATTEMPTS,
        )

        self.assertNotIn(
            challenge_b.challenge_id,
            registry._approved_challenges,
        )

        self.assertEqual(
            len(registry._approvals),
            1,
        )

        acquired = (
            registry._state_lock.acquire(
                blocking=False
            )
        )

        self.assertTrue(acquired)

        if acquired:
            registry._state_lock.release()

        with (
            patch(
                "sanitization_authorization._utc_now",
                return_value=at,
            ),
            patch(
                "sanitization_authorization."
                "_new_approval_token",
                return_value=(
                    "appr_R6_RECOVERY_0123456789ABCDEF"
                ),
            ),
        ):
            recovered = (
                registry.record_human_approval(
                    challenge_b.challenge_id
                )
            )

        self.assertEqual(
            recovered.challenge_id,
            challenge_b.challenge_id,
        )

    def test_create_challenge_rechecks_expiry_after_lock_entry(
        self,
    ):
        (
            _registry,
            record,
            request,
            _challenge,
            snapshot,
            at,
        ) = self._phase6a2_create_challenge(
            request_id=(
                "PHASE6A2-R6-LOCK-TIME-SEED"
            )
        )

        with (
            patch(
                "sanitization_authorization."
                "collect_current_drive_discovery",
                return_value=snapshot,
            ),
            patch(
                "sanitization_authorization._utc_now",
                return_value=at,
            ),
        ):
            decision = (
                auth.evaluate_current_authorization_prerequisites(
                    request,
                    record,
                )
            )

        valid_until = auth._parse_utc(
            decision.prerequisite_valid_until_utc,
            "decision.prerequisite_valid_until_utc",
        )

        expired = (
            valid_until
            + timedelta(seconds=1)
        )

        registry = auth.ApprovalRegistry()

        with (
            patch(
                "sanitization_authorization."
                "evaluate_current_authorization_prerequisites",
                return_value=decision,
            ),
            patch(
                "sanitization_authorization."
                "decision_is_current",
                return_value=True,
            ),
            patch(
                "sanitization_authorization._utc_now",
                side_effect=(
                    at,
                    expired,
                ),
            ),
            patch(
                "sanitization_authorization."
                "_new_approval_token",
            ) as token_mock,
        ):
            with self.assertRaises(
                auth.ApprovalError
            ):
                registry.create_challenge(
                    request,
                    record,
                )

        token_mock.assert_not_called()

        self.assertEqual(
            registry._challenges,
            {},
        )

    def test_malformed_generated_challenge_tokens_fail_bounded_without_state(
        self,
    ):
        invalid_tokens = (
            "",
            "   ",
            "apch_",
            "appr_WRONG_PREFIX",
            " apch_LEADING_SPACE",
            "apch_TRAILING_SPACE ",
            "apch_CONTROL\nVALUE",
            None,
            123,
        )

        (
            _seed_registry,
            record,
            _seed_request,
            _seed_challenge,
            snapshot,
            at,
        ) = self._phase6a2_create_challenge(
            request_id=(
                "PHASE6A2-R7-MALFORMED-CHAL-SEED"
            )
        )

        for index, invalid_token in enumerate(
            invalid_tokens
        ):
            with self.subTest(
                token=repr(invalid_token)
            ):
                registry = auth.ApprovalRegistry()

                request = self._phase6a2_request(
                    record,
                    request_id=(
                        f"PHASE6A2-R7-MALFORMED-CHAL-{index}"
                    ),
                    at=at - timedelta(seconds=60),
                )

                with (
                    patch(
                        "sanitization_authorization."
                        "collect_current_drive_discovery",
                        return_value=snapshot,
                    ),
                    patch(
                        "sanitization_authorization._utc_now",
                        return_value=at,
                    ),
                    patch(
                        "sanitization_authorization."
                        "_new_approval_token",
                        return_value=invalid_token,
                    ) as token_mock,
                ):
                    with self.assertRaises(
                        auth.ApprovalError
                    ):
                        registry.create_challenge(
                            request,
                            record,
                        )

                self.assertEqual(
                    token_mock.call_count,
                    auth._APPROVAL_TOKEN_ALLOCATION_MAX_ATTEMPTS,
                )

                self.assertEqual(
                    registry._challenges,
                    {},
                )

                acquired = (
                    registry._state_lock.acquire(
                        blocking=False
                    )
                )

                self.assertTrue(acquired)

                if acquired:
                    registry._state_lock.release()

    def test_malformed_generated_approval_tokens_fail_bounded_without_consuming_challenge(
        self,
    ):
        invalid_tokens = (
            "",
            "   ",
            "appr_",
            "apch_WRONG_PREFIX",
            " appr_LEADING_SPACE",
            "appr_TRAILING_SPACE ",
            "appr_CONTROL\nVALUE",
            None,
            123,
        )

        (
            _seed_registry,
            record,
            _seed_request,
            _seed_challenge,
            snapshot,
            at,
        ) = self._phase6a2_create_challenge(
            request_id=(
                "PHASE6A2-R7-MALFORMED-APPR-SEED"
            )
        )

        for index, invalid_token in enumerate(
            invalid_tokens
        ):
            with self.subTest(
                token=repr(invalid_token)
            ):
                registry = auth.ApprovalRegistry()

                request = self._phase6a2_request(
                    record,
                    request_id=(
                        f"PHASE6A2-R7-MALFORMED-APPR-{index}"
                    ),
                    at=at - timedelta(seconds=60),
                )

                challenge_token = (
                    "apch_R7_VALID_"
                    f"{index:04d}_0123456789ABCDEF"
                )

                with (
                    patch(
                        "sanitization_authorization."
                        "collect_current_drive_discovery",
                        return_value=snapshot,
                    ),
                    patch(
                        "sanitization_authorization._utc_now",
                        return_value=at,
                    ),
                    patch(
                        "sanitization_authorization."
                        "_new_approval_token",
                        return_value=challenge_token,
                    ),
                ):
                    challenge = (
                        registry.create_challenge(
                            request,
                            record,
                        )
                    )

                with (
                    patch(
                        "sanitization_authorization._utc_now",
                        return_value=at,
                    ),
                    patch(
                        "sanitization_authorization."
                        "_new_approval_token",
                        return_value=invalid_token,
                    ) as token_mock,
                ):
                    with self.assertRaises(
                        auth.ApprovalError
                    ):
                        registry.record_human_approval(
                            challenge.challenge_id
                        )

                self.assertEqual(
                    token_mock.call_count,
                    auth._APPROVAL_TOKEN_ALLOCATION_MAX_ATTEMPTS,
                )

                self.assertEqual(
                    registry._approvals,
                    {},
                )

                self.assertNotIn(
                    challenge.challenge_id,
                    registry._approved_challenges,
                )

                acquired = (
                    registry._state_lock.acquire(
                        blocking=False
                    )
                )

                self.assertTrue(acquired)

                if acquired:
                    registry._state_lock.release()

    def test_malformed_challenge_token_then_valid_token_recovers(
        self,
    ):
        (
            _seed_registry,
            record,
            _seed_request,
            _seed_challenge,
            snapshot,
            at,
        ) = self._phase6a2_create_challenge(
            request_id=(
                "PHASE6A2-R7-CHAL-RECOVERY-SEED"
            )
        )

        registry = auth.ApprovalRegistry()

        request = self._phase6a2_request(
            record,
            request_id=(
                "PHASE6A2-R7-CHAL-RECOVERY"
            ),
            at=at - timedelta(seconds=60),
        )

        valid_token = (
            "apch_R7_RECOVERY_0123456789ABCDEF"
        )

        with (
            patch(
                "sanitization_authorization."
                "collect_current_drive_discovery",
                return_value=snapshot,
            ),
            patch(
                "sanitization_authorization._utc_now",
                return_value=at,
            ),
            patch(
                "sanitization_authorization."
                "_new_approval_token",
                side_effect=(
                    "",
                    valid_token,
                ),
            ) as token_mock,
        ):
            challenge = registry.create_challenge(
                request,
                record,
            )

        self.assertEqual(
            token_mock.call_count,
            2,
        )

        self.assertEqual(
            challenge.challenge_id,
            valid_token,
        )

        self.assertIn(
            valid_token,
            registry._challenges,
        )

        self.assertTrue(
            auth._approval_challenge_integrity_valid(
                challenge
            )
        )

    def test_malformed_approval_token_then_valid_token_recovers(
        self,
    ):
        (
            _seed_registry,
            record,
            _seed_request,
            _seed_challenge,
            snapshot,
            at,
        ) = self._phase6a2_create_challenge(
            request_id=(
                "PHASE6A2-R7-APPR-RECOVERY-SEED"
            )
        )

        registry = auth.ApprovalRegistry()

        request = self._phase6a2_request(
            record,
            request_id=(
                "PHASE6A2-R7-APPR-RECOVERY"
            ),
            at=at - timedelta(seconds=60),
        )

        with (
            patch(
                "sanitization_authorization."
                "collect_current_drive_discovery",
                return_value=snapshot,
            ),
            patch(
                "sanitization_authorization._utc_now",
                return_value=at,
            ),
            patch(
                "sanitization_authorization."
                "_new_approval_token",
                return_value=(
                    "apch_R7_APPR_RECOVERY_"
                    "0123456789ABCDEF"
                ),
            ),
        ):
            challenge = registry.create_challenge(
                request,
                record,
            )

        valid_approval_token = (
            "appr_R7_RECOVERY_0123456789ABCDEF"
        )

        with (
            patch(
                "sanitization_authorization._utc_now",
                return_value=at,
            ),
            patch(
                "sanitization_authorization."
                "_new_approval_token",
                side_effect=(
                    "",
                    valid_approval_token,
                ),
            ) as token_mock,
        ):
            evidence = (
                registry.record_human_approval(
                    challenge.challenge_id
                )
            )

        self.assertEqual(
            token_mock.call_count,
            2,
        )

        self.assertEqual(
            evidence.approval_id,
            valid_approval_token,
        )

        self.assertIn(
            valid_approval_token,
            registry._approvals,
        )

        self.assertIn(
            challenge.challenge_id,
            registry._approved_challenges,
        )

        self.assertTrue(
            auth._approval_evidence_integrity_valid(
                evidence
            )
        )

if __name__ == "__main__":
    unittest.main()
