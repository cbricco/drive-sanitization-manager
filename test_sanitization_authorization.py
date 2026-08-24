from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timezone
import inspect
import json
import unittest
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


if __name__ == "__main__":
    unittest.main()
