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

    def test_phase6b_known_method_policy_metadata_is_exact(
        self,
    ):
        policy = auth.get_sanitization_method_policy(
            "phase5-policy-only"
        )

        self.assertIsInstance(
            policy,
            auth.SanitizationMethodPolicy,
        )

        self.assertEqual(
            policy.method_profile_id,
            "phase5-policy-only",
        )

        self.assertEqual(
            policy.operation,
            "sanitize",
        )

        self.assertTrue(policy.policy_only)
        self.assertFalse(policy.execution_supported)

        self.assertEqual(
            [field.name for field in fields(
                auth.SanitizationMethodPolicy
            )],
            [
                "method_profile_id",
                "operation",
                "policy_only",
                "execution_supported",
            ],
        )

    def test_phase6b_method_policy_is_frozen(
        self,
    ):
        policy = auth.get_sanitization_method_policy(
            "phase5-policy-only"
        )

        self.assertIsNotNone(policy)

        with self.assertRaises(FrozenInstanceError):
            policy.operation = "other"

    def test_phase6b_method_policy_lookup_is_deterministic(
        self,
    ):
        first = auth.get_sanitization_method_policy(
            "phase5-policy-only"
        )

        second = auth.get_sanitization_method_policy(
            "phase5-policy-only"
        )

        self.assertIsNotNone(first)
        self.assertIs(first, second)

        self.assertIsInstance(
            auth._SANITIZATION_METHOD_POLICIES,
            tuple,
        )

        self.assertEqual(
            auth._SANITIZATION_METHOD_POLICIES,
            (first,),
        )

    def test_phase6b_unknown_and_malformed_policy_lookup_fails_closed(
        self,
    ):
        malformed = (
            None,
            123,
            "",
            "   ",
            "phase5-policy-only ",
            " phase5-policy-only",
            "phase5-\npolicy-only",
            "unknown",
        )

        for value in malformed:
            with self.subTest(value=repr(value)):
                self.assertIsNone(
                    auth.get_sanitization_method_policy(
                        value
                    )
                )

    def test_phase6b_known_policy_preserves_positive_prerequisite_path(
        self,
    ):
        decision = self.evaluate()

        self.assertEqual(
            decision.status,
            STATUS_PREREQUISITES_MET,
        )

        self.assertEqual(
            decision.reason_codes,
            (),
        )

    def test_phase6b_unknown_policy_refuses_with_precise_reason(
        self,
    ):
        record = self.record()

        request = replace(
            self.request(record),
            method_profile_id="unknown",
        )

        decision = self.evaluate(
            record=record,
            request=request,
        )

        self.assertEqual(
            decision.status,
            STATUS_REFUSED,
        )

        self.assertReason(
            decision,
            "METHOD_PROFILE_UNSUPPORTED",
        )

        self.assertReason(
            decision,
            "METHOD_PROFILE_UNKNOWN",
        )

    def test_phase6b_known_policy_wrong_operation_refuses(
        self,
    ):
        record = self.record()

        request = replace(
            self.request(record),
            operation="other",
        )

        decision = self.evaluate(
            record=record,
            request=request,
        )

        self.assertEqual(
            decision.status,
            STATUS_REFUSED,
        )

        self.assertReason(
            decision,
            "OPERATION_UNSUPPORTED",
        )

        self.assertReason(
            decision,
            "METHOD_PROFILE_OPERATION_MISMATCH",
        )

    def test_phase6b_policy_registry_preserves_request_hash_binding_without_execution(
        self,
    ):
        request = self.request()

        changed = replace(
            request,
            method_profile_id="unknown",
        )

        self.assertNotEqual(
            request_hash(request),
            request_hash(changed),
        )

        policy = auth.get_sanitization_method_policy(
            "phase5-policy-only"
        )

        self.assertIsNotNone(policy)
        self.assertTrue(policy.policy_only)
        self.assertFalse(policy.execution_supported)

        field_names = {
            field.name
            for field in fields(
                auth.SanitizationMethodPolicy
            )
        }

        for forbidden in (
            "command",
            "executable",
            "callback",
            "device",
            "path",
            "executor",
        ):
            self.assertNotIn(
                forbidden,
                field_names,
            )

    def test_phase6b_evaluator_does_not_normalize_method_profile_id(
        self,
    ):
        record = self.record()
        request = self.request(record)

        malformed_or_nonexact = (
            "phase5-policy-only ",
            " phase5-policy-only",
            "PHASE5-POLICY-ONLY",
            "phase5-\npolicy-only",
        )

        for method_profile_id in malformed_or_nonexact:
            with self.subTest(
                method_profile_id=repr(method_profile_id)
            ):
                decision = self.evaluate(
                    record=record,
                    request=replace(
                        request,
                        method_profile_id=method_profile_id,
                    ),
                )

                self.assertEqual(
                    decision.status,
                    STATUS_REFUSED,
                )

                self.assertReason(
                    decision,
                    "METHOD_PROFILE_UNSUPPORTED",
                )

                self.assertReason(
                    decision,
                    "METHOD_PROFILE_UNKNOWN",
                )

    def test_phase6b_evaluator_does_not_normalize_operation(
        self,
    ):
        record = self.record()
        request = self.request(record)

        malformed_or_nonexact = (
            "sanitize ",
            " sanitize",
            "SANITIZE",
            "sanitize\t",
            "sanitize\n",
        )

        for operation in malformed_or_nonexact:
            with self.subTest(
                operation=repr(operation)
            ):
                changed = replace(
                    request,
                    operation=operation,
                )

                self.assertNotEqual(
                    request_hash(request),
                    request_hash(changed),
                )

                decision = self.evaluate(
                    record=record,
                    request=changed,
                )

                self.assertEqual(
                    decision.status,
                    STATUS_REFUSED,
                )

                self.assertReason(
                    decision,
                    "OPERATION_UNSUPPORTED",
                )

                self.assertReason(
                    decision,
                    "METHOD_PROFILE_OPERATION_MISMATCH",
                )

    def test_phase6bb_capability_metadata_is_exact(
        self,
    ):
        metadata = (
            auth.get_sanitization_method_capability_metadata(
                "phase5-policy-only"
            )
        )

        self.assertIsInstance(
            metadata,
            auth.SanitizationMethodCapabilityMetadata,
        )

        self.assertEqual(
            [field.name for field in fields(
                auth.SanitizationMethodCapabilityMetadata
            )],
            [
                "method_profile_id",
                "capability_class",
                "requires_strong_identity",
                "requires_unmounted",
                "requires_writable",
                "requires_unprotected",
                "requires_non_system_target",
                "requires_unambiguous_target",
                "requires_no_review_required",
                "verification_expectation",
            ],
        )

        self.assertEqual(
            metadata.method_profile_id,
            "phase5-policy-only",
        )

        self.assertEqual(
            metadata.capability_class,
            "policy_only",
        )

        self.assertTrue(
            metadata.requires_strong_identity
        )
        self.assertTrue(
            metadata.requires_unmounted
        )
        self.assertTrue(
            metadata.requires_writable
        )
        self.assertTrue(
            metadata.requires_unprotected
        )
        self.assertTrue(
            metadata.requires_non_system_target
        )
        self.assertTrue(
            metadata.requires_unambiguous_target
        )
        self.assertTrue(
            metadata.requires_no_review_required
        )

        self.assertEqual(
            metadata.verification_expectation,
            "not_applicable",
        )

    def test_phase6bb_capability_metadata_is_frozen(
        self,
    ):
        metadata = (
            auth.get_sanitization_method_capability_metadata(
                "phase5-policy-only"
            )
        )

        self.assertIsNotNone(metadata)

        with self.assertRaises(FrozenInstanceError):
            metadata.requires_writable = False

    def test_phase6bb_capability_lookup_is_exact_and_deterministic(
        self,
    ):
        first = (
            auth.get_sanitization_method_capability_metadata(
                "phase5-policy-only"
            )
        )

        second = (
            auth.get_sanitization_method_capability_metadata(
                "phase5-policy-only"
            )
        )

        self.assertIsNotNone(first)
        self.assertIs(first, second)

        for invalid in (
            None,
            True,
            0,
            b"phase5-policy-only",
            "",
            "   ",
            "phase5-policy-only ",
            " phase5-policy-only",
            "PHASE5-POLICY-ONLY",
            "phase5-\npolicy-only",
            "unknown",
        ):
            with self.subTest(invalid=repr(invalid)):
                self.assertIsNone(
                    auth.get_sanitization_method_capability_metadata(
                        invalid
                    )
                )

    def test_phase6bb_capability_metadata_validation_fails_closed(
        self,
    ):
        metadata = (
            auth.get_sanitization_method_capability_metadata(
                "phase5-policy-only"
            )
        )

        self.assertIsNotNone(metadata)

        malformed = (
            replace(
                metadata,
                capability_class="unknown",
            ),
            replace(
                metadata,
                requires_writable=False,
            ),
            replace(
                metadata,
                requires_writable=1,
            ),
            replace(
                metadata,
                requires_unmounted=False,
            ),
            replace(
                metadata,
                verification_expectation="required",
            ),
            replace(
                metadata,
                method_profile_id="phase5-policy-only ",
            ),
        )

        for candidate in malformed:
            with self.subTest(candidate=candidate):
                self.assertFalse(
                    auth._sanitization_method_capability_metadata_valid(
                        candidate
                    )
                )

    def test_phase6bb_duplicate_or_missing_capability_registry_fails_closed(
        self,
    ):
        metadata = (
            auth.get_sanitization_method_capability_metadata(
                "phase5-policy-only"
            )
        )

        self.assertIsNotNone(metadata)

        for registry in (
            (),
            (metadata, metadata),
            (
                replace(
                    metadata,
                    method_profile_id="unknown",
                ),
            ),
        ):
            with self.subTest(registry=registry):
                with patch.object(
                    auth,
                    "_SANITIZATION_METHOD_CAPABILITIES",
                    registry,
                ):
                    self.assertFalse(
                        auth._sanitization_method_capability_registry_valid()
                    )

                    self.assertIsNone(
                        auth.get_sanitization_method_capability_metadata(
                            "phase5-policy-only"
                        )
                    )

    def test_phase6bb_capability_registry_requires_exact_policy_binding(
        self,
    ):
        metadata = (
            auth.get_sanitization_method_capability_metadata(
                "phase5-policy-only"
            )
        )

        policy = auth.get_sanitization_method_policy(
            "phase5-policy-only"
        )

        self.assertIsNotNone(metadata)
        self.assertIsNotNone(policy)

        self.assertTrue(
            auth._sanitization_method_capability_registry_valid()
        )

        with patch.object(
            auth,
            "_SANITIZATION_METHOD_POLICIES",
            (policy, policy),
        ):
            self.assertFalse(
                auth._sanitization_method_capability_registry_valid()
            )

            self.assertIsNone(
                auth.get_sanitization_method_capability_metadata(
                    "phase5-policy-only"
                )
            )

    def test_phase6bb_capability_metadata_has_no_execution_surface(
        self,
    ):
        metadata = (
            auth.get_sanitization_method_capability_metadata(
                "phase5-policy-only"
            )
        )

        self.assertIsNotNone(metadata)

        field_names = {
            field.name
            for field in fields(
                auth.SanitizationMethodCapabilityMetadata
            )
        }

        for forbidden in (
            "command",
            "executable",
            "callback",
            "function",
            "handler",
            "device",
            "path",
            "executor",
            "arguments",
            "argv",
            "shell",
        ):
            self.assertNotIn(
                forbidden,
                field_names,
            )

        lookup_source = inspect.getsource(
            auth.get_sanitization_method_capability_metadata
        )

        for forbidden in (
            "subprocess",
            "os.system",
            "Popen",
            "shell=True",
            "exec(",
            "eval(",
            "/dev/",
        ):
            self.assertNotIn(
                forbidden,
                lookup_source,
            )

    def test_phase6bc_exact_safe_binding_satisfies_constraints(
        self,
    ):
        binding = auth.TargetIdentityBinding(
            path="/dev/syn-a",
            serial="SERIAL-A",
            wwn="WWN-A",
            size_bytes=1_000_000,
            model="Synthetic Model",
            transport="usb",
            read_only=False,
            mounted=False,
            protected=False,
            system_protected=False,
            review_required=False,
            ambiguous=False,
        )

        result = auth.evaluate_sanitization_method_constraints(
            "phase5-policy-only",
            binding,
        )

        self.assertIsInstance(
            result,
            auth.SanitizationMethodConstraintEvaluation,
        )

        self.assertEqual(
            result.method_profile_id,
            "phase5-policy-only",
        )

        self.assertIsInstance(
            result.target_binding_hash,
            str,
        )

        self.assertTrue(
            result.target_binding_hash.startswith(
                "sha256:"
            )
        )

        self.assertEqual(
            result.status,
            auth.METHOD_CONSTRAINT_STATUS_SATISFIED,
        )

        self.assertEqual(
            result.reason_codes,
            (),
        )

    def test_phase6bc_constraint_evaluation_is_frozen_and_deterministic(
        self,
    ):
        binding = auth.TargetIdentityBinding(
            path="/dev/syn-a",
            serial="SERIAL-A",
            wwn="WWN-A",
            size_bytes=1_000_000,
            model="Synthetic Model",
            transport="usb",
            read_only=False,
            mounted=False,
            protected=False,
            system_protected=False,
            review_required=False,
            ambiguous=False,
        )

        first = auth.evaluate_sanitization_method_constraints(
            "phase5-policy-only",
            binding,
        )

        second = auth.evaluate_sanitization_method_constraints(
            "phase5-policy-only",
            binding,
        )

        self.assertEqual(first, second)

        with self.assertRaises(FrozenInstanceError):
            first.status = "other"

    def test_phase6bc_target_binding_hash_changes_with_binding(
        self,
    ):
        first_binding = auth.TargetIdentityBinding(
            path="/dev/syn-a",
            serial="SERIAL-A",
            wwn="WWN-A",
            size_bytes=1_000_000,
            model="Synthetic Model",
            transport="usb",
            read_only=False,
            mounted=False,
            protected=False,
            system_protected=False,
            review_required=False,
            ambiguous=False,
        )

        second_binding = replace(
            first_binding,
            path="/dev/syn-b",
        )

        first = auth.evaluate_sanitization_method_constraints(
            "phase5-policy-only",
            first_binding,
        )

        second = auth.evaluate_sanitization_method_constraints(
            "phase5-policy-only",
            second_binding,
        )

        self.assertEqual(
            first.status,
            auth.METHOD_CONSTRAINT_STATUS_SATISFIED,
        )

        self.assertEqual(
            second.status,
            auth.METHOD_CONSTRAINT_STATUS_SATISFIED,
        )

        self.assertNotEqual(
            first.target_binding_hash,
            second.target_binding_hash,
        )

    def test_phase6bc_unknown_or_malformed_method_fails_closed(
        self,
    ):
        binding = auth.TargetIdentityBinding(
            path="/dev/syn-a",
            serial="SERIAL-A",
            wwn="WWN-A",
            size_bytes=1_000_000,
            model="Synthetic Model",
            transport="usb",
            read_only=False,
            mounted=False,
            protected=False,
            system_protected=False,
            review_required=False,
            ambiguous=False,
        )

        for method_profile_id in (
            None,
            True,
            0,
            "",
            "   ",
            "phase5-policy-only ",
            " phase5-policy-only",
            "PHASE5-POLICY-ONLY",
            "unknown",
        ):
            with self.subTest(
                method_profile_id=repr(
                    method_profile_id
                )
            ):
                result = (
                    auth.evaluate_sanitization_method_constraints(
                        method_profile_id,
                        binding,
                    )
                )

                self.assertEqual(
                    result.status,
                    auth.METHOD_CONSTRAINT_STATUS_EVALUATION_FAILED,
                )

                self.assertIn(
                    "METHOD_CONSTRAINT_METADATA_UNAVAILABLE",
                    result.reason_codes,
                )

                self.assertIsNotNone(
                    result.target_binding_hash
                )

                self.assertEqual(
                    result.method_profile_id,
                    (
                        method_profile_id
                        if isinstance(
                            method_profile_id,
                            str,
                        )
                        else ""
                    ),
                )

    def test_phase6bc_malformed_target_binding_fails_closed(
        self,
    ):
        binding = auth.TargetIdentityBinding(
            path="/dev/syn-a",
            serial="SERIAL-A",
            wwn="WWN-A",
            size_bytes=1_000_000,
            model="Synthetic Model",
            transport="usb",
            read_only=False,
            mounted=False,
            protected=False,
            system_protected=False,
            review_required=False,
            ambiguous=False,
        )

        malformed = (
            None,
            replace(
                binding,
                path="   ",
            ),
            replace(
                binding,
                size_bytes=0,
            ),
            replace(
                binding,
                mounted=1,
            ),
            replace(
                binding,
                serial=123,
            ),
        )

        for candidate in malformed:
            with self.subTest(
                candidate=repr(candidate)
            ):
                result = (
                    auth.evaluate_sanitization_method_constraints(
                        "phase5-policy-only",
                        candidate,
                    )
                )

                self.assertEqual(
                    result.status,
                    auth.METHOD_CONSTRAINT_STATUS_EVALUATION_FAILED,
                )

                self.assertEqual(
                    result.reason_codes,
                    (
                        "METHOD_CONSTRAINT_TARGET_BINDING_INVALID",
                    ),
                )

                self.assertIsNone(
                    result.target_binding_hash
                )

    def test_phase6bc_strong_identity_constraint_fails_closed(
        self,
    ):
        binding = auth.TargetIdentityBinding(
            path="/dev/syn-a",
            serial=None,
            wwn=None,
            size_bytes=1_000_000,
            model="Synthetic Model",
            transport="usb",
            read_only=False,
            mounted=False,
            protected=False,
            system_protected=False,
            review_required=False,
            ambiguous=False,
        )

        result = auth.evaluate_sanitization_method_constraints(
            "phase5-policy-only",
            binding,
        )

        self.assertEqual(
            result.status,
            auth.METHOD_CONSTRAINT_STATUS_EVALUATION_FAILED,
        )

        self.assertEqual(
            result.reason_codes,
            (
                "METHOD_CONSTRAINT_STRONG_IDENTITY_REQUIRED",
            ),
        )

        self.assertIsNotNone(
            result.target_binding_hash
        )

    def test_phase6bc_hard_constraints_refuse(
        self,
    ):
        binding = auth.TargetIdentityBinding(
            path="/dev/syn-a",
            serial="SERIAL-A",
            wwn="WWN-A",
            size_bytes=1_000_000,
            model="Synthetic Model",
            transport="usb",
            read_only=False,
            mounted=False,
            protected=False,
            system_protected=False,
            review_required=False,
            ambiguous=False,
        )

        cases = (
            (
                replace(
                    binding,
                    system_protected=True,
                ),
                "METHOD_CONSTRAINT_SYSTEM_TARGET",
            ),
            (
                replace(
                    binding,
                    protected=True,
                ),
                "METHOD_CONSTRAINT_TARGET_PROTECTED",
            ),
            (
                replace(
                    binding,
                    mounted=True,
                ),
                "METHOD_CONSTRAINT_TARGET_MOUNTED",
            ),
            (
                replace(
                    binding,
                    read_only=True,
                ),
                "METHOD_CONSTRAINT_TARGET_READ_ONLY",
            ),
        )

        for candidate, expected_reason in cases:
            with self.subTest(
                expected_reason=expected_reason
            ):
                result = (
                    auth.evaluate_sanitization_method_constraints(
                        "phase5-policy-only",
                        candidate,
                    )
                )

                self.assertEqual(
                    result.status,
                    auth.METHOD_CONSTRAINT_STATUS_REFUSED,
                )

                self.assertEqual(
                    result.reason_codes,
                    (expected_reason,),
                )

    def test_phase6bc_review_constraints_require_review(
        self,
    ):
        binding = auth.TargetIdentityBinding(
            path="/dev/syn-a",
            serial="SERIAL-A",
            wwn="WWN-A",
            size_bytes=1_000_000,
            model="Synthetic Model",
            transport="usb",
            read_only=False,
            mounted=False,
            protected=False,
            system_protected=False,
            review_required=False,
            ambiguous=False,
        )

        cases = (
            (
                replace(
                    binding,
                    ambiguous=True,
                ),
                "METHOD_CONSTRAINT_TARGET_AMBIGUOUS",
            ),
            (
                replace(
                    binding,
                    review_required=True,
                ),
                "METHOD_CONSTRAINT_TARGET_REVIEW_REQUIRED",
            ),
        )

        for candidate, expected_reason in cases:
            with self.subTest(
                expected_reason=expected_reason
            ):
                result = (
                    auth.evaluate_sanitization_method_constraints(
                        "phase5-policy-only",
                        candidate,
                    )
                )

                self.assertEqual(
                    result.status,
                    auth.METHOD_CONSTRAINT_STATUS_REVIEW_REQUIRED,
                )

                self.assertEqual(
                    result.reason_codes,
                    (expected_reason,),
                )

    def test_phase6bc_status_precedence_and_no_execution_surface(
        self,
    ):
        binding = auth.TargetIdentityBinding(
            path="/dev/syn-a",
            serial="SERIAL-A",
            wwn="WWN-A",
            size_bytes=1_000_000,
            model="Synthetic Model",
            transport="usb",
            read_only=False,
            mounted=True,
            protected=False,
            system_protected=False,
            review_required=True,
            ambiguous=True,
        )

        result = auth.evaluate_sanitization_method_constraints(
            "phase5-policy-only",
            binding,
        )

        self.assertEqual(
            result.status,
            auth.METHOD_CONSTRAINT_STATUS_REFUSED,
        )

        self.assertEqual(
            result.reason_codes,
            (
                "METHOD_CONSTRAINT_TARGET_MOUNTED",
                "METHOD_CONSTRAINT_TARGET_AMBIGUOUS",
                "METHOD_CONSTRAINT_TARGET_REVIEW_REQUIRED",
            ),
        )

        field_names = {
            field.name
            for field in fields(
                auth.SanitizationMethodConstraintEvaluation
            )
        }

        for forbidden in (
            "authorized",
            "approved",
            "command",
            "executable",
            "callback",
            "executor",
            "device",
            "path",
            "argv",
            "arguments",
        ):
            self.assertNotIn(
                forbidden,
                field_names,
            )

        source = inspect.getsource(
            auth.evaluate_sanitization_method_constraints
        )

        for forbidden in (
            "subprocess",
            "os.system",
            "Popen",
            "shell=True",
            "exec(",
            "eval(",
            "collect_current_drive_discovery",
            "/dev/",
        ):
            self.assertNotIn(
                forbidden,
                source,
            )

    def test_phase6ca_builds_exact_frozen_deterministic_synthetic_plan(
        self,
    ):
        binding = auth.TargetIdentityBinding(
            path="synthetic://drive-a",
            serial="SERIAL-A",
            wwn="WWN-A",
            size_bytes=1_000_000,
            model="Synthetic Model",
            transport="synthetic",
            read_only=False,
            mounted=False,
            protected=False,
            system_protected=False,
            review_required=False,
            ambiguous=False,
        )

        constraints = (
            auth.evaluate_sanitization_method_constraints(
                "phase5-policy-only",
                binding,
            )
        )

        first = auth.build_synthetic_sanitization_plan(
            method_profile_id="phase5-policy-only",
            operation="sanitize",
            synthetic_target_id="synthetic://drive-a",
            target_binding=binding,
            constraint_evaluation=constraints,
        )

        second = auth.build_synthetic_sanitization_plan(
            method_profile_id="phase5-policy-only",
            operation="sanitize",
            synthetic_target_id="synthetic://drive-a",
            target_binding=binding,
            constraint_evaluation=constraints,
        )

        self.assertEqual(first, second)

        self.assertEqual(
            first.plan_mode,
            auth.SYNTHETIC_SANITIZATION_PLAN_MODE,
        )

        self.assertEqual(
            first.schema_version,
            auth.SYNTHETIC_SANITIZATION_PLAN_SCHEMA_VERSION,
        )

        self.assertEqual(
            first.method_profile_id,
            "phase5-policy-only",
        )

        self.assertEqual(
            first.operation,
            "sanitize",
        )

        self.assertEqual(
            first.synthetic_target_id,
            "synthetic://drive-a",
        )

        self.assertEqual(
            first.target_binding_hash,
            constraints.target_binding_hash,
        )

        self.assertTrue(
            first.plan_id.startswith("splan_")
        )

        self.assertTrue(
            first.plan_hash.startswith("sha256:")
        )

        self.assertTrue(
            auth._synthetic_sanitization_plan_integrity_valid(
                first
            )
        )

        with self.assertRaises(FrozenInstanceError):
            first.operation = "other"

    def test_phase6ca_rejects_real_or_malformed_target_namespace(
        self,
    ):
        safe_binding = auth.TargetIdentityBinding(
            path="synthetic://drive-a",
            serial="SERIAL-A",
            wwn="WWN-A",
            size_bytes=1_000_000,
            model="Synthetic Model",
            transport="synthetic",
            read_only=False,
            mounted=False,
            protected=False,
            system_protected=False,
            review_required=False,
            ambiguous=False,
        )

        safe_constraints = (
            auth.evaluate_sanitization_method_constraints(
                "phase5-policy-only",
                safe_binding,
            )
        )

        invalid_ids = (
            "/dev/sda",
            "/tmp/fake-drive",
            "file:///tmp/fake-drive",
            "synthetic://",
            "synthetic://drive/a",
            "synthetic://drive a",
            "synthetic://drive-a ",
            " synthetic://drive-a",
            "SYNTHETIC://drive-a",
            "synthetic://..",
        )

        for synthetic_target_id in invalid_ids:
            with self.subTest(
                synthetic_target_id=synthetic_target_id
            ):
                with self.assertRaises(
                    auth.SyntheticSanitizationPlanError
                ):
                    auth.build_synthetic_sanitization_plan(
                        method_profile_id=(
                            "phase5-policy-only"
                        ),
                        operation="sanitize",
                        synthetic_target_id=(
                            synthetic_target_id
                        ),
                        target_binding=safe_binding,
                        constraint_evaluation=(
                            safe_constraints
                        ),
                    )

        real_binding = replace(
            safe_binding,
            path="/dev/sda",
        )

        real_constraints = (
            auth.evaluate_sanitization_method_constraints(
                "phase5-policy-only",
                real_binding,
            )
        )

        self.assertEqual(
            real_constraints.status,
            auth.METHOD_CONSTRAINT_STATUS_SATISFIED,
        )

        with self.assertRaises(
            auth.SyntheticSanitizationPlanError
        ):
            auth.build_synthetic_sanitization_plan(
                method_profile_id="phase5-policy-only",
                operation="sanitize",
                synthetic_target_id="/dev/sda",
                target_binding=real_binding,
                constraint_evaluation=real_constraints,
            )

    def test_phase6ca_requires_exact_target_binding_to_synthetic_id(
        self,
    ):
        binding = auth.TargetIdentityBinding(
            path="synthetic://drive-a",
            serial="SERIAL-A",
            wwn="WWN-A",
            size_bytes=1_000_000,
            model="Synthetic Model",
            transport="synthetic",
            read_only=False,
            mounted=False,
            protected=False,
            system_protected=False,
            review_required=False,
            ambiguous=False,
        )

        constraints = (
            auth.evaluate_sanitization_method_constraints(
                "phase5-policy-only",
                binding,
            )
        )

        with self.assertRaises(
            auth.SyntheticSanitizationPlanError
        ):
            auth.build_synthetic_sanitization_plan(
                method_profile_id="phase5-policy-only",
                operation="sanitize",
                synthetic_target_id="synthetic://drive-b",
                target_binding=binding,
                constraint_evaluation=constraints,
            )

        changed_binding = replace(
            binding,
            path="synthetic://drive-b",
        )

        changed_constraints = (
            auth.evaluate_sanitization_method_constraints(
                "phase5-policy-only",
                changed_binding,
            )
        )

        first = auth.build_synthetic_sanitization_plan(
            method_profile_id="phase5-policy-only",
            operation="sanitize",
            synthetic_target_id="synthetic://drive-a",
            target_binding=binding,
            constraint_evaluation=constraints,
        )

        second = auth.build_synthetic_sanitization_plan(
            method_profile_id="phase5-policy-only",
            operation="sanitize",
            synthetic_target_id="synthetic://drive-b",
            target_binding=changed_binding,
            constraint_evaluation=changed_constraints,
        )

        self.assertNotEqual(
            first.target_binding_hash,
            second.target_binding_hash,
        )

        self.assertNotEqual(
            first.plan_hash,
            second.plan_hash,
        )

        self.assertNotEqual(
            first.plan_id,
            second.plan_id,
        )

    def test_phase6ca_recomputes_and_requires_exact_constraint_result(
        self,
    ):
        binding = auth.TargetIdentityBinding(
            path="synthetic://drive-a",
            serial="SERIAL-A",
            wwn="WWN-A",
            size_bytes=1_000_000,
            model="Synthetic Model",
            transport="synthetic",
            read_only=False,
            mounted=False,
            protected=False,
            system_protected=False,
            review_required=False,
            ambiguous=False,
        )

        constraints = (
            auth.evaluate_sanitization_method_constraints(
                "phase5-policy-only",
                binding,
            )
        )

        forged_hash = replace(
            constraints,
            target_binding_hash=(
                "sha256:" + ("0" * 64)
            ),
        )

        with self.assertRaises(
            auth.SyntheticSanitizationPlanError
        ):
            auth.build_synthetic_sanitization_plan(
                method_profile_id="phase5-policy-only",
                operation="sanitize",
                synthetic_target_id="synthetic://drive-a",
                target_binding=binding,
                constraint_evaluation=forged_hash,
            )

        forged_status = replace(
            constraints,
            status=(
                auth.METHOD_CONSTRAINT_STATUS_REFUSED
            ),
        )

        with self.assertRaises(
            auth.SyntheticSanitizationPlanError
        ):
            auth.build_synthetic_sanitization_plan(
                method_profile_id="phase5-policy-only",
                operation="sanitize",
                synthetic_target_id="synthetic://drive-a",
                target_binding=binding,
                constraint_evaluation=forged_status,
            )

    def test_phase6ca_rejects_unsatisfied_constraint_results(
        self,
    ):
        safe = auth.TargetIdentityBinding(
            path="synthetic://drive-a",
            serial="SERIAL-A",
            wwn="WWN-A",
            size_bytes=1_000_000,
            model="Synthetic Model",
            transport="synthetic",
            read_only=False,
            mounted=False,
            protected=False,
            system_protected=False,
            review_required=False,
            ambiguous=False,
        )

        unsafe_bindings = (
            replace(
                safe,
                mounted=True,
            ),
            replace(
                safe,
                read_only=True,
            ),
            replace(
                safe,
                protected=True,
            ),
            replace(
                safe,
                system_protected=True,
            ),
            replace(
                safe,
                ambiguous=True,
            ),
            replace(
                safe,
                review_required=True,
            ),
            replace(
                safe,
                serial=None,
                wwn=None,
            ),
        )

        for binding in unsafe_bindings:
            with self.subTest(binding=binding):
                constraints = (
                    auth.evaluate_sanitization_method_constraints(
                        "phase5-policy-only",
                        binding,
                    )
                )

                self.assertNotEqual(
                    constraints.status,
                    auth.METHOD_CONSTRAINT_STATUS_SATISFIED,
                )

                with self.assertRaises(
                    auth.SyntheticSanitizationPlanError
                ):
                    auth.build_synthetic_sanitization_plan(
                        method_profile_id=(
                            "phase5-policy-only"
                        ),
                        operation="sanitize",
                        synthetic_target_id=(
                            "synthetic://drive-a"
                        ),
                        target_binding=binding,
                        constraint_evaluation=constraints,
                    )

    def test_phase6ca_requires_exact_method_and_operation_binding(
        self,
    ):
        binding = auth.TargetIdentityBinding(
            path="synthetic://drive-a",
            serial="SERIAL-A",
            wwn="WWN-A",
            size_bytes=1_000_000,
            model="Synthetic Model",
            transport="synthetic",
            read_only=False,
            mounted=False,
            protected=False,
            system_protected=False,
            review_required=False,
            ambiguous=False,
        )

        constraints = (
            auth.evaluate_sanitization_method_constraints(
                "phase5-policy-only",
                binding,
            )
        )

        cases = (
            (
                "phase5-policy-only ",
                "sanitize",
            ),
            (
                " phase5-policy-only",
                "sanitize",
            ),
            (
                "PHASE5-POLICY-ONLY",
                "sanitize",
            ),
            (
                "unknown",
                "sanitize",
            ),
            (
                "phase5-policy-only",
                "sanitize ",
            ),
            (
                "phase5-policy-only",
                " sanitize",
            ),
            (
                "phase5-policy-only",
                "SANITIZE",
            ),
        )

        for method_profile_id, operation in cases:
            with self.subTest(
                method_profile_id=method_profile_id,
                operation=operation,
            ):
                with self.assertRaises(
                    auth.SyntheticSanitizationPlanError
                ):
                    auth.build_synthetic_sanitization_plan(
                        method_profile_id=(
                            method_profile_id
                        ),
                        operation=operation,
                        synthetic_target_id=(
                            "synthetic://drive-a"
                        ),
                        target_binding=binding,
                        constraint_evaluation=constraints,
                    )

    def test_phase6ca_plan_integrity_detects_tampering(
        self,
    ):
        binding = auth.TargetIdentityBinding(
            path="synthetic://drive-a",
            serial="SERIAL-A",
            wwn="WWN-A",
            size_bytes=1_000_000,
            model="Synthetic Model",
            transport="synthetic",
            read_only=False,
            mounted=False,
            protected=False,
            system_protected=False,
            review_required=False,
            ambiguous=False,
        )

        constraints = (
            auth.evaluate_sanitization_method_constraints(
                "phase5-policy-only",
                binding,
            )
        )

        plan = auth.build_synthetic_sanitization_plan(
            method_profile_id="phase5-policy-only",
            operation="sanitize",
            synthetic_target_id="synthetic://drive-a",
            target_binding=binding,
            constraint_evaluation=constraints,
        )

        self.assertTrue(
            auth._synthetic_sanitization_plan_integrity_valid(
                plan
            )
        )

        tampered = (
            replace(
                plan,
                operation="other",
            ),
            replace(
                plan,
                synthetic_target_id="synthetic://drive-b",
            ),
            replace(
                plan,
                target_binding_hash=(
                    "sha256:" + ("0" * 64)
                ),
            ),
            replace(
                plan,
                constraint_evaluation_hash=(
                    "sha256:" + ("1" * 64)
                ),
            ),
            replace(
                plan,
                plan_hash=(
                    "sha256:" + ("2" * 64)
                ),
            ),
            replace(
                plan,
                plan_id="splan_" + ("3" * 64),
            ),
        )

        for candidate in tampered:
            with self.subTest(candidate=candidate):
                self.assertFalse(
                    auth._synthetic_sanitization_plan_integrity_valid(
                        candidate
                    )
                )

    def test_phase6ca_plan_surface_contains_no_executor_or_approval_authority(
        self,
    ):
        field_names = {
            field.name
            for field in fields(
                auth.SyntheticSanitizationPlan
            )
        }

        expected = {
            "plan_id",
            "schema_version",
            "plan_mode",
            "method_profile_id",
            "operation",
            "synthetic_target_id",
            "target_binding_hash",
            "constraint_evaluation_hash",
            "plan_hash",
        }

        self.assertEqual(
            field_names,
            expected,
        )

        for forbidden in (
            "approved",
            "authorized",
            "command",
            "executable",
            "callback",
            "executor",
            "device_handle",
            "argv",
            "arguments",
            "shell",
            "result",
            "success",
        ):
            self.assertNotIn(
                forbidden,
                field_names,
            )

        source = inspect.getsource(
            auth.build_synthetic_sanitization_plan
        )

        for forbidden in (
            "subprocess",
            "os.system",
            "Popen",
            "shell=True",
            "exec(",
            "eval(",
            "collect_current_drive_discovery",
            "ApprovalRegistry",
            "record_human_approval",
            "revalidate_approval",
            "open(",
        ):
            self.assertNotIn(
                forbidden,
                source,
            )

    def _phase6cb_fixture(
        self,
        payload=b"synthetic secret",
    ):
        binding = auth.TargetIdentityBinding(
            path="synthetic://drive-a",
            serial="SERIAL-A",
            wwn="WWN-A",
            size_bytes=1_000_000,
            model="Synthetic Model",
            transport="synthetic",
            read_only=False,
            mounted=False,
            protected=False,
            system_protected=False,
            review_required=False,
            ambiguous=False,
        )

        constraints = (
            auth.evaluate_sanitization_method_constraints(
                "phase5-policy-only",
                binding,
            )
        )

        plan = auth.build_synthetic_sanitization_plan(
            method_profile_id="phase5-policy-only",
            operation="sanitize",
            synthetic_target_id="synthetic://drive-a",
            target_binding=binding,
            constraint_evaluation=constraints,
        )

        target = auth.SyntheticSanitizationMemoryTarget(
            synthetic_target_id="synthetic://drive-a",
            target_binding_hash=plan.target_binding_hash,
            payload=payload,
        )

        return binding, constraints, plan, target

    def test_phase6cb_runs_exact_frozen_deterministic_memory_simulation(
        self,
    ):
        _, _, plan, target = self._phase6cb_fixture()

        first = auth.run_synthetic_sanitization_plan(
            plan=plan,
            target=target,
        )

        second = auth.run_synthetic_sanitization_plan(
            plan=plan,
            target=target,
        )

        self.assertEqual(first, second)

        self.assertEqual(
            first.run_mode,
            auth.SYNTHETIC_SANITIZATION_RUN_MODE,
        )

        self.assertEqual(
            first.status,
            auth.SYNTHETIC_SANITIZATION_RUN_STATUS_COMPLETED,
        )

        self.assertEqual(
            first.plan_id,
            plan.plan_id,
        )

        self.assertEqual(
            first.plan_hash,
            plan.plan_hash,
        )

        self.assertEqual(
            first.synthetic_target_id,
            target.synthetic_target_id,
        )

        self.assertEqual(
            first.target_binding_hash,
            target.target_binding_hash,
        )

        self.assertEqual(
            first.bytes_processed,
            len(target.payload),
        )

        self.assertTrue(
            first.run_id.startswith("srun_")
        )

        self.assertTrue(
            auth._synthetic_sanitization_run_result_integrity_valid(
                first
            )
        )

        with self.assertRaises(FrozenInstanceError):
            first.status = "other"

    def test_phase6cb_memory_target_is_frozen(
        self,
    ):
        _, _, _, target = self._phase6cb_fixture()

        self.assertIs(
            type(target.payload),
            bytes,
        )

        with self.assertRaises(FrozenInstanceError):
            target.payload = b"changed"

        with self.assertRaises(FrozenInstanceError):
            target.synthetic_target_id = (
                "synthetic://drive-b"
            )

    def test_phase6cb_rejects_target_identity_or_binding_mismatch(
        self,
    ):
        _, _, plan, target = self._phase6cb_fixture()

        wrong_id = replace(
            target,
            synthetic_target_id="synthetic://drive-b",
        )

        wrong_hash = replace(
            target,
            target_binding_hash=(
                "sha256:" + ("0" * 64)
            ),
        )

        for candidate in (
            wrong_id,
            wrong_hash,
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(
                    auth.SyntheticSanitizationRunError
                ):
                    auth.run_synthetic_sanitization_plan(
                        plan=plan,
                        target=candidate,
                    )

        real_named = replace(
            target,
            synthetic_target_id="/dev/sda",
        )

        with self.assertRaises(
            auth.SyntheticSanitizationRunError
        ):
            auth.run_synthetic_sanitization_plan(
                plan=plan,
                target=real_named,
            )

    def test_phase6cb_rejects_invalid_payload_types_and_sizes(
        self,
    ):
        _, _, plan, target = self._phase6cb_fixture()

        invalid_targets = (
            replace(
                target,
                payload=b"",
            ),
            replace(
                target,
                payload=bytearray(b"abc"),
            ),
            replace(
                target,
                payload=memoryview(b"abc"),
            ),
            replace(
                target,
                payload="abc",
            ),
            replace(
                target,
                payload=(
                    b"x"
                    * (
                        auth.SYNTHETIC_SANITIZATION_MAX_PAYLOAD_BYTES
                        + 1
                    )
                ),
            ),
        )

        for candidate in invalid_targets:
            with self.subTest(
                payload_type=type(candidate.payload).__name__,
                payload_length=(
                    len(candidate.payload)
                    if hasattr(candidate.payload, "__len__")
                    else None
                ),
            ):
                with self.assertRaises(
                    auth.SyntheticSanitizationRunError
                ):
                    auth.run_synthetic_sanitization_plan(
                        plan=plan,
                        target=candidate,
                    )

    def test_phase6cb_rejects_tampered_plan(
        self,
    ):
        _, _, plan, target = self._phase6cb_fixture()

        tampered = (
            replace(
                plan,
                operation="other",
            ),
            replace(
                plan,
                synthetic_target_id="synthetic://drive-b",
            ),
            replace(
                plan,
                target_binding_hash=(
                    "sha256:" + ("0" * 64)
                ),
            ),
            replace(
                plan,
                plan_hash=(
                    "sha256:" + ("1" * 64)
                ),
            ),
            replace(
                plan,
                plan_id="splan_" + ("2" * 64),
            ),
        )

        for candidate in tampered:
            with self.subTest(candidate=candidate):
                self.assertFalse(
                    auth._synthetic_sanitization_plan_integrity_valid(
                        candidate
                    )
                )

                with self.assertRaises(
                    auth.SyntheticSanitizationRunError
                ):
                    auth.run_synthetic_sanitization_plan(
                        plan=candidate,
                        target=target,
                    )

    def test_phase6cb_rejects_rehashed_plan_outside_trusted_policy(
        self,
    ):
        _, _, plan, target = self._phase6cb_fixture()

        payload = (
            auth._synthetic_sanitization_plan_payload(
                schema_version=plan.schema_version,
                plan_mode=plan.plan_mode,
                method_profile_id=plan.method_profile_id,
                operation="other",
                synthetic_target_id=plan.synthetic_target_id,
                target_binding_hash=plan.target_binding_hash,
                constraint_evaluation_hash=(
                    plan.constraint_evaluation_hash
                ),
            )
        )

        forged_hash = auth._canonical_hash(
            payload
        )

        forged = replace(
            plan,
            operation="other",
            plan_hash=forged_hash,
            plan_id=(
                "splan_"
                + forged_hash.split(":", 1)[1]
            ),
        )

        self.assertTrue(
            auth._synthetic_sanitization_plan_integrity_valid(
                forged
            )
        )

        with self.assertRaises(
            auth.SyntheticSanitizationRunError
        ):
            auth.run_synthetic_sanitization_plan(
                plan=forged,
                target=target,
            )

    def test_phase6cb_preserves_input_payload_and_zero_models_output(
        self,
    ):
        original = b"\x01\x02\x03secret"

        _, _, plan, target = (
            self._phase6cb_fixture(
                payload=original
            )
        )

        before = target.payload

        result = auth.run_synthetic_sanitization_plan(
            plan=plan,
            target=target,
        )

        self.assertEqual(
            target.payload,
            before,
        )

        self.assertIs(
            target.payload,
            before,
        )

        self.assertEqual(
            result.input_payload_hash,
            auth._synthetic_memory_payload_hash(
                original
            ),
        )

        self.assertEqual(
            result.output_payload_hash,
            auth._synthetic_memory_payload_hash(
                bytes(len(original))
            ),
        )

        self.assertNotEqual(
            result.input_payload_hash,
            result.output_payload_hash,
        )

    def test_phase6cb_run_result_integrity_detects_tampering(
        self,
    ):
        _, _, plan, target = self._phase6cb_fixture()

        result = auth.run_synthetic_sanitization_plan(
            plan=plan,
            target=target,
        )

        self.assertTrue(
            auth._synthetic_sanitization_run_result_integrity_valid(
                result
            )
        )

        tampered = (
            replace(
                result,
                status="other",
            ),
            replace(
                result,
                plan_hash="sha256:" + ("0" * 64),
            ),
            replace(
                result,
                synthetic_target_id="synthetic://drive-b",
            ),
            replace(
                result,
                output_payload_hash=(
                    "sha256:" + ("1" * 64)
                ),
            ),
            replace(
                result,
                bytes_processed=(
                    result.bytes_processed + 1
                ),
            ),
            replace(
                result,
                result_hash="sha256:" + ("2" * 64),
            ),
            replace(
                result,
                run_id="srun_" + ("3" * 64),
            ),
        )

        for candidate in tampered:
            with self.subTest(candidate=candidate):
                self.assertFalse(
                    auth._synthetic_sanitization_run_result_integrity_valid(
                        candidate
                    )
                )

    def test_phase6cb_runner_surface_has_no_external_execution_authority(
        self,
    ):
        target_fields = {
            field.name
            for field in fields(
                auth.SyntheticSanitizationMemoryTarget
            )
        }

        self.assertEqual(
            target_fields,
            {
                "synthetic_target_id",
                "target_binding_hash",
                "payload",
            },
        )

        result_fields = {
            field.name
            for field in fields(
                auth.SyntheticSanitizationRunResult
            )
        }

        self.assertEqual(
            result_fields,
            {
                "run_id",
                "schema_version",
                "run_mode",
                "status",
                "plan_id",
                "plan_hash",
                "method_profile_id",
                "operation",
                "synthetic_target_id",
                "target_binding_hash",
                "constraint_evaluation_hash",
                "input_payload_hash",
                "output_payload_hash",
                "bytes_processed",
                "result_hash",
            },
        )

        source = inspect.getsource(
            auth.run_synthetic_sanitization_plan
        )

        for forbidden in (
            "subprocess",
            "os.system",
            "Popen",
            "shell=True",
            "exec(",
            "eval(",
            "open(",
            "collect_current_drive_discovery",
            "ApprovalRegistry",
            "record_human_approval",
            "revalidate_approval",
            "write_text",
            "write_bytes",
            "unlink",
            "remove(",
            "/dev/",
        ):
            self.assertNotIn(
                forbidden,
                source,
            )

    def test_phase6cc_integrates_synthetic_evidence_without_claiming_success(
        self,
    ):
        _, _, plan, target = self._phase6cb_fixture(
            payload=b"synthetic evidence"
        )

        result = auth.run_synthetic_sanitization_plan(
            plan=plan,
            target=target,
        )

        record = DriveRecord(
            internal_record_id="DRV-6CC-A",
            batch_job_id="JOB-6CC",
            linux_device_path="synthetic://drive-a",
        )

        integrated = (
            auth.build_drive_record_with_synthetic_run_evidence(
                record=record,
                plan=plan,
                result=result,
            )
        )

        self.assertEqual(
            integrated.sanitization_status,
            "not_started",
        )
        self.assertIsNone(
            integrated.sanitization_result
        )
        self.assertEqual(
            integrated.verification_result,
            "not_performed",
        )
        self.assertEqual(
            integrated.final_status,
            "pending",
        )

        self.assertEqual(
            integrated.sanitization_measurements,
            {
                "synthetic_evidence_origin":
                    auth.SYNTHETIC_RUN_EVIDENCE_ORIGIN,
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
            },
        )

        self.assertEqual(
            integrated.evidence_hashes,
            {
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
            },
        )

    def test_phase6cc_integration_is_deterministic_and_preserves_original(
        self,
    ):
        _, _, plan, target = self._phase6cb_fixture()

        result = auth.run_synthetic_sanitization_plan(
            plan=plan,
            target=target,
        )

        record = DriveRecord(
            internal_record_id="DRV-6CC-B",
            batch_job_id="JOB-6CC",
            linux_device_path="synthetic://drive-a",
            sanitization_measurements={
                "preexisting": "keep",
            },
            evidence_hashes={
                "preexisting_hash":
                    "sha256:preexisting",
            },
        )

        first = (
            auth.build_drive_record_with_synthetic_run_evidence(
                record=record,
                plan=plan,
                result=result,
            )
        )

        second = (
            auth.build_drive_record_with_synthetic_run_evidence(
                record=record,
                plan=plan,
                result=result,
            )
        )

        self.assertEqual(first, second)
        self.assertIsNot(first, record)

        self.assertEqual(
            record.sanitization_measurements,
            {"preexisting": "keep"},
        )

        self.assertEqual(
            record.evidence_hashes,
            {
                "preexisting_hash":
                    "sha256:preexisting"
            },
        )

        self.assertEqual(
            first.sanitization_measurements[
                "preexisting"
            ],
            "keep",
        )

        self.assertEqual(
            first.evidence_hashes[
                "preexisting_hash"
            ],
            "sha256:preexisting",
        )

    def test_phase6cc_rejects_record_target_or_result_binding_mismatch(
        self,
    ):
        _, _, plan, target = self._phase6cb_fixture()

        result = auth.run_synthetic_sanitization_plan(
            plan=plan,
            target=target,
        )

        wrong_record = DriveRecord(
            internal_record_id="DRV-6CC-C",
            batch_job_id="JOB-6CC",
            linux_device_path="synthetic://drive-b",
        )

        with self.assertRaises(
            auth.SyntheticRunEvidenceIntegrationError
        ):
            auth.build_drive_record_with_synthetic_run_evidence(
                record=wrong_record,
                plan=plan,
                result=result,
            )

        matching_record = DriveRecord(
            internal_record_id="DRV-6CC-D",
            batch_job_id="JOB-6CC",
            linux_device_path="synthetic://drive-a",
        )

        tampered = replace(
            result,
            result_hash="sha256:" + ("0" * 64),
        )

        with self.assertRaises(
            auth.SyntheticRunEvidenceIntegrationError
        ):
            auth.build_drive_record_with_synthetic_run_evidence(
                record=matching_record,
                plan=plan,
                result=tampered,
            )

    def test_phase6cc_rejects_record_with_existing_outcome_state(
        self,
    ):
        _, _, plan, target = self._phase6cb_fixture()

        result = auth.run_synthetic_sanitization_plan(
            plan=plan,
            target=target,
        )

        base = DriveRecord(
            internal_record_id="DRV-6CC-E",
            batch_job_id="JOB-6CC",
            linux_device_path="synthetic://drive-a",
        )

        cases = (
            replace(
                base,
                sanitization_status="succeeded",
            ),
            replace(
                base,
                sanitization_result="claimed result",
            ),
            replace(
                base,
                verification_result="passed",
            ),
            replace(
                base,
                final_status="complete",
            ),
        )

        for record in cases:
            with self.subTest(record=record):
                with self.assertRaises(
                    auth.SyntheticRunEvidenceIntegrationError
                ):
                    auth.build_drive_record_with_synthetic_run_evidence(
                        record=record,
                        plan=plan,
                        result=result,
                    )

    def test_phase6cc_rejects_reserved_synthetic_evidence_collision(
        self,
    ):
        _, _, plan, target = self._phase6cb_fixture()

        result = auth.run_synthetic_sanitization_plan(
            plan=plan,
            target=target,
        )

        measurement_collision = DriveRecord(
            internal_record_id="DRV-6CC-F",
            batch_job_id="JOB-6CC",
            linux_device_path="synthetic://drive-a",
            sanitization_measurements={
                "synthetic_run_id": "existing",
            },
        )

        hash_collision = DriveRecord(
            internal_record_id="DRV-6CC-G",
            batch_job_id="JOB-6CC",
            linux_device_path="synthetic://drive-a",
            evidence_hashes={
                "synthetic_plan_hash":
                    "sha256:existing",
            },
        )

        for record in (
            measurement_collision,
            hash_collision,
        ):
            with self.subTest(record=record):
                with self.assertRaises(
                    auth.SyntheticRunEvidenceIntegrationError
                ):
                    auth.build_drive_record_with_synthetic_run_evidence(
                        record=record,
                        plan=plan,
                        result=result,
                    )

    def test_phase6cc_integration_surface_has_no_execution_or_io(
        self,
    ):
        source = inspect.getsource(
            auth.build_drive_record_with_synthetic_run_evidence
        )

        for forbidden in (
            "subprocess",
            "os.system",
            "Popen",
            "shell=True",
            "exec(",
            "eval(",
            "open(",
            "collect_current_drive_discovery",
            "ApprovalRegistry",
            "record_human_approval",
            "revalidate_approval",
            "write_text",
            "write_bytes",
            "unlink",
            "remove(",
            "/dev/",
        ):
            self.assertNotIn(
                forbidden,
                source,
            )

    def _phase6da_success(
        self,
        *,
        request_id="PHASE6DA-REQ",
    ):
        (
            registry,
            record,
            request,
            challenge,
            evidence,
            snapshot,
            at,
        ) = self._phase6a2_start_approval(
            request_id=request_id
        )

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

        return (
            registry,
            record,
            request,
            challenge,
            evidence,
            result,
            snapshot,
            at,
        )

    def test_phase6da_builds_exact_frozen_deterministic_trusted_binding(
        self,
    ):
        (
            registry,
            record,
            request,
            challenge,
            evidence,
            revalidation,
            _snapshot,
            _at,
        ) = self._phase6da_success()

        first = auth.build_trusted_execution_binding(
            registry=registry,
            approval_id=evidence.approval_id,
            request=request,
            record=record,
        )

        second = auth.build_trusted_execution_binding(
            registry=registry,
            approval_id=evidence.approval_id,
            request=request,
            record=record,
        )

        self.assertEqual(first, second)

        self.assertEqual(
            first.status,
            auth.EXECUTION_BINDING_STATUS_SATISFIED,
        )
        self.assertEqual(
            first.approval_id,
            evidence.approval_id,
        )
        self.assertEqual(
            first.challenge_id,
            challenge.challenge_id,
        )
        self.assertEqual(
            first.approval_evidence_hash,
            evidence.evidence_hash,
        )
        self.assertEqual(
            first.revalidation_id,
            revalidation.revalidation_id,
        )
        self.assertEqual(
            first.request_hash,
            auth.request_hash(request),
        )
        self.assertEqual(
            first.record_snapshot_hash,
            auth.record_snapshot_hash(record),
        )
        self.assertEqual(
            first.method_profile_id,
            request.method_profile_id,
        )
        self.assertEqual(
            first.operation,
            request.operation,
        )

        self.assertTrue(
            auth._trusted_execution_binding_integrity_valid(
                first
            )
        )

        with self.assertRaises(FrozenInstanceError):
            first.status = "other"

    def test_phase6da_registry_public_surface_unchanged_and_success_is_privately_retained(
        self,
    ):
        (
            registry,
            _record,
            _request,
            _challenge,
            evidence,
            revalidation,
            _snapshot,
            _at,
        ) = self._phase6da_success(
            request_id="PHASE6DA-PRIVATE-STORE"
        )

        public_methods = {
            name
            for name, value
            in inspect.getmembers(
                auth.ApprovalRegistry,
                predicate=inspect.isfunction,
            )
            if not name.startswith("_")
        }

        self.assertEqual(
            public_methods,
            {
                "create_challenge",
                "record_human_approval",
                "revalidate_approval",
            },
        )

        self.assertIn(
            evidence.approval_id,
            registry._successful_revalidations,
        )

        stored_revalidation, fresh = (
            registry._successful_revalidations[
                evidence.approval_id
            ]
        )

        self.assertEqual(
            stored_revalidation,
            revalidation,
        )
        self.assertIsInstance(
            fresh,
            auth.AuthorizationDecision,
        )
        self.assertEqual(
            fresh.decision_id,
            revalidation.fresh_prerequisite_decision_id,
        )

    def test_phase6da_failed_revalidation_is_not_retained_or_bindable(
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
        ) = self._phase6a2_start_approval(
            request_id="PHASE6DA-FAILED"
        )

        unsafe = self.snapshot([
            self.device(
                mountpoints=["/mnt/phase6da"]
            )
        ])

        failed = self._phase6a2_revalidate(
            registry,
            evidence,
            request,
            record,
            unsafe,
            at=at + timedelta(seconds=1),
        )

        self.assertEqual(
            failed.status,
            auth.APPROVAL_STATUS_REVALIDATION_FAILED,
        )

        self.assertNotIn(
            evidence.approval_id,
            registry._successful_revalidations,
        )

        with self.assertRaises(
            auth.TrustedExecutionBindingError
        ):
            auth.build_trusted_execution_binding(
                registry=registry,
                approval_id=evidence.approval_id,
                request=request,
                record=record,
            )

    def test_phase6da_rejects_changed_request_identity_or_method(
        self,
    ):
        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            _revalidation,
            _snapshot,
            _at,
        ) = self._phase6da_success(
            request_id="PHASE6DA-REQUEST-BINDING"
        )

        cases = (
            replace(
                request,
                request_id="PHASE6DA-OTHER",
            ),
            replace(
                request,
                method_profile_id="unknown",
            ),
            replace(
                request,
                operation="sanitize ",
            ),
        )

        for changed in cases:
            with self.subTest(changed=changed):
                with self.assertRaises(
                    auth.TrustedExecutionBindingError
                ):
                    auth.build_trusted_execution_binding(
                        registry=registry,
                        approval_id=evidence.approval_id,
                        request=changed,
                        record=record,
                    )

    def test_phase6da_rejects_changed_record_snapshot(
        self,
    ):
        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            _revalidation,
            _snapshot,
            _at,
        ) = self._phase6da_success(
            request_id="PHASE6DA-RECORD-BINDING"
        )

        changed = replace(
            record,
            intended_action="different-action",
        )

        with self.assertRaises(
            auth.TrustedExecutionBindingError
        ):
            auth.build_trusted_execution_binding(
                registry=registry,
                approval_id=evidence.approval_id,
                request=request,
                record=changed,
            )

    def test_phase6da_rejects_registry_provenance_tampering(
        self,
    ):
        cases = (
            "approval_removed",
            "challenge_unapproved",
            "approval_unconsumed",
            "success_removed",
        )

        for label in cases:
            with self.subTest(label=label):
                (
                    registry,
                    record,
                    request,
                    challenge,
                    evidence,
                    _revalidation,
                    _snapshot,
                    _at,
                ) = self._phase6da_success(
                    request_id=(
                        "PHASE6DA-PROVENANCE-"
                        + label
                    )
                )

                if label == "approval_removed":
                    registry._approvals.pop(
                        evidence.approval_id
                    )
                elif label == "challenge_unapproved":
                    registry._approved_challenges.remove(
                        challenge.challenge_id
                    )
                elif label == "approval_unconsumed":
                    registry._consumed_approvals.remove(
                        evidence.approval_id
                    )
                elif label == "success_removed":
                    registry._successful_revalidations.pop(
                        evidence.approval_id
                    )

                with self.assertRaises(
                    auth.TrustedExecutionBindingError
                ):
                    auth.build_trusted_execution_binding(
                        registry=registry,
                        approval_id=evidence.approval_id,
                        request=request,
                        record=record,
                    )

    def test_phase6da_rejects_tampered_retained_revalidation(
        self,
    ):
        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            revalidation,
            _snapshot,
            _at,
        ) = self._phase6da_success(
            request_id="PHASE6DA-TAMPER-REVALIDATION"
        )

        _, fresh = (
            registry._successful_revalidations[
                evidence.approval_id
            ]
        )

        tampered = replace(
            revalidation,
            status=(
                auth.APPROVAL_STATUS_REVALIDATION_FAILED
            ),
        )

        registry._successful_revalidations[
            evidence.approval_id
        ] = (
            tampered,
            fresh,
        )

        with self.assertRaises(
            auth.TrustedExecutionBindingError
        ):
            auth.build_trusted_execution_binding(
                registry=registry,
                approval_id=evidence.approval_id,
                request=request,
                record=record,
            )

    def test_phase6da_rejects_tampered_retained_fresh_decision(
        self,
    ):
        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            revalidation,
            _snapshot,
            _at,
        ) = self._phase6da_success(
            request_id="PHASE6DA-TAMPER-FRESH"
        )

        _, fresh = (
            registry._successful_revalidations[
                evidence.approval_id
            ]
        )

        unsafe_binding = replace(
            fresh.target_binding,
            mounted=True,
        )

        tampered_fresh = replace(
            fresh,
            target_binding=unsafe_binding,
        )

        registry._successful_revalidations[
            evidence.approval_id
        ] = (
            revalidation,
            tampered_fresh,
        )

        with self.assertRaises(
            auth.TrustedExecutionBindingError
        ):
            auth.build_trusted_execution_binding(
                registry=registry,
                approval_id=evidence.approval_id,
                request=request,
                record=record,
            )

    def test_phase6da_fails_closed_when_method_registry_is_untrusted(
        self,
    ):
        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            _revalidation,
            _snapshot,
            _at,
        ) = self._phase6da_success(
            request_id="PHASE6DA-METHOD-REGISTRY"
        )

        with patch.object(
            auth,
            "_SANITIZATION_METHOD_CAPABILITIES",
            (),
        ):
            with self.assertRaises(
                auth.TrustedExecutionBindingError
            ):
                auth.build_trusted_execution_binding(
                    registry=registry,
                    approval_id=evidence.approval_id,
                    request=request,
                    record=record,
                )

    def test_phase6da_binding_integrity_and_surface_are_non_executing(
        self,
    ):
        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            _revalidation,
            _snapshot,
            _at,
        ) = self._phase6da_success(
            request_id="PHASE6DA-SURFACE"
        )

        binding = auth.build_trusted_execution_binding(
            registry=registry,
            approval_id=evidence.approval_id,
            request=request,
            record=record,
        )

        field_names = {
            field.name
            for field in fields(
                auth.TrustedExecutionBindingDecision
            )
        }

        for forbidden in (
            "approved",
            "authorized",
            "command",
            "executable",
            "executor",
            "callback",
            "device_handle",
            "argv",
            "arguments",
            "shell",
            "success",
            "wipe",
        ):
            self.assertNotIn(
                forbidden,
                field_names,
            )

        self.assertEqual(
            binding.status,
            "execution_binding_satisfied",
        )

        self.assertNotIn(
            "authorized",
            binding.status,
        )

        tampered = replace(
            binding,
            operation="other",
        )

        self.assertFalse(
            auth._trusted_execution_binding_integrity_valid(
                tampered
            )
        )

        source = inspect.getsource(
            auth.build_trusted_execution_binding
        )

        for forbidden in (
            "collect_current_drive_discovery",
            "record_human_approval(",
            "revalidate_approval(",
            "subprocess",
            "os.system",
            "Popen",
            "shell=True",
            "exec(",
            "eval(",
            "open(",
            "write_text",
            "write_bytes",
            "unlink",
            "remove(",
        ):
            self.assertNotIn(
                forbidden,
                source,
            )

    def test_phase6db_builds_frozen_current_one_shot_gate(
        self,
    ):
        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            _revalidation,
            _snapshot,
            at,
        ) = self._phase6da_success(
            request_id="PHASE6DB-GATE"
        )

        binding = auth.build_trusted_execution_binding(
            registry=registry,
            approval_id=evidence.approval_id,
            request=request,
            record=record,
        )

        with patch(
            "sanitization_authorization._utc_now",
            return_value=at + timedelta(seconds=2),
        ):
            gate = auth.satisfy_one_shot_execution_gate(
                registry=registry,
                approval_id=evidence.approval_id,
                request=request,
                record=record,
            )

        self.assertEqual(
            gate.status,
            auth.EXECUTION_GATE_STATUS_SATISFIED,
        )

        self.assertEqual(
            gate.binding_id,
            binding.binding_id,
        )

        self.assertEqual(
            gate.request_hash,
            binding.request_hash,
        )

        self.assertEqual(
            gate.record_snapshot_hash,
            binding.record_snapshot_hash,
        )

        self.assertEqual(
            gate.target_binding_hash,
            binding.target_binding_hash,
        )

        self.assertEqual(
            gate.method_profile_id,
            binding.method_profile_id,
        )

        self.assertEqual(
            gate.operation,
            binding.operation,
        )

        self.assertTrue(
            auth._one_shot_execution_gate_integrity_valid(
                gate
            )
        )

        self.assertIn(
            binding.binding_id,
            registry._consumed_execution_bindings,
        )

        with self.assertRaises(FrozenInstanceError):
            gate.status = "other"

    def test_phase6db_replay_is_rejected(
        self,
    ):
        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            _revalidation,
            _snapshot,
            at,
        ) = self._phase6da_success(
            request_id="PHASE6DB-REPLAY"
        )

        with patch(
            "sanitization_authorization._utc_now",
            return_value=at + timedelta(seconds=2),
        ):
            first = auth.satisfy_one_shot_execution_gate(
                registry=registry,
                approval_id=evidence.approval_id,
                request=request,
                record=record,
            )

            with self.assertRaisesRegex(
                auth.OneShotExecutionGateError,
                "already been consumed",
            ):
                auth.satisfy_one_shot_execution_gate(
                    registry=registry,
                    approval_id=evidence.approval_id,
                    request=request,
                    record=record,
                )

        self.assertEqual(
            registry._consumed_execution_bindings,
            {first.binding_id},
        )

    def test_phase6db_concurrent_consumption_allows_exactly_one_gate(
        self,
    ):
        from concurrent.futures import ThreadPoolExecutor

        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            _revalidation,
            _snapshot,
            at,
        ) = self._phase6da_success(
            request_id="PHASE6DB-CONCURRENT"
        )

        def attempt():
            try:
                return (
                    "ok",
                    auth.satisfy_one_shot_execution_gate(
                        registry=registry,
                        approval_id=evidence.approval_id,
                        request=request,
                        record=record,
                    ),
                )
            except auth.OneShotExecutionGateError as exc:
                return ("error", str(exc))

        with patch(
            "sanitization_authorization._utc_now",
            return_value=at + timedelta(seconds=2),
        ):
            with ThreadPoolExecutor(
                max_workers=8
            ) as executor:
                results = list(
                    executor.map(
                        lambda _index: attempt(),
                        range(8),
                    )
                )

        successes = [
            value
            for status, value in results
            if status == "ok"
        ]

        failures = [
            value
            for status, value in results
            if status == "error"
        ]

        self.assertEqual(
            len(successes),
            1,
        )

        self.assertEqual(
            len(failures),
            7,
        )

        self.assertEqual(
            registry._consumed_execution_bindings,
            {successes[0].binding_id},
        )

    def test_phase6db_stale_binding_fails_without_consumption(
        self,
    ):
        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            _revalidation,
            _snapshot,
            at,
        ) = self._phase6da_success(
            request_id="PHASE6DB-STALE"
        )

        binding = auth.build_trusted_execution_binding(
            registry=registry,
            approval_id=evidence.approval_id,
            request=request,
            record=record,
        )

        with patch(
            "sanitization_authorization._utc_now",
            return_value=at + timedelta(seconds=400),
        ):
            with self.assertRaisesRegex(
                auth.OneShotExecutionGateError,
                "stale",
            ):
                auth.satisfy_one_shot_execution_gate(
                    registry=registry,
                    approval_id=evidence.approval_id,
                    request=request,
                    record=record,
                )

        self.assertNotIn(
            binding.binding_id,
            registry._consumed_execution_bindings,
        )

    def test_phase6db_clock_rollback_fails_without_consumption(
        self,
    ):
        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            _revalidation,
            _snapshot,
            at,
        ) = self._phase6da_success(
            request_id="PHASE6DB-ROLLBACK"
        )

        binding = auth.build_trusted_execution_binding(
            registry=registry,
            approval_id=evidence.approval_id,
            request=request,
            record=record,
        )

        with patch(
            "sanitization_authorization._utc_now",
            return_value=at - timedelta(seconds=30),
        ):
            with self.assertRaisesRegex(
                auth.OneShotExecutionGateError,
                "rolled back",
            ):
                auth.satisfy_one_shot_execution_gate(
                    registry=registry,
                    approval_id=evidence.approval_id,
                    request=request,
                    record=record,
                )

        self.assertNotIn(
            binding.binding_id,
            registry._consumed_execution_bindings,
        )

    def test_phase6db_rechecks_currentness_after_lock_acquisition(
        self,
    ):
        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            _revalidation,
            _snapshot,
            at,
        ) = self._phase6da_success(
            request_id="PHASE6DB-LOCK-TIME"
        )

        binding = auth.build_trusted_execution_binding(
            registry=registry,
            approval_id=evidence.approval_id,
            request=request,
            record=record,
        )

        with patch(
            "sanitization_authorization._utc_now",
            side_effect=(
                at + timedelta(seconds=2),
                at + timedelta(seconds=400),
            ),
        ):
            with self.assertRaisesRegex(
                auth.OneShotExecutionGateError,
                "expired before atomic consumption",
            ):
                auth.satisfy_one_shot_execution_gate(
                    registry=registry,
                    approval_id=evidence.approval_id,
                    request=request,
                    record=record,
                )

        self.assertNotIn(
            binding.binding_id,
            registry._consumed_execution_bindings,
        )

    def test_phase6db_rejects_changed_request_or_record(
        self,
    ):
        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            _revalidation,
            _snapshot,
            at,
        ) = self._phase6da_success(
            request_id="PHASE6DB-IDENTITY"
        )

        changed_request = replace(
            request,
            operation="sanitize ",
        )

        changed_record = replace(
            record,
            intended_action="changed",
        )

        for candidate_request, candidate_record in (
            (changed_request, record),
            (request, changed_record),
        ):
            with self.subTest(
                request=candidate_request,
                record=candidate_record,
            ):
                with patch(
                    "sanitization_authorization._utc_now",
                    return_value=at + timedelta(seconds=2),
                ):
                    with self.assertRaises(
                        auth.OneShotExecutionGateError
                    ):
                        auth.satisfy_one_shot_execution_gate(
                            registry=registry,
                            approval_id=evidence.approval_id,
                            request=candidate_request,
                            record=candidate_record,
                        )

        self.assertEqual(
            registry._consumed_execution_bindings,
            set(),
        )

    def test_phase6db_rejects_registry_provenance_tampering(
        self,
    ):
        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            _revalidation,
            _snapshot,
            at,
        ) = self._phase6da_success(
            request_id="PHASE6DB-PROVENANCE"
        )

        registry._successful_revalidations.pop(
            evidence.approval_id
        )

        with patch(
            "sanitization_authorization._utc_now",
            return_value=at + timedelta(seconds=2),
        ):
            with self.assertRaises(
                auth.OneShotExecutionGateError
            ):
                auth.satisfy_one_shot_execution_gate(
                    registry=registry,
                    approval_id=evidence.approval_id,
                    request=request,
                    record=record,
                )

        self.assertEqual(
            registry._consumed_execution_bindings,
            set(),
        )

    def test_phase6db_gate_integrity_detects_tampering(
        self,
    ):
        (
            registry,
            record,
            request,
            _challenge,
            evidence,
            _revalidation,
            _snapshot,
            at,
        ) = self._phase6da_success(
            request_id="PHASE6DB-INTEGRITY"
        )

        with patch(
            "sanitization_authorization._utc_now",
            return_value=at + timedelta(seconds=2),
        ):
            gate = auth.satisfy_one_shot_execution_gate(
                registry=registry,
                approval_id=evidence.approval_id,
                request=request,
                record=record,
            )

        self.assertTrue(
            auth._one_shot_execution_gate_integrity_valid(
                gate
            )
        )

        cases = (
            replace(
                gate,
                status="other",
            ),
            replace(
                gate,
                binding_id="xeb_" + ("0" * 64),
            ),
            replace(
                gate,
                target_binding_hash=(
                    "sha256:" + ("1" * 64)
                ),
            ),
            replace(
                gate,
                operation="other",
            ),
            replace(
                gate,
                gate_id="xgate_" + ("2" * 64),
            ),
            replace(
                gate,
                evaluated_at_utc=(
                    gate.prerequisite_valid_until_utc
                    .replace("Z", "")
                    + "Z"
                ),
                gate_id="xgate_" + ("3" * 64),
            ),
        )

        for candidate in cases:
            with self.subTest(candidate=candidate):
                self.assertFalse(
                    auth._one_shot_execution_gate_integrity_valid(
                        candidate
                    )
                )

    def test_phase6db_surface_is_non_executing_and_registry_api_unchanged(
        self,
    ):
        public_methods = {
            name
            for name, value
            in inspect.getmembers(
                auth.ApprovalRegistry,
                predicate=inspect.isfunction,
            )
            if not name.startswith("_")
        }

        self.assertEqual(
            public_methods,
            {
                "create_challenge",
                "record_human_approval",
                "revalidate_approval",
            },
        )

        signature = inspect.signature(
            auth.satisfy_one_shot_execution_gate
        )

        self.assertEqual(
            tuple(signature.parameters),
            (
                "registry",
                "approval_id",
                "request",
                "record",
            ),
        )

        field_names = {
            field.name
            for field in fields(
                auth.OneShotExecutionGateDecision
            )
        }

        for forbidden in (
            "approved",
            "authorized",
            "command",
            "executable",
            "executor",
            "callback",
            "device_handle",
            "argv",
            "arguments",
            "shell",
            "success",
            "wipe",
        ):
            self.assertNotIn(
                forbidden,
                field_names,
            )

        source = inspect.getsource(
            auth.satisfy_one_shot_execution_gate
        )

        for forbidden in (
            "collect_current_drive_discovery",
            "record_human_approval(",
            "revalidate_approval(",
            "subprocess",
            "os.system",
            "Popen",
            "shell=True",
            "exec(",
            "eval(",
            "open(",
            "write_text",
            "write_bytes",
            "unlink",
            "remove(",
        ):
            self.assertNotIn(
                forbidden,
                source,
            )

if __name__ == "__main__":
    unittest.main()
