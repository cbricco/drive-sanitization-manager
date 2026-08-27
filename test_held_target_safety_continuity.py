from dataclasses import FrozenInstanceError, fields
from datetime import datetime, timezone
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import held_target_safety_continuity as continuity


_NOW = datetime(
    2026,
    8,
    26,
    15,
    0,
    0,
    tzinfo=timezone.utc,
)


class _HeldReference:
    def __init__(
        self,
        *,
        closed=False,
        handoff_id="xhnd_" + ("a" * 64),
        target_path="/dev/syn-a",
        target_major_minor="8:0",
        target_binding_hash="sha256:" + ("b" * 64),
    ):
        self.closed = closed
        self.handoff_id = handoff_id
        self.target_path = target_path
        self.target_major_minor = target_major_minor
        self.target_binding_hash = target_binding_hash


class _FreshDecision:
    def __init__(
        self,
        *,
        status=None,
        execution_supported=False,
        executor_eligible=False,
        requires_separate_executor_authorization=True,
        target_read_only=False,
        target_mounted=False,
        target_protected=False,
        target_system_protected=False,
        target_review_required=False,
        target_ambiguous=False,
        handoff_id="xhnd_" + ("a" * 64),
        revalidation_id="ptrv_" + ("c" * 64),
        target_path="/dev/syn-a",
        target_major_minor="8:0",
        binding_hash="sha256:" + ("b" * 64),
        evaluated_at_utc="2026-08-26T14:59:55Z",
        valid_until_utc="2026-08-26T15:00:25Z",
    ):
        if status is None:
            status = (
                continuity.auth
                .FRESH_TARGET_REVALIDATION_STATUS_SATISFIED
            )

        self.status = status
        self.execution_supported = execution_supported
        self.executor_eligible = executor_eligible
        self.requires_separate_executor_authorization = (
            requires_separate_executor_authorization
        )
        self.target_read_only = target_read_only
        self.target_mounted = target_mounted
        self.target_protected = target_protected
        self.target_system_protected = (
            target_system_protected
        )
        self.target_review_required = (
            target_review_required
        )
        self.target_ambiguous = target_ambiguous
        self.handoff_id = handoff_id
        self.revalidation_id = revalidation_id
        self.target_path = target_path
        self.target_major_minor = target_major_minor
        self.fresh_target_binding_hash = (
            binding_hash
        )
        self.evaluated_at_utc = (
            evaluated_at_utc
        )
        self.valid_until_utc = (
            valid_until_utc
        )


class HeldTargetSafetyContinuityTests(
    unittest.TestCase
):
    def held(self, **changes):
        return _HeldReference(**changes)

    def fresh(self, **changes):
        return _FreshDecision(**changes)

    def run_continuity(
        self,
        reference,
    ):
        return (
            continuity
            .revalidate_held_target_safety_continuity(
                held_reference=reference,
                registry=object(),
                approval_id="approval",
                request=object(),
                record=object(),
                journal=object(),
                gate=object(),
            )
        )

    def environment(
        self,
        *,
        fresh=None,
        integrity=True,
        side_effect=None,
    ):
        if fresh is None:
            fresh = self.fresh()

        return (
            patch.object(
                continuity.held_ref,
                "HeldKernelTargetReference",
                _HeldReference,
            ),
            patch.object(
                continuity.auth,
                "FreshPhysicalTargetRevalidationDecision",
                _FreshDecision,
            ),
            patch.object(
                continuity.auth,
                "_fresh_physical_target_revalidation_integrity_valid",
                return_value=integrity,
            ),
            patch.object(
                continuity.auth,
                "revalidate_physical_target_for_execution_handoff",
                return_value=fresh,
                side_effect=side_effect,
            ),
            patch.object(
                continuity,
                "_utc_now",
                return_value=_NOW,
            ),
        )

    def test_success_is_frozen_non_authorizing_and_exactly_bound(
        self,
    ):
        reference = self.held()
        fresh = self.fresh()
        patches = self.environment(
            fresh=fresh
        )

        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3] as revalidate,
            patches[4],
        ):
            decision = self.run_continuity(
                reference
            )

        revalidate.assert_called_once()

        self.assertEqual(
            decision.handoff_id,
            reference.handoff_id,
        )
        self.assertEqual(
            decision.target_path,
            reference.target_path,
        )
        self.assertEqual(
            decision.target_major_minor,
            reference.target_major_minor,
        )
        self.assertEqual(
            decision.target_binding_hash,
            reference.target_binding_hash,
        )
        self.assertEqual(
            decision.revalidation_id,
            fresh.revalidation_id,
        )
        self.assertEqual(
            decision.valid_until_utc,
            fresh.valid_until_utc,
        )

        self.assertFalse(
            decision.execution_supported
        )
        self.assertFalse(
            decision.executor_eligible
        )
        self.assertTrue(
            decision
            .requires_separate_executor_authorization
        )
        self.assertTrue(
            decision.continuity_id.startswith(
                "hsc_"
            )
        )

        with self.assertRaises(
            FrozenInstanceError
        ):
            decision.status = "changed"

    def test_closed_reference_fails_before_revalidation(
        self,
    ):
        reference = self.held(
            closed=True
        )
        patches = self.environment()

        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3] as revalidate,
            patches[4],
        ):
            with self.assertRaises(
                continuity
                .HeldTargetSafetyContinuityError
            ):
                self.run_continuity(
                    reference
                )

        revalidate.assert_not_called()

    def test_wrong_reference_type_fails_before_revalidation(
        self,
    ):
        reference = SimpleNamespace(
            closed=False,
            handoff_id=(
                "xhnd_" + ("a" * 64)
            ),
            target_path="/dev/syn-a",
            target_major_minor="8:0",
            target_binding_hash=(
                "sha256:" + ("b" * 64)
            ),
        )

        patches = self.environment()

        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3] as revalidate,
            patches[4],
        ):
            with self.assertRaises(
                continuity
                .HeldTargetSafetyContinuityError
            ):
                self.run_continuity(
                    reference
                )

        revalidate.assert_not_called()

    def test_malformed_held_identity_fails_before_revalidation(
        self,
    ):
        cases = (
            {"handoff_id": ""},
            {
                "target_path":
                    " /dev/syn-a"
            },
            {
                "target_major_minor":
                    "08:0"
            },
            {
                "target_binding_hash":
                    "sha256:not-a-digest"
            },
        )

        for changes in cases:
            with self.subTest(
                changes=changes
            ):
                patches = (
                    self.environment()
                )

                with (
                    patches[0],
                    patches[1],
                    patches[2],
                    patches[3] as revalidate,
                    patches[4],
                ):
                    with self.assertRaises(
                        continuity
                        .HeldTargetSafetyContinuityError
                    ):
                        self.run_continuity(
                            self.held(
                                **changes
                            )
                        )

                revalidate.assert_not_called()

    def test_reference_closing_during_revalidation_fails_closed(
        self,
    ):
        reference = self.held()

        def close_during_revalidation(
            **_arguments,
        ):
            reference.closed = True
            return self.fresh()

        patches = self.environment(
            side_effect=(
                close_during_revalidation
            )
        )

        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3] as revalidate,
            patches[4],
        ):
            with self.assertRaises(
                continuity
                .HeldTargetSafetyContinuityError
            ):
                self.run_continuity(
                    reference
                )

        revalidate.assert_called_once()

    def test_revalidation_exception_is_controlled(
        self,
    ):
        patches = self.environment(
            side_effect=RuntimeError(
                "synthetic fresh-revalidation failure"
            )
        )

        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3] as revalidate,
            patches[4],
        ):
            with self.assertRaises(
                continuity
                .HeldTargetSafetyContinuityError
            ):
                self.run_continuity(
                    self.held()
                )

        revalidate.assert_called_once()

    def test_keyboard_interrupt_and_system_exit_propagate(
        self,
    ):
        for error in (
            KeyboardInterrupt(),
            SystemExit(7),
        ):
            with self.subTest(
                error=type(error).__name__
            ):
                patches = self.environment(
                    side_effect=error
                )

                with (
                    patches[0],
                    patches[1],
                    patches[2],
                    patches[3],
                    patches[4],
                ):
                    with self.assertRaises(
                        type(error)
                    ):
                        self.run_continuity(
                            self.held()
                        )

    def test_invalid_fresh_provenance_or_authority_fails_closed(
        self,
    ):
        cases = (
            (
                "integrity",
                self.fresh(),
                False,
            ),
            (
                "status",
                self.fresh(
                    status="not-satisfied"
                ),
                True,
            ),
            (
                "execution-supported",
                self.fresh(
                    execution_supported=True
                ),
                True,
            ),
            (
                "executor-eligible",
                self.fresh(
                    executor_eligible=True
                ),
                True,
            ),
            (
                "executor-authorization",
                self.fresh(
                    requires_separate_executor_authorization=False
                ),
                True,
            ),
        )

        for (
            label,
            fresh,
            integrity,
        ) in cases:
            with self.subTest(
                label=label
            ):
                patches = self.environment(
                    fresh=fresh,
                    integrity=integrity,
                )

                with (
                    patches[0],
                    patches[1],
                    patches[2],
                    patches[3],
                    patches[4],
                ):
                    with self.assertRaises(
                        continuity
                        .HeldTargetSafetyContinuityError
                    ):
                        self.run_continuity(
                            self.held()
                        )

    def test_malformed_fresh_object_or_integrity_checker_fails_closed(
        self,
    ):
        malformed = self.fresh()
        del malformed.target_mounted

        cases = (
            malformed,
            self.fresh(
                target_mounted=1
            ),
        )

        for fresh in cases:
            with self.subTest(
                fresh=fresh.__dict__
            ):
                patches = self.environment(
                    fresh=fresh
                )

                with (
                    patches[0],
                    patches[1],
                    patches[2],
                    patches[3],
                    patches[4],
                ):
                    with self.assertRaises(
                        continuity
                        .HeldTargetSafetyContinuityError
                    ):
                        self.run_continuity(
                            self.held()
                        )

        patches = self.environment()

        with (
            patches[0],
            patches[1],
            patch.object(
                continuity.auth,
                "_fresh_physical_target_revalidation_integrity_valid",
                side_effect=RuntimeError(
                    "synthetic integrity failure"
                ),
            ),
            patches[3],
            patches[4],
        ):
            with self.assertRaises(
                continuity
                .HeldTargetSafetyContinuityError
            ):
                self.run_continuity(
                    self.held()
                )

    def test_each_fresh_safety_blocker_fails_closed(
        self,
    ):
        blockers = (
            "target_read_only",
            "target_mounted",
            "target_protected",
            "target_system_protected",
            "target_review_required",
            "target_ambiguous",
        )

        for blocker in blockers:
            with self.subTest(
                blocker=blocker
            ):
                patches = self.environment(
                    fresh=self.fresh(
                        **{
                            blocker:
                                True
                        }
                    )
                )

                with (
                    patches[0],
                    patches[1],
                    patches[2],
                    patches[3],
                    patches[4],
                ):
                    with self.assertRaises(
                        continuity
                        .HeldTargetSafetyContinuityError
                    ):
                        self.run_continuity(
                            self.held()
                        )

    def test_each_held_identity_mismatch_fails_closed(
        self,
    ):
        changed = (
            self.fresh(
                handoff_id=(
                    "xhnd_"
                    + ("d" * 64)
                )
            ),
            self.fresh(
                target_path="/dev/syn-b"
            ),
            self.fresh(
                target_major_minor="8:16"
            ),
            self.fresh(
                binding_hash=(
                    "sha256:"
                    + ("e" * 64)
                )
            ),
        )

        for fresh in changed:
            with self.subTest(
                fresh=fresh.__dict__
            ):
                patches = self.environment(
                    fresh=fresh
                )

                with (
                    patches[0],
                    patches[1],
                    patches[2],
                    patches[3],
                    patches[4],
                ):
                    with self.assertRaises(
                        continuity
                        .HeldTargetSafetyContinuityError
                    ):
                        self.run_continuity(
                            self.held()
                        )

    def test_expired_future_or_malformed_fresh_time_fails_closed(
        self,
    ):
        cases = (
            self.fresh(
                evaluated_at_utc=(
                    "2026-08-26T14:59:00Z"
                ),
                valid_until_utc=(
                    "2026-08-26T14:59:59Z"
                ),
            ),
            self.fresh(
                evaluated_at_utc=(
                    "2026-08-26T15:00:01Z"
                ),
                valid_until_utc=(
                    "2026-08-26T15:00:30Z"
                ),
            ),
            self.fresh(
                evaluated_at_utc=(
                    "not-a-time"
                )
            ),
            self.fresh(
                valid_until_utc=(
                    "not-a-time"
                )
            ),
        )

        for fresh in cases:
            with self.subTest(
                fresh=fresh.__dict__
            ):
                patches = self.environment(
                    fresh=fresh
                )

                with (
                    patches[0],
                    patches[1],
                    patches[2],
                    patches[3],
                    patches[4],
                ):
                    with self.assertRaises(
                        continuity
                        .HeldTargetSafetyContinuityError
                    ):
                        self.run_continuity(
                            self.held()
                        )

    def test_continuity_id_is_deterministic_for_same_fresh_evidence(
        self,
    ):
        reference = self.held()
        fresh = self.fresh()
        decisions = []

        for _ in range(2):
            patches = self.environment(
                fresh=fresh
            )

            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                patches[4],
            ):
                decisions.append(
                    self.run_continuity(
                        reference
                    )
                )

        self.assertEqual(
            decisions[0].continuity_id,
            decisions[1].continuity_id,
        )

    def test_public_decision_surface_contains_no_fd_or_execution_capability(
        self,
    ):
        names = {
            field.name
            for field in fields(
                continuity
                .HeldTargetSafetyContinuityDecision
            )
        }

        self.assertNotIn(
            "fd",
            names,
        )
        self.assertNotIn(
            "fileno",
            names,
        )
        self.assertNotIn(
            "command",
            names,
        )
        self.assertNotIn(
            "executor",
            names,
        )
        self.assertNotIn(
            "callback",
            names,
        )

        public_functions = [
            name
            for (
                name,
                value,
            ) in vars(
                continuity
            ).items()
            if (
                callable(value)
                and getattr(
                    value,
                    "__module__",
                    None,
                )
                == continuity.__name__
                and not name.startswith("_")
                and name
                not in (
                    "HeldTargetSafetyContinuityDecision",
                    "HeldTargetSafetyContinuityError",
                )
            )
        ]

        self.assertEqual(
            public_functions,
            [
                "revalidate_held_target_safety_continuity"
            ],
        )


if __name__ == "__main__":
    unittest.main()
