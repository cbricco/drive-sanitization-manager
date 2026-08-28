from contextlib import contextmanager
import copy
from dataclasses import replace
from datetime import datetime, timezone
import os
import pickle
import stat
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import kernel_target_reference as ref
import sanitization_authorization as auth


UTC = timezone.utc


class HeldKernelTargetReferenceTests(unittest.TestCase):
    FD = 41

    NOW = datetime(
        2026,
        8,
        26,
        3,
        0,
        2,
        tzinfo=UTC,
    )

    @staticmethod
    def hash_value(character):
        return "sha256:" + character * 64

    def decision(self, **changes):
        values = dict(
            revalidation_id="ptrv_" + "a" * 64,
            policy_version=(
                auth.FRESH_TARGET_REVALIDATION_POLICY_VERSION
            ),
            schema_version=(
                auth.FRESH_TARGET_REVALIDATION_SCHEMA_VERSION
            ),
            status=(
                auth.FRESH_TARGET_REVALIDATION_STATUS_SATISFIED
            ),
            handoff_id="xhnd_" + "b" * 64,
            gate_id="xgate_" + "c" * 64,
            binding_id="xeb_" + "d" * 64,
            journal_entry_hash=self.hash_value("e"),
            fresh_prerequisite_decision_id=(
                "decision-" + "f" * 64
            ),
            fresh_discovery_snapshot_hash=(
                self.hash_value("1")
            ),
            request_id="REQ-B3A",
            request_hash=self.hash_value("2"),
            record_snapshot_hash=self.hash_value("3"),
            method_profile_id="phase5-policy-only",
            operation="sanitize",
            prior_target_binding_hash=(
                self.hash_value("4")
            ),
            fresh_target_binding_hash=(
                self.hash_value("4")
            ),
            constraint_evaluation_hash=(
                self.hash_value("5")
            ),
            target_path="/dev/syn-a",
            target_major_minor="8:0",
            target_serial="SERIAL-A",
            target_wwn="WWN-A",
            target_size_bytes=1_000_000,
            target_model="Synthetic Model",
            target_transport="usb",
            target_read_only=False,
            target_mounted=False,
            target_protected=False,
            target_system_protected=False,
            target_review_required=False,
            target_ambiguous=False,
            discovery_captured_at_utc=(
                "2026-08-26T03:00:00Z"
            ),
            evaluated_at_utc=(
                "2026-08-26T03:00:01Z"
            ),
            valid_until_utc=(
                "2026-08-26T03:05:01Z"
            ),
            execution_supported=False,
            executor_eligible=False,
            requires_separate_executor_authorization=True,
        )

        values.update(changes)

        return (
            auth.FreshPhysicalTargetRevalidationDecision(
                **values
            )
        )

    @contextmanager
    def fd_environment(
        self,
        *,
        major=8,
        minor=0,
        mode=None,
        flags=None,
        inheritable=False,
        integrity=True,
        close_side_effect=None,
    ):
        if mode is None:
            mode = stat.S_IFBLK | 0o600

        if flags is None:
            flags = os.O_RDONLY

        info = SimpleNamespace(
            st_mode=mode,
            st_rdev=os.makedev(
                major,
                minor,
            ),
        )

        with (
            patch(
                "kernel_target_reference."
                "auth."
                "_fresh_physical_target_revalidation_integrity_valid",
                return_value=integrity,
            ) as integrity_mock,
            patch(
                "kernel_target_reference._utc_now",
                return_value=self.NOW,
            ),
            patch(
                "kernel_target_reference.os.fstat",
                return_value=info,
            ) as fstat_mock,
            patch(
                "kernel_target_reference.fcntl.fcntl",
                return_value=flags,
            ) as flags_mock,
            patch(
                "kernel_target_reference.os.get_inheritable",
                return_value=inheritable,
            ) as inheritable_mock,
            patch(
                "kernel_target_reference.os.close",
                side_effect=close_side_effect,
            ) as close_mock,
        ):
            yield SimpleNamespace(
                integrity=integrity_mock,
                fstat=fstat_mock,
                flags=flags_mock,
                inheritable=inheritable_mock,
                close=close_mock,
            )

    def test_adopts_valid_descriptor_without_exposing_public_fd(self):
        decision = self.decision()

        with self.fd_environment() as mocks:
            held = (
                ref.adopt_held_kernel_target_reference(
                    self.FD,
                    decision,
                )
            )

            self.assertFalse(held.closed)
            self.assertEqual(
                held.target_path,
                "/dev/syn-a",
            )
            self.assertEqual(
                held.target_major_minor,
                "8:0",
            )
            self.assertEqual(
                held.revalidation_id,
                decision.revalidation_id,
            )
            self.assertEqual(
                held.handoff_id,
                decision.handoff_id,
            )
            self.assertEqual(
                held.target_binding_hash,
                decision.fresh_target_binding_hash,
            )

            self.assertFalse(
                hasattr(held, "fd")
            )
            self.assertFalse(
                hasattr(held, "fileno")
            )

            mocks.fstat.assert_called_once_with(
                self.FD
            )
            mocks.flags.assert_called_once_with(
                self.FD,
                ref.fcntl.F_GETFL,
            )
            mocks.inheritable.assert_called_once_with(
                self.FD
            )
            mocks.close.assert_not_called()

            held.close()

            self.assertTrue(held.closed)
            mocks.close.assert_called_once_with(
                self.FD
            )

    def test_close_is_idempotent_and_close_failure_never_retries_fd(self):
        decision = self.decision()

        with self.fd_environment() as mocks:
            held = (
                ref.adopt_held_kernel_target_reference(
                    self.FD,
                    decision,
                )
            )

            held.close()
            held.close()

            self.assertTrue(held.closed)
            mocks.close.assert_called_once_with(
                self.FD
            )

        with self.fd_environment(
            close_side_effect=OSError(
                "synthetic close failure"
            )
        ) as mocks:
            held = (
                ref.adopt_held_kernel_target_reference(
                    self.FD,
                    decision,
                )
            )

            with self.assertRaises(
                ref.HeldKernelTargetReferenceError
            ):
                held.close()

            self.assertTrue(held.closed)

            # Reusing/retrying the integer would be unsafe if the kernel
            # had already closed and recycled the descriptor number.
            held.close()

            mocks.close.assert_called_once_with(
                self.FD
            )

    def test_context_manager_closes_exactly_once(self):
        with self.fd_environment() as mocks:
            held = (
                ref.adopt_held_kernel_target_reference(
                    self.FD,
                    self.decision(),
                )
            )

            with held as active:
                self.assertIs(
                    active,
                    held,
                )
                self.assertFalse(
                    held.closed
                )

            self.assertTrue(
                held.closed
            )
            mocks.close.assert_called_once_with(
                self.FD
            )

            with self.assertRaises(
                ref.HeldKernelTargetReferenceError
            ):
                held.__enter__()

    def test_non_block_descriptor_fails_closed_and_is_closed(self):
        with self.fd_environment(
            mode=stat.S_IFREG | 0o600
        ) as mocks:
            with self.assertRaises(
                ref.HeldKernelTargetReferenceError
            ):
                ref.adopt_held_kernel_target_reference(
                    self.FD,
                    self.decision(),
                )

            mocks.close.assert_called_once_with(
                self.FD
            )

    def test_kernel_device_number_mismatch_fails_closed_and_is_closed(self):
        with self.fd_environment(
            major=8,
            minor=16,
        ) as mocks:
            with self.assertRaises(
                ref.HeldKernelTargetReferenceError
            ):
                ref.adopt_held_kernel_target_reference(
                    self.FD,
                    self.decision(),
                )

            mocks.close.assert_called_once_with(
                self.FD
            )

    def test_write_capable_descriptors_are_rejected(self):
        for flags in (
            os.O_WRONLY,
            os.O_RDWR,
        ):
            with (
                self.subTest(flags=flags),
                self.fd_environment(
                    flags=flags
                ) as mocks,
            ):
                with self.assertRaises(
                    ref.HeldKernelTargetReferenceError
                ):
                    ref.adopt_held_kernel_target_reference(
                        self.FD,
                        self.decision(),
                    )

                mocks.close.assert_called_once_with(
                    self.FD
                )

    def test_inheritable_and_opath_descriptors_are_rejected(self):
        with self.fd_environment(
            inheritable=True
        ) as mocks:
            with self.assertRaises(
                ref.HeldKernelTargetReferenceError
            ):
                ref.adopt_held_kernel_target_reference(
                    self.FD,
                    self.decision(),
                )

            mocks.close.assert_called_once_with(
                self.FD
            )

        if hasattr(os, "O_PATH"):
            with self.fd_environment(
                flags=(
                    os.O_RDONLY
                    | os.O_PATH
                )
            ) as mocks:
                with self.assertRaises(
                    ref.HeldKernelTargetReferenceError
                ):
                    ref.adopt_held_kernel_target_reference(
                        self.FD,
                        self.decision(),
                    )

                mocks.close.assert_called_once_with(
                    self.FD
                )

    def test_invalid_provenance_or_authority_state_fails_closed(self):
        cases = (
            (
                self.decision(),
                False,
            ),
            (
                self.decision(
                    execution_supported=True
                ),
                True,
            ),
            (
                self.decision(
                    executor_eligible=True
                ),
                True,
            ),
            (
                self.decision(
                    requires_separate_executor_authorization=False
                ),
                True,
            ),
        )

        for decision, integrity in cases:
            with (
                self.subTest(
                    decision=decision,
                    integrity=integrity,
                ),
                self.fd_environment(
                    integrity=integrity
                ) as mocks,
            ):
                with self.assertRaises(
                    ref.HeldKernelTargetReferenceError
                ):
                    ref.adopt_held_kernel_target_reference(
                        self.FD,
                        decision,
                    )

                mocks.close.assert_called_once_with(
                    self.FD
                )

    def test_expired_or_future_revalidation_fails_closed(self):
        cases = (
            self.decision(
                valid_until_utc=(
                    "2026-08-26T03:00:01Z"
                )
            ),
            self.decision(
                evaluated_at_utc=(
                    "2026-08-26T03:00:03Z"
                )
            ),
        )

        for decision in cases:
            with (
                self.subTest(decision=decision),
                self.fd_environment() as mocks,
            ):
                with self.assertRaises(
                    ref.HeldKernelTargetReferenceError
                ):
                    ref.adopt_held_kernel_target_reference(
                        self.FD,
                        decision,
                    )

                mocks.close.assert_called_once_with(
                    self.FD
                )

    def test_reference_cannot_be_copied_deepcopied_or_pickled(self):
        with self.fd_environment() as mocks:
            held = (
                ref.adopt_held_kernel_target_reference(
                    self.FD,
                    self.decision(),
                )
            )

            for operation in (
                lambda: copy.copy(held),
                lambda: copy.deepcopy(held),
                lambda: pickle.dumps(held),
            ):
                with (
                    self.subTest(
                        operation=operation
                    ),
                    self.assertRaises(
                        ref.HeldKernelTargetReferenceError
                    ),
                ):
                    operation()

            self.assertFalse(
                held.closed
            )

            held.close()

            mocks.close.assert_called_once_with(
                self.FD
            )

    def _r3_lifecycle_reference(self):
        decision = SimpleNamespace(
            target_path="/dev/synthetic-r3-b3a",
            revalidation_id="r3-revalidation",
            handoff_id="xhnd_" + ("a" * 64),
            fresh_target_binding_hash="sha256:" + ("b" * 64),
        )
        return ref.HeldKernelTargetReference(
            ref._CONSTRUCTION_TOKEN,
            fd=73,
            decision=decision,
            observed_major_minor="8:0",
        )

    def test_r3_private_lifecycle_scope_is_opaque_and_public_api_unchanged(self):
        reference = self._r3_lifecycle_reference()

        with patch.object(ref.os, "close") as close_mock:
            scope = ref._locked_kernel_target_reference_scope(
                reference
            )

            with scope as active:
                self.assertEqual(
                    active.identity,
                    (
                        reference.handoff_id,
                        reference.target_path,
                        reference.target_major_minor,
                        reference.target_binding_hash,
                    ),
                )

                for name in (
                    "fd",
                    "fileno",
                    "read",
                    "write",
                    "seek",
                    "callback",
                    "command",
                    "subprocess",
                    "executor",
                    "execute",
                ):
                    self.assertFalse(
                        hasattr(active, name),
                        name,
                    )

            self.assertNotIn(
                "_locked_kernel_target_reference_scope",
                ref.__all__,
            )
            self.assertNotIn(
                "_LockedKernelTargetReferenceScope",
                ref.__all__,
            )
            reference.close()
            close_mock.assert_called_once_with(73)

    def test_r3_lifecycle_scope_blocks_close_until_exit(self):
        reference = self._r3_lifecycle_reference()
        close_started = threading.Event()
        close_finished = threading.Event()

        with patch.object(ref.os, "close") as close_mock:
            def closer():
                close_started.set()
                reference.close()
                close_finished.set()

            with ref._locked_kernel_target_reference_scope(
                reference
            ):
                thread = threading.Thread(
                    target=closer
                )
                thread.start()
                self.assertTrue(
                    close_started.wait(1.0)
                )
                self.assertFalse(
                    close_finished.wait(0.05)
                )
                self.assertFalse(reference.closed)

            self.assertTrue(
                close_finished.wait(1.0)
            )
            thread.join()
            self.assertTrue(reference.closed)
            close_mock.assert_called_once_with(73)

    def test_r3_lifecycle_scope_reentry_and_reuse_refuse(self):
        reference = self._r3_lifecycle_reference()

        with patch.object(ref.os, "close"):
            scope = ref._locked_kernel_target_reference_scope(
                reference
            )

            with scope:
                with self.assertRaisesRegex(
                    ref.HeldKernelTargetReferenceError,
                    "single-use",
                ):
                    scope.__enter__()

            with self.assertRaisesRegex(
                ref.HeldKernelTargetReferenceError,
                "single-use",
            ):
                scope.__enter__()

            reference.close()

    def test_r3_lifecycle_scope_exception_releases_close_path(self):
        reference = self._r3_lifecycle_reference()

        with patch.object(ref.os, "close") as close_mock:
            with self.assertRaisesRegex(
                RuntimeError,
                "synthetic lifecycle failure",
            ):
                with ref._locked_kernel_target_reference_scope(
                    reference
                ):
                    raise RuntimeError(
                        "synthetic lifecycle failure"
                    )

            reference.close()
            self.assertTrue(reference.closed)
            close_mock.assert_called_once_with(73)


if __name__ == "__main__":
    unittest.main()
