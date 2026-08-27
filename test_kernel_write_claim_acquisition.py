from contextlib import ExitStack
import ast
import copy
from datetime import datetime, timezone
import errno
import inspect
import os
from pathlib import Path
import pickle
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import kernel_write_claim_acquisition as claim


_NOW = datetime(
    2026, 8, 27, 14, 30, 0,
    tzinfo=timezone.utc,
)


class _HeldReference:
    def __init__(
        self,
        *,
        closed=False,
        handoff_id="xhnd_" + ("a" * 64),
        target_path="/dev/synthetic-b3ef-target",
        target_major_minor="8:0",
        target_binding_hash="sha256:" + ("b" * 64),
    ):
        self.closed = closed
        self.handoff_id = handoff_id
        self.target_path = target_path
        self.target_major_minor = target_major_minor
        self.target_binding_hash = target_binding_hash


class _Continuity:
    def __init__(
        self,
        *,
        continuity_id="hsc_" + ("c" * 64),
        handoff_id="xhnd_" + ("a" * 64),
        target_path="/dev/synthetic-b3ef-target",
        target_major_minor="8:0",
        target_binding_hash="sha256:" + ("b" * 64),
        evaluated_at_utc="2026-08-27T14:29:55Z",
        valid_until_utc="2026-08-27T14:34:55Z",
        execution_supported=False,
        executor_eligible=False,
        requires_separate_executor_authorization=True,
        integrity=True,
    ):
        self.continuity_id = continuity_id
        self.handoff_id = handoff_id
        self.target_path = target_path
        self.target_major_minor = target_major_minor
        self.target_binding_hash = target_binding_hash
        self.evaluated_at_utc = evaluated_at_utc
        self.valid_until_utc = valid_until_utc
        self.execution_supported = execution_supported
        self.executor_eligible = executor_eligible
        self.requires_separate_executor_authorization = (
            requires_separate_executor_authorization
        )
        self.integrity = integrity


class KernelWriteClaimAcquisitionTests(unittest.TestCase):
    FD = 61

    def setUp(self):
        # Every test in this class globally mocks the production os.open seam
        # before any acquisition call can occur. No real block-device open is
        # possible through the B3E-F module during these tests.
        self.open_patcher = patch.object(
            claim.os,
            "open",
        )
        self.open_mock = self.open_patcher.start()
        self.addCleanup(self.open_patcher.stop)

    def held(self, **changes):
        return _HeldReference(**changes)

    def continuity(self, **changes):
        return _Continuity(**changes)

    def run_claim(self, reference):
        return claim.acquire_kernel_write_claim(
            held_reference=reference,
            registry=object(),
            approval_id="approval",
            request=object(),
            record=object(),
            journal=object(),
            gate=object(),
        )

    def environment(
        self,
        *,
        reference,
        before=None,
        after=None,
        open_return=FD,
        open_side_effect=None,
        mode=None,
        major=8,
        minor=0,
        descriptor_flags=None,
        inheritable=False,
        close_side_effect=None,
    ):
        if before is None:
            before = self.continuity()
        if after is None:
            after = self.continuity(
                continuity_id="hsc_" + ("d" * 64),
            )
        if mode is None:
            mode = stat.S_IFBLK | 0o600
        if descriptor_flags is None:
            descriptor_flags = os.O_RDWR

        info = SimpleNamespace(
            st_mode=mode,
            st_rdev=os.makedev(major, minor),
        )

        self.open_mock.reset_mock()
        self.open_mock.return_value = open_return
        self.open_mock.side_effect = open_side_effect

        stack = ExitStack()
        stack.enter_context(
            patch.object(
                claim.held_ref,
                "HeldKernelTargetReference",
                _HeldReference,
            )
        )
        stack.enter_context(
            patch.object(
                claim.continuity,
                "HeldTargetSafetyContinuityDecision",
                _Continuity,
            )
        )
        revalidate = stack.enter_context(
            patch.object(
                claim.continuity,
                "revalidate_held_target_safety_continuity",
                side_effect=[before, after],
            )
        )
        integrity = stack.enter_context(
            patch.object(
                claim.continuity,
                "_held_target_safety_continuity_integrity_valid",
                side_effect=lambda decision: decision.integrity,
            )
        )
        fstat = stack.enter_context(
            patch.object(
                claim.os,
                "fstat",
                return_value=info,
            )
        )
        flags = stack.enter_context(
            patch.object(
                claim.fcntl,
                "fcntl",
                return_value=descriptor_flags,
            )
        )
        inheritable_mock = stack.enter_context(
            patch.object(
                claim.os,
                "get_inheritable",
                return_value=inheritable,
            )
        )
        close = stack.enter_context(
            patch.object(
                claim.os,
                "close",
                side_effect=close_side_effect,
            )
        )
        stack.enter_context(
            patch.object(
                claim,
                "_utc_now",
                return_value=_NOW,
            )
        )

        return SimpleNamespace(
            stack=stack,
            revalidate=revalidate,
            integrity=integrity,
            fstat=fstat,
            flags=flags,
            inheritable=inheritable_mock,
            close=close,
        )

    def test_success_uses_exact_trusted_path_flags_and_is_non_authorizing(self):
        reference = self.held()
        before = self.continuity()
        after = self.continuity(
            continuity_id="hsc_" + ("d" * 64),
        )
        mocks = self.environment(
            reference=reference,
            before=before,
            after=after,
        )

        with mocks.stack:
            held_claim = self.run_claim(reference)

            expected_flags = (
                os.O_RDWR
                | os.O_EXCL
                | os.O_NOFOLLOW
                | os.O_CLOEXEC
            )

            self.open_mock.assert_called_once_with(
                reference.target_path,
                expected_flags,
            )
            self.assertEqual(mocks.revalidate.call_count, 2)
            self.assertEqual(mocks.integrity.call_count, 2)
            self.assertIs(
                held_claim._held_reference,
                reference,
            )

            self.assertTrue(held_claim.live)
            self.assertFalse(held_claim.closed)
            self.assertEqual(held_claim.handoff_id, reference.handoff_id)
            self.assertEqual(held_claim.target_path, reference.target_path)
            self.assertEqual(
                held_claim.target_major_minor,
                reference.target_major_minor,
            )
            self.assertEqual(
                held_claim.target_binding_hash,
                reference.target_binding_hash,
            )
            self.assertEqual(
                held_claim.pre_continuity_id,
                before.continuity_id,
            )
            self.assertEqual(
                held_claim.post_continuity_id,
                after.continuity_id,
            )

            self.assertTrue(
                held_claim.kernel_exclusive_claim_acquired
            )
            self.assertFalse(
                held_claim.absolute_write_exclusion_guaranteed
            )
            self.assertFalse(
                held_claim.ordinary_raw_writers_excluded
            )
            self.assertFalse(held_claim.execution_supported)
            self.assertFalse(held_claim.executor_eligible)
            self.assertTrue(
                held_claim.requires_separate_executor_authorization
            )

            for name in (
                "fd",
                "fileno",
                "read",
                "write",
                "seek",
                "execute",
                "command",
            ):
                self.assertFalse(
                    hasattr(held_claim, name),
                    name,
                )

            self.assertFalse(
                hasattr(held_claim, "__dict__")
            )

            held_claim.close()
            self.assertTrue(held_claim.closed)
            self.assertFalse(held_claim.live)
            mocks.close.assert_called_once_with(self.FD)
            self.assertFalse(reference.closed)

    def test_signature_has_no_substitutable_path_flags_continuity_or_executor(self):
        parameters = inspect.signature(
            claim.acquire_kernel_write_claim
        ).parameters

        for forbidden in (
            "path",
            "target_path",
            "flags",
            "continuity",
            "continuity_decision",
            "fd",
            "opener",
            "open_fn",
            "executor",
            "command",
        ):
            self.assertNotIn(
                forbidden,
                parameters,
            )

    def test_required_flags_are_exact_and_missing_platform_flag_fails_closed(self):
        expected = (
            os.O_RDWR
            | os.O_EXCL
            | os.O_NOFOLLOW
            | os.O_CLOEXEC
        )
        self.assertEqual(
            claim._required_open_flags(),
            expected,
        )

        # Temporarily remove one required platform flag and restore it.
        original = claim.os.O_EXCL
        try:
            delattr(claim.os, "O_EXCL")
            with self.assertRaises(
                claim.KernelWriteClaimAcquisitionError
            ):
                claim._required_open_flags()
        finally:
            setattr(claim.os, "O_EXCL", original)

    def test_pre_continuity_failures_never_open(self):
        cases = (
            self.continuity(integrity=False),
            self.continuity(
                evaluated_at_utc="2026-08-27T14:00:00Z",
                valid_until_utc="2026-08-27T14:05:00Z",
            ),
            self.continuity(executor_eligible=True),
        )

        for before in cases:
            with self.subTest(before=before):
                reference = self.held()
                mocks = self.environment(
                    reference=reference,
                    before=before,
                )

                with mocks.stack:
                    with self.assertRaises(
                        claim.KernelWriteClaimAcquisitionError
                    ):
                        self.run_claim(reference)

                self.open_mock.assert_not_called()
                mocks.close.assert_not_called()

    def test_wrong_reference_type_fails_before_continuity_or_open(self):
        reference = SimpleNamespace(
            closed=False,
            handoff_id="xhnd_" + ("a" * 64),
            target_path="/dev/synthetic-b3ef-target",
            target_major_minor="8:0",
            target_binding_hash="sha256:" + ("b" * 64),
        )
        mocks = self.environment(
            reference=reference,
        )

        with mocks.stack:
            with self.assertRaises(
                claim.KernelWriteClaimAcquisitionError
            ):
                self.run_claim(reference)

        mocks.revalidate.assert_not_called()
        self.open_mock.assert_not_called()
        mocks.close.assert_not_called()

    def test_ebusy_and_other_open_failures_never_claim_ownership(self):
        cases = (
            (
                OSError(errno.EBUSY, "synthetic busy"),
                "busy",
            ),
            (
                OSError(errno.EACCES, "synthetic denied"),
                "acquisition failed",
            ),
        )

        for open_error, message in cases:
            with self.subTest(open_error=open_error):
                reference = self.held()
                mocks = self.environment(
                    reference=reference,
                    open_side_effect=open_error,
                )

                with mocks.stack:
                    with self.assertRaisesRegex(
                        claim.KernelWriteClaimAcquisitionError,
                        message,
                    ):
                        self.run_claim(reference)

                self.open_mock.assert_called_once()
                mocks.fstat.assert_not_called()
                mocks.close.assert_not_called()

    def test_invalid_descriptor_return_never_closes_unknown_value(self):
        for invalid in (-1, "61", True):
            with self.subTest(invalid=invalid):
                reference = self.held()
                mocks = self.environment(
                    reference=reference,
                    open_return=invalid,
                )

                with mocks.stack:
                    with self.assertRaises(
                        claim.KernelWriteClaimAcquisitionError
                    ):
                        self.run_claim(reference)

                mocks.close.assert_not_called()

    def test_wrong_descriptor_identity_fails_closed_and_closes_once(self):
        reference = self.held()
        mocks = self.environment(
            reference=reference,
            major=8,
            minor=16,
        )

        with mocks.stack:
            with self.assertRaises(
                claim.KernelWriteClaimAcquisitionError
            ):
                self.run_claim(reference)

        mocks.close.assert_called_once_with(self.FD)
        self.assertEqual(mocks.revalidate.call_count, 1)

    def test_descriptor_mode_flags_and_inheritance_fail_closed(self):
        cases = [
            {
                "mode": stat.S_IFREG | 0o600,
            },
            {
                "descriptor_flags": os.O_RDONLY,
            },
            {
                "inheritable": True,
            },
        ]

        if hasattr(os, "O_PATH"):
            cases.append(
                {
                    "descriptor_flags": (
                        os.O_RDWR | os.O_PATH
                    ),
                }
            )

        for changes in cases:
            with self.subTest(changes=changes):
                reference = self.held()
                mocks = self.environment(
                    reference=reference,
                    **changes,
                )

                with mocks.stack:
                    with self.assertRaises(
                        claim.KernelWriteClaimAcquisitionError
                    ):
                        self.run_claim(reference)

                mocks.close.assert_called_once_with(
                    self.FD
                )

    def test_b3a_closure_during_open_fails_closed_and_closes_new_fd_only(self):
        reference = self.held()

        def close_b3a_then_return(*args):
            reference.closed = True
            return self.FD

        mocks = self.environment(
            reference=reference,
            open_side_effect=close_b3a_then_return,
        )

        with mocks.stack:
            with self.assertRaises(
                claim.KernelWriteClaimAcquisitionError
            ):
                self.run_claim(reference)

        mocks.close.assert_called_once_with(self.FD)
        self.assertTrue(reference.closed)
        self.assertEqual(mocks.revalidate.call_count, 1)

    def test_post_continuity_failures_close_owned_descriptor(self):
        cases = (
            self.continuity(
                continuity_id="hsc_" + ("d" * 64),
                target_major_minor="8:16",
            ),
            self.continuity(
                continuity_id="hsc_" + ("d" * 64),
                integrity=False,
            ),
            self.continuity(
                continuity_id="hsc_" + ("d" * 64),
                evaluated_at_utc="2026-08-27T14:00:00Z",
                valid_until_utc="2026-08-27T14:05:00Z",
            ),
        )

        for after in cases:
            with self.subTest(after=after):
                reference = self.held()
                mocks = self.environment(
                    reference=reference,
                    after=after,
                )

                with mocks.stack:
                    with self.assertRaises(
                        claim.KernelWriteClaimAcquisitionError
                    ):
                        self.run_claim(reference)

                mocks.close.assert_called_once_with(self.FD)
                self.assertEqual(mocks.revalidate.call_count, 2)

    def test_constructor_failure_closes_owned_descriptor_once(self):
        reference = self.held()
        mocks = self.environment(reference=reference)

        with mocks.stack:
            with patch.object(
                claim,
                "HeldKernelWriteClaim",
                side_effect=RuntimeError(
                    "synthetic constructor failure"
                ),
            ):
                with self.assertRaisesRegex(
                    claim.KernelWriteClaimAcquisitionError,
                    "claim acquisition failed",
                ):
                    self.run_claim(reference)

        mocks.close.assert_called_once_with(self.FD)

    def test_failure_cleanup_close_error_is_not_retried(self):
        reference = self.held()
        mocks = self.environment(
            reference=reference,
            major=8,
            minor=16,
            close_side_effect=OSError(
                "synthetic close failure"
            ),
        )

        with mocks.stack:
            with self.assertRaisesRegex(
                claim.KernelWriteClaimAcquisitionError,
                "must not be reused",
            ):
                self.run_claim(reference)

        mocks.close.assert_called_once_with(self.FD)

    def test_claim_close_error_invalidates_and_is_not_retried(self):
        reference = self.held()
        mocks = self.environment(
            reference=reference,
            close_side_effect=OSError(
                "synthetic close failure"
            ),
        )

        with mocks.stack:
            held_claim = self.run_claim(reference)

            with self.assertRaises(
                claim.KernelWriteClaimAcquisitionError
            ):
                held_claim.close()

            self.assertTrue(held_claim.closed)
            self.assertFalse(held_claim.live)

            held_claim.close()

        mocks.close.assert_called_once_with(self.FD)

    def test_claim_cannot_be_copied_or_serialized(self):
        reference = self.held()
        mocks = self.environment(reference=reference)

        with mocks.stack:
            held_claim = self.run_claim(reference)

            for operation in (
                lambda: copy.copy(held_claim),
                lambda: copy.deepcopy(held_claim),
                lambda: pickle.dumps(held_claim),
            ):
                with self.subTest(operation=operation):
                    with self.assertRaises(
                        claim.KernelWriteClaimAcquisitionError
                    ):
                        operation()

            held_claim.close()

        mocks.close.assert_called_once_with(self.FD)

    def test_b3a_closure_after_success_invalidates_live_state(self):
        reference = self.held()
        mocks = self.environment(reference=reference)

        with mocks.stack:
            held_claim = self.run_claim(reference)
            reference.closed = True

            self.assertFalse(held_claim.live)

            with self.assertRaises(
                claim.KernelWriteClaimAcquisitionError
            ):
                held_claim.__enter__()

            held_claim.close()

        mocks.close.assert_called_once_with(self.FD)

    def test_production_source_has_one_open_and_no_io_or_executor_surface(self):
        source_path = Path(claim.__file__)
        text = source_path.read_text(
            encoding="utf-8"
        )
        tree = ast.parse(text)

        os_open_calls = []
        forbidden_os_calls = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func

            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "os"
            ):
                if func.attr == "open":
                    os_open_calls.append(node)
                if func.attr in {
                    "read",
                    "write",
                    "pread",
                    "pwrite",
                    "lseek",
                }:
                    forbidden_os_calls.append(node)

        self.assertEqual(len(os_open_calls), 1)
        self.assertEqual(forbidden_os_calls, [])

        open_call = os_open_calls[0]
        self.assertEqual(len(open_call.args), 2)
        self.assertIsInstance(open_call.args[0], ast.Attribute)
        self.assertEqual(open_call.args[0].attr, "target_path")
        self.assertIsInstance(open_call.args[1], ast.Name)
        self.assertEqual(open_call.args[1].id, "flags")

        self.assertNotIn("subprocess", text)
        self.assertNotIn("Popen", text)
        self.assertNotIn("ioctl", text)
        self.assertNotIn("O_WRONLY", text)

        self.assertEqual(
            claim.__all__,
            [
                "KERNEL_WRITE_CLAIM_ACQUISITION_POLICY_VERSION",
                "HeldKernelWriteClaim",
                "KernelWriteClaimAcquisitionError",
                "acquire_kernel_write_claim",
            ],
        )

    def test_test_harness_mocks_os_open_before_every_acquisition(self):
        self.assertIsInstance(
            self.open_mock,
            Mock,
        )
        self.open_mock.assert_not_called()
