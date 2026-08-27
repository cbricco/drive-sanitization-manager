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

import kernel_write_claim_candidate as claim


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
        target_path="/dev/syn-a",
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
        target_path="/dev/syn-a",
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


class KernelWriteClaimCandidateTests(unittest.TestCase):
    FD = 51

    def held(self, **changes):
        return _HeldReference(**changes)

    def continuity(self, **changes):
        return _Continuity(**changes)

    def run_candidate(self, reference):
        return claim.acquire_mocked_kernel_write_claim_candidate(
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
        acquire_return=FD,
        acquire_side_effect=None,
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
        acquire = stack.enter_context(
            patch.object(
                claim,
                "_acquire_mocked_write_descriptor",
                return_value=acquire_return,
                side_effect=acquire_side_effect,
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

        mocks = SimpleNamespace(
            stack=stack,
            revalidate=revalidate,
            integrity=integrity,
            acquire=acquire,
            fstat=fstat,
            flags=flags,
            inheritable=inheritable_mock,
            close=close,
        )
        return mocks

    def test_exact_modeled_open_flags(self):
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

    def test_success_is_bound_non_authorizing_and_not_absolute_exclusion(self):
        reference = self.held()
        before = self.continuity()
        after = self.continuity(
            continuity_id="hsc_" + ("d" * 64)
        )
        mocks = self.environment(
            reference=reference,
            before=before,
            after=after,
        )

        with mocks.stack:
            candidate = self.run_candidate(reference)

            self.assertTrue(candidate.live)
            self.assertFalse(candidate.closed)
            self.assertEqual(
                candidate.handoff_id,
                reference.handoff_id,
            )
            self.assertEqual(
                candidate.target_path,
                reference.target_path,
            )
            self.assertEqual(
                candidate.target_major_minor,
                reference.target_major_minor,
            )
            self.assertEqual(
                candidate.target_binding_hash,
                reference.target_binding_hash,
            )
            self.assertEqual(
                candidate.pre_continuity_id,
                before.continuity_id,
            )
            self.assertEqual(
                candidate.post_continuity_id,
                after.continuity_id,
            )

            self.assertTrue(
                candidate.kernel_exclusive_claim_acquired
            )
            self.assertFalse(
                candidate.absolute_write_exclusion_guaranteed
            )
            self.assertFalse(
                candidate.ordinary_raw_writers_excluded
            )
            self.assertFalse(
                candidate.execution_supported
            )
            self.assertFalse(
                candidate.executor_eligible
            )
            self.assertTrue(
                candidate.requires_separate_executor_authorization
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
                    hasattr(candidate, name),
                    name,
                )

            self.assertFalse(
                hasattr(candidate, "__dict__")
            )

            mocks.acquire.assert_called_once_with(
                reference.target_path,
                (
                    os.O_RDWR
                    | os.O_EXCL
                    | os.O_NOFOLLOW
                    | os.O_CLOEXEC
                ),
            )
            mocks.fstat.assert_called_once_with(self.FD)
            mocks.flags.assert_called_once_with(
                self.FD,
                claim.fcntl.F_GETFL,
            )
            mocks.inheritable.assert_called_once_with(
                self.FD
            )
            self.assertEqual(
                mocks.revalidate.call_count,
                2,
            )
            for call in mocks.revalidate.call_args_list:
                self.assertIs(
                    call.kwargs["held_reference"],
                    reference,
                )

            candidate.close()
            self.assertTrue(candidate.closed)
            self.assertFalse(candidate.live)
            mocks.close.assert_called_once_with(self.FD)
            self.assertFalse(reference.closed)

    def test_continuity_is_directly_generated_twice_not_caller_supplied(self):
        parameters = inspect.signature(
            claim.acquire_mocked_kernel_write_claim_candidate
        ).parameters
        self.assertNotIn(
            "continuity",
            parameters,
        )
        self.assertNotIn(
            "continuity_decision",
            parameters,
        )

        reference = self.held()
        mocks = self.environment(reference=reference)

        with mocks.stack:
            candidate = self.run_candidate(reference)
            self.assertEqual(mocks.revalidate.call_count, 2)
            self.assertEqual(mocks.integrity.call_count, 2)
            candidate.close()

    def test_default_production_acquisition_seam_fails_closed(self):
        reference = self.held()
        before = self.continuity()

        with (
            patch.object(
                claim.held_ref,
                "HeldKernelTargetReference",
                _HeldReference,
            ),
            patch.object(
                claim.continuity,
                "HeldTargetSafetyContinuityDecision",
                _Continuity,
            ),
            patch.object(
                claim.continuity,
                "revalidate_held_target_safety_continuity",
                return_value=before,
            ) as revalidate,
            patch.object(
                claim.continuity,
                "_held_target_safety_continuity_integrity_valid",
                return_value=True,
            ),
            patch.object(
                claim,
                "_utc_now",
                return_value=_NOW,
            ),
            patch.object(
                claim.os,
                "fstat",
            ) as fstat,
        ):
            with self.assertRaises(
                claim.KernelWriteClaimCandidateError
            ):
                self.run_candidate(reference)

        revalidate.assert_called_once()
        fstat.assert_not_called()

    def test_ebusy_is_refused_without_claiming_ownership(self):
        reference = self.held()
        mocks = self.environment(
            reference=reference,
            acquire_side_effect=OSError(
                errno.EBUSY,
                "synthetic busy",
            ),
        )

        with mocks.stack:
            with self.assertRaisesRegex(
                claim.KernelWriteClaimCandidateError,
                "busy",
            ):
                self.run_candidate(reference)

        mocks.fstat.assert_not_called()
        mocks.close.assert_not_called()
        self.assertEqual(
            mocks.revalidate.call_count,
            1,
        )

    def test_wrong_descriptor_identity_fails_closed(self):
        reference = self.held()
        mocks = self.environment(
            reference=reference,
            major=8,
            minor=16,
        )

        with mocks.stack:
            with self.assertRaises(
                claim.KernelWriteClaimCandidateError
            ):
                self.run_candidate(reference)

        mocks.close.assert_called_once_with(self.FD)
        self.assertEqual(
            mocks.revalidate.call_count,
            1,
        )

    def test_stale_pre_continuity_never_acquires(self):
        reference = self.held()
        stale = self.continuity(
            evaluated_at_utc="2026-08-27T14:00:00Z",
            valid_until_utc="2026-08-27T14:05:00Z",
        )
        mocks = self.environment(
            reference=reference,
            before=stale,
        )

        with mocks.stack:
            with self.assertRaisesRegex(
                claim.KernelWriteClaimCandidateError,
                "not current",
            ):
                self.run_candidate(reference)

        mocks.acquire.assert_not_called()
        mocks.close.assert_not_called()

    def test_pre_continuity_integrity_failure_never_acquires(self):
        reference = self.held()
        before = self.continuity(
            integrity=False,
        )
        mocks = self.environment(
            reference=reference,
            before=before,
        )

        with mocks.stack:
            with self.assertRaises(
                claim.KernelWriteClaimCandidateError
            ):
                self.run_candidate(reference)

        mocks.acquire.assert_not_called()
        mocks.close.assert_not_called()

    def test_post_continuity_identity_change_fails_closed(self):
        reference = self.held()
        after = self.continuity(
            continuity_id="hsc_" + ("d" * 64),
            target_major_minor="8:16",
        )
        mocks = self.environment(
            reference=reference,
            after=after,
        )

        with mocks.stack:
            with self.assertRaises(
                claim.KernelWriteClaimCandidateError
            ):
                self.run_candidate(reference)

        self.assertEqual(
            mocks.revalidate.call_count,
            2,
        )
        mocks.close.assert_called_once_with(self.FD)

    def test_post_continuity_integrity_failure_fails_closed(self):
        reference = self.held()
        after = self.continuity(
            continuity_id="hsc_" + ("d" * 64),
            integrity=False,
        )
        mocks = self.environment(
            reference=reference,
            after=after,
        )

        with mocks.stack:
            with self.assertRaises(
                claim.KernelWriteClaimCandidateError
            ):
                self.run_candidate(reference)

        mocks.close.assert_called_once_with(self.FD)

    def test_b3a_closure_during_acquisition_fails_closed(self):
        reference = self.held()

        def close_b3a_then_return(*args):
            reference.closed = True
            return self.FD

        mocks = self.environment(
            reference=reference,
            acquire_side_effect=close_b3a_then_return,
        )

        with mocks.stack:
            with self.assertRaises(
                claim.KernelWriteClaimCandidateError
            ):
                self.run_candidate(reference)

        mocks.close.assert_called_once_with(self.FD)
        self.assertEqual(
            mocks.revalidate.call_count,
            1,
        )

    def test_b3a_closure_after_success_invalidates_candidate(self):
        reference = self.held()
        mocks = self.environment(reference=reference)

        with mocks.stack:
            candidate = self.run_candidate(reference)
            reference.closed = True

            self.assertFalse(candidate.live)

            with self.assertRaises(
                claim.KernelWriteClaimCandidateError
            ):
                candidate.__enter__()

            candidate.close()
            mocks.close.assert_called_once_with(self.FD)

    def test_invalid_descriptor_return_never_closes_unknown_value(self):
        for invalid in (-1, "51", True):
            with self.subTest(invalid=invalid):
                reference = self.held()
                mocks = self.environment(
                    reference=reference,
                    acquire_return=invalid,
                )

                with mocks.stack:
                    with self.assertRaises(
                        claim.KernelWriteClaimCandidateError
                    ):
                        self.run_candidate(reference)

                mocks.close.assert_not_called()

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
                        claim.KernelWriteClaimCandidateError
                    ):
                        self.run_candidate(reference)

                mocks.close.assert_called_once_with(
                    self.FD
                )

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
                claim.KernelWriteClaimCandidateError,
                "must not be reused",
            ):
                self.run_candidate(reference)

        mocks.close.assert_called_once_with(self.FD)

    def test_candidate_close_error_is_not_retried(self):
        reference = self.held()
        mocks = self.environment(
            reference=reference,
            close_side_effect=OSError(
                "synthetic close failure"
            ),
        )

        with mocks.stack:
            candidate = self.run_candidate(reference)

            with self.assertRaises(
                claim.KernelWriteClaimCandidateError
            ):
                candidate.close()

            self.assertTrue(candidate.closed)
            self.assertFalse(candidate.live)

            candidate.close()

        mocks.close.assert_called_once_with(self.FD)

    def test_candidate_cannot_be_copied_or_serialized(self):
        reference = self.held()
        mocks = self.environment(reference=reference)

        with mocks.stack:
            candidate = self.run_candidate(reference)

            for operation in (
                lambda: copy.copy(candidate),
                lambda: copy.deepcopy(candidate),
                lambda: pickle.dumps(candidate),
            ):
                with self.subTest(operation=operation):
                    with self.assertRaises(
                        claim.KernelWriteClaimCandidateError
                    ):
                        operation()

            candidate.close()

        mocks.close.assert_called_once_with(self.FD)

    def test_wrong_reference_type_fails_before_continuity_or_acquisition(self):
        reference = SimpleNamespace(
            closed=False,
            handoff_id="xhnd_" + ("a" * 64),
            target_path="/dev/syn-a",
            target_major_minor="8:0",
            target_binding_hash="sha256:" + ("b" * 64),
        )
        mocks = self.environment(
            reference=reference,
        )

        with mocks.stack:
            with self.assertRaises(
                claim.KernelWriteClaimCandidateError
            ):
                self.run_candidate(reference)

        mocks.revalidate.assert_not_called()
        mocks.acquire.assert_not_called()
        mocks.close.assert_not_called()

    def test_production_source_has_no_real_open_or_executor_surface(self):
        source_path = Path(claim.__file__)
        text = source_path.read_text(
            encoding="utf-8"
        )
        tree = ast.parse(text)

        real_open_calls = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "os"
                and func.attr == "open"
            ):
                real_open_calls.append(node)

        self.assertEqual(real_open_calls, [])
        self.assertNotIn("subprocess", text)
        self.assertNotIn("Popen", text)
        self.assertNotIn("ioctl", text)
        self.assertNotIn("O_WRONLY", text)

        self.assertEqual(
            claim.__all__,
            [
                "KERNEL_WRITE_CLAIM_CANDIDATE_POLICY_VERSION",
                "HeldKernelWriteClaimCandidate",
                "KernelWriteClaimCandidateError",
                "acquire_mocked_kernel_write_claim_candidate",
            ],
        )
