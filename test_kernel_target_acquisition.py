from contextlib import contextmanager
import os
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import kernel_target_acquisition as acq


class _Decision:
    def __init__(
        self,
        *,
        target_path="/dev/syn-a",
        target_major_minor="8:0",
        handoff_id="xhnd_" + ("a" * 64),
        binding_hash="sha256:" + ("b" * 64),
    ):
        self.status = acq.auth.FRESH_TARGET_REVALIDATION_STATUS_SATISFIED
        self.execution_supported = False
        self.executor_eligible = False
        self.requires_separate_executor_authorization = True
        self.target_read_only = False
        self.target_mounted = False
        self.target_protected = False
        self.target_system_protected = False
        self.target_review_required = False
        self.target_ambiguous = False
        self.handoff_id = handoff_id
        self.target_path = target_path
        self.target_major_minor = target_major_minor
        self.fresh_target_binding_hash = binding_hash


class KernelTargetAcquisitionTests(unittest.TestCase):
    FD = 41

    def decision(self, **changes):
        return _Decision(**changes)

    def block_info(self, *, major=8, minor=0, block=True):
        mode = (stat.S_IFBLK if block else stat.S_IFREG) | 0o600
        return SimpleNamespace(
            st_mode=mode,
            st_rdev=os.makedev(major, minor),
        )

    def acquire(self):
        return acq.acquire_held_kernel_target_reference(
            registry=object(),
            approval_id="approval",
            request=object(),
            record=object(),
            journal=object(),
            gate=object(),
        )

    @contextmanager
    def environment(
        self,
        *,
        decisions=None,
        integrity=True,
        open_error=None,
        info=None,
        fstat_error=None,
        flags=None,
        flags_error=None,
        inheritable=False,
        inheritable_error=None,
        close_error=None,
        adopt_error=None,
    ):
        if decisions is None:
            decisions = (self.decision(), self.decision())
        if info is None:
            info = self.block_info()
        if flags is None:
            flags = os.O_RDONLY

        with (
            patch.object(
                acq.auth,
                "FreshPhysicalTargetRevalidationDecision",
                _Decision,
            ),
            patch.object(
                acq.auth,
                "_fresh_physical_target_revalidation_integrity_valid",
                return_value=integrity,
            ),
            patch.object(
                acq.auth,
                "revalidate_physical_target_for_execution_handoff",
                side_effect=list(decisions),
            ) as revalidate,
            patch(
                "kernel_target_acquisition.os.open",
                return_value=self.FD,
                side_effect=open_error,
            ) as open_mock,
            patch(
                "kernel_target_acquisition.os.fstat",
                return_value=info,
                side_effect=fstat_error,
            ) as fstat_mock,
            patch(
                "kernel_target_acquisition.fcntl.fcntl",
                return_value=flags,
                side_effect=flags_error,
            ) as flags_mock,
            patch(
                "kernel_target_acquisition.os.get_inheritable",
                return_value=inheritable,
                side_effect=inheritable_error,
            ) as inheritable_mock,
            patch(
                "kernel_target_acquisition.os.close",
                side_effect=close_error,
            ) as close_mock,
            patch(
                "kernel_target_acquisition.held_ref."
                "adopt_held_kernel_target_reference",
                return_value=object(),
                side_effect=adopt_error,
            ) as adopt,
        ):
            yield SimpleNamespace(
                revalidate=revalidate,
                open=open_mock,
                fstat=fstat_mock,
                flags=flags_mock,
                inheritable=inheritable_mock,
                close=close_mock,
                adopt=adopt,
            )

    def test_exact_acquisition_flags(self):
        if not (
            hasattr(os, "O_NOFOLLOW")
            and hasattr(os, "O_CLOEXEC")
        ):
            self.skipTest("required Linux flags unavailable")
        self.assertEqual(
            acq._required_open_flags(),
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )

    def test_required_open_flags_fail_closed_when_platform_flag_is_missing(self):
        original_os = acq.os
        cases = (
            SimpleNamespace(
                O_RDONLY=original_os.O_RDONLY,
                O_CLOEXEC=original_os.O_CLOEXEC,
            ),
            SimpleNamespace(
                O_RDONLY=original_os.O_RDONLY,
                O_NOFOLLOW=original_os.O_NOFOLLOW,
            ),
        )
        for fake_os in cases:
            with self.subTest(attributes=vars(fake_os)):
                with patch.object(acq, "os", fake_os):
                    with self.assertRaises(
                        acq.KernelTargetAcquisitionError
                    ):
                        acq._required_open_flags()

    def test_success_uses_trusted_path_and_transfers_once(self):
        before = self.decision()
        after = self.decision()
        with self.environment(
            decisions=(before, after)
        ) as mocks:
            self.acquire()

        mocks.open.assert_called_once_with(
            before.target_path,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        self.assertEqual(mocks.revalidate.call_count, 2)
        mocks.adopt.assert_called_once_with(self.FD, after)
        mocks.close.assert_not_called()

    def test_invalid_first_revalidation_never_opens(self):
        with self.environment(integrity=False) as mocks:
            with self.assertRaises(
                acq.KernelTargetAcquisitionError
            ):
                self.acquire()

        self.assertEqual(mocks.revalidate.call_count, 1)
        mocks.open.assert_not_called()
        mocks.close.assert_not_called()
        mocks.adopt.assert_not_called()

    def test_open_failure_never_claims_ownership(self):
        with self.environment(
            open_error=OSError("synthetic open failure")
        ) as mocks:
            with self.assertRaises(
                acq.KernelTargetAcquisitionError
            ):
                self.acquire()

        self.assertEqual(mocks.revalidate.call_count, 1)
        mocks.close.assert_not_called()
        mocks.adopt.assert_not_called()

    def test_fstat_failure_fails_closed_before_second_revalidation(self):
        with self.environment(
            fstat_error=OSError("synthetic fstat failure")
        ) as mocks:
            with self.assertRaises(
                acq.KernelTargetAcquisitionError
            ):
                self.acquire()

        mocks.fstat.assert_called_once_with(self.FD)
        self.assertEqual(mocks.revalidate.call_count, 1)
        mocks.close.assert_called_once_with(self.FD)
        mocks.adopt.assert_not_called()

    def test_non_block_or_kernel_number_mismatch_fails_closed(self):
        cases = (
            self.block_info(block=False),
            self.block_info(major=8, minor=16),
        )
        for info in cases:
            with self.subTest(info=info):
                with self.environment(info=info) as mocks:
                    with self.assertRaises(
                        acq.KernelTargetAcquisitionError
                    ):
                        self.acquire()

                self.assertEqual(mocks.revalidate.call_count, 1)
                mocks.close.assert_called_once_with(self.FD)
                mocks.adopt.assert_not_called()

    def test_descriptor_flag_inspection_failures_fail_closed(self):
        cases = (
            {
                "flags_error": OSError(
                    "synthetic F_GETFL failure"
                ),
            },
            {
                "flags": "not-an-int",
            },
        )

        if hasattr(os, "O_PATH"):
            cases += (
                {
                    "flags": os.O_RDONLY | os.O_PATH,
                },
            )

        for settings in cases:
            with self.subTest(settings=settings):
                with self.environment(**settings) as mocks:
                    with self.assertRaises(
                        acq.KernelTargetAcquisitionError
                    ):
                        self.acquire()

                self.assertEqual(mocks.revalidate.call_count, 1)
                mocks.close.assert_called_once_with(self.FD)
                mocks.adopt.assert_not_called()

    def test_write_capable_or_inheritable_fd_fails_closed(self):
        cases = (
            (os.O_WRONLY, False),
            (os.O_RDWR, False),
            (os.O_RDONLY, True),
        )
        for flags, inheritable in cases:
            with self.subTest(
                flags=flags,
                inheritable=inheritable,
            ):
                with self.environment(
                    flags=flags,
                    inheritable=inheritable,
                ) as mocks:
                    with self.assertRaises(
                        acq.KernelTargetAcquisitionError
                    ):
                        self.acquire()

                self.assertEqual(mocks.revalidate.call_count, 1)
                mocks.close.assert_called_once_with(self.FD)
                mocks.adopt.assert_not_called()

    def test_inheritance_inspection_failure_fails_closed(self):
        with self.environment(
            inheritable_error=OSError(
                "synthetic inheritance query failure"
            )
        ) as mocks:
            with self.assertRaises(
                acq.KernelTargetAcquisitionError
            ):
                self.acquire()

        mocks.inheritable.assert_called_once_with(self.FD)
        self.assertEqual(mocks.revalidate.call_count, 1)
        mocks.close.assert_called_once_with(self.FD)
        mocks.adopt.assert_not_called()

    def test_second_revalidation_identity_change_fails_closed(self):
        changed = (
            self.decision(
                handoff_id="xhnd_" + ("c" * 64)
            ),
            self.decision(target_path="/dev/syn-b"),
            self.decision(target_major_minor="8:16"),
            self.decision(
                binding_hash="sha256:" + ("d" * 64)
            ),
        )
        for after in changed:
            with self.subTest(after=after.__dict__):
                with self.environment(
                    decisions=(self.decision(), after)
                ) as mocks:
                    with self.assertRaises(
                        acq.KernelTargetAcquisitionError
                    ):
                        self.acquire()

                self.assertEqual(mocks.revalidate.call_count, 2)
                mocks.close.assert_called_once_with(self.FD)
                mocks.adopt.assert_not_called()

    def test_second_revalidation_exception_fails_closed(self):
        with self.environment(
            decisions=(
                self.decision(),
                RuntimeError(
                    "synthetic post-open revalidation failure"
                ),
            )
        ) as mocks:
            with self.assertRaises(
                acq.KernelTargetAcquisitionError
            ):
                self.acquire()

        self.assertEqual(mocks.revalidate.call_count, 2)
        mocks.close.assert_called_once_with(self.FD)
        mocks.adopt.assert_not_called()

    def test_acquisition_close_failure_is_not_retried(self):
        with self.environment(
            info=self.block_info(block=False),
            close_error=OSError("synthetic close failure"),
        ) as mocks:
            with self.assertRaises(
                acq.KernelTargetAcquisitionError
            ):
                self.acquire()

        self.assertEqual(mocks.revalidate.call_count, 1)
        mocks.close.assert_called_once_with(self.FD)
        mocks.adopt.assert_not_called()

    def test_b3a_owns_fd_once_adoption_begins(self):
        error = acq.held_ref.HeldKernelTargetReferenceError(
            "synthetic adoption failure"
        )
        with self.environment(adopt_error=error) as mocks:
            with self.assertRaises(
                acq.KernelTargetAcquisitionError
            ):
                self.acquire()

        mocks.adopt.assert_called_once()
        mocks.close.assert_not_called()


if __name__ == "__main__":
    unittest.main()
