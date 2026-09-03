import json
import os
import stat
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import synthetic_block_device_harness as synth


_REAL_LSTAT = os.lstat
_REAL_FSYNC = os.fsync


def block_mode():
    return stat.S_IFBLK | 0o600


class DurableSyntheticBlockEvidenceTests(unittest.TestCase):
    OFFSET = 1024 * 1024
    LENGTH = 65536
    PATTERN = 0x3C

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        self.root = Path(self.tmp.name)
        os.chmod(self.root, 0o700)

        self.image = self.root / "synthetic.bin"

        with self.image.open("wb") as fh:
            fh.truncate(2 * 1024 * 1024)

        os.chmod(self.image, 0o600)

        self.evidence_root = (
            self.root / ".dsm-synthetic-block-evidence"
        )
        self.evidence_root.mkdir(mode=0o700)

    def snapshot(self):
        with patch.object(
            synth,
            "_active_loop_devices",
            return_value=frozenset(),
        ):
            return synth.snapshot_active_loop_devices()

    def acquire(
        self,
        *,
        loop_path="/dev/loop77",
        major_minor="7:77",
    ):
        minor = int(major_minor.split(":")[1])

        path_stat = SimpleNamespace(
            st_mode=block_mode(),
            st_rdev=os.makedev(7, minor),
        )

        fd_stat = SimpleNamespace(
            st_mode=block_mode(),
            st_rdev=os.makedev(7, minor),
        )

        def guarded_lstat(path):
            if path == loop_path:
                return path_stat
            return _REAL_LSTAT(path)

        with ExitStack() as stack:
            stack.enter_context(
                patch.object(
                    synth.os,
                    "lstat",
                    side_effect=guarded_lstat,
                )
            )
            stack.enter_context(
                patch.object(
                    synth.os,
                    "open",
                    return_value=91,
                )
            )
            stack.enter_context(
                patch.object(
                    synth.os,
                    "fstat",
                    return_value=fd_stat,
                )
            )
            stack.enter_context(
                patch.object(synth.os, "set_inheritable")
            )
            stack.enter_context(
                patch.object(
                    synth.os,
                    "get_inheritable",
                    return_value=False,
                )
            )
            stack.enter_context(
                patch.object(synth.os, "close")
            )
            stack.enter_context(
                patch.object(
                    synth,
                    "_device_has_children",
                    return_value=False,
                )
            )
            stack.enter_context(
                patch.object(
                    synth,
                    "_device_is_mounted",
                    return_value=False,
                )
            )
            stack.enter_context(
                patch.object(
                    synth,
                    "_real_backing_path",
                    return_value=os.path.realpath(self.image),
                )
            )

            return synth.acquire_disposable_loop_block_medium(
                self.snapshot(),
                loop_path=loop_path,
                backing_image=str(self.image),
                expected_major_minor=major_minor,
            )

    def evidence_paths(self, medium):
        return synth._durable_evidence_paths(
            self.evidence_root,
            medium,
        )

    def run_success(self, medium, *, pwrite_effect=None):
        before = b"\xA5" * medium.size_bytes
        after = bytearray(before)
        after[
            self.OFFSET:self.OFFSET + self.LENGTH
        ] = bytes((self.PATTERN,)) * self.LENGTH
        after = bytes(after)

        reads = iter((before, after))

        def fake_pread(fd, size, offset):
            self.assertEqual(fd, medium._fd)
            self.assertEqual(size, medium.size_bytes)
            self.assertEqual(offset, 0)
            return next(reads)

        def fake_pwrite(fd, data, offset):
            if pwrite_effect is not None:
                return pwrite_effect(fd, data, offset)
            self.assertEqual(fd, medium._fd)
            self.assertEqual(offset, self.OFFSET)
            return len(data)

        def guarded_fsync(fd):
            if fd == medium._fd:
                return None
            return _REAL_FSYNC(fd)

        with patch.object(
            synth,
            "_revalidate_medium",
        ), patch.object(
            synth.os,
            "pread",
            side_effect=fake_pread,
        ), patch.object(
            synth.os,
            "pwrite",
            side_effect=fake_pwrite,
        ), patch.object(
            synth.os,
            "fsync",
            side_effect=guarded_fsync,
        ):
            return synth.execute_bounded_synthetic_pattern_pass(
                medium,
                evidence_root=self.evidence_root,
                offset=self.OFFSET,
                length=self.LENGTH,
                pattern_byte=self.PATTERN,
            )

    def test_only_public_destructive_entry_is_durable(self):
        public_execute = sorted(
            name
            for name, value in vars(synth).items()
            if name.startswith("execute_")
            and callable(value)
        )

        self.assertEqual(
            public_execute,
            ["execute_bounded_synthetic_pattern_pass"],
        )

        self.assertTrue(
            hasattr(
                synth,
                "_execute_bounded_synthetic_pattern_pass_once",
            )
        )

        self.assertFalse(
            hasattr(
                synth,
                "execute_bounded_synthetic_pattern_pass_durable",
            )
        )

    def test_changed_geometry_cannot_bypass_ambiguous_attempt(self):
        first = self.acquire(
            loop_path="/dev/loop77",
            major_minor="7:77",
        )

        with patch.object(
            synth,
            "_revalidate_medium",
        ), patch.object(
            synth,
            "_execute_bounded_synthetic_pattern_pass_once",
            side_effect=RuntimeError("ambiguous-attempt"),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "ambiguous-attempt",
            ):
                synth.execute_bounded_synthetic_pattern_pass(
                    first,
                    evidence_root=self.evidence_root,
                    offset=self.OFFSET,
                    length=self.LENGTH,
                    pattern_byte=self.PATTERN,
                )

        second = self.acquire(
            loop_path="/dev/loop88",
            major_minor="7:88",
        )

        with patch.object(
            synth,
            "_revalidate_medium",
        ), patch.object(
            synth,
            "_execute_bounded_synthetic_pattern_pass_once",
        ) as executor:
            with self.assertRaisesRegex(
                synth.SyntheticBlockDeviceError,
                "replay refused",
            ):
                synth.execute_bounded_synthetic_pattern_pass(
                    second,
                    evidence_root=self.evidence_root,
                    offset=self.OFFSET + 512,
                    length=self.LENGTH - 512,
                    pattern_byte=0x7E,
                )

        executor.assert_not_called()

    def test_alternate_evidence_root_is_refused(self):
        medium = self.acquire()

        alternate = self.root / "alternate-evidence"
        alternate.mkdir(mode=0o700)

        with patch.object(
            synth,
            "_revalidate_medium",
        ), patch.object(
            synth,
            "_execute_bounded_synthetic_pattern_pass_once",
        ) as executor:
            with self.assertRaisesRegex(
                synth.SyntheticBlockDeviceError,
                "backing-image-bound root",
            ):
                synth.execute_bounded_synthetic_pattern_pass(
                    medium,
                    evidence_root=alternate,
                    offset=self.OFFSET,
                    length=self.LENGTH,
                    pattern_byte=self.PATTERN,
                )

        executor.assert_not_called()

    def test_preexisting_result_refuses_before_destructive_primitive(self):
        medium = self.acquire()
        _, result_path = self.evidence_paths(medium)

        result_path.write_bytes(b"sentinel")
        os.chmod(result_path, 0o600)

        with patch.object(
            synth,
            "_revalidate_medium",
        ), patch.object(
            synth,
            "_execute_bounded_synthetic_pattern_pass_once",
        ) as executor:
            with self.assertRaisesRegex(
                synth.SyntheticBlockDeviceError,
                "result exists",
            ):
                synth.execute_bounded_synthetic_pattern_pass(
                    medium,
                    evidence_root=self.evidence_root,
                    offset=self.OFFSET,
                    length=self.LENGTH,
                    pattern_byte=self.PATTERN,
                )

        executor.assert_not_called()
        self.assertFalse(medium.consumed)
        self.assertEqual(
            result_path.read_bytes(),
            b"sentinel",
        )

    def test_public_gate_uses_medium_lock(self):
        medium = self.acquire()

        class ProbeLock:
            def __init__(self):
                self.entered = 0
                self.exited = 0

            def __enter__(self):
                self.entered += 1
                return self

            def __exit__(self, exc_type, exc, tb):
                self.exited += 1

        probe = ProbeLock()
        object.__setattr__(medium, "_lock", probe)

        with patch.object(
            synth,
            "_validate_durable_execution_request",
            side_effect=RuntimeError("stop-after-lock"),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "stop-after-lock",
            ):
                synth.execute_bounded_synthetic_pattern_pass(
                    medium,
                    evidence_root=self.evidence_root,
                    offset=self.OFFSET,
                    length=self.LENGTH,
                    pattern_byte=self.PATTERN,
                )

        self.assertEqual(probe.entered, 1)
        self.assertEqual(probe.exited, 1)

    def test_evidence_key_survives_loop_number_reuse(self):
        first = self.acquire(
            loop_path="/dev/loop77",
            major_minor="7:77",
        )
        second = self.acquire(
            loop_path="/dev/loop88",
            major_minor="7:88",
        )

        self.assertEqual(
            self.evidence_paths(first),
            self.evidence_paths(second),
        )

    def test_evidence_root_must_be_private(self):
        medium = self.acquire()
        os.chmod(self.evidence_root, 0o755)

        with patch.object(
            synth,
            "_revalidate_medium",
        ), patch.object(
            synth,
            "_execute_bounded_synthetic_pattern_pass_once",
        ) as executor:
            with self.assertRaises(
                synth.SyntheticBlockDeviceError
            ):
                synth.execute_bounded_synthetic_pattern_pass(
                    medium,
                    evidence_root=self.evidence_root,
                    offset=self.OFFSET,
                    length=self.LENGTH,
                    pattern_byte=self.PATTERN,
                )

        executor.assert_not_called()

    def test_invalid_geometry_creates_no_evidence(self):
        medium = self.acquire()

        with patch.object(
            synth,
            "_revalidate_medium",
        ), patch.object(
            synth,
            "_execute_bounded_synthetic_pattern_pass_once",
        ) as executor:
            with self.assertRaises(
                synth.SyntheticBlockDeviceError
            ):
                synth.execute_bounded_synthetic_pattern_pass(
                    medium,
                    evidence_root=self.evidence_root,
                    offset=medium.size_bytes,
                    length=1,
                    pattern_byte=self.PATTERN,
                )

        executor.assert_not_called()

        self.assertEqual(
            [
                p
                for p in self.evidence_root.iterdir()
                if p.suffix == ".json"
            ],
            [],
        )

    def test_attempt_is_durable_before_destructive_write(self):
        medium = self.acquire()
        attempt_path, result_path = self.evidence_paths(medium)

        def inspect_then_write(fd, data, offset):
            self.assertTrue(attempt_path.exists())
            self.assertFalse(result_path.exists())

            attempt = synth._read_durable_private_record(
                attempt_path
            )
            self.assertEqual(
                attempt["state"],
                synth.DURABLE_BLOCK_ATTEMPTING,
            )
            self.assertFalse(
                attempt["automatic_replay_allowed"]
            )
            return len(data)

        self.run_success(
            medium,
            pwrite_effect=inspect_then_write,
        )

    def test_success_persists_conservative_attempt_and_result(self):
        medium = self.acquire()
        result = self.run_success(medium)

        attempt_path, result_path = self.evidence_paths(medium)

        self.assertTrue(attempt_path.exists())
        self.assertTrue(result_path.exists())

        self.assertEqual(
            stat.S_IMODE(os.lstat(attempt_path).st_mode),
            0o600,
        )
        self.assertEqual(
            stat.S_IMODE(os.lstat(result_path).st_mode),
            0o600,
        )

        attempt = synth._read_durable_private_record(
            attempt_path
        )
        durable_result = synth._read_durable_private_record(
            result_path
        )

        self.assertEqual(
            attempt["state"],
            synth.DURABLE_BLOCK_ATTEMPTING,
        )
        self.assertEqual(
            durable_result["state"],
            synth.DURABLE_BLOCK_RESULT_RECORDED,
        )
        self.assertEqual(
            durable_result["attempt_state"],
            synth.DURABLE_BLOCK_ATTEMPTING,
        )

        for document in (attempt, durable_result):
            self.assertFalse(
                document["automatic_replay_allowed"]
            )
            self.assertFalse(
                document["production_execution"]
            )
            self.assertFalse(
                document["physical_drive_accessed"]
            )
            self.assertFalse(
                document["sanitization_verified"]
            )
            self.assertTrue(
                document["block_special_device_accessed"]
            )
            self.assertTrue(
                document[
                    "synthetic_loop_block_device_accessed"
                ]
            )

        self.assertTrue(
            durable_result["synthetic_pattern_verified"]
        )
        self.assertTrue(
            durable_result["outside_region_verified"]
        )
        self.assertEqual(
            durable_result["bytes_overwritten"],
            self.LENGTH,
        )
        self.assertEqual(
            durable_result["before_sha256"],
            result.before_sha256,
        )
        self.assertEqual(
            durable_result["after_sha256"],
            result.after_sha256,
        )

    def test_attempt_crash_refuses_replay_after_reacquisition(self):
        first = self.acquire(
            loop_path="/dev/loop77",
            major_minor="7:77",
        )

        with patch.object(
            synth,
            "_revalidate_medium",
        ), patch.object(
            synth,
            "_execute_bounded_synthetic_pattern_pass_once",
            side_effect=RuntimeError("after-attempt-crash"),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "after-attempt-crash",
            ):
                synth.execute_bounded_synthetic_pattern_pass(
                    first,
                    evidence_root=self.evidence_root,
                    offset=self.OFFSET,
                    length=self.LENGTH,
                    pattern_byte=self.PATTERN,
                )

        attempt_path, result_path = self.evidence_paths(first)
        self.assertTrue(attempt_path.exists())
        self.assertFalse(result_path.exists())

        second = self.acquire(
            loop_path="/dev/loop88",
            major_minor="7:88",
        )

        with patch.object(
            synth,
            "_revalidate_medium",
        ), patch.object(
            synth,
            "_execute_bounded_synthetic_pattern_pass_once",
        ) as executor:
            with self.assertRaisesRegex(
                synth.SyntheticBlockDeviceError,
                "replay refused",
            ):
                synth.execute_bounded_synthetic_pattern_pass(
                    second,
                    evidence_root=self.evidence_root,
                    offset=self.OFFSET,
                    length=self.LENGTH,
                    pattern_byte=self.PATTERN,
                )

        executor.assert_not_called()

    def test_mid_write_failure_leaves_attempt_and_refuses_replay(self):
        first = self.acquire()

        def fail_write(fd, data, offset):
            raise RuntimeError("synthetic-mid-write-failure")

        with self.assertRaisesRegex(
            RuntimeError,
            "synthetic-mid-write-failure",
        ):
            self.run_success(
                first,
                pwrite_effect=fail_write,
            )

        attempt_path, result_path = self.evidence_paths(first)
        self.assertTrue(attempt_path.exists())
        self.assertFalse(result_path.exists())
        self.assertTrue(first.consumed)

        second = self.acquire(
            loop_path="/dev/loop88",
            major_minor="7:88",
        )

        with patch.object(
            synth,
            "_revalidate_medium",
        ), patch.object(
            synth,
            "_execute_bounded_synthetic_pattern_pass_once",
        ) as executor:
            with self.assertRaisesRegex(
                synth.SyntheticBlockDeviceError,
                "replay refused",
            ):
                synth.execute_bounded_synthetic_pattern_pass(
                    second,
                    evidence_root=self.evidence_root,
                    offset=self.OFFSET,
                    length=self.LENGTH,
                    pattern_byte=self.PATTERN,
                )

        executor.assert_not_called()

    def test_result_persistence_failure_remains_nonreplayable(self):
        first = self.acquire()

        with patch.object(
            synth,
            "_persist_durable_block_result",
            side_effect=RuntimeError("result-persist-failure"),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "result-persist-failure",
            ):
                self.run_success(first)

        attempt_path, result_path = self.evidence_paths(first)
        self.assertTrue(attempt_path.exists())
        self.assertFalse(result_path.exists())
        self.assertTrue(first.consumed)

        second = self.acquire(
            loop_path="/dev/loop88",
            major_minor="7:88",
        )

        with patch.object(
            synth,
            "_revalidate_medium",
        ), patch.object(
            synth,
            "_execute_bounded_synthetic_pattern_pass_once",
        ) as executor:
            with self.assertRaisesRegex(
                synth.SyntheticBlockDeviceError,
                "replay refused",
            ):
                synth.execute_bounded_synthetic_pattern_pass(
                    second,
                    evidence_root=self.evidence_root,
                    offset=self.OFFSET,
                    length=self.LENGTH,
                    pattern_byte=self.PATTERN,
                )

        executor.assert_not_called()

    def test_preexisting_result_evidence_is_never_overwritten(self):
        medium = self.acquire()
        attempt_path, result_path = self.evidence_paths(medium)

        result_path.write_bytes(b"sentinel")
        os.chmod(result_path, 0o600)

        with self.assertRaisesRegex(
            synth.SyntheticBlockDeviceError,
            "result exists",
        ):
            self.run_success(medium)

        self.assertFalse(attempt_path.exists())
        self.assertEqual(
            result_path.read_bytes(),
            b"sentinel",
        )
        self.assertFalse(medium.consumed)

    def test_tampered_attempt_blocks_result_persistence(self):
        medium = self.acquire()
        attempt_path, result_path = self.evidence_paths(medium)

        def tamper_then_return(
            value,
            *,
            offset,
            length,
            pattern_byte,
        ):
            document = json.loads(
                attempt_path.read_text(encoding="utf-8")
            )
            document["physical_drive_accessed"] = True
            attempt_path.write_text(
                json.dumps(document) + "\n",
                encoding="utf-8",
            )
            os.chmod(attempt_path, 0o600)

            return synth.SyntheticBlockResult(
                synth._TOKEN,
                loop_major_minor=value.major_minor,
                write_offset=offset,
                write_length=length,
                before_sha256="0" * 64,
                after_sha256="1" * 64,
            )

        with patch.object(
            synth,
            "_revalidate_medium",
        ), patch.object(
            synth,
            "_execute_bounded_synthetic_pattern_pass_once",
            side_effect=tamper_then_return,
        ):
            with self.assertRaisesRegex(
                synth.SyntheticBlockDeviceError,
                "integrity failed",
            ):
                synth.execute_bounded_synthetic_pattern_pass(
                    medium,
                    evidence_root=self.evidence_root,
                    offset=self.OFFSET,
                    length=self.LENGTH,
                    pattern_byte=self.PATTERN,
                )

        self.assertFalse(result_path.exists())

    def test_tampered_result_record_is_not_trusted(self):
        medium = self.acquire()
        self.run_success(medium)

        _, result_path = self.evidence_paths(medium)

        document = json.loads(
            result_path.read_text(encoding="utf-8")
        )
        document["sanitization_verified"] = True
        result_path.write_text(
            json.dumps(document) + "\n",
            encoding="utf-8",
        )
        os.chmod(result_path, 0o600)

        with self.assertRaisesRegex(
            synth.SyntheticBlockDeviceError,
            "integrity failed",
        ):
            synth._read_durable_private_record(
                result_path
            )

    def test_post_result_crash_remains_nonreplayable_after_reacquisition(
        self,
    ):
        from unittest import mock as local_mock

        first = self.acquire()
        attempt_path, result_path = self.evidence_paths(first)

        original = synth._persist_durable_block_result

        def persist_then_crash(*args, **kwargs):
            original(*args, **kwargs)
            raise RuntimeError("simulated post-result crash")

        with local_mock.patch.object(
            synth,
            "_persist_durable_block_result",
            side_effect=persist_then_crash,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "simulated post-result crash",
            ):
                self.run_success(first)

        self.assertTrue(attempt_path.exists())
        self.assertTrue(result_path.exists())
        self.assertTrue(first.consumed)

        second = self.acquire()

        with local_mock.patch.object(
            synth,
            "_revalidate_medium",
        ), local_mock.patch.object(
            synth,
            "_execute_bounded_synthetic_pattern_pass_once",
        ) as executor:
            with self.assertRaisesRegex(
                synth.SyntheticBlockDeviceError,
                "result exists",
            ):
                synth.execute_bounded_synthetic_pattern_pass(
                    second,
                    evidence_root=self.evidence_root,
                    offset=self.OFFSET,
                    length=self.LENGTH,
                    pattern_byte=self.PATTERN,
                )

        executor.assert_not_called()

    def test_evidence_root_symlink_replacement_is_refused(self):
        medium = self.acquire()

        symlink_target = (
            self.evidence_root.parent
            / ".dsm-synthetic-block-evidence-symlink-target"
        )

        self.evidence_root.rmdir()
        symlink_target.mkdir(mode=0o700)

        os.symlink(
            symlink_target,
            self.evidence_root,
            target_is_directory=True,
        )

        with self.assertRaises(
            synth.SyntheticBlockDeviceError,
        ):
            self.run_success(medium)

        self.assertFalse(medium.consumed)

    def test_concurrent_same_medium_calls_reach_destructive_primitive_once(
        self,
    ):
        import threading
        from unittest import mock as local_mock

        medium = self.acquire()

        entered_executor = threading.Event()
        release_executor = threading.Event()
        second_started = threading.Event()

        outcomes = []
        outcomes_lock = threading.Lock()

        def blocked_executor(*args, **kwargs):
            entered_executor.set()

            if not release_executor.wait(timeout=5):
                raise AssertionError(
                    "timed out waiting to release destructive primitive"
                )

            raise RuntimeError(
                "simulated first destructive execution failure"
            )

        def invoke(label, started=None):
            if started is not None:
                started.set()

            try:
                synth.execute_bounded_synthetic_pattern_pass(
                    medium,
                    evidence_root=self.evidence_root,
                    offset=self.OFFSET,
                    length=self.LENGTH,
                    pattern_byte=self.PATTERN,
                )
            except BaseException as error:
                with outcomes_lock:
                    outcomes.append(
                        (label, "error", error)
                    )
            else:
                with outcomes_lock:
                    outcomes.append(
                        (label, "returned", None)
                    )

        with local_mock.patch.object(
            synth,
            "_revalidate_medium",
        ), local_mock.patch.object(
            synth,
            "_execute_bounded_synthetic_pattern_pass_once",
            side_effect=blocked_executor,
        ) as executor:
            first_thread = threading.Thread(
                target=invoke,
                args=("first",),
                daemon=True,
            )

            second_thread = threading.Thread(
                target=invoke,
                args=("second", second_started),
                daemon=True,
            )

            first_thread.start()

            self.assertTrue(
                entered_executor.wait(timeout=5),
                "first call did not reach destructive primitive",
            )

            second_thread.start()

            self.assertTrue(
                second_started.wait(timeout=5),
                "second call did not start",
            )

            second_thread.join(timeout=0.1)

            self.assertTrue(
                second_thread.is_alive(),
                "second call was not serialized behind medium lock",
            )

            release_executor.set()

            first_thread.join(timeout=5)
            second_thread.join(timeout=5)

        self.assertFalse(first_thread.is_alive())
        self.assertFalse(second_thread.is_alive())

        self.assertEqual(
            executor.call_count,
            1,
        )

        self.assertEqual(
            len(outcomes),
            2,
        )

        by_label = {
            label: (state, error)
            for label, state, error in outcomes
        }

        self.assertEqual(
            by_label["first"][0],
            "error",
        )
        self.assertIsInstance(
            by_label["first"][1],
            RuntimeError,
        )

        self.assertEqual(
            by_label["second"][0],
            "error",
        )
        self.assertIsInstance(
            by_label["second"][1],
            synth.SyntheticBlockDeviceError,
        )

    def test_hard_linked_backing_image_is_refused_on_reacquisition(
        self,
    ):
        medium = self.acquire()

        alias = medium._backing_path + ".hardlink-alias"

        os.link(
            medium._backing_path,
            alias,
        )

        try:
            self.assertEqual(
                os.lstat(medium._backing_path).st_nlink,
                2,
            )

            with self.assertRaisesRegex(
                synth.SyntheticBlockDeviceError,
                "exactly one hard link",
            ):
                self.acquire()
        finally:
            if os.path.lexists(alias):
                os.unlink(alias)

    def test_hard_link_created_after_acquisition_is_refused(
        self,
    ):
        medium = self.acquire()

        alias = medium._backing_path + ".hardlink-alias"

        os.link(
            medium._backing_path,
            alias,
        )

        try:
            self.assertEqual(
                os.lstat(medium._backing_path).st_nlink,
                2,
            )

            with self.assertRaisesRegex(
                synth.SyntheticBlockDeviceError,
                "exactly one hard link",
            ):
                synth._validate_private_backing_image(
                    medium._backing_path
                )
        finally:
            if os.path.lexists(alias):
                os.unlink(alias)

        self.assertEqual(
            os.lstat(medium._backing_path).st_nlink,
            1,
        )

    def test_recreated_backing_inode_gets_distinct_durable_identity(
        self,
    ):
        from types import SimpleNamespace

        medium = self.acquire()

        old_identity = synth._durable_evidence_id(
            medium
        )
        old_inode = medium._image_ino
        old_device = medium._image_dev
        old_path = medium._backing_path
        old_size = medium._size

        replacement = old_path + ".replacement"

        with open(replacement, "wb") as stream:
            stream.truncate(old_size)

        os.chmod(replacement, 0o600)

        replacement_stat = os.lstat(replacement)

        self.assertEqual(
            replacement_stat.st_nlink,
            1,
        )

        os.replace(
            replacement,
            old_path,
        )

        backing_path, recreated_stat = (
            synth._validate_private_backing_image(
                old_path
            )
        )

        self.assertEqual(
            backing_path,
            old_path,
        )
        self.assertEqual(
            recreated_stat.st_size,
            old_size,
        )
        self.assertEqual(
            recreated_stat.st_nlink,
            1,
        )

        self.assertNotEqual(
            (
                recreated_stat.st_dev,
                recreated_stat.st_ino,
            ),
            (
                old_device,
                old_inode,
            ),
        )

        # The already-acquired medium retains the exact old image
        # identity. Replacing the pathname does not rewrite history.
        self.assertEqual(
            medium._image_dev,
            old_device,
        )
        self.assertEqual(
            medium._image_ino,
            old_inode,
        )

        recreated_medium = SimpleNamespace(
            _backing_path=backing_path,
            _image_dev=recreated_stat.st_dev,
            _image_ino=recreated_stat.st_ino,
            _size=recreated_stat.st_size,
        )

        recreated_identity = synth._durable_evidence_id(
            recreated_medium
        )

        self.assertNotEqual(
            recreated_identity,
            old_identity,
        )


if __name__ == "__main__":
    unittest.main()
