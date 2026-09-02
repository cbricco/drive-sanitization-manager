from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import pickle
import stat
import tempfile
import unittest
from unittest.mock import patch

import synthetic_execution_harness as synth


class SyntheticExecutionHarnessTests(unittest.TestCase):
    def private_root(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        os.chmod(temp.name, 0o700)
        return Path(temp.name)

    def medium(self, size=4096):
        medium = synth.create_disposable_synthetic_medium(
            self.private_root(), size_bytes=size
        )
        self.addCleanup(medium.close)
        return medium

    def test_new_medium_is_private_regular_file_only(self):
        medium = self.medium(8192)
        info = os.lstat(medium._path)
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertEqual(info.st_size, 8192)
        self.assertTrue(medium.synthetic_only)
        self.assertFalse(medium.production_eligible)
        self.assertFalse(medium.real_block_device_supported)

    def test_existing_file_is_never_adopted(self):
        root = self.private_root()
        existing = root / "important.bin"
        existing.write_bytes(b"important")
        os.chmod(existing, 0o600)
        medium = synth.create_disposable_synthetic_medium(root, size_bytes=4096)
        self.addCleanup(medium.close)
        self.assertNotEqual(medium._path, existing)
        self.assertEqual(existing.read_bytes(), b"important")

    def test_nonprivate_and_symlink_roots_are_refused(self):
        root = self.private_root()
        os.chmod(root, 0o755)
        with self.assertRaises(synth.SyntheticExecutionError):
            synth.create_disposable_synthetic_medium(root)

        target = self.private_root()
        parent = self.private_root()
        link = parent / "link"
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaises(synth.SyntheticExecutionError):
            synth.create_disposable_synthetic_medium(link)

    def test_size_is_bounded(self):
        root = self.private_root()
        for value in (0, -1, synth.MAX_SIZE + 1):
            with self.subTest(value=value):
                with self.assertRaises(synth.SyntheticExecutionError):
                    synth.create_disposable_synthetic_medium(
                        root, size_bytes=value
                    )

    def test_successful_zero_pass_is_synthetic_only(self):
        medium = self.medium(16384)
        result = synth.execute_disposable_synthetic_zero_pass(medium)
        self.assertEqual(result.bytes_overwritten, 16384)
        self.assertTrue(result.write_returned)
        self.assertTrue(result.synthetic_pattern_verified)
        self.assertFalse(result.sanitization_verified)
        self.assertFalse(result.production_execution)
        self.assertFalse(result.real_block_device_accessed)
        self.assertFalse(result.automatic_replay_allowed)
        self.assertEqual(result.attempt_state, synth.ATTEMPTING)
        self.assertEqual(os.pread(medium._fd, 16384, 0), b"\x00" * 16384)

    def test_attempting_tombstone_precedes_execution_write(self):
        medium = self.medium()
        events = []
        real_persist = synth._persist_attempt_locked
        real_pwrite = os.pwrite

        def persist(m):
            result = real_persist(m)
            events.append("tombstone")
            return result

        def pwrite(fd, data, offset):
            events.append("pwrite")
            return real_pwrite(fd, data, offset)

        with patch.object(
            synth, "_persist_attempt_locked", side_effect=persist
        ), patch.object(synth.os, "pwrite", side_effect=pwrite):
            synth.execute_disposable_synthetic_zero_pass(medium)

        self.assertEqual(events[0], "tombstone")
        self.assertIn("pwrite", events[1:])

    def test_tombstone_is_conservative_and_persistent(self):
        medium = self.medium()
        synth.execute_disposable_synthetic_zero_pass(medium)
        doc = json.loads(medium._marker.read_text(encoding="utf-8"))
        self.assertEqual(doc["state"], synth.ATTEMPTING)
        self.assertFalse(doc["automatic_replay_allowed"])
        self.assertFalse(doc["production_execution"])
        self.assertFalse(doc["real_block_device_accessed"])
        payload = dict(doc)
        record_hash = payload.pop("record_hash")
        self.assertEqual(record_hash, synth._hash(payload))
        self.assertTrue(medium._marker.exists())

    def test_second_execution_is_refused(self):
        medium = self.medium()
        synth.execute_disposable_synthetic_zero_pass(medium)
        with self.assertRaises(synth.SyntheticExecutionError):
            synth.execute_disposable_synthetic_zero_pass(medium)

    def test_durable_marker_refuses_replay_if_memory_flag_is_tampered(self):
        medium = self.medium()
        synth.execute_disposable_synthetic_zero_pass(medium)
        medium._attempted = False
        with self.assertRaisesRegex(
            synth.SyntheticExecutionError, "replay refused"
        ):
            synth.execute_disposable_synthetic_zero_pass(medium)

    def test_write_failure_remains_ambiguous_and_nonreplayable(self):
        medium = self.medium(8192)
        with patch.object(
            synth.os, "pwrite", side_effect=OSError("synthetic write failure")
        ):
            with self.assertRaises(OSError):
                synth.execute_disposable_synthetic_zero_pass(medium)
        self.assertTrue(medium.attempted)
        self.assertTrue(medium._marker.exists())
        with self.assertRaises(synth.SyntheticExecutionError):
            synth.execute_disposable_synthetic_zero_pass(medium)

    def test_verification_failure_remains_nonreplayable(self):
        medium = self.medium()
        with patch.object(synth.os, "pread", return_value=b"\x01" * 4096):
            with self.assertRaises(synth.SyntheticExecutionError):
                synth.execute_disposable_synthetic_zero_pass(medium)
        self.assertTrue(medium.attempted)
        self.assertTrue(medium._marker.exists())
        with self.assertRaises(synth.SyntheticExecutionError):
            synth.execute_disposable_synthetic_zero_pass(medium)

    def test_block_device_shape_is_refused_before_attempt(self):
        medium = self.medium()
        real_info = os.fstat(medium._fd)

        class FakeInfo:
            st_mode = stat.S_IFBLK | 0o600
            st_uid = real_info.st_uid
            st_dev = real_info.st_dev
            st_ino = real_info.st_ino
            st_size = real_info.st_size

        with patch.object(
            synth.os, "fstat", return_value=FakeInfo()
        ), patch.object(synth.os, "pwrite") as pwrite:
            with self.assertRaises(synth.SyntheticExecutionError):
                synth.execute_disposable_synthetic_zero_pass(medium)
            pwrite.assert_not_called()
        self.assertFalse(medium._marker.exists())

    def test_execution_does_not_reopen_medium_path(self):
        medium = self.medium()
        real_open = os.open

        def guarded_open(path, *args, **kwargs):
            if Path(path) == medium._path:
                raise AssertionError("medium path reopened")
            return real_open(path, *args, **kwargs)

        with patch.object(synth.os, "open", side_effect=guarded_open):
            result = synth.execute_disposable_synthetic_zero_pass(medium)
        self.assertTrue(result.synthetic_pattern_verified)

    def test_closed_or_wrong_medium_is_refused(self):
        with self.assertRaises(synth.SyntheticExecutionError):
            synth.execute_disposable_synthetic_zero_pass(object())
        medium = self.medium()
        medium.close()
        with self.assertRaises(synth.SyntheticExecutionError):
            synth.execute_disposable_synthetic_zero_pass(medium)

    def test_medium_and_result_are_noncopyable_nonserializable(self):
        medium = self.medium()
        for op in (
            lambda: copy.copy(medium),
            lambda: copy.deepcopy(medium),
            lambda: pickle.dumps(medium),
        ):
            with self.assertRaises(synth.SyntheticExecutionError):
                op()
        result = synth.execute_disposable_synthetic_zero_pass(medium)
        for op in (
            lambda: copy.copy(result),
            lambda: copy.deepcopy(result),
            lambda: pickle.dumps(result),
        ):
            with self.assertRaises(synth.SyntheticExecutionError):
                op()

    def test_public_medium_surface_has_no_raw_fd_or_io(self):
        public = {
            name for name in dir(synth.DisposableSyntheticMedium)
            if not name.startswith("_")
        }
        forbidden = {
            "fd", "fileno", "read", "write", "seek", "descriptor",
            "execute", "executor", "command", "callback",
        }
        self.assertTrue(public.isdisjoint(forbidden))

    def test_source_has_no_subprocess_device_path_or_ioctl(self):
        source = Path(synth.__file__).read_text(encoding="utf-8")
        for marker in (
            "subprocess", "Popen", "os.system", "/dev/",
            "losetup", "wipefs", "shred", "ioctl",
        ):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, source)


if __name__ == "__main__":
    unittest.main()
