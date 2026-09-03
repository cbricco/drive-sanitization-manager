import copy
import os
import pickle
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import synthetic_block_device_harness as synth

_REAL_LSTAT = os.lstat


def block_mode():
    return stat.S_IFBLK | 0o600


class SyntheticBlockHarnessTests(unittest.TestCase):
    LOOP = "/dev/loop77"
    MAJMIN = "7:77"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        self.image = os.path.join(self.tmp.name, "synthetic.bin")

        with open(self.image, "wb") as fh:
            fh.truncate(2 * 1024 * 1024)

        os.chmod(self.image, 0o600)

        self.image_stat = os.stat(self.image)

        self.path_stat = SimpleNamespace(
            st_mode=block_mode(),
            st_rdev=os.makedev(7, 77),
        )
        self.fd_stat = SimpleNamespace(
            st_mode=block_mode(),
            st_rdev=os.makedev(7, 77),
        )

    def snapshot(self, active=()):
        with patch.object(
            synth,
            "_active_loop_devices",
            return_value=frozenset(active),
        ):
            return synth.snapshot_active_loop_devices()

    def acquisition_patches(self):
        return (
            patch.object(
                synth.os,
                "lstat",
                side_effect=lambda path: (
                    self.path_stat
                    if path == self.LOOP
                    else _REAL_LSTAT(path)
                ),
            ),
            patch.object(
                synth.os,
                "open",
                return_value=91,
            ),
            patch.object(
                synth.os,
                "fstat",
                return_value=self.fd_stat,
            ),
            patch.object(
                synth.os,
                "set_inheritable",
            ),
            patch.object(
                synth.os,
                "get_inheritable",
                return_value=False,
            ),
            patch.object(
                synth.os,
                "close",
            ),
            patch.object(
                synth,
                "_device_has_children",
                return_value=False,
            ),
            patch.object(
                synth,
                "_device_is_mounted",
                return_value=False,
            ),
            patch.object(
                synth,
                "_real_backing_path",
                return_value=os.path.realpath(self.image),
            ),
        )

    def acquire(self):
        patches = self.acquisition_patches()

        with patches[0], patches[1], patches[2], patches[3], \
             patches[4], patches[5], patches[6], patches[7], patches[8]:
            return synth.acquire_disposable_loop_block_medium(
                self.snapshot(),
                loop_path=self.LOOP,
                backing_image=self.image,
                expected_major_minor=self.MAJMIN,
            )

    def test_snapshot_inspection_failure_fails_closed(self):
        with patch.object(
            synth.glob,
            "glob",
            return_value=["/sys/class/block/loop77"],
        ):
            with patch(
                "builtins.open",
                side_effect=PermissionError("denied"),
            ):
                with self.assertRaises(
                    synth.SyntheticBlockDeviceError
                ):
                    synth.snapshot_active_loop_devices()

    def test_snapshot_state_is_immutable(self):
        snapshot = self.snapshot((self.LOOP,))

        with self.assertRaises(
            synth.SyntheticBlockDeviceError
        ):
            snapshot._active = frozenset()

        self.assertEqual(
            snapshot._active,
            frozenset((self.LOOP,)),
        )

    def test_snapshot_is_internal_and_nonserializable(self):
        snapshot = self.snapshot()

        for op in (
            lambda: copy.copy(snapshot),
            lambda: copy.deepcopy(snapshot),
            lambda: pickle.dumps(snapshot),
        ):
            with self.assertRaises(synth.SyntheticBlockDeviceError):
                op()

        with self.assertRaises(synth.SyntheticBlockDeviceError):
            synth.LoopDeviceSnapshot(object(), frozenset())

    def test_physical_drive_path_is_refused_before_open(self):
        snapshot = self.snapshot()

        with patch.object(synth.os, "open") as opener:
            with self.assertRaises(synth.SyntheticBlockDeviceError):
                synth.acquire_disposable_loop_block_medium(
                    snapshot,
                    loop_path="/dev/sda",
                    backing_image=self.image,
                    expected_major_minor="8:0",
                )

        opener.assert_not_called()

    def test_preexisting_loop_is_refused_before_open(self):
        snapshot = self.snapshot((self.LOOP,))

        with patch.object(synth.os, "open") as opener:
            with self.assertRaises(synth.SyntheticBlockDeviceError):
                synth.acquire_disposable_loop_block_medium(
                    snapshot,
                    loop_path=self.LOOP,
                    backing_image=self.image,
                    expected_major_minor=self.MAJMIN,
                )

        opener.assert_not_called()

    def test_non_loop_major_is_refused(self):
        self.path_stat = SimpleNamespace(
            st_mode=block_mode(),
            st_rdev=os.makedev(8, 77),
        )

        patches = self.acquisition_patches()

        with patches[0], patches[1] as opener, patches[2], patches[3], \
             patches[4], patches[5], patches[6], patches[7], patches[8]:
            with self.assertRaises(synth.SyntheticBlockDeviceError):
                synth.acquire_disposable_loop_block_medium(
                    self.snapshot(),
                    loop_path=self.LOOP,
                    backing_image=self.image,
                    expected_major_minor=self.MAJMIN,
                )

        opener.assert_not_called()

    def test_wrong_backing_image_is_refused(self):
        patches = self.acquisition_patches()

        patches = list(patches)
        patches[8] = patch.object(
            synth,
            "_real_backing_path",
            return_value="/some/other/file",
        )

        with patches[0], patches[1] as opener, patches[2], patches[3], \
             patches[4], patches[5], patches[6], patches[7], patches[8]:
            with self.assertRaises(synth.SyntheticBlockDeviceError):
                synth.acquire_disposable_loop_block_medium(
                    self.snapshot(),
                    loop_path=self.LOOP,
                    backing_image=self.image,
                    expected_major_minor=self.MAJMIN,
                )

        opener.assert_not_called()

    def test_full_zero_offset_loop_geometry_is_accepted(self):
        root = "/sys/class/block/loop77"

        values = {
            f"{root}/loop/backing_file": self.image,
            f"{root}/loop/offset": "0",
            f"{root}/loop/sizelimit": "0",
            f"{root}/ro": "0",
            f"{root}/size": str(self.image_stat.st_size // 512),
        }

        with patch.object(
            synth,
            "_read_sysfs_text",
            side_effect=lambda path, label: values[path],
        ):
            resolved = synth._real_backing_path(self.LOOP)

        self.assertEqual(
            resolved,
            os.path.realpath(self.image),
        )

    def test_nonzero_loop_offset_is_refused(self):
        root = "/sys/class/block/loop77"

        values = {
            f"{root}/loop/backing_file": self.image,
            f"{root}/loop/offset": "512",
            f"{root}/loop/sizelimit": "0",
            f"{root}/ro": "0",
            f"{root}/size": str(
                (self.image_stat.st_size - 512) // 512
            ),
        }

        with patch.object(
            synth,
            "_read_sysfs_text",
            side_effect=lambda path, label: values[path],
        ):
            with self.assertRaises(
                synth.SyntheticBlockDeviceError
            ):
                synth._real_backing_path(self.LOOP)

    def test_kernel_read_only_loop_is_refused(self):
        root = "/sys/class/block/loop77"

        values = {
            f"{root}/loop/backing_file": self.image,
            f"{root}/loop/offset": "0",
            f"{root}/loop/sizelimit": "0",
            f"{root}/ro": "1",
            f"{root}/size": str(
                self.image_stat.st_size // 512
            ),
        }

        with patch.object(
            synth,
            "_read_sysfs_text",
            side_effect=lambda path, label: values[path],
        ):
            with self.assertRaises(
                synth.SyntheticBlockDeviceError
            ):
                synth._real_backing_path(self.LOOP)

    def test_loop_size_limit_is_refused(self):
        root = "/sys/class/block/loop77"

        values = {
            f"{root}/loop/backing_file": self.image,
            f"{root}/loop/offset": "0",
            f"{root}/loop/sizelimit": str(1024 * 1024),
            f"{root}/ro": "0",
            f"{root}/size": str((1024 * 1024) // 512),
        }

        with patch.object(
            synth,
            "_read_sysfs_text",
            side_effect=lambda path, label: values[path],
        ):
            with self.assertRaises(
                synth.SyntheticBlockDeviceError
            ):
                synth._real_backing_path(self.LOOP)

    def test_loop_capacity_must_equal_full_backing_image(self):
        root = "/sys/class/block/loop77"

        values = {
            f"{root}/loop/backing_file": self.image,
            f"{root}/loop/offset": "0",
            f"{root}/loop/sizelimit": "0",
            f"{root}/ro": "0",
            f"{root}/size": str(
                (self.image_stat.st_size // 512) - 1
            ),
        }

        with patch.object(
            synth,
            "_read_sysfs_text",
            side_effect=lambda path, label: values[path],
        ):
            with self.assertRaises(
                synth.SyntheticBlockDeviceError
            ):
                synth._real_backing_path(self.LOOP)

    def test_mounted_loop_is_refused(self):
        patches = list(self.acquisition_patches())

        patches[7] = patch.object(
            synth,
            "_device_is_mounted",
            return_value=True,
        )

        with patches[0], patches[1] as opener, patches[2], patches[3], \
             patches[4], patches[5], patches[6], patches[7], patches[8]:
            with self.assertRaises(synth.SyntheticBlockDeviceError):
                synth.acquire_disposable_loop_block_medium(
                    self.snapshot(),
                    loop_path=self.LOOP,
                    backing_image=self.image,
                    expected_major_minor=self.MAJMIN,
                )

        opener.assert_not_called()

    def test_child_devices_are_refused(self):
        patches = list(self.acquisition_patches())

        patches[6] = patch.object(
            synth,
            "_device_has_children",
            return_value=True,
        )

        with patches[0], patches[1] as opener, patches[2], patches[3], \
             patches[4], patches[5], patches[6], patches[7], patches[8]:
            with self.assertRaises(synth.SyntheticBlockDeviceError):
                synth.acquire_disposable_loop_block_medium(
                    self.snapshot(),
                    loop_path=self.LOOP,
                    backing_image=self.image,
                    expected_major_minor=self.MAJMIN,
                )

        opener.assert_not_called()

    def test_acquisition_uses_rdwr_and_noninheritable_descriptor(self):
        patches = self.acquisition_patches()

        with patches[0], patches[1] as opener, patches[2], \
             patches[3] as set_inheritable, patches[4], patches[5], \
             patches[6], patches[7], patches[8]:

            medium = synth.acquire_disposable_loop_block_medium(
                self.snapshot(),
                loop_path=self.LOOP,
                backing_image=self.image,
                expected_major_minor=self.MAJMIN,
            )

        args = opener.call_args.args
        self.assertEqual(args[0], self.LOOP)
        self.assertTrue(args[1] & os.O_RDWR)
        set_inheritable.assert_called_once_with(91, False)
        self.assertEqual(medium.major_minor, self.MAJMIN)

    def test_final_backing_privacy_change_is_refused_and_closed(self):
        good = (
            os.path.realpath(self.image),
            self.image_stat,
        )

        patches = self.acquisition_patches()

        with patch.object(
            synth,
            "_validate_private_backing_image",
            side_effect=[
                good,
                synth.SyntheticBlockDeviceError(
                    "synthetic backing image must have mode 0600"
                ),
            ],
        ), patches[0], patches[1], patches[2], patches[3],              patches[4], patches[5] as closer, patches[6],              patches[7], patches[8]:

            with self.assertRaises(
                synth.SyntheticBlockDeviceError
            ):
                synth.acquire_disposable_loop_block_medium(
                    self.snapshot(),
                    loop_path=self.LOOP,
                    backing_image=self.image,
                    expected_major_minor=self.MAJMIN,
                )

        closer.assert_called_once_with(91)

    def test_inheritable_descriptor_is_refused_and_closed(self):
        patches = list(self.acquisition_patches())
        patches[4] = patch.object(
            synth.os,
            "get_inheritable",
            return_value=True,
        )

        with patches[0], patches[1], patches[2], patches[3], patches[4], \
             patches[5] as closer, patches[6], patches[7], patches[8]:
            with self.assertRaises(synth.SyntheticBlockDeviceError):
                synth.acquire_disposable_loop_block_medium(
                    self.snapshot(),
                    loop_path=self.LOOP,
                    backing_image=self.image,
                    expected_major_minor=self.MAJMIN,
                )

        closer.assert_called_once_with(91)

    def test_backing_image_must_be_sector_aligned(self):
        snapshot = self.snapshot()

        with open(self.image, "r+b") as fh:
            fh.truncate((2 * 1024 * 1024) + 1)

        with patch.object(synth.os, "open") as opener:
            with self.assertRaises(
                synth.SyntheticBlockDeviceError
            ):
                synth.acquire_disposable_loop_block_medium(
                    snapshot,
                    loop_path=self.LOOP,
                    backing_image=self.image,
                    expected_major_minor=self.MAJMIN,
                )

        opener.assert_not_called()

    def test_backing_image_must_be_private_regular_file(self):
        snapshot = self.snapshot()

        os.chmod(self.image, 0o644)

        with self.assertRaises(synth.SyntheticBlockDeviceError):
            synth.acquire_disposable_loop_block_medium(
                snapshot,
                loop_path=self.LOOP,
                backing_image=self.image,
                expected_major_minor=self.MAJMIN,
            )

    def test_medium_authority_state_is_immutable(self):
        medium = self.acquire()

        original = {
            "_loop_path": medium._loop_path,
            "_backing_path": medium._backing_path,
            "_fd": medium._fd,
            "_rdev": medium._rdev,
            "_major": medium._major,
            "_minor": medium._minor,
            "_size": medium._size,
            "_image_dev": medium._image_dev,
            "_image_ino": medium._image_ino,
            "_consumed": medium._consumed,
            "_closed": medium._closed,
        }

        attempts = (
            ("_loop_path", "/dev/loop1"),
            ("_backing_path", "/tmp/other"),
            ("_fd", 999),
            ("_rdev", os.makedev(7, 1)),
            ("_major", 8),
            ("_minor", 1),
            ("_size", 1),
            ("_image_dev", 0),
            ("_image_ino", 0),
            ("_consumed", False),
            ("_closed", True),
        )

        for name, value in attempts:
            with self.subTest(name=name):
                with self.assertRaises(
                    synth.SyntheticBlockDeviceError
                ):
                    setattr(medium, name, value)

        for name, value in original.items():
            self.assertEqual(getattr(medium, name), value)

        with patch.object(synth.os, "close") as closer:
            medium.close()

        closer.assert_called_once_with(original["_fd"])
        self.assertTrue(medium.closed)

    def test_medium_is_noncopyable_nonserializable(self):
        medium = self.acquire()

        for op in (
            lambda: copy.copy(medium),
            lambda: copy.deepcopy(medium),
            lambda: pickle.dumps(medium),
        ):
            with self.assertRaises(synth.SyntheticBlockDeviceError):
                op()

    def execution_environment(self, medium, before, after):
        calls = {"read": 0}

        def fake_pread(fd, size, offset):
            self.assertEqual(fd, medium._fd)
            self.assertEqual(size, medium._size)
            self.assertEqual(offset, 0)

            calls["read"] += 1
            return before if calls["read"] == 1 else after

        return (
            patch.object(synth, "_revalidate_medium"),
            patch.object(
                synth.os,
                "pread",
                side_effect=fake_pread,
            ),
            patch.object(
                synth.os,
                "pwrite",
                return_value=65536,
            ),
            patch.object(synth.os, "fsync"),
        )

    def test_bounded_execution_writes_only_requested_region(self):
        medium = self.acquire()

        offset = 1024 * 1024
        length = 65536

        before = bytes(medium.size_bytes)
        after = bytearray(before)
        after[offset:offset + length] = b"\x3c" * length
        after = bytes(after)

        patches = self.execution_environment(
            medium,
            before,
            after,
        )

        with patches[0], patches[1], patches[2] as writer, patches[3]:
            result = synth.execute_bounded_synthetic_pattern_pass(
                medium,
                offset=offset,
                length=length,
            )

        writer.assert_called_once()

        args = writer.call_args.args
        self.assertEqual(args[0], medium._fd)
        self.assertEqual(args[2], offset)
        self.assertEqual(len(args[1]), length)
        self.assertEqual(set(args[1]), {0x3C})

        self.assertTrue(result.synthetic_pattern_verified)
        self.assertTrue(result.outside_region_verified)

    def test_result_remains_explicitly_nonproduction(self):
        medium = self.acquire()

        offset = 1024 * 1024
        length = 65536

        before = bytes(medium.size_bytes)
        after = bytearray(before)
        after[offset:offset + length] = b"\x3c" * length
        after = bytes(after)

        patches = self.execution_environment(
            medium,
            before,
            after,
        )

        with patches[0], patches[1], patches[2], patches[3]:
            result = synth.execute_bounded_synthetic_pattern_pass(
                medium,
                offset=offset,
                length=length,
            )

        self.assertFalse(result.sanitization_verified)
        self.assertFalse(result.production_execution)

        self.assertTrue(result.block_special_device_accessed)
        self.assertFalse(result.physical_drive_accessed)
        self.assertTrue(
            result.synthetic_loop_block_device_accessed
        )

        # Do not reintroduce the ambiguous old claim. A loop device is
        # genuinely block-special even though it is not a physical drive.
        self.assertFalse(
            hasattr(result, "real_block_device_accessed")
        )

        self.assertFalse(result.automatic_replay_allowed)

    def test_outside_region_change_fails_closed(self):
        medium = self.acquire()

        offset = 1024 * 1024
        length = 65536

        before = bytes(medium.size_bytes)
        after = bytearray(before)
        after[offset:offset + length] = b"\x3c" * length
        after[0] = 1
        after = bytes(after)

        patches = self.execution_environment(
            medium,
            before,
            after,
        )

        with patches[0], patches[1], patches[2], patches[3]:
            with self.assertRaises(
                synth.SyntheticBlockDeviceError
            ):
                synth.execute_bounded_synthetic_pattern_pass(
                    medium,
                    offset=offset,
                    length=length,
                )

        self.assertTrue(medium.consumed)

    def test_revalidation_refuses_backing_image_privacy_change(self):
        medium = self.acquire()

        os.chmod(self.image, 0o644)

        def guarded_lstat(path):
            if path == self.LOOP:
                return self.path_stat
            return _REAL_LSTAT(path)

        with patch.object(
            synth.os,
            "lstat",
            side_effect=guarded_lstat,
        ), patch.object(
            synth.os,
            "fstat",
            return_value=self.fd_stat,
        ), patch.object(
            synth,
            "_device_has_children",
            return_value=False,
        ), patch.object(
            synth,
            "_device_is_mounted",
            return_value=False,
        ), patch.object(
            synth,
            "_real_backing_path",
            return_value=os.path.realpath(self.image),
        ), patch.object(
            synth.os,
            "get_inheritable",
            return_value=False,
        ):
            with self.assertRaises(
                synth.SyntheticBlockDeviceError
            ):
                synth._revalidate_medium(medium)

    def test_failed_execution_is_nonreplayable(self):
        medium = self.acquire()

        with patch.object(
            synth,
            "_revalidate_medium",
            side_effect=synth.SyntheticBlockDeviceError("boom"),
        ):
            with self.assertRaises(synth.SyntheticBlockDeviceError):
                synth.execute_bounded_synthetic_pattern_pass(
                    medium,
                    offset=1024 * 1024,
                    length=65536,
                )

        self.assertTrue(medium.consumed)

        with self.assertRaises(synth.SyntheticBlockDeviceError):
            synth.execute_bounded_synthetic_pattern_pass(
                medium,
                offset=1024 * 1024,
                length=65536,
            )

    def test_result_safety_claims_are_immutable(self):
        medium = self.acquire()

        offset = 1024 * 1024
        length = 65536

        before = bytes(medium.size_bytes)
        after = bytearray(before)
        after[offset:offset + length] = b"\x3c" * length
        after = bytes(after)

        patches = self.execution_environment(
            medium,
            before,
            after,
        )

        with patches[0], patches[1], patches[2], patches[3]:
            result = synth.execute_bounded_synthetic_pattern_pass(
                medium,
                offset=offset,
                length=length,
            )

        attempts = (
            ("sanitization_verified", True),
            ("production_execution", True),
            ("block_special_device_accessed", False),
            ("physical_drive_accessed", True),
            ("synthetic_loop_block_device_accessed", False),
            ("automatic_replay_allowed", True),
            ("loop_major_minor", "8:0"),
        )

        for name, value in attempts:
            with self.subTest(name=name):
                with self.assertRaises(
                    synth.SyntheticBlockDeviceError
                ):
                    setattr(result, name, value)

        self.assertFalse(result.sanitization_verified)
        self.assertFalse(result.production_execution)
        self.assertTrue(result.block_special_device_accessed)
        self.assertFalse(result.physical_drive_accessed)
        self.assertTrue(
            result.synthetic_loop_block_device_accessed
        )
        self.assertFalse(result.automatic_replay_allowed)
        self.assertEqual(result.loop_major_minor, self.MAJMIN)

    def test_result_is_noncopyable_nonserializable(self):
        medium = self.acquire()

        offset = 1024 * 1024
        length = 65536

        before = bytes(medium.size_bytes)
        after = bytearray(before)
        after[offset:offset + length] = b"\x3c" * length
        after = bytes(after)

        patches = self.execution_environment(
            medium,
            before,
            after,
        )

        with patches[0], patches[1], patches[2], patches[3]:
            result = synth.execute_bounded_synthetic_pattern_pass(
                medium,
                offset=offset,
                length=length,
            )

        for op in (
            lambda: copy.copy(result),
            lambda: copy.deepcopy(result),
            lambda: pickle.dumps(result),
        ):
            with self.assertRaises(synth.SyntheticBlockDeviceError):
                op()


if __name__ == "__main__":
    unittest.main()
