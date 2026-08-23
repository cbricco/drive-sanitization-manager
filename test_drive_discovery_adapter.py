import inspect
import json
import subprocess
import unittest
from unittest.mock import call, patch

from drive_discovery import DiscoveryError
from drive_discovery_adapter import (
    DiscoveryCollectionError, DiscoverySnapshot, FINDMNT_ROOT_COMMAND,
    LSBLK_COMMAND, SAFE_COMMAND_ENV, collect_current_drive_discovery,
)

LSBLK_BYTES = b'''{\n "blockdevices": [{
 "name":"syn-root", "kname":"syn-root", "path":"/dev/syn-root",
 "type":"disk", "size":4096, "serial":"SYN-SERIAL-ROOT",
 "children":[{"name":"syn-root1", "path":"/dev/syn-root1", "type":"part"}]
 }]}\n'''
FINDMNT_BYTES = b'{"filesystems":[{"target":"/","source":"/dev/syn-root1"}]}'


def result(stdout=b"", stderr=b"", returncode=0):
    return subprocess.CompletedProcess((), returncode, stdout, stderr)


class DriveDiscoveryAdapterTests(unittest.TestCase):
    def successful_mock(self):
        return patch("drive_discovery_adapter.subprocess.run", side_effect=[
            result(LSBLK_BYTES), result(FINDMNT_BYTES),
        ])

    def test_commands_and_subprocess_boundary_are_fixed(self):
        self.assertEqual(LSBLK_COMMAND, (
            "lsblk", "--json", "--bytes", "--output",
            "NAME,KNAME,PATH,TYPE,SIZE,MODEL,SERIAL,TRAN,ROTA,RM,RO,WWN,PKNAME,FSTYPE,MOUNTPOINTS",
        ))
        self.assertEqual(FINDMNT_ROOT_COMMAND, (
            "findmnt", "--json", "--target", "/", "--output", "TARGET,SOURCE",
        ))
        with self.successful_mock() as run:
            collect_current_drive_discovery()
        common = dict(
            shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, timeout=5, env=SAFE_COMMAND_ENV,
        )
        self.assertEqual(run.call_args_list, [
            call(LSBLK_COMMAND, **common), call(FINDMNT_ROOT_COMMAND, **common),
        ])
        self.assertEqual(dict(SAFE_COMMAND_ENV), {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C",
        })

    def test_success_preserves_evidence_source_and_marks_system_parent(self):
        with self.successful_mock():
            snapshot = collect_current_drive_discovery()
        self.assertIsInstance(snapshot, DiscoverySnapshot)
        self.assertEqual(snapshot.captured_lsblk_json, LSBLK_BYTES)
        self.assertEqual(snapshot.protected_sources, ("/dev/syn-root1",))
        self.assertIsInstance(snapshot.drives, tuple)
        self.assertTrue(snapshot.drives[0].system)
        self.assertEqual(snapshot.drives[0].name, "syn-root")

    def test_exact_nonblank_source_is_not_normalized(self):
        source = "  /dev/syn-root1  "
        lsblk = json.dumps({"blockdevices": [{
            "name": source, "type": "disk", "serial": "SYN-ID"
        }]}).encode()
        findmnt = json.dumps({
            "filesystems": [{"target": "/", "source": source}]
        }).encode()
        with patch("drive_discovery_adapter.subprocess.run", side_effect=[
            result(lsblk), result(findmnt),
        ]):
            snapshot = collect_current_drive_discovery()
        self.assertEqual(snapshot.protected_sources, (source,))

    def test_nonzero_commands_fail_closed(self):
        for effects in ([result(returncode=7)],
                        [result(LSBLK_BYTES), result(returncode=8)]):
            with self.subTest(effects=effects), patch(
                "drive_discovery_adapter.subprocess.run", side_effect=effects
            ), self.assertRaises(DiscoveryCollectionError):
                collect_current_drive_discovery()

    def test_each_command_timeout_fails_closed(self):
        timeout = subprocess.TimeoutExpired(("synthetic",), 5)
        for effects in ([timeout], [result(LSBLK_BYTES), timeout]):
            with self.subTest(effects=effects), patch(
                "drive_discovery_adapter.subprocess.run", side_effect=effects
            ), self.assertRaises(DiscoveryCollectionError):
                collect_current_drive_discovery()

    def test_oserror_fails_closed(self):
        with patch("drive_discovery_adapter.subprocess.run",
                   side_effect=OSError("synthetic")):
            with self.assertRaises(DiscoveryCollectionError):
                collect_current_drive_discovery()

    def test_oversized_stdout_and_stderr_fail_closed_for_both_commands(self):
        cases = [
            ([result(b"xx")], {"max_stdout_bytes": 1}),
            ([result(b"", b"xx")], {"max_stderr_bytes": 1}),
            ([result(b""), result(b"xx")], {"max_stdout_bytes": 1}),
            ([result(b""), result(b"", b"xx")], {"max_stderr_bytes": 1}),
        ]
        for effects, kwargs in cases:
            with self.subTest(effects=effects), patch(
                "drive_discovery_adapter.subprocess.run", side_effect=effects
            ), self.assertRaises(DiscoveryCollectionError):
                collect_current_drive_discovery(**kwargs)

    def test_invalid_findmnt_shapes_fail_closed(self):
        documents = [
            b"{", b"[]", b"{}", b'{"filesystems":[]}',
            b'{"filesystems":[{},{}]}', b'{"filesystems":[42]}',
            b'{"filesystems":[{"target":"/else","source":"/dev/syn-root1"}]}',
            b'{"filesystems":[{"target":"/","source":"   "}]}',
            b'{"filesystems":[{"target":"/","source":42}]}',
            b'{"filesystems":[{"target":"/"}]}',
        ]
        for document in documents:
            with self.subTest(document=document), patch(
                "drive_discovery_adapter.subprocess.run",
                side_effect=[result(LSBLK_BYTES), result(document)],
            ), self.assertRaises(DiscoveryCollectionError):
                collect_current_drive_discovery()

    def test_parser_errors_surface_for_bad_lsblk_unmatched_and_ambiguity(self):
        cases = [
            (b"{", FINDMNT_BYTES),
            (b'{"blockdevices":[]}', FINDMNT_BYTES),
            (b'{"blockdevices":[{"name":"syn-a","path":"/dev/syn-dup","type":"disk"},'
             b'{"name":"syn-b","path":"/dev/syn-dup","type":"disk"}]}',
             b'{"filesystems":[{"target":"/","source":"/dev/syn-dup"}]}'),
        ]
        for lsblk, findmnt in cases:
            with self.subTest(lsblk=lsblk), patch(
                "drive_discovery_adapter.subprocess.run",
                side_effect=[result(lsblk), result(findmnt)],
            ), self.assertRaises(DiscoveryError):
                collect_current_drive_discovery()

    def test_bounds_reject_bool_zero_negative_and_wrong_types(self):
        for name in ("timeout_seconds", "max_stdout_bytes", "max_stderr_bytes"):
            values = (True, False, 0, -1, "5")
            if name == "timeout_seconds":
                values += (float("inf"), float("nan"))
            for value in values:
                with self.subTest(name=name, value=value), patch(
                    "drive_discovery_adapter.subprocess.run"
                ) as run, self.assertRaises(DiscoveryCollectionError):
                    collect_current_drive_discovery(**{name: value})
                run.assert_not_called()

    def test_snapshot_is_frozen_and_has_no_destructive_authority(self):
        with self.successful_mock():
            snapshot = collect_current_drive_discovery()
        with self.assertRaises((AttributeError, TypeError)):
            snapshot.drives = ()
        forbidden = (
            "eligible", "sanitization_eligible", "authorized", "approved",
            "safe_to_wipe", "wipe_allowed", "destructive_authority",
        )
        for observation in (snapshot,) + snapshot.drives:
            for field in forbidden:
                self.assertFalse(hasattr(observation, field))

    def test_public_api_cannot_substitute_commands_or_executables(self):
        parameters = inspect.signature(collect_current_drive_discovery).parameters
        self.assertEqual(set(parameters), {
            "timeout_seconds", "max_stdout_bytes", "max_stderr_bytes",
        })
        for parameter in parameters.values():
            self.assertEqual(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
        with self.assertRaises(TypeError):
            collect_current_drive_discovery(command=("synthetic",))


if __name__ == "__main__":
    unittest.main()
