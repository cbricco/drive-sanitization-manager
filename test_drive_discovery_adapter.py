import inspect
import json
import subprocess
import unittest
from dataclasses import fields
from unittest.mock import call, patch

from drive_discovery import DiscoveryError
from drive_discovery_adapter import (
    DiscoveryCollectionError, DiscoverySnapshot, FINDMNT_ROOT_COMMAND,
    FINDMNT_REAL_COMMAND, LSBLK_COMMAND, SWAPON_COMMAND, SAFE_COMMAND_ENV,
    collect_current_drive_discovery,
)

LSBLK_BYTES = b'{"blockdevices":[{"name":"syn-root","path":"/dev/syn-root","type":"disk","size":4096,"serial":"ID","children":[{"name":"syn-root1","path":"/dev/syn-root1","type":"part"},{"name":"boot","path":"/dev/boot","type":"part"},{"name":"swap","path":"/dev/swap","type":"part"}]}]}'
FINDMNT_BYTES = b'{"filesystems":[{"target":"/","source":"/dev/syn-root1"}]}'
REAL_BYTES = b'{"filesystems":[{"target":"/","source":"/dev/syn-root1","fstype":"ext4"}]}'


def result(stdout=b"", stderr=b"", returncode=0):
    return subprocess.CompletedProcess((), returncode, stdout, stderr)


def real(entries):
    return json.dumps({"filesystems": entries}).encode()


class DriveDiscoveryAdapterTests(unittest.TestCase):
    def successful_mock(self, lsblk=LSBLK_BYTES, root=FINDMNT_BYTES,
                        all_real=REAL_BYTES, swap=b""):
        return patch("drive_discovery_adapter.subprocess.run", side_effect=[
            result(lsblk), result(root), result(all_real), result(swap),
        ])

    def test_commands_and_subprocess_boundary_are_fixed(self):
        self.assertEqual(LSBLK_COMMAND, (
            "lsblk", "--json", "--bytes", "--output",
            "NAME,KNAME,PATH,TYPE,SIZE,MODEL,SERIAL,TRAN,ROTA,RM,RO,WWN,PKNAME,FSTYPE,MOUNTPOINTS",
        ))
        self.assertEqual(FINDMNT_ROOT_COMMAND, (
            "findmnt", "--json", "--target", "/", "--output", "TARGET,SOURCE",
        ))
        self.assertEqual(FINDMNT_REAL_COMMAND, (
            "findmnt", "--json", "--list", "--kernel", "--real", "--output",
            "TARGET,SOURCE,FSTYPE",
        ))
        self.assertEqual(SWAPON_COMMAND, (
            "swapon", "--show=NAME,TYPE", "--raw", "--noheadings",
        ))
        with self.successful_mock() as run:
            collect_current_drive_discovery()
        common = dict(shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                      stderr=subprocess.PIPE, check=False, timeout=5,
                      env=SAFE_COMMAND_ENV)
        self.assertEqual(run.call_args_list, [
            call(command, **common) for command in (
                LSBLK_COMMAND, FINDMNT_ROOT_COMMAND, FINDMNT_REAL_COMMAND,
                SWAPON_COMMAND,
            )
        ])
        self.assertEqual(dict(SAFE_COMMAND_ENV), {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C",
        })
        self.assertIn("--list", FINDMNT_REAL_COMMAND)

    def test_success_preserves_evidence_source_and_marks_system_parent(self):
        with self.successful_mock():
            snapshot = collect_current_drive_discovery()
        self.assertIsInstance(snapshot, DiscoverySnapshot)
        self.assertEqual((snapshot.captured_lsblk_json,
                          snapshot.captured_findmnt_root_json,
                          snapshot.captured_findmnt_real_json,
                          snapshot.captured_swapon_output),
                         (LSBLK_BYTES, FINDMNT_BYTES, REAL_BYTES, b""))
        self.assertEqual(snapshot.protected_sources, ("/dev/syn-root1",))
        self.assertIsInstance(snapshot.drives, tuple)
        self.assertTrue(snapshot.drives[0].system)
        self.assertEqual(snapshot.drives[0].name, "syn-root")

    def test_exact_nonblank_source_is_not_normalized(self):
        source = "  /dev/syn-root1  "
        root = real([{"target": "/", "source": source}])
        rr = real([{"target": "/", "source": source, "fstype": None}])
        lsblk = json.dumps({"blockdevices": [{"name": source, "type": "disk",
                                               "serial": "ID"}]}).encode()
        with self.successful_mock(lsblk, root, rr):
            snapshot = collect_current_drive_discovery()
        self.assertEqual(snapshot.protected_sources, (source,))

    def test_nonzero_commands_fail_closed(self):
        for index in range(4):
            effects = [result(LSBLK_BYTES), result(FINDMNT_BYTES),
                       result(REAL_BYTES), result()]
            effects[index] = result(returncode=7)
            with self.subTest(index=index), patch(
                    "drive_discovery_adapter.subprocess.run", side_effect=effects), \
                    self.assertRaises(DiscoveryCollectionError):
                collect_current_drive_discovery()

    def test_each_command_timeout_fails_closed(self):
        for index in range(4):
            effects = [result(LSBLK_BYTES), result(FINDMNT_BYTES),
                       result(REAL_BYTES), result()]
            effects[index] = subprocess.TimeoutExpired(("synthetic",), 5)
            with self.subTest(index=index), patch(
                    "drive_discovery_adapter.subprocess.run", side_effect=effects), \
                    self.assertRaises(DiscoveryCollectionError):
                collect_current_drive_discovery()

    def test_oserror_fails_closed(self):
        with patch("drive_discovery_adapter.subprocess.run", side_effect=OSError()), \
                self.assertRaises(DiscoveryCollectionError):
            collect_current_drive_discovery()

    def test_oversized_stdout_and_stderr_fail_closed_for_both_commands(self):
        for index in range(4):
            for stream in ("stdout", "stderr"):
                effects = [result(LSBLK_BYTES), result(FINDMNT_BYTES),
                           result(REAL_BYTES), result()]
                effects[index] = result(b"xx") if stream == "stdout" else result(b"", b"xx")
                kwargs = {"max_stdout_bytes": 1} if stream == "stdout" else {"max_stderr_bytes": 1}
                with self.subTest(index=index, stream=stream), patch(
                        "drive_discovery_adapter.subprocess.run", side_effect=effects), \
                        self.assertRaises(DiscoveryCollectionError):
                    collect_current_drive_discovery(**kwargs)

    def test_invalid_findmnt_shapes_fail_closed(self):
        documents = [
            b"{", b"[]", b"{}", b'{"filesystems":[]}',
            b'{"filesystems":[{},{}]}', b'{"filesystems":[42]}',
            b'{"filesystems":[{"target":"/else","source":"/dev/syn-root1"}]}',
            b'{"filesystems":[{"target":"/","source":" "}]}',
            b'{"filesystems":[{"target":"/","source":42}]}',
            b'{"filesystems":[{"target":"/"}]}',
        ]
        for document in documents:
            with self.subTest(document=document), self.successful_mock(root=document), \
                    self.assertRaises(DiscoveryCollectionError):
                collect_current_drive_discovery()

    def test_parser_errors_surface_for_bad_lsblk_unmatched_and_ambiguity(self):
        duplicate = (b'{"blockdevices":[{"name":"a","path":"/dev/dup","type":"disk"},'
                     b'{"name":"b","path":"/dev/dup","type":"disk"}]}')
        cases = [
            (b"{", FINDMNT_BYTES, REAL_BYTES),
            (b'{"blockdevices":[]}', FINDMNT_BYTES, REAL_BYTES),
            (duplicate,
             b'{"filesystems":[{"target":"/","source":"/dev/dup"}]}',
             b'{"filesystems":[{"target":"/","source":"/dev/dup","fstype":null}]}'),
        ]
        for lsblk, root, rr in cases:
            with self.subTest(lsblk=lsblk), self.successful_mock(lsblk, root, rr), \
                    self.assertRaises(DiscoveryError):
                collect_current_drive_discovery()

    def test_bounds_reject_bool_zero_negative_and_wrong_types(self):
        for name in ("timeout_seconds", "max_stdout_bytes", "max_stderr_bytes"):
            values = (True, False, 0, -1, "5")
            if name == "timeout_seconds":
                values += (float("inf"), float("nan"))
            for value in values:
                with self.subTest(name=name, value=value), patch(
                        "drive_discovery_adapter.subprocess.run") as run, \
                        self.assertRaises(DiscoveryCollectionError):
                    collect_current_drive_discovery(**{name: value})
                run.assert_not_called()

    def test_snapshot_is_frozen_and_has_no_destructive_authority(self):
        with self.successful_mock():
            snapshot = collect_current_drive_discovery()
        with self.assertRaises((AttributeError, TypeError)):
            snapshot.drives = ()
        self.assertEqual([field.name for field in fields(DiscoverySnapshot)][:3],
                         ["captured_lsblk_json", "protected_sources", "drives"])
        forbidden = ("eligible", "sanitization_eligible", "authorized", "approved",
                     "safe_to_wipe", "wipe_allowed", "destructive_authority")
        for observation in (snapshot,) + snapshot.drives:
            for name in forbidden:
                self.assertFalse(hasattr(observation, name))

    def test_public_api_cannot_substitute_commands_or_executables(self):
        parameters = inspect.signature(collect_current_drive_discovery).parameters
        self.assertEqual(tuple(parameters),
                         ("timeout_seconds", "max_stdout_bytes", "max_stderr_bytes"))
        for parameter in parameters.values():
            self.assertEqual(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
        for kwargs in ({"command": ("x",)}, {"executable": "x"},
                       {"lsblk_command": ("x",)}, {"findmnt_executable": "x"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(TypeError):
                collect_current_drive_discovery(**kwargs)

    def test_root_cross_check_missing_duplicate_and_disagreement(self):
        cases = [real([]), real([
            {"target": "/", "source": "/dev/syn-root1", "fstype": None},
            {"target": "/", "source": "/dev/syn-root1", "fstype": None},
        ]), real([{"target": "/", "source": "/dev/other", "fstype": None}])]
        for rr in cases:
            with self.subTest(rr=rr), self.successful_mock(all_real=rr), \
                    self.assertRaises(DiscoveryCollectionError):
                collect_current_drive_discovery()

    def test_critical_mount_families_and_component_descendants(self):
        targets = ["/boot", "/usr/lib", "/var/lib", "/etc/x", "/bin",
                   "/sbin/x", "/lib/x", "/lib64/x"]
        entries = [{"target": "/", "source": "/dev/syn-root1", "fstype": "x"}]
        entries += [{"target": target, "source": "/dev/boot", "fstype": None}
                    for target in targets]
        with self.successful_mock(all_real=real(entries)):
            snapshot = collect_current_drive_discovery()
        self.assertEqual(snapshot.protected_sources, ("/dev/syn-root1", "/dev/boot"))

    def test_various_is_not_var_family(self):
        rr = real([{"target": "/", "source": "/dev/syn-root1", "fstype": None},
                   {"target": "/various", "source": "/dev/unmatched", "fstype": None}])
        with self.successful_mock(all_real=rr):
            self.assertEqual(collect_current_drive_discovery().protected_sources,
                             ("/dev/syn-root1",))

    def test_ordinary_mounts_are_not_system_sources(self):
        entries = [{"target": "/", "source": "/dev/syn-root1", "fstype": None}]
        entries += [{"target": target, "source": "/dev/unmatched", "fstype": None}
                    for target in ("/mnt", "/media", "/run/media/x", "/home", "/srv", "/opt")]
        with self.successful_mock(all_real=real(entries)):
            self.assertEqual(collect_current_drive_discovery().protected_sources,
                             ("/dev/syn-root1",))

    def test_protected_sources_exact_dedup_and_deterministic_order(self):
        entries = [{"target": "/", "source": "/dev/syn-root1", "fstype": None},
                   {"target": "/var", "source": "/dev/boot", "fstype": None},
                   {"target": "/boot", "source": "/dev/boot", "fstype": None}]
        swap = b"/dev/swap partition\n/dev/boot partition\n/dev/swap partition\n"
        with self.successful_mock(all_real=real(entries), swap=swap):
            snapshot = collect_current_drive_discovery()
        self.assertEqual(snapshot.protected_sources,
                         ("/dev/syn-root1", "/dev/boot", "/dev/swap"))

    def test_all_real_children_key_is_rejected(self):
        for value in ([], None, {}):
            rr = real([{"target": "/", "source": "/dev/syn-root1",
                        "fstype": None, "children": value}])
            with self.subTest(value=value), self.successful_mock(all_real=rr), \
                    self.assertRaises(DiscoveryCollectionError):
                collect_current_drive_discovery()

    def test_all_real_entry_contract_is_strict(self):
        bad = [42, {"target": "", "source": "x", "fstype": None},
               {"target": "/", "source": "", "fstype": None},
               {"target": "/", "source": "x", "fstype": 3}]
        for entry in bad:
            with self.subTest(entry=entry), self.successful_mock(all_real=real([entry])), \
                    self.assertRaises(DiscoveryCollectionError):
                collect_current_drive_discovery()

    def test_file_swap_is_evidence_only(self):
        raw = b"/swap file file\n"
        with self.successful_mock(swap=raw):
            snapshot = collect_current_drive_discovery()
        self.assertEqual(snapshot.captured_swapon_output, raw)
        self.assertEqual(snapshot.protected_sources, ("/dev/syn-root1",))

    def test_partition_swap_is_protected_and_owned(self):
        with self.successful_mock(swap=b"/dev/swap partition\n"):
            snapshot = collect_current_drive_discovery()
        self.assertEqual(snapshot.protected_sources, ("/dev/syn-root1", "/dev/swap"))

    def test_swap_name_may_contain_interior_spaces(self):
        source = "/dev/swap name"
        lsblk = json.dumps({"blockdevices": [{"name": "d", "path": "/dev/d",
            "type": "disk", "serial": "ID", "children": [
                {"name": "r", "path": "/dev/syn-root1", "type": "part"},
                {"name": "s", "path": source, "type": "part"}]}]}).encode()
        with self.successful_mock(lsblk=lsblk,
                                  swap=(source + " partition\n").encode()):
            self.assertIn(source, collect_current_drive_discovery().protected_sources)

    def test_swap_trim_required_is_rejected(self):
        # Historical identity retained. Leading whitespace means the
        # reported NAME itself would require normalization and must fail.
        for raw in (
            b" /dev/swap partition\n",
            b"\t/dev/swap partition\n",
        ):
            with (
                self.subTest(raw=raw),
                self.successful_mock(swap=raw),
                self.assertRaises(DiscoveryCollectionError),
            ):
                collect_current_drive_discovery()

    def test_swapon_host_padding_is_accepted_and_evidence_preserved(self):
        # Real util-linux output may contain padding after the final TYPE.
        raw = b"/swap.img file  \n"
        with self.successful_mock(swap=raw):
            snapshot = collect_current_drive_discovery()

        self.assertEqual(snapshot.captured_swapon_output, raw)
        self.assertEqual(
            snapshot.protected_sources,
            ("/dev/syn-root1",),
        )

        # If the command ever regresses to the five-column default shape,
        # the parser must still fail closed rather than treating PRIO as TYPE.
        wrong_shape = b"/swap.img file 4G 964K -1  \n"
        with (
            self.successful_mock(swap=wrong_shape),
            self.assertRaises(DiscoveryCollectionError),
        ):
            collect_current_drive_discovery()

    def test_malformed_unknown_and_invalid_utf8_swap_fail_closed(self):
        for raw in (b"oneword\n", b"/dev/swap device\n", b"\xff"):
            with self.subTest(raw=raw), self.successful_mock(swap=raw), \
                    self.assertRaises(DiscoveryCollectionError):
                collect_current_drive_discovery()

    def test_unmatched_partition_swap_fails_closed(self):
        with self.successful_mock(swap=b"/dev/nope partition\n"), \
                self.assertRaises(DiscoveryError):
            collect_current_drive_discovery()

    def test_nonbyte_results_fail_closed_for_each_command(self):
        for index in range(4):
            effects = [result(LSBLK_BYTES), result(FINDMNT_BYTES),
                       result(REAL_BYTES), result()]
            effects[index] = result("text")
            with self.subTest(index=index), patch(
                    "drive_discovery_adapter.subprocess.run", side_effect=effects), \
                    self.assertRaises(DiscoveryCollectionError):
                collect_current_drive_discovery()

    def test_empty_swap_is_accepted_as_exact_evidence(self):
        with self.successful_mock(swap=b""):
            snapshot = collect_current_drive_discovery()
        self.assertEqual(snapshot.captured_swapon_output, b"")
        self.assertEqual(snapshot.protected_sources, ("/dev/syn-root1",))


if __name__ == "__main__":
    unittest.main()
