import inspect
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from dataclasses import fields
from unittest.mock import call, patch

from drive_discovery import DiscoveryError
from drive_discovery_adapter import (
    DiscoveryCollectionError, DiscoverySnapshot, FINDMNT_ROOT_COMMAND,
    FINDMNT_REAL_COMMAND, FSTAB_COMMAND, LSBLK_COMMAND, SWAPON_COMMAND, SAFE_COMMAND_ENV,
    collect_current_drive_discovery, _check_crypttab, _check_lvm_backup,
    _check_mdadm, _check_resume, _check_special_topology, _check_systemd_units,
)

LSBLK_BYTES = b'{"blockdevices":[{"name":"syn-root","path":"/dev/syn-root","type":"disk","size":4096,"serial":"ID","children":[{"name":"syn-root1","path":"/dev/syn-root1","type":"part"},{"name":"boot","path":"/dev/boot","type":"part"},{"name":"swap","path":"/dev/swap","type":"part"}]}]}'
FINDMNT_BYTES = b'{"filesystems":[{"target":"/","source":"/dev/syn-root1"}]}'
REAL_BYTES = b'{"filesystems":[{"target":"/","source":"/dev/syn-root1","fstype":"ext4"}]}'
FSTAB_BYTES = b'{"filesystems":[]}'


def result(stdout=b"", stderr=b"", returncode=0):
    return subprocess.CompletedProcess((), returncode, stdout, stderr)


def real(entries):
    return json.dumps({"filesystems": entries}).encode()


class DriveDiscoveryAdapterTests(unittest.TestCase):
    def successful_mock(self, lsblk=LSBLK_BYTES, root=FINDMNT_BYTES,
                        all_real=REAL_BYTES, swap=b"", fstab=FSTAB_BYTES):
        return patch("drive_discovery_adapter.subprocess.run", side_effect=[
            result(lsblk), result(root), result(all_real), result(swap), result(fstab),
        ])

    def test_commands_and_subprocess_boundary_are_fixed(self):
        self.assertEqual(LSBLK_COMMAND, (
            "lsblk", "--json", "--bytes", "--output",
            "NAME,KNAME,PATH,TYPE,SIZE,MODEL,SERIAL,TRAN,ROTA,RM,RO,WWN,PKNAME,FSTYPE,MOUNTPOINTS,UUID,PARTUUID,LABEL",
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
        self.assertEqual(FSTAB_COMMAND, (
            "findmnt", "--fstab", "--json", "--list", "--output",
            "TARGET,SOURCE,FSTYPE",
        ))
        with self.successful_mock() as run:
            collect_current_drive_discovery()
        common = dict(shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                      stderr=subprocess.PIPE, check=False, timeout=5,
                      env=SAFE_COMMAND_ENV)
        self.assertEqual(run.call_args_list, [
            call(command, **common) for command in (
                LSBLK_COMMAND, FINDMNT_ROOT_COMMAND, FINDMNT_REAL_COMMAND,
                SWAPON_COMMAND, FSTAB_COMMAND,
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
        self.assertEqual(snapshot.captured_findmnt_fstab_json, FSTAB_BYTES)
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
        for index in range(5):
            effects = [result(LSBLK_BYTES), result(FINDMNT_BYTES),
                       result(REAL_BYTES), result(), result(FSTAB_BYTES)]
            effects[index] = result(returncode=7)
            with self.subTest(index=index), patch(
                    "drive_discovery_adapter.subprocess.run", side_effect=effects), \
                    self.assertRaises(DiscoveryCollectionError):
                collect_current_drive_discovery()

    def test_each_command_timeout_fails_closed(self):
        for index in range(5):
            effects = [result(LSBLK_BYTES), result(FINDMNT_BYTES),
                       result(REAL_BYTES), result(), result(FSTAB_BYTES)]
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
        for index in range(5):
            for stream in ("stdout", "stderr"):
                effects = [result(LSBLK_BYTES), result(FINDMNT_BYTES),
                           result(REAL_BYTES), result(), result(FSTAB_BYTES)]
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
        for index in range(5):
            effects = [result(LSBLK_BYTES), result(FINDMNT_BYTES),
                       result(REAL_BYTES), result(), result(FSTAB_BYTES)]
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


    def test_configured_identity_forms_protect_unmounted_parent(self):
        forms = (
            "UUID=id-u",
            "PARTUUID=id-p",
            "LABEL=id-l",
            "/dev/disk/by-uuid/id-u",
            "/dev/disk/by-partuuid/id-p",
            "/dev/disk/by-label/id-l",
            "/dev/configured",
        )
        for source in forms:
            lsblk = json.dumps({
                "blockdevices": [
                    {
                        "name": "rootdisk",
                        "path": "/dev/rootdisk",
                        "type": "disk",
                        "size": 4096,
                        "serial": "SYN-ROOT",
                        "children": [
                            {
                                "name": "rootpart",
                                "path": "/dev/syn-root1",
                                "type": "part",
                            }
                        ],
                    },
                    {
                        "name": "configureddisk",
                        "path": "/dev/configureddisk",
                        "type": "disk",
                        "size": 8192,
                        "serial": "SYN-CONFIGURED",
                        "children": [
                            {
                                "name": "configured",
                                "path": "/dev/configured",
                                "type": "part",
                                "uuid": "id-u",
                                "partuuid": "id-p",
                                "label": "id-l",
                            }
                        ],
                    },
                ]
            }).encode()

            configured = real([
                {
                    "target": "/boot",
                    "source": source,
                    "fstype": "ext4",
                }
            ])

            with self.subTest(source=source), self.successful_mock(
                lsblk=lsblk,
                fstab=configured,
            ):
                snapshot = collect_current_drive_discovery()

            drives = {
                drive.path: drive
                for drive in snapshot.drives
            }

            self.assertEqual(
                snapshot.protected_sources,
                ("/dev/syn-root1", "/dev/configured"),
            )
            self.assertTrue(drives["/dev/rootdisk"].system)
            self.assertTrue(drives["/dev/configureddisk"].system)


    def test_configured_var_and_component_descendant_are_critical(self):
        for target in ("/var", "/var/lib/data"):
            configured = real([{"target": target, "source": "/dev/boot", "fstype": "ext4"}])
            with self.subTest(target=target), self.successful_mock(fstab=configured):
                self.assertIn("/dev/boot", collect_current_drive_discovery().protected_sources)

    def test_configured_identifier_zero_duplicate_and_unsupported_fail_closed(self):
        duplicate = json.dumps({"blockdevices": [
            {"name": "disk", "path": "/dev/disk", "type": "disk", "serial": "ID",
             "children": [{"name": "root", "path": "/dev/syn-root1", "type": "part"},
                          {"name": "a", "path": "/dev/a", "type": "part", "uuid": "dup"},
                          {"name": "b", "path": "/dev/b", "type": "part", "uuid": "dup"}]}]}).encode()
        cases = ((LSBLK_BYTES, "UUID=missing"), (duplicate, "UUID=dup"),
                 (LSBLK_BYTES, "disk-specification"))
        for lsblk, source in cases:
            configured = real([{"target": "/boot", "source": source, "fstype": "ext4"}])
            with self.subTest(source=source), self.successful_mock(lsblk=lsblk, fstab=configured), \
                    self.assertRaises(DiscoveryCollectionError):
                collect_current_drive_discovery()

    def test_ordinary_and_network_configured_entries_do_not_protect(self):
        entries = [{"target": target, "source": "/dev/boot", "fstype": "ext4"}
                   for target in ("/home", "/mnt", "/media", "/run/media/x", "/srv", "/opt")]
        entries += [{"target": "/home", "source": "server:/share", "fstype": "nfs"},
                    {"target": "/mnt", "source": "//server/share", "fstype": "cifs"}]
        with self.successful_mock(fstab=real(entries)):
            self.assertEqual(collect_current_drive_discovery().protected_sources,
                             ("/dev/syn-root1",))

    def test_configured_file_swap_is_evidence_only(self):
        configured = real([{"target": "none", "source": "/swap.img", "fstype": "swap"}])
        with self.successful_mock(fstab=configured):
            snapshot = collect_current_drive_discovery()
        self.assertEqual(snapshot.captured_findmnt_fstab_json, configured)
        self.assertEqual(snapshot.protected_sources, ("/dev/syn-root1",))

    def test_inactive_configured_swap_identity_forms_are_protected(self):
        lsblk = json.dumps({
            "blockdevices": [
                {
                    "name": "rootdisk",
                    "path": "/dev/rootdisk",
                    "type": "disk",
                    "size": 4096,
                    "serial": "SYN-ROOT",
                    "children": [
                        {
                            "name": "rootpart",
                            "path": "/dev/syn-root1",
                            "type": "part",
                        }
                    ],
                },
                {
                    "name": "swapdisk",
                    "path": "/dev/swapdisk",
                    "type": "disk",
                    "size": 8192,
                    "serial": "SYN-SWAP",
                    "children": [
                        {
                            "name": "swap",
                            "path": "/dev/swap",
                            "type": "part",
                            "uuid": "su",
                            "partuuid": "sp",
                            "label": "sl",
                        }
                    ],
                },
            ]
        }).encode()

        for source in (
            "/dev/swap",
            "UUID=su",
            "PARTUUID=sp",
            "LABEL=sl",
            "/dev/disk/by-uuid/su",
            "/dev/disk/by-partuuid/sp",
            "/dev/disk/by-label/sl",
        ):
            configured = real([
                {
                    "target": "none",
                    "source": source,
                    "fstype": "swap",
                }
            ])

            with self.subTest(source=source), self.successful_mock(
                lsblk=lsblk,
                fstab=configured,
            ):
                snapshot = collect_current_drive_discovery()

            drives = {
                drive.path: drive
                for drive in snapshot.drives
            }

            self.assertIn(
                "/dev/swap",
                snapshot.protected_sources,
            )
            self.assertTrue(drives["/dev/rootdisk"].system)
            self.assertTrue(drives["/dev/swapdisk"].system)


    def test_malformed_fstab_json_and_relevant_entries_fail_closed(self):
        documents = (b"{", b"[]", b"{}", b'{"filesystems":{}}',
                     real([42]), real([{"target": "/boot", "source": 3, "fstype": "ext4"}]),
                     real([{"target": "/boot", "source": "/dev/boot", "fstype": None}]))
        for document in documents:
            with self.subTest(document=document), self.successful_mock(fstab=document), \
                    self.assertRaises(DiscoveryCollectionError):
                collect_current_drive_discovery()

    def test_configured_dedup_and_order_are_deterministic(self):
        configured = real([
            {"target": "/var", "source": "/dev/swap", "fstype": "ext4"},
            {"target": "/boot", "source": "/dev/boot", "fstype": "ext4"},
            {"target": "/etc", "source": "/dev/boot", "fstype": "ext4"},
            {"target": "/usr", "source": "/dev/syn-root1", "fstype": "ext4"},
        ])
        with self.successful_mock(fstab=configured):
            snapshot = collect_current_drive_discovery()
        self.assertEqual(snapshot.protected_sources,
                         ("/dev/syn-root1", "/dev/boot", "/dev/swap"))


    def test_coverage_crypttab_blank_active_and_malformed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary, "crypttab")
            path.write_text("  # comment\n\n")
            _check_crypttab(str(path))
            for content in ("vault /dev/synthetic none luks\n", "only-one-field\n"):
                path.write_text(content)
                with self.subTest(content=content), self.assertRaises(DiscoveryCollectionError):
                    _check_crypttab(str(path))

    def test_coverage_resume_absent_disabled_active_and_malformed(self):
        with tempfile.TemporaryDirectory() as temporary:
            cmdline = Path(temporary, "cmdline")
            resume = Path(temporary, "resume")
            cmdline.write_text("quiet synthetic=1\n")
            _check_resume(str(cmdline), str(resume))
            cmdline.write_text("quiet resume=none\n")
            resume.write_text("RESUME=none\n")
            _check_resume(str(cmdline), str(resume))
            for kernel, config in (("resume=/dev/synthetic", ""),
                                   ("quiet", "RESUME=/dev/synthetic"),
                                   ("quiet", "RESUME")):
                cmdline.write_text(kernel)
                resume.write_text(config)
                with self.subTest(kernel=kernel, config=config), self.assertRaises(DiscoveryCollectionError):
                    _check_resume(str(cmdline), str(resume))

    def test_coverage_systemd_snap_native_swap_and_fake(self):
        snap = """[Mount]\nWhat=/var/lib/snapd/snaps/sample_7.snap\nWhere=/snap/sample/7\nType=squashfs\n"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unit = root / "snap-sample-7.mount"
            unit.write_text(snap)
            _check_systemd_units(str(root))
            unit.rename(root / "snap-fake-7.mount")
            with self.assertRaises(DiscoveryCollectionError):
                _check_systemd_units(str(root))
        for name in ("native.mount", "native.swap"):
            with tempfile.TemporaryDirectory() as temporary:
                Path(temporary, name).write_text("[Mount]\nWhat=/dev/synthetic\nWhere=/mnt/x\n")
                with self.subTest(name=name), self.assertRaises(DiscoveryCollectionError):
                    _check_systemd_units(temporary)

    def test_coverage_systemd_symlinks_masks_and_bounds(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.symlink("/dev/null", root / "masked.mount")
            _check_systemd_units(str(root))
            os.symlink("/dev/synthetic", root / "suspicious.swap")
            with self.assertRaises(DiscoveryCollectionError):
                _check_systemd_units(str(root))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            Path(root, "a").write_text("")
            Path(root, "b").write_text("")
            with self.assertRaises(DiscoveryCollectionError):
                _check_systemd_units(str(root), max_entries=1)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            Path(root, "native.mount").write_text("x" * 3)
            with self.assertRaises(DiscoveryCollectionError):
                _check_systemd_units(str(root), max_unit_bytes=2)
            with self.assertRaises(DiscoveryCollectionError):
                _check_systemd_units(str(root), max_total_bytes=2)

    def test_coverage_systemd_malformed_and_unreadable_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary, "snap-sample-7.mount")
            path.write_bytes(b"\xff")
            with self.assertRaises(DiscoveryCollectionError):
                _check_systemd_units(temporary)
        with patch("drive_discovery_adapter.os.scandir", side_effect=PermissionError()), \
                self.assertRaises(DiscoveryCollectionError):
            _check_systemd_units("/synthetic-fixed-root")

    def test_coverage_special_topology_layers_fail_closed(self):
        for kind in ("crypt", "lvm", "dm", "md", "md127", "raid0", "raid10"):
            document = json.dumps({"blockdevices": [{"type": "disk", "children": [
                {"type": kind}]}]}).encode()
            with self.subTest(kind=kind), self.assertRaises(DiscoveryCollectionError):
                _check_special_topology(document)
        _check_special_topology(b'{"blockdevices":[{"type":"disk","children":[{"type":"part"}]}]}')

    def test_coverage_mdadm_array_and_irrelevant_configuration(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary, "mdadm.conf")
            path.write_text("# ARRAY ignored\nDEVICE partitions\n")
            _check_mdadm((str(path), str(Path(temporary, "absent"))))
            path.write_text("ARRAY /dev/md/synthetic metadata=1.2\n")
            with self.assertRaises(DiscoveryCollectionError):
                _check_mdadm((str(path),))
            path.write_text("ARRAY\n")
            with self.assertRaises(DiscoveryCollectionError):
                _check_mdadm((str(path),))

    def test_coverage_lvm_backup_absent_empty_and_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            absent = str(Path(temporary, "absent"))
            _check_lvm_backup(absent)
            backup = Path(temporary, "backup")
            backup.mkdir()
            _check_lvm_backup(str(backup))
            Path(backup, "synthetic-vg").write_text("metadata is intentionally not read")
            with self.assertRaises(DiscoveryCollectionError):
                _check_lvm_backup(str(backup))

    def test_snap_exact_squashfs_type_is_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            Path(temporary, "snap-sample-7.mount").write_text(
                "[Mount]\nWhat=/var/lib/snapd/snaps/sample_7.snap\n"
                "Where=/snap/sample/7\nType=squashfs\n")
            _check_systemd_units(temporary)

    def test_snap_missing_type_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            Path(temporary, "snap-sample-7.mount").write_text(
                "[Mount]\nWhat=/var/lib/snapd/snaps/sample_7.snap\n"
                "Where=/snap/sample/7\n")
            with self.assertRaises(DiscoveryCollectionError):
                _check_systemd_units(temporary)

    def test_snap_non_squashfs_type_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            Path(temporary, "snap-sample-7.mount").write_text(
                "[Mount]\nWhat=/var/lib/snapd/snaps/sample_7.snap\n"
                "Where=/snap/sample/7\nType=ext4\n")
            with self.assertRaises(DiscoveryCollectionError):
                _check_systemd_units(temporary)

    def test_snap_duplicate_type_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            Path(temporary, "snap-sample-7.mount").write_text(
                "[Mount]\nWhat=/var/lib/snapd/snaps/sample_7.snap\n"
                "Where=/snap/sample/7\nType=squashfs\nType=squashfs\n")
            with self.assertRaises(DiscoveryCollectionError):
                _check_systemd_units(temporary)

    def test_empty_lvm_backup_directory_is_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            backup = Path(temporary, "backup")
            backup.mkdir()
            _check_lvm_backup(str(backup))

    def test_lvm_regular_metadata_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            backup = Path(temporary, "backup")
            backup.mkdir()
            Path(backup, "synthetic-vg").write_text("metadata is intentionally not read")
            with self.assertRaises(DiscoveryCollectionError):
                _check_lvm_backup(str(backup))

    def test_lvm_subdirectory_entry_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            backup = Path(temporary, "backup")
            backup.mkdir()
            Path(backup, "nested").mkdir()
            with self.assertRaises(DiscoveryCollectionError):
                _check_lvm_backup(str(backup))

    def test_lvm_symlink_entry_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            backup = Path(temporary, "backup")
            backup.mkdir()
            os.symlink("missing-target", backup / "synthetic-link")
            with self.assertRaises(DiscoveryCollectionError):
                _check_lvm_backup(str(backup))

    def test_coverage_paths_are_not_publicly_substitutable(self):
        parameters = inspect.signature(collect_current_drive_discovery).parameters
        for name in ("crypttab_path", "cmdline_path", "resume_path", "systemd_path",
                     "mdadm_path", "lvm_backup_path"):
            self.assertNotIn(name, parameters)
            with self.assertRaises(TypeError):
                collect_current_drive_discovery(**{name: "/synthetic"})


if __name__ == "__main__":
    unittest.main()
