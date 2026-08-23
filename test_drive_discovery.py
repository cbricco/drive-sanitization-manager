import copy
import json
import unittest

from drive_discovery import DiscoveryError, parse_lsblk_json


class DriveDiscoveryTests(unittest.TestCase):
    def parse(self, devices, **kwargs):
        return parse_lsblk_json(json.dumps({"blockdevices": devices}), **kwargs)

    def test_sata_disk_children_and_identity_are_preserved(self):
        drives = self.parse([{
            "name": "syn-a", "kname": "syn-a", "path": "/dev/syn-a",
            "type": "disk", "size": 1000, "model": "SYN-MODEL-001",
            "serial": "SYN-SERIAL-001", "wwn": "SYN-WWN-001",
            "tran": "sata", "rota": True, "rm": False, "ro": False,
            "children": [{"name": "syn-a1", "path": "/dev/syn-a1",
                          "type": "part", "pkname": "syn-a", "fstype": "ext4"}],
        }])
        self.assertEqual(len(drives), 1)
        drive = drives[0]
        self.assertEqual((drive.serial, drive.wwn, drive.transport),
                         ("SYN-SERIAL-001", "SYN-WWN-001", "sata"))
        self.assertEqual(drive.children[0].parent_name, "syn-a")
        self.assertEqual(drive.children[0].filesystem_type, "ext4")

    def test_nvme_partition_is_child_not_physical_drive(self):
        drives = self.parse([{
            "name": "syn-nvme0n1", "path": "/dev/syn-nvme0n1", "type": "disk",
            "size": 2000, "serial": "SYN-SERIAL-002", "tran": "nvme",
            "children": [{"name": "syn-nvme0n1p1", "path": "/dev/syn-nvme0n1p1",
                          "type": "part"}],
        }])
        self.assertEqual([d.name for d in drives], ["syn-nvme0n1"])
        self.assertEqual(drives[0].children[0].name, "syn-nvme0n1p1")

    def test_top_level_partition_and_loop_are_excluded(self):
        self.assertEqual(self.parse([
            {"name": "syn-a1", "type": "part"},
            {"name": "loop-syn", "type": "loop"},
        ]), ())

    def test_usb_removable_observations(self):
        drive = self.parse([{
            "name": "syn-usb", "path": "/dev/syn-usb", "type": "disk",
            "size": 500, "serial": "SYN-SERIAL-USB", "tran": "usb", "rm": 1,
        }])[0]
        self.assertTrue(drive.removable)
        self.assertEqual(drive.transport, "usb")

    def test_missing_serial_and_wwn_remain_none_and_require_review(self):
        drive = self.parse([{"name": "syn-a", "path": "/dev/syn-a",
                             "type": "disk", "size": 10}])[0]
        self.assertIsNone(drive.serial)
        self.assertIsNone(drive.wwn)
        self.assertTrue(drive.review_required)
        self.assertFalse(hasattr(drive, "eligible"))

    def test_duplicate_strong_identity_fails_closed(self):
        drives = self.parse([
            {"name": "syn-a", "type": "disk", "serial": "SYN-SERIAL-DUP"},
            {"name": "syn-b", "type": "disk", "serial": "SYN-SERIAL-DUP"},
        ])
        for drive in drives:
            self.assertTrue(drive.protected)
            self.assertTrue(drive.review_required)
            self.assertTrue(drive.ambiguous)
            self.assertIn("duplicate strong identity", drive.review_reasons[0])

    def test_protected_descendant_protects_parent(self):
        drive = self.parse([{
            "name": "syn-a", "path": "/dev/syn-a", "type": "disk",
            "serial": "SYN-SERIAL-003",
            "children": [{"name": "syn-a2", "path": "/dev/syn-a2", "type": "part"}],
        }], protected_sources=("/dev/syn-a2",))[0]
        self.assertTrue(drive.protected)
        self.assertEqual(drive.protection_reasons,
                         ("protected source /dev/syn-a2 matches disk or descendant",))

    def test_mounted_descendant_is_observed_on_parent(self):
        drive = self.parse([{
            "name": "syn-a", "type": "disk", "serial": "SYN-SERIAL-004",
            "children": [{"name": "syn-a1", "type": "part",
                          "mountpoints": [None, "/synthetic/mount"]}],
        }])[0]
        self.assertTrue(drive.mounted)
        self.assertEqual(drive.observed_mountpoints, ("/synthetic/mount",))

    def test_unmounted_is_observation_not_eligibility(self):
        drive = self.parse([{"name": "syn-a", "type": "disk",
                             "serial": "SYN-SERIAL-005", "mountpoints": [None]}])[0]
        self.assertFalse(drive.mounted)
        self.assertFalse(hasattr(drive, "authorized"))
        self.assertFalse(hasattr(drive, "safe_to_wipe"))

    def test_zero_byte_removable_requires_review(self):
        drive = self.parse([{"name": "syn-zero", "type": "disk", "size": 0,
                             "rm": True, "serial": "SYN-SERIAL-ZERO"}])[0]
        self.assertTrue(drive.review_required)
        self.assertIn("reported size is zero bytes", drive.review_reasons)

    def test_malformed_json_and_top_level_shapes(self):
        with self.assertRaises(DiscoveryError):
            parse_lsblk_json("{")
        for value in ([], None, {"blockdevices": {}}, {}):
            with self.subTest(value=value), self.assertRaises(DiscoveryError):
                parse_lsblk_json(json.dumps(value))

    def test_malformed_device_and_children_structures(self):
        malformed = [42, {"name": "syn-a", "children": {}},
                     {"name": "syn-a", "mountpoints": "bad"}]
        for item in malformed:
            with self.subTest(item=item), self.assertRaises(DiscoveryError):
                self.parse([item])

    def test_missing_optional_metadata_is_not_invented(self):
        drive = self.parse([{"type": "disk"}])[0]
        for field in ("name", "kname", "path", "size", "model", "serial",
                      "transport", "rotational", "removable", "read_only", "wwn"):
            self.assertIsNone(getattr(drive, field))

    def test_caller_object_not_mutated(self):
        source = {"blockdevices": [{"name": "syn-a", "type": "disk",
                                     "children": [{"name": "syn-a1", "type": "part"}]}]}
        before = copy.deepcopy(source)
        parse_lsblk_json(json.dumps(source))
        self.assertEqual(source, before)

    def test_results_and_reason_ordering_are_deterministic(self):
        source = json.dumps({"blockdevices": [
            {"name": "syn-b", "type": "disk", "serial": "SYN-SERIAL-DUP",
             "children": [{"name": "syn-b1", "type": "part", "mountpoint": "/z"}]},
            {"name": "syn-a", "type": "disk", "serial": "SYN-SERIAL-DUP"},
        ]})
        first = parse_lsblk_json(source, protected_sources=("/dev/syn-b1",))
        second = parse_lsblk_json(source, protected_sources=("/dev/syn-b1",))
        self.assertEqual(first, second)
        self.assertEqual([drive.name for drive in first], ["syn-b", "syn-a"])

    def test_bytes_input(self):
        result = parse_lsblk_json(b'{"blockdevices": []}')
        self.assertEqual(result, ())


    def test_strict_byte_sizes(self):
        for value in ("not-a-number", -1, 1.5, "1000", True, {}, []):
            with self.subTest(value=value), self.assertRaises(DiscoveryError):
                self.parse([{"type": "disk", "size": value}])

    def test_unknown_size_remains_none(self):
        drive = self.parse([{"type": "disk", "size": None,
                             "serial": "SYN-SERIAL-SIZE"}])[0]
        self.assertIsNone(drive.size)

    def test_normalized_duplicate_serial_preserves_reported_values(self):
        drives = self.parse([
            {"name": "syn-a", "type": "disk", "serial": " SYN-SERIAL-DUP "},
            {"name": "syn-b", "type": "disk", "serial": "syn-serial-dup"},
        ])
        self.assertEqual([drive.serial for drive in drives],
                         [" SYN-SERIAL-DUP ", "syn-serial-dup"])
        for drive in drives:
            self.assertTrue(drive.protected)
            self.assertTrue(drive.ambiguous)
            self.assertTrue(drive.review_required)
            self.assertFalse(drive.system)

    def test_normalized_duplicate_wwn_preserves_reported_values(self):
        drives = self.parse([
            {"name": "syn-a", "type": "disk", "wwn": "0xABCDEF"},
            {"name": "syn-b", "type": "disk", "wwn": "0xabcdef"},
        ])
        self.assertEqual([drive.wwn for drive in drives], ["0xABCDEF", "0xabcdef"])
        for drive in drives:
            self.assertTrue(drive.protected)
            self.assertTrue(drive.ambiguous)
            self.assertFalse(drive.system_protected)

    def test_invalid_or_unmatched_protected_source_raises(self):
        devices = [{"name": "syn-a", "path": "/dev/syn-a", "type": "disk"}]
        for source in ("/dev/not-reported", "", "   ", 42, None):
            with self.subTest(source=source), self.assertRaises(DiscoveryError):
                self.parse(devices, protected_sources=(source,))

    def test_matched_descendant_is_system_storage(self):
        drive = self.parse([{
            "name": "syn-root", "type": "disk", "serial": "SYN-SERIAL-ROOT",
            "children": [{"name": "syn-root2", "path": "/dev/syn-root2",
                          "type": "part"}],
        }], protected_sources=("/dev/syn-root2",))[0]
        self.assertTrue(drive.protected)
        self.assertTrue(drive.system)
        self.assertTrue(drive.system_protected)

    def test_no_destructive_authority_observations(self):
        drive = self.parse([{"type": "disk"}])[0]
        for field in ("eligible", "sanitization_eligible", "authorized", "approved",
                      "safe_to_wipe", "wipe_allowed"):
            self.assertFalse(hasattr(drive, field))


    def test_whitespace_only_serial_requires_review(self):
        drive = self.parse([{"type": "disk", "serial": "   "}])[0]
        self.assertEqual(drive.serial, "   ")
        self.assertTrue(drive.review_required)
        self.assertIn("missing strong identity", drive.review_reasons[0])

    def test_whitespace_only_wwn_requires_review(self):
        drive = self.parse([{"type": "disk", "wwn": "\t "}])[0]
        self.assertEqual(drive.wwn, "\t ")
        self.assertTrue(drive.review_required)
        self.assertIn("missing strong identity", drive.review_reasons[0])

    def test_blank_serial_and_usable_wwn_are_preserved(self):
        drive = self.parse([{
            "type": "disk", "serial": "   ", "wwn": " SYN-WWN-OK "
        }])[0]
        self.assertEqual((drive.serial, drive.wwn), ("   ", " SYN-WWN-OK "))
        self.assertFalse(drive.review_required)

    def test_blank_serials_are_not_duplicate_identity(self):
        drives = self.parse([
            {"name": "syn-blank-a", "type": "disk", "serial": "   "},
            {"name": "syn-blank-b", "type": "disk", "serial": "   "},
        ])
        for drive in drives:
            self.assertTrue(drive.review_required)
            self.assertFalse(drive.ambiguous)
            self.assertFalse(drive.protected)
            self.assertNotIn("duplicate strong identity", " ".join(drive.review_reasons))

    def test_missing_or_null_top_level_type_raises(self):
        for device in ({"name": "syn-untyped"},
                       {"name": "syn-null-type", "type": None}):
            with self.subTest(device=device), self.assertRaises(DiscoveryError):
                self.parse([device])

    def test_empty_or_whitespace_type_raises(self):
        for value in ("", "   ", "\t"):
            with self.subTest(value=value), self.assertRaises(DiscoveryError):
                self.parse([{"name": "syn-bad-type", "type": value}])

    def test_child_missing_type_raises(self):
        with self.assertRaises(DiscoveryError):
            self.parse([{
                "name": "syn-parent", "type": "disk",
                "children": [{"name": "syn-untyped-child"}],
            }])

    def test_duplicate_physical_disk_path_raises(self):
        with self.assertRaises(DiscoveryError):
            self.parse([
                {"name": "syn-path-a", "path": "/dev/syn-dup", "type": "disk"},
                {"name": "syn-path-b", "path": "/dev/syn-dup", "type": "disk"},
            ])

    def test_overlapping_descendant_identifier_raises(self):
        with self.assertRaises(DiscoveryError):
            self.parse([
                {"name": "syn-tree-a", "type": "disk", "children": [
                    {"name": "syn-shared-child", "type": "part"}
                ]},
                {"name": "syn-tree-b", "type": "disk", "children": [
                    {"path": "/dev/syn-shared-child", "type": "part"}
                ]},
            ])

    def test_protected_source_matching_multiple_trees_raises(self):
        with self.assertRaises(DiscoveryError):
            self.parse([
                {"name": "syn-protected-a", "type": "disk", "children": [
                    {"name": "syn-protected-shared", "type": "part"}
                ]},
                {"name": "syn-protected-b", "type": "disk", "children": [
                    {"kname": "syn-protected-shared", "type": "part"}
                ]},
            ], protected_sources=("/dev/syn-protected-shared",))

    def test_unique_physical_disk_topology_parses(self):
        drives = self.parse([
            {"name": "syn-unique-a", "path": "/dev/syn-unique-a",
             "type": "disk", "serial": "SYN-UNIQUE-A", "children": [
                 {"name": "syn-unique-a1", "type": "part"}
             ]},
            {"name": "syn-unique-b", "path": "/dev/syn-unique-b",
             "type": "disk", "serial": "SYN-UNIQUE-B", "children": [
                 {"name": "syn-unique-b1", "type": "part"}
             ]},
        ])
        self.assertEqual([drive.name for drive in drives],
                         ["syn-unique-a", "syn-unique-b"])

    def test_matched_protected_descendant_still_yields_system_true(self):
        drive = self.parse([{
            "name": "syn-system", "type": "disk", "serial": "SYN-SYSTEM-ID",
            "children": [{"name": "syn-system1", "type": "part"}],
        }], protected_sources=("/dev/syn-system1",))[0]
        self.assertTrue(drive.system)
        self.assertTrue(drive.system_protected)

    def test_final_model_has_no_destructive_authority_fields(self):
        drive = self.parse([{"type": "disk"}])[0]
        for field in ("eligible", "authorized", "approved", "safe_to_wipe",
                      "wipe_allowed", "destructive_authority"):
            self.assertFalse(hasattr(drive, field))


if __name__ == "__main__":
    unittest.main()
