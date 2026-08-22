import csv
import io
import tempfile
import unittest
from pathlib import Path

from drive_sanitization_cli import (
    add_drive,
    create_batch,
    format_batch,
    main,
    transition_batch_intake,
    transition_drive_intake,
)
from drive_sanitization_manager import (
    DuplicateIdentifierError,
    InvalidStatusTransitionError,
    load_json,
)


class DriveSanitizationCLITests(unittest.TestCase):
    def make_batch(self):
        return create_batch(
            batch_job_id="JOB-SYN-CLI-1",
            customer_organization_reference="Synthetic Organization",
            customer_job_reference_number="SYN-REF-1",
            date_received="2026-08-20",
            operator_technician="Synthetic Technician",
            creation_timestamp="2026-08-20T09:00:00Z",
            last_updated_timestamp="2026-08-20T09:00:00Z",
        )

    def invoke(self, arguments):
        output = io.StringIO()
        errors = io.StringIO()
        result = main(arguments, stdout=output, stderr=errors)
        return result, output.getvalue(), errors.getvalue()

    def _create_args(self, output):
        return [
            "create", "--batch-job-id", "JOB-SYN-CLI-BOUNDARY",
            "--customer-organization-reference", "Synthetic Organization",
            "--customer-job-reference-number", "SYN-REF-BOUNDARY",
            "--date-received", "2026-08-21",
            "--operator-technician", "Synthetic Technician",
            "--creation-timestamp", "2026-08-21T09:00:00Z",
            "--last-updated-timestamp", "2026-08-21T09:00:00Z",
            "--output", str(output),
        ]

    def test_create_batch_through_cli_logic(self):
        batch = self.make_batch()
        self.assertEqual(batch.batch_job_id, "JOB-SYN-CLI-1")
        self.assertEqual(batch.intake_status, "pending")
        self.assertEqual(batch.total_drive_count, 0)

    def test_add_drive_and_show_recorded_state(self):
        batch = self.make_batch()
        drive = add_drive(
            batch,
            internal_record_id="DRV-SYN-CLI-1",
            customer_asset_tag="ASSET-SYN-1",
            manufacturer="Synthetic Manufacturer",
            model="Synthetic Model",
            serial_number="SERIAL-SYN-1",
            capacity_bytes=1000,
            capacity_human="1 kB",
            media_type="synthetic-media",
            interface_type="synthetic-interface",
            stable_device_identifier="STABLE-SYN-1",
        )
        drive.intake_review_notes = "Synthetic review note"
        shown = format_batch(batch)
        self.assertEqual(drive.batch_job_id, batch.batch_job_id)
        self.assertEqual(batch.total_drive_count, 1)
        self.assertIn("Drive: DRV-SYN-CLI-1", shown)
        self.assertIn("Internal record ID: DRV-SYN-CLI-1", shown)
        self.assertIn("Customer asset tag: ASSET-SYN-1", shown)
        self.assertIn("Manufacturer: Synthetic Manufacturer", shown)
        self.assertIn("Model: Synthetic Model", shown)
        self.assertIn("Serial number: SERIAL-SYN-1", shown)
        self.assertIn("Capacity: 1 kB", shown)
        self.assertNotIn("Capacity: 1000", shown)
        self.assertIn("Media type: synthetic-media", shown)
        self.assertIn("Interface type: synthetic-interface", shown)
        self.assertIn("Stable device identifier: STABLE-SYN-1", shown)
        self.assertIn("Intake status: pending", shown)
        self.assertIn("Sanitization status: not_started", shown)
        self.assertIn("Sanitization eligibility: unknown", shown)
        self.assertIn("Final status: pending", shown)
        self.assertIn("Intake review notes: Synthetic review note", shown)

    def test_show_omits_absent_identity_and_falls_back_to_capacity_bytes(self):
        batch = self.make_batch()
        add_drive(batch, internal_record_id="DRV-SYN-CLI-MIN", capacity_bytes=2048)
        shown = format_batch(batch)
        self.assertIn("Capacity: 2048 bytes", shown)
        self.assertNotIn("Customer asset tag:", shown)
        self.assertNotIn("Manufacturer:", shown)
        self.assertNotIn("Serial number:", shown)

    def test_controlled_drive_and_batch_intake_transitions(self):
        batch = self.make_batch()
        add_drive(batch, internal_record_id="DRV-SYN-CLI-1")
        transition_drive_intake(batch, "DRV-SYN-CLI-1", "in_progress")
        transition_drive_intake(batch, "DRV-SYN-CLI-1", "complete")
        transition_batch_intake(batch, "complete")
        self.assertEqual(batch.drives[0].intake_status, "complete")
        self.assertEqual(batch.intake_status, "complete")
        self.assertEqual(batch.drives[0].sanitization_status, "not_started")

    def test_duplicate_identifier_error_is_clear(self):
        batch = self.make_batch()
        add_drive(batch, internal_record_id="DRV-SYN-CLI-1", serial_number="SERIAL-SYN-1")
        with self.assertRaisesRegex(DuplicateIdentifierError, "serial_number"):
            add_drive(batch, internal_record_id="DRV-SYN-CLI-2", serial_number=" serial-syn-1 ")

    def test_duplicate_identifier_through_cli_is_controlled_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.json"
            first_drive = root / "first-drive.json"
            duplicate_output = root / "duplicate.json"
            self.assertEqual(self.invoke(self._create_args(source))[0], 0)
            self.assertEqual(self.invoke([
                "add-drive", str(source), "--internal-record-id", "DRV-SYN-CLI-DUP-1",
                "--serial-number", "SERIAL-SYN-DUP", "--output", str(first_drive),
            ])[0], 0)
            result, _, errors = self.invoke([
                "add-drive", str(first_drive), "--internal-record-id", "DRV-SYN-CLI-DUP-2",
                "--serial-number", " serial-syn-dup ", "--output", str(duplicate_output),
            ])
            self.assertNotEqual(result, 0)
            self.assertIn("serial_number", errors)
            self.assertIn("unique", errors)
            self.assertNotIn("Traceback", errors)
            self.assertFalse(duplicate_output.exists())

    def test_premature_transition_error_is_clear(self):
        batch = self.make_batch()
        add_drive(batch, internal_record_id="DRV-SYN-CLI-1")
        with self.assertRaisesRegex(InvalidStatusTransitionError, "every drive"):
            transition_batch_intake(batch, "complete")
        with self.assertRaisesRegex(InvalidStatusTransitionError, "cannot change"):
            transition_drive_intake(batch, "DRV-SYN-CLI-1", "complete")

    def test_premature_batch_intake_through_cli_is_controlled_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.json"
            with_drive = root / "with-drive.json"
            premature_output = root / "premature.json"
            self.assertEqual(self.invoke(self._create_args(source))[0], 0)
            self.assertEqual(self.invoke([
                "add-drive", str(source), "--internal-record-id", "DRV-SYN-CLI-PREMATURE",
                "--output", str(with_drive),
            ])[0], 0)
            result, _, errors = self.invoke([
                "batch-intake", str(with_drive), "--status", "complete",
                "--output", str(premature_output),
            ])
            self.assertNotEqual(result, 0)
            self.assertIn("every drive intake is complete", errors)
            self.assertNotIn("Traceback", errors)
            self.assertFalse(premature_output.exists())

    def test_cli_save_reopen_resume_and_csv_export(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.json"
            second = root / "second.json"
            report = root / "report.csv"
            create_args = [
                "create", "--batch-job-id", "JOB-SYN-CLI-2",
                "--customer-organization-reference", "Synthetic Organization",
                "--customer-job-reference-number", "SYN-REF-2",
                "--date-received", "2026-08-21",
                "--operator-technician", "Synthetic Technician",
                "--creation-timestamp", "2026-08-21T09:00:00Z",
                "--last-updated-timestamp", "2026-08-21T09:00:00Z",
                "--output", str(first),
            ]
            result, _, errors = self.invoke(create_args)
            self.assertEqual((result, errors), (0, ""))
            result, _, errors = self.invoke([
                "add-drive", str(first), "--internal-record-id", "DRV-SYN-CLI-2",
                "--serial-number", "SERIAL-SYN-2", "--output", str(second),
            ])
            self.assertEqual((result, errors), (0, ""))
            resumed = load_json(second)
            self.assertEqual(resumed.drives[0].internal_record_id, "DRV-SYN-CLI-2")
            result, _, errors = self.invoke(["export-csv", str(second), "--output", str(report)])
            self.assertEqual((result, errors), (0, ""))
            with report.open(encoding="utf-8-sig", newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(rows[0]["serial_number"], "SERIAL-SYN-2")

    def test_no_overwrite_returns_controlled_error_and_preserves_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "existing.json"
            target.write_text("KEEP", encoding="utf-8")
            result, _, errors = self.invoke([
                "create", "--batch-job-id", "JOB-SYN-CLI-3",
                "--customer-organization-reference", "Synthetic Organization",
                "--customer-job-reference-number", "SYN-REF-3",
                "--date-received", "2026-08-21",
                "--operator-technician", "Synthetic Technician",
                "--creation-timestamp", "2026-08-21T09:00:00Z",
                "--last-updated-timestamp", "2026-08-21T09:00:00Z",
                "--output", str(target),
            ])
            self.assertNotEqual(result, 0)
            self.assertIn("refusing to overwrite", errors)
            self.assertEqual(target.read_text(encoding="utf-8"), "KEEP")

    def test_intake_completion_is_not_presented_as_sanitization_completion(self):
        batch = self.make_batch()
        add_drive(batch, internal_record_id="DRV-SYN-CLI-4")
        transition_drive_intake(batch, "DRV-SYN-CLI-4", "in_progress")
        transition_drive_intake(batch, "DRV-SYN-CLI-4", "complete")
        transition_batch_intake(batch, "complete")
        shown = format_batch(batch)
        self.assertIn("intake completion records inventory only", shown)
        self.assertIn("Sanitization status: not_started", shown)
        self.assertNotIn("Sanitization status: complete", shown)

    def test_ordinary_invalid_input_returns_error_without_traceback(self):
        result, _, errors = self.invoke([
            "create", "--batch-job-id", " ",
            "--customer-organization-reference", "Synthetic Organization",
            "--customer-job-reference-number", "SYN-REF-4",
            "--date-received", "2026-08-21",
            "--operator-technician", "Synthetic Technician",
            "--creation-timestamp", "2026-08-21T09:00:00Z",
            "--last-updated-timestamp", "2026-08-21T09:00:00Z",
            "--output", "unused.json",
        ])
        self.assertNotEqual(result, 0)
        self.assertIn("batch_job_id", errors)
        self.assertNotIn("Traceback", errors)

    def test_argparse_type_error_is_controlled(self):
        result, _, errors = self.invoke([
            "add-drive", "missing.json", "--internal-record-id", "DRV-SYN-CLI-5",
            "--capacity-bytes", "not-a-number", "--output", "unused.json",
        ])
        self.assertNotEqual(result, 0)
        self.assertIn("invalid int value", errors)
        self.assertNotIn("Traceback", errors)


if __name__ == "__main__":
    unittest.main()
