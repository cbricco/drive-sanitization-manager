import csv
import json
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

from drive_sanitization_manager import (
    BatchRecord,
    DriveRecord,
    MalformedRecordError,
    OutputExistsError,
    UnsupportedSchemaVersionError,
    export_csv,
    load_json,
    save_json,
)


class RecordsFoundationTests(unittest.TestCase):
    def make_batch(self):
        drives = [
            DriveRecord(
                internal_record_id="DRV-SYN-001", batch_job_id="JOB-SYN-100", customer_asset_tag="ASSET-SYN-A",
                manufacturer="ExampleDriveCo", model="SyntheticSSD", serial_number="SYN-SERIAL-001",
                capacity_bytes=1000000000, capacity_human="1 GB", media_type="SSD", interface_type="SATA",
                linux_device_path="synthetic://drive-a", stable_device_identifier="synthetic-id-a",
                intake_timestamp="2026-01-02T09:00:00Z", operator="Tech Example",
                initial_condition_notes="Synthetic fixture; intact", mounted=False, system_protected=False,
                protection_reason=None, health_smart_summary="Synthetic summary only", intended_action="sanitize",
                intended_disposition="reuse", sanitization_eligibility_status="eligible",
                sanitization_status="failed", sanitization_method="synthetic overwrite simulation",
                sanitization_tool="SyntheticTool", sanitization_tool_version="1.0",
                sanitization_start_timestamp="2026-01-03T10:00:00Z",
                sanitization_end_timestamp="2026-01-03T10:05:00Z", sanitization_result="failed",
                sanitization_failure_error="Synthetic write error", sanitization_measurements={"bytes_processed": 512},
                sanitization_operator_notes="Retain for review", verification_required=True,
                verification_method="synthetic sample", verification_tool="SyntheticVerifier",
                verification_timestamp="2026-01-03T10:06:00Z", verification_result="failed",
                verification_failure_details="Sanitization did not complete",
                verification_reviewer_operator="Reviewer Example", verification_notes="Review required",
                raw_sanitization_log_reference="evidence/synthetic-wipe.log",
                raw_verification_log_reference="evidence/synthetic-verify.log",
                source_intake_record_reference="intake/SYN-001", report_path_reference="reports/SYN-001.csv",
                evidence_hashes={"synthetic-wipe.log": "sha256:synthetic-not-real"}, final_status="failed",
                final_disposition="quarantine", disposition_timestamp="2026-01-03T11:00:00Z",
                disposition_classification="other", disposition_notes="Synthetic failed unit",
            ),
            DriveRecord(
                internal_record_id="DRV-SYN-002", batch_job_id="JOB-SYN-100", customer_asset_tag="ASSET-SYN-B",
                serial_number="SYN-SERIAL-002", sanitization_eligibility_status="review_needed",
                sanitization_status="incomplete", sanitization_result="interrupted synthetic attempt",
                sanitization_failure_error="Synthetic interruption", verification_required=True,
                verification_result="review_needed", verification_failure_details="Verification pending",
                final_status="incomplete", final_disposition="hold for review",
            ),
        ]
        return BatchRecord(
            batch_job_id="JOB-SYN-100", customer_organization_reference="Synthetic Organization Alpha",
            customer_job_reference_number="CUST-SYN-REF-77", date_received="2026-01-02",
            authorization_reference_notes="Synthetic authorization REF-SYN-AUTH",
            processing_date="2026-01-03", operator_technician="Tech Example", total_drive_count=2,
            overall_batch_status="review_needed", final_batch_disposition="partial hold",
            general_notes="Entirely synthetic test batch", creation_timestamp="2026-01-02T08:00:00Z",
            last_updated_timestamp="2026-01-03T12:00:00Z", drives=drives,
        )

    def test_multiple_drives_and_json_round_trip_all_fields(self):
        batch = self.make_batch()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.json"
            save_json(batch, path)
            loaded = load_json(path)
        self.assertEqual(loaded, batch)
        self.assertEqual(asdict(loaded), asdict(batch))
        self.assertEqual(len(loaded.drives), 2)

    def test_csv_one_row_per_drive_and_preserves_references_and_states(self):
        batch = self.make_batch()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.csv"
            export_csv(batch, path)
            with path.open(encoding="utf-8-sig", newline="") as stream:
                rows = list(csv.DictReader(stream))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["customer_organization_reference"], "Synthetic Organization Alpha")
        self.assertEqual(rows[1]["customer_job_reference_number"], "CUST-SYN-REF-77")
        self.assertEqual(rows[0]["customer_asset_tag"], "ASSET-SYN-A")
        self.assertEqual(rows[0]["sanitization_status"], "failed")
        self.assertEqual(rows[1]["sanitization_status"], "incomplete")
        self.assertEqual(rows[0]["verification_result"], "failed")
        self.assertEqual(rows[1]["verification_result"], "review_needed")
        self.assertEqual(rows[1]["final_status"], "incomplete")

    def test_malformed_json_and_malformed_record_fail_clearly(self):
        with tempfile.TemporaryDirectory() as directory:
            invalid_json = Path(directory) / "invalid.json"
            invalid_json.write_text("{broken", encoding="utf-8")
            with self.assertRaisesRegex(MalformedRecordError, "malformed JSON"):
                load_json(invalid_json)
            invalid_record = Path(directory) / "invalid-record.json"
            invalid_record.write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
            with self.assertRaisesRegex(MalformedRecordError, "missing fields"):
                load_json(invalid_record)

    def test_unsupported_schema_version_fails_clearly(self):
        data = asdict(self.make_batch())
        data["schema_version"] = 99
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "future.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(UnsupportedSchemaVersionError, "unsupported schema version 99"):
                load_json(path)

    def test_json_and_csv_never_overwrite_existing_outputs(self):
        batch = self.make_batch()
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "record.json"
            csv_path = Path(directory) / "report.csv"
            json_path.write_text("KEEP JSON", encoding="utf-8")
            csv_path.write_text("KEEP CSV", encoding="utf-8")
            with self.assertRaises(OutputExistsError):
                save_json(batch, json_path)
            with self.assertRaises(OutputExistsError):
                export_csv(batch, csv_path)
            self.assertEqual(json_path.read_text(encoding="utf-8"), "KEEP JSON")
            self.assertEqual(csv_path.read_text(encoding="utf-8"), "KEEP CSV")

    def test_record_existence_does_not_imply_success(self):
        drive = DriveRecord(internal_record_id="DRV-SYN-DEFAULT", batch_job_id="JOB-SYN-DEFAULT")
        self.assertEqual(drive.sanitization_status, "not_started")
        self.assertIsNone(drive.sanitization_result)
        self.assertEqual(drive.verification_result, "not_performed")
        self.assertEqual(drive.final_status, "pending")

    def test_invalid_required_status_is_rejected(self):
        batch = self.make_batch()
        batch.drives[0].sanitization_status = "probably fine"
        with self.assertRaisesRegex(MalformedRecordError, "sanitization_status"):
            batch.validate()


if __name__ == "__main__":
    unittest.main()
