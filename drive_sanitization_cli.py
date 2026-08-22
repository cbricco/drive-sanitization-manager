"""Technician-facing CLI for non-destructive intake record management."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence, TextIO

from drive_sanitization_manager import (
    BatchRecord,
    DriveRecord,
    RecordError,
    export_csv,
    load_json,
    save_json,
)


class CLIError(ValueError):
    """An input or command error suitable for display to a technician."""


class TechnicianArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CLIError(message)


def optional_text(value: str | None) -> str | None:
    """Turn omitted or blank optional input into an unknown value."""
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def create_batch(
    *, batch_job_id: str, customer_organization_reference: str,
    customer_job_reference_number: str, date_received: str,
    operator_technician: str, creation_timestamp: str,
    last_updated_timestamp: str, overall_batch_status: str = "received",
    authorization_reference_notes: str | None = None,
    processing_date: str | None = None,
    final_batch_disposition: str | None = None,
    general_notes: str | None = None,
) -> BatchRecord:
    """Create and validate one manually supplied batch record."""
    batch = BatchRecord(
        batch_job_id=batch_job_id,
        customer_organization_reference=customer_organization_reference,
        customer_job_reference_number=customer_job_reference_number,
        date_received=date_received,
        authorization_reference_notes=optional_text(authorization_reference_notes),
        processing_date=optional_text(processing_date),
        operator_technician=operator_technician,
        overall_batch_status=overall_batch_status,
        final_batch_disposition=optional_text(final_batch_disposition),
        general_notes=optional_text(general_notes),
        creation_timestamp=creation_timestamp,
        last_updated_timestamp=last_updated_timestamp,
    )
    batch.validate()
    return batch


def add_drive(
    batch: BatchRecord, *, internal_record_id: str,
    customer_asset_tag: str | None = None, manufacturer: str | None = None,
    model: str | None = None, serial_number: str | None = None,
    capacity_bytes: int | None = None, capacity_human: str | None = None,
    media_type: str | None = None, interface_type: str | None = None,
    stable_device_identifier: str | None = None,
    intake_timestamp: str | None = None, operator: str | None = None,
    initial_condition_notes: str | None = None,
) -> DriveRecord:
    """Add a manually supplied drive through the model's checked operation."""
    drive = DriveRecord(
        internal_record_id=internal_record_id,
        batch_job_id=batch.batch_job_id,
        customer_asset_tag=optional_text(customer_asset_tag),
        manufacturer=optional_text(manufacturer),
        model=optional_text(model),
        serial_number=optional_text(serial_number),
        capacity_bytes=capacity_bytes,
        capacity_human=optional_text(capacity_human),
        media_type=optional_text(media_type),
        interface_type=optional_text(interface_type),
        stable_device_identifier=optional_text(stable_device_identifier),
        intake_timestamp=optional_text(intake_timestamp),
        operator=optional_text(operator),
        initial_condition_notes=optional_text(initial_condition_notes),
    )
    batch.add_drive(drive)
    return drive


def transition_drive_intake(batch: BatchRecord, internal_record_id: str, status: str) -> DriveRecord:
    """Find a drive and apply its model-controlled intake transition."""
    drive = next((item for item in batch.drives if item.internal_record_id == internal_record_id), None)
    if drive is None:
        raise CLIError(f"drive record not found: {internal_record_id}")
    drive.transition_intake(status)
    return drive


def transition_batch_intake(batch: BatchRecord, status: str) -> None:
    """Apply the model-controlled batch intake transition."""
    batch.transition_intake(status)


def format_batch(batch: BatchRecord) -> str:
    """Render recorded state with intake and sanitization clearly separated."""
    batch.validate()
    lines = [
        f"Batch: {batch.batch_job_id}",
        f"Intake status: {batch.intake_status}",
        f"Overall recorded batch status: {batch.overall_batch_status}",
        f"Recorded drives: {len(batch.drives)}",
        "Safety: intake completion records inventory only; it is not sanitization completion.",
    ]
    if batch.intake_review_notes:
        lines.append(f"Intake review notes: {batch.intake_review_notes}")
    if not batch.drives:
        lines.append("Drives: none recorded")
    for drive in batch.drives:
        lines.append(f"Drive: {drive.internal_record_id}")
        identity_fields = (
            ("Internal record ID", drive.internal_record_id),
            ("Customer asset tag", drive.customer_asset_tag),
            ("Manufacturer", drive.manufacturer),
            ("Model", drive.model),
            ("Serial number", drive.serial_number),
            ("Capacity", drive.capacity_human if drive.capacity_human is not None else (
                f"{drive.capacity_bytes} bytes" if drive.capacity_bytes is not None else None
            )),
            ("Media type", drive.media_type),
            ("Interface type", drive.interface_type),
            ("Stable device identifier", drive.stable_device_identifier),
        )
        for label, value in identity_fields:
            if value is not None:
                lines.append(f"  {label}: {value}")
        lines.extend((
            f"  Intake status: {drive.intake_status}",
            f"  Sanitization status: {drive.sanitization_status}",
            f"  Sanitization eligibility: {drive.sanitization_eligibility_status}",
            f"  Final status: {drive.final_status}",
        ))
        if drive.intake_review_notes:
            lines.append(f"  Intake review notes: {drive.intake_review_notes}")
    return "\n".join(lines) + "\n"


def _add_batch_fields(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--batch-job-id", required=True)
    parser.add_argument("--customer-organization-reference", required=True)
    parser.add_argument("--customer-job-reference-number", required=True)
    parser.add_argument("--date-received", required=True)
    parser.add_argument("--operator-technician", required=True)
    parser.add_argument("--creation-timestamp", required=True)
    parser.add_argument("--last-updated-timestamp", required=True)
    parser.add_argument("--overall-batch-status", default="received")
    parser.add_argument("--authorization-reference-notes")
    parser.add_argument("--processing-date")
    parser.add_argument("--final-batch-disposition")
    parser.add_argument("--general-notes")


def _add_drive_fields(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--internal-record-id", required=True)
    parser.add_argument("--customer-asset-tag")
    parser.add_argument("--manufacturer")
    parser.add_argument("--model")
    parser.add_argument("--serial-number")
    parser.add_argument("--capacity-bytes", type=int)
    parser.add_argument("--capacity-human")
    parser.add_argument("--media-type")
    parser.add_argument("--interface-type")
    parser.add_argument("--stable-device-identifier")
    parser.add_argument("--intake-timestamp")
    parser.add_argument("--operator")
    parser.add_argument("--initial-condition-notes")


def build_parser() -> argparse.ArgumentParser:
    parser = TechnicianArgumentParser(
        prog="drive-sanitization-manager",
        description="Manage manually supplied intake records without performing sanitization.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    create = commands.add_parser("create", help="create a new batch JSON record")
    _add_batch_fields(create)
    create.add_argument("--output", required=True, type=Path)

    add = commands.add_parser("add-drive", help="add a drive and write a new JSON record")
    add.add_argument("record", type=Path)
    add.add_argument("--output", required=True, type=Path)
    _add_drive_fields(add)

    show = commands.add_parser("show", help="show a saved batch and its drives")
    show.add_argument("record", type=Path)

    drive_status = commands.add_parser("drive-intake", help="change one drive's intake status")
    drive_status.add_argument("record", type=Path)
    drive_status.add_argument("--internal-record-id", required=True)
    drive_status.add_argument("--status", required=True)
    drive_status.add_argument("--output", required=True, type=Path)

    batch_status = commands.add_parser("batch-intake", help="change batch intake status")
    batch_status.add_argument("record", type=Path)
    batch_status.add_argument("--status", required=True)
    batch_status.add_argument("--output", required=True, type=Path)

    csv_command = commands.add_parser("export-csv", help="export the existing CSV report")
    csv_command.add_argument("record", type=Path)
    csv_command.add_argument("--output", required=True, type=Path)
    return parser


def _public_values(namespace: argparse.Namespace, excluded: set[str]) -> dict[str, object]:
    return {name: value for name, value in vars(namespace).items() if name not in excluded}


def run(namespace: argparse.Namespace, stdout: TextIO) -> None:
    command = namespace.command
    if command == "create":
        batch = create_batch(**_public_values(namespace, {"command", "output"}))
        save_json(batch, namespace.output)
        stdout.write(f"Created batch record: {namespace.output}\n")
    elif command == "show":
        stdout.write(format_batch(load_json(namespace.record)))
    elif command == "add-drive":
        batch = load_json(namespace.record)
        drive = add_drive(batch, **_public_values(namespace, {"command", "record", "output"}))
        save_json(batch, namespace.output)
        stdout.write(f"Added drive {drive.internal_record_id}; wrote new record: {namespace.output}\n")
    elif command == "drive-intake":
        batch = load_json(namespace.record)
        drive = transition_drive_intake(batch, namespace.internal_record_id, namespace.status)
        save_json(batch, namespace.output)
        stdout.write(f"Drive {drive.internal_record_id} intake status: {drive.intake_status}\n")
    elif command == "batch-intake":
        batch = load_json(namespace.record)
        transition_batch_intake(batch, namespace.status)
        save_json(batch, namespace.output)
        stdout.write(f"Batch intake status: {batch.intake_status}\n")
    elif command == "export-csv":
        batch = load_json(namespace.record)
        export_csv(batch, namespace.output)
        stdout.write(f"Exported CSV report: {namespace.output}\n")
    else:
        raise CLIError(f"unsupported command: {command}")


def main(
    argv: Sequence[str] | None = None,
    *, stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run the CLI and return a process-style result without ordinary tracebacks."""
    output = stdout if stdout is not None else sys.stdout
    errors = stderr if stderr is not None else sys.stderr
    try:
        namespace = build_parser().parse_args(argv)
        run(namespace, output)
    except (CLIError, RecordError, OSError, ValueError) as exc:
        errors.write(f"Error: {exc}\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
