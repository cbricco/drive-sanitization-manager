# Drive Sanitization Manager

Drive Sanitization Manager is a Python/Linux utility being developed to
help technicians inventory drives, preserve processing records, and produce
clear reports without treating recordkeeping as proof that sanitization
occurred.

The current version provides a non-destructive records and technician-intake
workflow. Physical-drive discovery and sanitization are not implemented.

## Version 1 Goal

The first version focuses on safe recordkeeping and technician intake before
any destructive drive operation is added.

It currently helps a technician:

- create and reopen batch records;
- manually identify and record drives;
- preserve customer and asset references;
- review useful drive identity and intake information from the command line;
- move drive and batch intake through controlled status changes;
- keep durable per-drive and per-batch JSON records;
- preserve fields for later sanitization and verification results;
- export records to CSV;
- refuse to silently overwrite existing output files;
- preserve failed, incomplete, or review-needed states instead of hiding them;
- keep real customer data separate from public portfolio examples.

Completing intake does not mark a drive as sanitized or verified.

## Safety Direction

Current development and automated tests use synthetic drive information only.

The current non-destructive implementation does NOT:

- erase a drive;
- run a disk-wiping command;
- access real `/dev` devices;
- require root;
- mount or unmount filesystems;
- modify partition tables;
- contain real customer information.

Any future destructive capability will require a separate safety and
authorization gate.

## Customer Data

Real customer records, device information, raw logs, and private reports must
not be committed to this public portfolio repository.

Tracked examples and tests must use synthetic data only.

## Development Status

Implemented:

1. Drive and batch record model
2. Durable JSON storage and reload
3. CSV export
4. Automated tests using synthetic data
5. Technician intake workflow with controlled status transitions
6. Non-destructive technician command-line interface

Planned for later stages:

7. Read-only Linux drive discovery
8. Safety and protected-device detection
9. Media-appropriate sanitization planning
10. Separately reviewed destructive-operation integration
11. Verification and customer reporting

The project does not claim that a drive has been securely sanitized merely
because a record exists. Sanitization results must come from an actual,
verified process.
