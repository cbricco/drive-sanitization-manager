# Version 1 Scope — Records Foundation

## Purpose

Build the non-destructive recordkeeping foundation for Drive Sanitization
Manager.

The first implementation must operate entirely on synthetic data and must not
access, alter, sanitize, mount, unmount, or otherwise operate on real storage
devices.

## Phase 2 Auto Lab Job 1

Implement:

1. A batch record model.
2. A per-drive record model.
3. Durable JSON serialization/storage.
4. Loading previously saved records without losing supported fields.
5. CSV export suitable for later customer delivery.
6. Validation of required identifiers and statuses.
7. Focused automated tests.
8. Synthetic examples/fixtures only.

## Batch Fields

The data model should be able to preserve at least:

- schema/version identifier
- batch/job ID
- customer/organization reference
- customer job/reference number
- date received
- authorization/reference notes
- processing date
- operator/technician
- total drive count
- overall batch status
- final batch disposition
- general notes
- creation timestamp
- last-updated timestamp

Customer fields must be generic. Real customer names/data must not appear in
tracked fixtures or examples.

## Per-Drive Identity Fields

Each drive record should be able to preserve at least:

- internal record ID
- batch/job ID
- customer asset tag
- manufacturer
- model
- serial number
- capacity in bytes
- human-readable capacity when reporting
- media type
- interface/connection type
- Linux device path
- stable device identifier
- intake date/time
- operator
- physical/initial-condition notes

## Safety / Intake Fields

Each record should be able to preserve:

- mounted status
- system/protected-drive determination
- protection reason
- health/SMART summary when later available
- intended action
- intended disposition
- sanitization eligibility/status

The Job 1 implementation does not need to inspect real devices. These fields
are records only and will be populated using synthetic data during testing.

## Sanitization Fields

The record must have durable places for later population of:

- sanitization status
- sanitization method
- wiping/sanitization tool
- tool version
- sanitization start timestamp
- sanitization end timestamp
- result
- failure/error information
- bytes/errors or other relevant outcome measurements
- operator notes

A failed or incomplete sanitization attempt must still leave a durable record.

## Verification Fields

The record must preserve places for:

- verification required
- verification method
- verification tool
- verification timestamp
- verification result
- verification failure/details
- reviewer/operator
- notes

## Evidence Fields

The record must support references to preserved evidence such as:

- raw sanitization log
- raw verification log
- source/intake record
- report path
- evidence hashes where appropriate

The data model should store references/metadata rather than embedding arbitrary
large logs directly into the main record.

## Final Disposition Fields

The record should preserve:

- final status
- final disposition
- disposition date/time
- return/reuse/destruction/other classification
- disposition notes

## Durable Storage Requirements

JSON is the authoritative full-record format for Version 1.

Requirements:

- records survive program restart;
- supported fields round-trip without loss;
- existing records are not silently overwritten;
- malformed records fail clearly;
- unsupported schema versions fail clearly;
- unknown or ambiguous required information is not guessed;
- writes should avoid leaving a falsely complete record after interruption.

## CSV Export Requirements

CSV is the initial customer-transfer/reporting format.

The export should:

- produce one row per drive;
- include useful batch identifiers;
- include drive identity;
- include customer asset/reference fields;
- include sanitization method/status/result;
- include verification method/result;
- include processing dates;
- include final disposition;
- preserve failure/review-needed status;
- contain no invented values;
- open normally in common spreadsheet software.

The full JSON record may contain more information than the CSV.

## Privacy Requirements

Real customer data must never be used in tracked examples or automated tests.

Runtime/customer storage locations must remain excluded by `.gitignore`.

Portfolio examples should use obviously synthetic organizations, serial
numbers, asset tags, and device identifiers.

## Acceptance Criteria

Job 1 is acceptable only when:

1. Synthetic batches and drive records can be created.
2. Records can be saved to JSON.
3. Saved records can be loaded with no supported-field loss.
4. Multiple drive records can belong to one batch.
5. CSV export produces correct per-drive rows.
6. Failed/incomplete sanitization states can be represented.
7. Verification states can be represented.
8. Customer/reference fields survive JSON and CSV processing.
9. Malformed/unsupported persisted data fails clearly.
10. Existing output protection is tested.
11. No real-device access exists.
12. No destructive command exists.
13. Tests use synthetic data only.
14. Automated tests pass.
15. Actual generated files/diffs are reviewed before promotion.

## Explicitly Out of Scope for Job 1

- `/dev` enumeration
- `lsblk` integration
- SMART execution
- root privileges
- mounting/unmounting
- disk wiping
- ATA Secure Erase
- NVMe Sanitize
- `nwipe`
- `shred`
- `dd`
- partition modification
- filesystem modification
- real customer data
- network access
- automatic promotion
- commit
- push
