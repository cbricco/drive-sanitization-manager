# Drive Sanitization Manager

Drive Sanitization Manager is a planned Python/Linux utility for safely
inventorying drives, preserving sanitization records, and producing clear
customer-facing reports.

The project is being developed in stages.

## Version 1 Goal

The first version focuses on safe recordkeeping before any destructive drive
operation is added.

It will help a technician:

- identify and record each drive;
- preserve customer and asset references;
- keep durable per-drive and per-batch records;
- record sanitization and verification results;
- export customer-friendly records to CSV;
- preserve failed or incomplete attempts instead of losing them;
- keep real customer data separate from public portfolio examples.

## Safety Direction

Initial development uses synthetic drive information only.

The first development stage will NOT:

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

## Planned Development

1. Drive/batch record model
2. Durable JSON storage
3. CSV export
4. Automated tests using synthetic data
5. Read-only Linux drive discovery
6. Safety/protected-device detection
7. Sanitization planning
8. Separately reviewed destructive-operation integration
9. Verification and customer reporting

The project does not claim that a drive has been securely sanitized merely
because a record exists. Sanitization results must come from an actual,
verified process.
