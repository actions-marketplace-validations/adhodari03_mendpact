# Local run history

History is an offline foundation for reviewing reliability over time. It builds on the
[evidence exporter](EVIDENCE_EXPORT.md), uses Python's bundled SQLite library, and requires no
new package, account, hosted database, MCP connection, model request, or provider credential.
It is development-branch functionality until a release containing it is published.

## Import and inspect

```bash
mkdir -p reports
mendpact history add examples/contracts/baseline-scan.json
mendpact history add examples/contracts/candidate-scan.json
mendpact history list
```

Only original `mendpact.scan.v1`, `mendpact.behavior.v1`, and `mendpact.guard.v1` reports are
accepted. An already-exported evidence summary lacks the target and comparison context needed
to import safely. Source validation reuses the exporter's bounded, single-read path. Validation
failure occurs before creating a database.

The default database is `reports/history.sqlite`. Its parent must already exist. Each subcommand
accepts `--database /absolute/path/to/history.sqlite` for an alternative private store.

Entries have local integer IDs. Always use returned IDs, not assumed consecutive numbers:
duplicates and deleted entries can leave gaps. Imports deduplicate by exact source-file SHA-256,
not by source-reported run ID. Identical bytes return the original entry and import timestamp.
Changing formatting produces a different digest and therefore a separate import.

Listing uses import order, newest first. The source capture time is also shown and may be old,
out of order, or supplied without a timezone. History does not verify that timestamp.

```bash
mendpact history list --limit 20
mendpact history list --limit 20 --before-id 42
```

The maximum page size is 100. Read commands never create a missing database and open an existing
database read-only. Imports use SQLite transactions and a unique source-digest constraint so
concurrent writes to an initialized store do not create duplicate entries. Concurrent first-time
initialization may require retrying one command; schema validation fails closed.

## Compare two entries

```bash
mendpact history compare 1 2 --output reports/history-comparison.json
```

The first ID is the reference and the second is the candidate. Use IDs from your own store. The
terminal renders a side-by-side table; `--output` optionally creates a new
`mendpact.history-comparison.v1` JSON artifact. Existing output files are never overwritten.

| Check | Behavior |
| --- | --- |
| Different exact target URL | Reject the comparison |
| Different source report type | Reject the comparison |
| Changed policy, waiver, or behavior-regression baseline evidence | Warn that verdicts may use different gates |
| Changed driver/model identity | Warn; this is not proof of model equivalence |
| Changed behavior suite/scenarios/catalog names/repetitions | Show both sides but withhold behavior numeric deltas |
| Changed contract baseline identity | Show both sides but withhold contract numeric deltas |
| Missing, skipped, or error stage | Withhold numeric deltas |
| Reversed or timezone-free source timestamps | Warn about chronology |

Numeric deltas are candidate minus reference for integer aggregate counts. Pass-rate strings and
thresholds are shown side by side without pretending rounded display values are precise numeric
measurements. No overall regression score, confidence interval, or automatic pass/fail verdict
is produced. A source status change is displayed literally, not labelled as an improvement.

The behavior context fingerprint includes scenario definitions, tool-catalog names, suite name,
and repetitions; scenario and catalog ordering does not matter. Original behavior reports do not
contain full server schemas, so equal fingerprints cannot prove that server schemas were equal.
Similarly, contract baseline identity is a source-supplied ID and target, not a digest of the
original baseline's contents. Source-file fingerprints are not signatures or live-call proofs.

Scan-count changes are descriptive only. Equal counts cannot establish that the same findings,
tools, or schemas were present. Use the full `diff`, `guard`, or `compare-models` commands with
original reports for actual CI decisions. Error/partial reports can be stored for troubleshooting,
but do not become complete evidence by being imported.

## What is stored

The database has an application identifier and schema version; unknown SQLite files or future
versions are rejected without attempting a migration. Each row stores:

- a local import ID and UTC import timestamp;
- the exact original file digest;
- the versioned minimized evidence summary;
- SHA-256 fingerprints of comparison context (target, policy, behavior setup, producer identity,
  and contract baseline identity where applicable).

Raw target URLs, report paths, source run IDs, prompts, arguments, names, provider responses,
credentials, and raw errors are not copied into the database. The source is read once and kept
transiently to calculate the summary and fingerprints. Stored counts and statuses are still
sensitive project information. Context hashes may be guessable for low-entropy inputs; they are
not anonymization, encryption, or authenticated signatures.

New databases use file permissions `0600`. Existing stores with group/other permissions,
symlinks in the path, hard-linked files, and non-regular files are refused. Keep the directory
private and do not use a shared writable or concurrently renamed directory. Path checks are
not a defense against an attacker controlling your filesystem or process. The current filesystem
safety implementation targets the same POSIX environments as evidence export (macOS/Linux).

The project ignores `reports/`, SQLite databases, and their journal/WAL/SHM sidecars. If you use
history in another repository, add the store directory and SQLite sidecars to that repository's
ignore rules before importing. Never publish the database, place it in the website source, or
upload it as a workflow artifact. Optional comparison JSON omits context fingerprints, but still
needs review before sharing its counts, outcomes, and source digests.

Local database files are user-controlled. Validation detects malformed entries but does not
authenticate them. Do not treat a database received from somebody else as trustworthy evidence.

## Explicit 14-day cleanup

```bash
mendpact history prune
```

This is read-only: it reports how many entries were imported **at least 14 days ago**. Entries
exactly 14 days old qualify. Import time, not the source's historical capture time, defines age.
Duplicates do not extend retention. Entries remain visible and present on disk until you run:

```bash
mendpact history prune --apply
```

`--apply` deletes eligible rows in a transaction. No original source report is deleted. There is
no history undo; you can reimport retained originals, which creates a new import lifetime. SQLite
secure-delete mode is enabled for writes, but this is logical cleanup, not a guarantee of secure
erasure from backups, snapshots, SSDs, or external copies. Cleanup is not scheduled automatically.
The 14-day window is intentionally not extended by a CLI override.

## Exit codes and CI

All successful history operations return `0`, including an import of failed/error evidence,
a descriptive comparison showing worse counts, and a prune dry run. Invalid input, unknown IDs,
incompatible target/type, unsafe storage, database errors, and output failures return `2`.
History does not use exit code `1` and must not replace a reliability gate.

The repository CI imports committed scan fixtures, verifies deduplication and comparison output,
and previews cleanup. It uploads only the fixture comparison JSON with the existing 14-day
fixture-evidence artifact. It does not upload the SQLite database or delete retained user history.

## Next boundary

This is local history, not a hosted beta. Project accounts, authorization, access-controlled
storage, explicit publication consent, hosted retention/deletion, and signing still require
separate implementation and review. No paid service or credential custody is introduced here.
