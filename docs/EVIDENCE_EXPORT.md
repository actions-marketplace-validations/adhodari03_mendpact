# Evidence export

`mendpact export-report` converts an existing report to a small, privacy-minimized artifact for
human review. It runs offline and does not discover a server, load credentials, call a provider,
execute an MCP tool, or publish files. This command is development-branch functionality until a
release containing it is published; do not expect it in the older `v0.2.0` Action.

## Quick start

With a current MendPact checkout installed, use a saved report:

```bash
mkdir -p reports
mendpact export-report guard-report.json --output reports/evidence.html
```

Open `reports/evidence.html` in a browser. It contains no JavaScript, external assets, network
links, or embedded raw source report, and includes a restrictive Content Security Policy.
Printing uses the browser's print dialog. The HTML is self-contained and can be attached to a
review after inspection; it is not automatically added to GitHub Pages.

For a zero-network example that does not need a running MCP server:

```bash
mendpact export-report examples/contracts/candidate-scan.json \
  --output reports/example-evidence.html
```

For machine consumption:

```bash
mendpact export-report guard-report.json \
  --format json --output reports/evidence.json
```

Each invocation creates one file. Create its parent directory first and choose a new filename
for a later export. The command refuses existing files, directories, symlink destinations, and
output directories with symlink ancestors. It writes to a same-directory temporary file and
atomically links the finished file into place without replacement. Output files are initially
owner-readable and owner-writable (`0600`) on supported POSIX filesystems. Copying or uploading
them changes their access boundary; file permissions are not encryption.

## Data contract and privacy boundary

Supported sources are `mendpact.scan.v1`, `mendpact.behavior.v1`, and `mendpact.guard.v1`.
Other report types, including model comparison, calibration, and conformance, are intentionally
not supported yet. The source must be a regular, non-symlink file of at most 10 MiB. Duplicate
JSON keys, non-finite JSON constants, malformed inputs, and unsupported schemas are rejected.

The versioned evidence JSON contains:

| Field | Meaning |
| --- | --- |
| `source_schema` | Supported source report format |
| `source_sha256` | SHA-256 of the exact original bytes, not a signature |
| `source_generated_at` | Timestamp supplied by the original report |
| `recorded_status` | Original passed, failed, or error outcome |
| `sections` | Stage statuses and allowlisted aggregate metrics |
| `notice`, `privacy` | Evidence limitations and sharing boundary |

Current scan and guard exports use `mendpact.evidence.v2` and require an `Evidence mode` metric so
live capture and offline deterministic recheck cannot be confused. Behavior-only exports remain
`mendpact.evidence.v1`. Existing v1 scan and guard summaries remain readable; regenerate a package
to add the explicit evidence-mode label. When a recheck contains a deterministic rule-impact
delta, the minimized export adds introduced, resolved, reclassified, and unchanged counts as one
all-or-none metric group. It omits the affected rule IDs and subjects.

The exporter constructs an allowlist projection rather than copying and trying to redact the
original JSON. It omits target URLs, IDs, server/tool/model names, catalog descriptions and
schemas, scenario text, arguments, tool-selection names, provider responses and response IDs,
raw errors, policy names, OAuth metadata, and waiver approver/reason/date fields. Source-provided
free text is never included in output or validation error messages. No `--include-private` mode
is provided.

Counts, thresholds, timestamps, stage outcomes, and file digests can still reveal information
about a project. Review even this minimized output before sharing. This is not anonymization or
a promise that an attacker cannot encode information into numeric source fields. Raw source
reports remain sensitive and are never bundled with the export.

## Interpreting the evidence

Scan counts are rebuilt from findings and capability nodes. Completed scan status must agree
with its severity threshold and recorded waiver presence. Completed behavior reports undergo
the existing trace/summary consistency checks; their grades are supplied evidence, not freshly
executed tests. Contract counts are rebuilt from changes, and completed contract status must
agree with its impact threshold and recorded waiver presence. Guard validates stage statuses,
target/scan linkage, and the aggregate outcome.

Recorded errors remain errors, including partial runs. A missing guard stage is skipped, not
passed. The exporter does not re-evaluate historical waiver expiry, rerun a grader against an
MCP schema, or establish the authenticity of the input. Replay is labelled as recorded replay;
other drivers are labelled as provider-labelled traces that have not been authenticated.

For example, a scan may pass with a high finding when its recorded failure threshold is critical.
The export shows both facts. It must not be described as a clean security bill of health.

The SHA-256 lets a reviewer who already has the private original identify the exact source:

```bash
shasum -a 256 guard-report.json
```

Formatting changes alter this digest. It proves neither who produced a report nor that a real
provider request took place. Signed attestations and public publication are separate future work.

## CI integration

Keep `scan`, `evaluate`, or `guard` as the reliability gate. Run the exporter afterwards using a
MendPact version that includes this command:

```yaml
- name: Export review summary
  if: always() && hashFiles('guard-report.json') != ''
  run: |
    mkdir -p reports
    mendpact export-report guard-report.json --output reports/evidence.html
```

Exit code `0` means export succeeded, even if the source outcome was failed or error. Exit code
`2` means input validation or writing failed. There is no export exit code `1`. Never replace the
original gate with the exporter or suppress the original gate's failure to generate a summary.

Publication or artifact upload is a separate consuming-workflow decision. An uploaded artifact
may be visible to people with access to the workflow, especially in a public repository. Use an
explicit short retention period such as 14 days and avoid broad upload globs that include the
raw report. The repository CI exports committed fixtures only; these are not customer evidence.

## Local verification

```bash
python -m pytest tests/test_evidence.py
python -m ruff check .
python -m mypy src
```

Tests cover minimization, HTML escaping, blocked network access, source integrity, source and
output safety, failed/error/skipped states, malformed inputs, and CLI behavior.
