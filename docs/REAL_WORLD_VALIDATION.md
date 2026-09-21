# Real-world validation playbook

Purpose: discover interoperability defects, misleading findings, and onboarding friction on
independently developed MCP servers. This is a small qualitative study, not a security audit or
benchmark. The setup is implemented; external target validation has not yet been performed by
this workflow. The local evidence API remains deferred.

## 1. Select and authorize targets

Start with two or three independently maintained implementations, preferably locally runnable
with synthetic data. Record an exact upstream commit/image digest, license, installation steps,
expected capabilities, and permission to test. Read/review upstream startup instructions before
running third-party code; use an isolated environment with no production credentials or mounts.
Public accessibility is not permission to test an endpoint. Do not run a bulk target list.

Cover a small read-only catalog, a richer schema/resource catalog, and (if explicitly approved)
an authenticated HTTPS deployment. MendPact currently scans Streamable HTTP, not stdio-only or
legacy SSE endpoints; record unsupported transports as a coverage gap rather than silently
installing a bridge. Target selection and current upstream instructions are tomorrow's work.

Default scope: two sequential discovery scans per target (each scan makes multiple MCP protocol
requests), then offline analysis. No automatic retries, concurrency, fuzzing, conformance runner,
tool calls, or live model evaluation. Stop on rate limiting, unexpected side effects, auth scope
uncertainty, or server instability. Agree any expansion separately. Metadata discovery is not
proof that a third-party server itself has no side effects.

## 2. Prepare a fresh local workspace

From the repository root, activate the existing development environment:

```bash
source .venv/bin/activate
python scripts/prepare_validation.py 2026-09-07-server-a
```

The script works offline and creates `reports/validation/2026-09-07-server-a/` with a private
directory, strict production and local policies, a review template, a draft machine-readable
authorization record, and a versioned manifest.
It records the Git revision, dirty-state flag, Python and selected package versions, template
hashes, and a 14-day manual cleanup reminder. It does not read environment-variable values,
contact servers, or assert that tests ran. Existing run directories are never reused. A partial
directory after an I/O failure must be inspected manually; no recursive deletion is attempted.
Use a new label for each target/revision or repeated experiment. `reports/` is already ignored.
Preparation fails before creating the workspace when installed MendPact package metadata is
missing, does not match `pyproject.toml`, or resolves outside this source checkout; reinstall the
editable project and use a fresh label.

The manifest is preparation provenance, not a signed attestation or dependency lockfile.
Prepare again after committing/pulling if you need provenance for that exact clean revision.
Complete `authorization.json` and the authorization section of `review.md` before running any
network command. The JSON record is the enforced gate; the Markdown file holds the fuller human
review. See the [guarded validation-session guide](VALIDATION_SESSION.md).

## 3. Preflight authorization offline

The guarded runner reads the target from ignored local evidence instead of a shell argument.
After recording real permission, a current approval window, the target profile, a maximum of two
scans, and the stop-condition acknowledgement in `authorization.json`, run:

```bash
validation_dir=reports/validation/2026-09-07-server-a
mendpact validation preflight "$validation_dir"
```

Preflight verifies private files, approval lifetime, safe target syntax, the strict policy bytes,
the exact clean Git revision, retention, and unused output names. It performs no DNS lookup,
network request, credential lookup, tool call, or provider call. A draft or stale workspace is not
ready.

## 4. Capture discovery with strict gates

Only after successful preflight and a final human review, start the approved network operation:

```bash
mendpact validation run "$validation_dir" --acknowledge-authorized
validation_exit=$?
printf 'Validation exit code: %s\n' "$validation_exit"
```

Run commands interactively without shell `errexit` and record the exit immediately. The runner
performs the approved one or two scans sequentially, never overwrites outputs, uses no retries,
and records exact report digests in `session.json`. It stops after an operational error. The target
URL, reviewer, and permission note are not copied into the session manifest.

For a deliberately isolated loopback HTTP server, use `local-strict.toml` instead. That policy
allows private addresses and HTTP but still fails on high scan findings and risky contract
changes. It is **not** suitable for production and does not restrict addresses to loopback by
itself. Never use the permissive `local-smoke.toml` to make external validation appear green.

Interpret scan exits: `0` gate passed, `1` findings reached the threshold, `2` error/incomplete.
Keep failures as evidence; do not weaken thresholds or add waivers merely to pass the study.
Inspect the full report locally. If authorization remains uncertain, stop and consult the
[authentication guide](AUTHENTICATION.md); a credential-free `auth-check` is an additional
network operation, not part of the default two-scan budget. Credential use needs separate review.

The guarded runner does not support credentials, tool execution, conformance, or provider calls.
Those require separately reviewed scope. See [the session guide](VALIDATION_SESSION.md) for the
authorization schema and exact boundaries.

## 5. Analyze offline

First verify the completed session and create its privacy-minimized aggregate summary:

```bash
mendpact validation summarize "$validation_dir"
```

This rereads the private authorization, workspace manifest, strict policy, session manifest, and
every recorded scan. It checks exact hashes, identities, timestamps, outcomes, target consistency,
private file modes, and retention without contacting the target. The new
`validation-summary.json` omits the target URL, alias, reviewer, permission note, scan IDs,
descriptions, finding details, and errors. It retains source hashes and aggregate counts, so hashes
remain linkable fingerprints rather than anonymization or signatures. A successful export means
the evidence was structurally verified; it does not change or replace a failed/error scan status.

For two complete captures, the summary also classifies their capability contracts as `stable` or
`changed`. An early operational error produces `unavailable`, not a false stability claim. Continue
with the detailed private analysis without promoting either capture as a trusted baseline:

```bash
mendpact diff "$validation_dir/scan-01.json" "$validation_dir/scan-02.json" \
  --fail-on risky --output "$validation_dir/contract-diff.json"
mendpact export-report "$validation_dir/scan-01.json" \
  --output "$validation_dir/evidence.html"
mendpact history add "$validation_dir/scan-01.json" \
  --database "$validation_dir/history.sqlite"
```

The standalone `diff` command uses `--fail-on risky`, not a policy-file option; this matches both
strict scan policies' contract threshold. Record each command's exit separately. Use fresh output
names; export refuses replacement, but not every command does.
Identical counts alone do not establish identical contracts. Failed scans can contain useful
complete evidence; error/partial scans must not be presented as complete coverage.

Review each finding against upstream source/schema documentation. A destructive-looking tool
name is a heuristic concern, not a confirmed exploitable vulnerability. Record suspected false
positives and unknowns separately. Read the generated review template for the evidence fields.
Do not invent replay decisions as proof of actual model behavior; behavioral evaluation is a
separate phase with reviewed scenarios and an explicitly approved provider budget if needed.

## 6. Close out and report honestly

Deliver a reviewed target matrix, reproducible defects, synthetic regression fixtures, and a
sanitized summary of what did/did not work. Mark blocked targets and unsupported features
explicitly. No minimum pass percentage is required: finding useful failures is a valid outcome.
Keep raw reports, server logs, local notes, URLs, and packages in the ignored workspace. Commit
only reviewed documentation and synthetic tests. Do not upload validation directories as CI
artifacts or publish them to GitHub Pages. Sharing requires a separate review and permission.

Delete raw workspaces manually within 14 days or sooner under the target owner's requirements.
The manifest reminder does not enforce deletion; `history prune` only cleans its selected history
database, not raw files or backups. No API server, background scheduler, or paid service is needed.
