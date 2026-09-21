# Guarded MCP validation sessions

`mendpact validation` turns the real-world validation playbook's metadata-capture step into a
bounded, reviewable workflow. It is designed for one explicitly authorized target per private
workspace. It does not grant permission to test a public server.

## 1. Prepare after merging

Start from the exact clean revision you intend to test:

```bash
git switch main
git pull --ff-only
source .venv/bin/activate
python scripts/prepare_validation.py 2026-09-13-server-a
```

Preparation is offline. It creates a private `reports/validation/<label>/` directory containing
strict production and loopback policies, `review.md`, a provenance manifest, and a draft
`authorization.json`. The directory is ignored by Git and scheduled for manual cleanup within 14
days.

## 2. Record permission locally

Open `authorization.json` locally and replace the draft fields only after the target owner or its
documented testing policy authorizes the exact scope. Do not commit this file.

```json
{
  "schema_version": "mendpact.validation-authorization.v1",
  "status": "approved",
  "target_alias": "server-a",
  "target_url": "https://authorized.example/mcp",
  "target_kind": "production_https",
  "approved_by": "local-reviewer-reference",
  "permission_reference": "local reference to the owner-approved metadata discovery scope",
  "approved_at": "2026-09-13T15:00:00Z",
  "expires_at": "2026-09-14T15:00:00Z",
  "max_discovery_scans": 2,
  "stop_conditions_acknowledged": true,
  "allow_authenticated": false,
  "allow_tool_execution": false,
  "allow_provider_calls": false
}
```

Use `production_https` for an authorized HTTPS deployment. Use `isolated_loopback` only for a
server running on `localhost`, `127.0.0.0/8`, or `::1`; the runner deliberately rejects other
private-network addresses. Approval must be current, cannot exceed 14 days, and cannot outlive the
workspace cleanup date. Keep the file private if your editor changes its permissions:

```bash
chmod 600 reports/validation/2026-09-13-server-a/authorization.json
```

This first runner intentionally rejects bearer credentials. An authenticated deployment requires
a separately reviewed procedure after credential-free validation reveals that need.

## 3. Run the offline preflight

```bash
validation_dir=reports/validation/2026-09-13-server-a
mendpact validation preflight "$validation_dir"
```

Preflight performs no DNS lookup or network request. It checks:

- the authorization schema, permission window, stop-condition acknowledgement, and two-scan cap;
- URL syntax and the selected production or isolated-loopback profile;
- private workspace and file permissions, regular files, and absence of symlinks;
- exact strict-policy bytes against the preparation manifest;
- the current clean Git revision against the prepared revision;
- the 14-day workspace boundary; and
- absence of earlier scan/session outputs.

If the checkout, policy, approval, or output state changed, prepare a fresh workspace. Do not edit
the manifest to make preflight pass.

## 4. Start the network operation deliberately

Only after reviewing the preflight output and the authorization again:

```bash
mendpact validation run "$validation_dir" --acknowledge-authorized
validation_exit=$?
printf 'Validation exit code: %s\n' "$validation_exit"
```

This is the point where network traffic begins. The runner reads the target from the ignored local
file so it does not need to appear as a shell argument. It performs one or two sequential MCP
metadata discovery scans using one strict policy. It has no retries, concurrency, conformance
runner, MCP tool calls, model calls, credential loading, publishing, or upload. An operational
error stops the second scan; a completed scan with policy findings is retained and does not prevent
the approved repeat capture.

The workspace receives `scan-01.json`, optionally `scan-02.json`, and
`mendpact.validation-session.v1` in `session.json`. The session manifest binds the authorization,
workspace, policy, target fingerprint, scan IDs, outcomes, and exact report bytes without copying
the target URL, reviewer, or permission note. It is local operational evidence, not a public
privacy-minimized report.

Exit codes are conservative: `0` means all planned scans passed policy, `1` means discovery
completed but at least one scan failed policy, and `2` means an operational error or invalid
preflight. None of these outcomes certifies security.

## 5. Verify and summarize offline

After the network command finishes, verify the exact session inputs and write an allowlisted local
summary:

```bash
mendpact validation summarize "$validation_dir"
```

This command makes no network request. It revalidates the private authorization, retention window,
strict policy, workspace provenance, session manifest, every scan schema, recorded status, report
hash, target match, policy snapshot, and aggregate counts. It refuses changed, missing, additional,
linked, oversized, or overly permissive files and never overwrites `validation-summary.json`.

The `mendpact.validation-summary.v1` output contains recorded outcomes, capability/finding counts,
source hashes, and an aggregate two-capture contract result. It omits the target URL and alias,
reviewer, permission note, scan IDs, capability names/descriptions, raw findings, and raw errors.
SHA-256 values can still be linkable and do not authenticate the evidence. `stable` means the two
complete capability graphs had no contract changes; `changed` means at least one change was counted;
`unavailable` means two complete graphs were not recorded. None of these labels proves service
safety, uptime, or that a live request occurred.

Summary creation exits `0` when the source evidence is valid even if its recorded status is
`failed` or `error`. Use the recorded status—not summary export success—as the reliability outcome.

## 6. Analyze and close out

If two complete reports exist, continue with offline diff, evidence export, history, and finding
triage from the [real-world validation playbook](REAL_WORLD_VALIDATION.md). Record actual exit codes
and limitations in `review.md`. Keep raw files local, obtain separate permission before sharing,
and manually remove the workspace by its manifest deadline or sooner.
