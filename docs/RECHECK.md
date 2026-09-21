# Offline scan recheck

`mendpact recheck` applies the installed MendPact version's deterministic metadata rules to a
previously saved, complete `mendpact.scan.v1` report. It is useful after rules change: maintainers
can see how a reviewed capability snapshot scores now without reconnecting to the MCP deployment.

```bash
mendpact recheck reports/original-scan.json \
  --policy mendpact.toml \
  --output reports/rechecked-scan.json
```

Without a policy file, use `--fail-on` to choose the minimum failing severity. The default is
`high`. Exit code `0` means the saved graph passes the current threshold, `1` means it fails, and
`2` means the input, configuration, or output is invalid.

## What changes

The command validates the original report, hashes its exact bytes, and runs the current
deterministic capability rules against its saved graph. Old deterministic findings are replaced,
then the current policy threshold and exact active waivers are applied. The new report retains the
original scan ID, target, graph, and capture time so it continues to identify the same snapshot.

The optional `recheck` object records:

- the original file's SHA-256;
- the recheck time and MendPact version;
- the original recorded status;
- the count of preserved authorization findings; and
- `authorization_refreshed: false`;
- a versioned deterministic `rule_delta`.

## Rule impact delta

The `rule_delta` explains how the installed deterministic rules changed the recorded result. It
counts distinct `(rule_id, subject)` pairs as:

- `introduced` when only the current rules report the pair;
- `resolved` when only the saved report contains the pair;
- `reclassified` when the pair remains but its severity changes; or
- `unchanged` when both reports contain the pair at the same severity.

Each introduced, resolved, or reclassified pair is included in `changes` with its before and after
severity. If duplicate findings share an identity, MendPact compares their highest recorded
severity so a lower duplicate cannot hide a more serious result. The terminal and GitHub Action
summaries show the counts and changed pairs. Privacy-minimized evidence exports retain only the
four aggregate counts, not rule IDs or subjects.

Authorization findings (`MP-AUTH-*`) are excluded because offline recheck cannot refresh their
network-derived evidence. Waiver changes are also excluded: the delta compares unwaived rule
outputs, then applies the selected current policy separately. This makes the delta an explanation
of deterministic rule impact, not a policy-change audit.

The output remains a `mendpact.scan.v1` report so existing diff, evidence, history, and job-summary
tools can read it. Those views label it as an offline deterministic recheck. The command creates a
new output file atomically and refuses to overwrite an existing file, including its source.

## What does not change

Recheck makes no network connection, performs no DNS lookup, sends no provider request, loads no
credential, and executes no MCP tool. It does not rediscover the deployment or refresh OAuth
metadata. Existing `MP-AUTH-*` findings stay visible but are explicitly counted as preserved,
unrefreshed evidence; current waivers are reapplied to them.

Because the graph may no longer match the deployed server, a recheck is not proof of current
production state. Run a new `mendpact scan` when endpoint freshness matters. A rechecked output
cannot be used as another recheck source, which keeps the provenance chain limited to one original
capture.

## Batch recheck

Use `recheck-batch` when the same current policy and installed rule set should be applied to many
original scans:

```bash
mendpact recheck-batch reports/original-scans \
  --policy mendpact.toml \
  --output-dir reports/recheck-2026-09-11
```

The source must be a directory. MendPact reads only its direct `.json` children, orders them
case-insensitively by filename, and refuses more than 100 inputs. It does not recurse or follow
symbolic links. The output must be a new directory, so a rerun cannot silently replace earlier
evidence. MendPact loads the policy once and gives every valid report the same recheck timestamp.

Outputs use neutral names from `recheck-001.json` through `recheck-100.json`. This order matches
the sorted inputs, while the manifest intentionally omits source filenames and targets. Each valid
item records its exact source SHA-256, recorded status, finding count, output filename, and
aggregate rule-delta counts. Invalid inputs retain only their position and the safe
`invalid_source` code. The manifest is local operational evidence and is not a privacy-minimized
public export.

The batch continues past an invalid report so the remaining saved scans are still useful. Its
exit code is conservative:

- `0`: every input was valid and passed the selected threshold;
- `1`: every input was valid, but at least one recheck failed policy;
- `2`: at least one input was invalid or batch setup/output failed.

An exit of `2` can coexist with successfully written reports. Inspect `batch-manifest.json` before
using those partial results. Infrastructure write failures remove only the newly created batch
files; original inputs are never changed. Run a fresh live scan whenever endpoint or OAuth
freshness matters.

## GitHub Action

The composite Action exposes the same offline boundary:

```yaml
- uses: adhodari03/mendpact@main
  with:
    mode: recheck
    source-report: mendpact/baselines/baseline-scan.json
    policy: mendpact.toml
    output: mendpact-rechecked-scan.json
```

Use `main` only for pre-release testing and replace it with a reviewed immutable release tag or
commit SHA. Recheck mode rejects target, authentication, and target-network allowance inputs.
Artifact upload remains the consuming workflow's responsibility; use no more than 14 days of
retention for temporary reports.
