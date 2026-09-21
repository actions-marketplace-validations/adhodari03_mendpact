# Policy as code

MendPact policies keep CI thresholds and target-network allowances in a reviewed TOML file. Policy
v2 extends the same trust boundary to model comparison and semantic-grader calibration. The policy
is resolved before work begins, embedded in JSON reports, and displayed in the GitHub job summary.

## Production policy

```toml
schema_version = "mendpact.policy.v2"
name = "production"
profile = "production"

scan_fail_on = "high"
contract_fail_on = "risky"
allow_private = false
allow_insecure_http = false

# Optional: this is an environment-variable name, never a token value.
bearer_token_env = "MENDPACT_ACCESS_TOKEN"

[model_comparison]
max_overall_pass_rate_drop = 0.02
max_scenario_pass_rate_drop = 0.05
allow_new_confusions = false

[semantic_calibration]
min_calibration_examples = 20
min_validation_examples = 20
min_validation_balanced_accuracy = 0.90
max_validation_false_accept_rate = 0.02
```

The production profile cannot be weakened below `high` scan findings or `risky` contract changes.
It always rejects private targets and plaintext HTTP. Model comparison cannot allow more than a
5% overall drop, a 10% per-scenario drop, or new confusion pairs. Semantic calibration requires at
least 20 examples in each split, balanced accuracy of at least 80%, and a false-accept rate no
higher than 5%. Stricter values remain valid.

Omitted v2 sections resolve to strict production defaults. The explicit values above make the
reviewed project choices visible. Policy v1 remains valid for authorization, scan, and guard, but
cannot be used by `compare-models` or `calibrate-grader`; migrate it by changing the schema version
and reviewing the two new sections.

Run a scan with the policy:

```bash
mendpact scan https://api.example/mcp \
  --policy examples/policies/production.toml \
  --output scan-report.json
```

Audit the public OAuth metadata chain without loading the policy's named token variable:

```bash
mendpact auth-check https://api.example/mcp \
  --policy examples/policies/production.toml \
  --output authorization-report.json
```

For `auth-check`, `scan_fail_on` is the authorization finding threshold. The policy's
`bearer_token_env` remains reportable configuration evidence but is never resolved or read by the
credential-free command.

Run the unified guard:

```bash
mendpact guard https://api.example/mcp \
  --baseline mendpact/baseline-scan.json \
  --scenario mendpact/scenarios.json \
  --replay mendpact/replay.json \
  --policy mendpact.toml \
  --output mendpact-guard-report.json
```

Apply the same reviewed policy to an offline model comparison:

```bash
mendpact compare-models reference.json candidate.json \
  --policy mendpact.toml \
  --output model-comparison.json
```

Or to semantic-grader calibration:

```bash
mendpact calibrate-grader semantic-labels.json \
  --policy mendpact.toml \
  --output semantic-calibration.json
```

Policy-controlled CLI flags cannot be supplied together with `--policy`. This avoids silently
overriding a reviewed policy at run time.

`bearer_token_env` records where a pre-issued token must be loaded. The variable must exist at run
time, and only its name is embedded in policy evidence. See the
[authenticated-target guide](AUTHENTICATION.md) for token and OAuth metadata boundaries.

## Local policy

The local profile keeps the same secure network defaults. Loopback/private targets and plaintext
HTTP must still be enabled explicitly:

```toml
schema_version = "mendpact.policy.v1"
name = "local-development"
profile = "local"

scan_fail_on = "high"
contract_fail_on = "risky"
allow_private = true
allow_insecure_http = true
```

Never reuse a local policy for a production target.

A local v2 policy may add `[model_comparison]` and `[semantic_calibration]` using smaller fixture
sizes or relaxed thresholds. Those local settings are never accepted as production settings merely
because the target URL happens to be public.

## Controlled waivers

Waivers are exact, reviewed exceptions for a single rule and subject. They remain visible in JSON,
terminal output, GitHub summaries, and annotations even while they prevent that result from
failing CI.

```toml
[[waivers]]
rule_id = "MP-MCP-004"
subject = "tool:delete_project"
reason = "Deletion is protected by a separately reviewed approval gate."
approved_by = "security@example.com"
approved_on = 2026-08-31
expires_on = 2026-09-14
```

The following boundaries are enforced:

- `rule_id` and `subject` must match the result exactly;
- the reason, approver, approval date, and expiration date are mandatory;
- expiration must be after approval and no more than 14 days later;
- `expires_on` is exclusive, so the waiver stops applying at the start of that date;
- approval dates cannot be in the future;
- duplicate rule-and-subject waivers are rejected;
- critical findings and breaking contract changes cannot be waived;
- expired waivers remain in policy evidence but automatically stop suppressing failure.

Renewal requires changing the approval and expiration dates in a new reviewed commit. This also
changes the policy SHA-256 retained in the report.

## GitHub Action

From the release containing policy support, the policy file owns the threshold and target
allowance inputs:

```yaml
- id: mendpact
  uses: adhodari03/mendpact@v0.3.0
  with:
    mode: guard
    target: https://api.example/mcp
    baseline: mendpact/baseline-scan.json
    scenario: mendpact/scenarios.json
    replay: mendpact/replay.json
    policy: mendpact.toml
    output: mendpact-guard-report.json
```

Do not combine `policy` with `allow-private`, `allow-insecure-http`, or command-specific threshold
options. The CLI and Action reject those combinations because the reviewed file is the source of
truth. Action threshold inputs default internally when no policy is supplied, so an omitted input
does not conflict with policy.

## Exit behavior

- Exit `0`: every stage passed under the resolved policy.
- Exit `1`: findings or contract changes reached the policy threshold, or behavior failed.
- Exit `2`: the policy, target, inputs, connection, or report could not be configured.

Reports retain the policy schema, name, profile, resolved thresholds, network allowances, waivers,
and SHA-256 digest so results can be tied back to the exact reviewed file.
