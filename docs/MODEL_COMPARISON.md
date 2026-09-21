# Model comparison

`mendpact compare-models` compares completed `mendpact.behavior.v1` artifacts without repeating
provider calls. It answers a narrow release question: does a candidate model preserve the same
tool-selection behavior on the same evaluation contract?

## Workflow

Run `mendpact evaluate` separately for the reference and candidate models, keeping the target,
scenario file, repetitions, and discovered tool catalog unchanged. Then compare the saved reports:

```bash
mendpact compare-models \
  reference-behavior.json \
  candidate-behavior.json \
  --max-overall-pass-rate-drop 0.02 \
  --max-scenario-pass-rate-drop 0.05 \
  --output model-comparison.json
```

More than one candidate may follow the reference. Each candidate is independently compared with
the same reference and receives its own status, deltas, confusion edges, and findings.

## Input integrity and comparability

Before calculating a result, MendPact rejects a report unless:

- it contains a non-error run, trial evidence, and a summary;
- every scenario has exactly the declared attempts from `1` through `repetitions`;
- scenario IDs and definitions are internally consistent;
- trace scenario IDs, provider names, and available tools agree with report metadata; and
- the stored summary can be rebuilt exactly from the trial evidence.

Run IDs must be unique. Candidate and reference reports must have the same target, suite name,
scenario definitions, repetition count, and tool catalog. Driver and model names may differ
because comparing those differences is the purpose of the command. The output records both the
requested report model and model names resolved by provider traces.

These checks make accidental comparisons difficult, but they do not prove that two live runs were
executed under identical provider-side settings or at the same time.

## Rules and exit codes

| Rule | Meaning | Default result |
| --- | --- | --- |
| `MP-MATRIX-001` | Overall candidate pass rate dropped beyond the configured allowance. | Failure |
| `MP-MATRIX-002` | One scenario regressed beyond its allowance, even if another improved. | Failure |
| `MP-MATRIX-003` | The candidate introduced a new expected-tool to selected-tool confusion pair. | Failure |

Both drop allowances default to `0`, making the comparison strict. Set
`--allow-new-confusions` only when new confusion pairs should remain visible warnings instead of
failures. Existing confusion pairs remain visible in snapshots; an increased count can still
trigger overall or per-scenario pass-rate rules.

The command exits `0` when all candidates pass, `1` when a valid comparison reaches a failure
threshold, and `2` when an input is invalid, incomparable, unreadable, or cannot be written.
Failed comparisons are still written when `--output` is supplied so CI retains the evidence.

## Output

The versioned `mendpact.model-comparison.v1` JSON artifact contains:

- one normalized reference snapshot and one snapshot per candidate;
- aggregate pass counts, token totals, and measured average latency;
- per-scenario pass rates and selected-tool frequency maps;
- signed candidate-minus-reference pass-rate deltas;
- new confusion edges and stable rule findings; and
- the thresholds that determined the exit code.

Token and latency fields are observational. A zero token total can mean the source driver did not
report usage, and average latency includes only trials that recorded latency. They are not failure
criteria in this version.

## Safety and cost

The comparison command parses local JSON and performs deterministic calculations. It never reads
an API key, contacts an MCP endpoint or provider, or executes a selected tool. Provider cost is
incurred only when creating new live behavior reports with `mendpact evaluate --driver openai`,
`--driver anthropic`, or `--driver gemini`.
Saved reports or deterministic replays can be compared repeatedly at no provider cost.

## Policy as code

Use `--policy mendpact.toml` to load model-comparison gates from the `[model_comparison]` section of
a `mendpact.policy.v2` file. The report retains the resolved policy and its source SHA-256. A v1
policy is rejected because it has no model-comparison contract. Command-line threshold options
cannot be combined with policy.

## GitHub Action

The composite Action exposes the same offline policy for one reference and one candidate per step:

```yaml
- uses: adhodari03/mendpact@v0.3.0
  with:
    mode: compare-models
    reference-report: mendpact/reference-behavior.json
    candidate-report: mendpact/candidate-behavior.json
    policy: mendpact.toml
    output: mendpact-model-comparison.json
```

The Action publishes a model matrix and compatibility findings in the GitHub job summary. Use a
separate step per candidate when comparing several candidate artifacts in one workflow.
