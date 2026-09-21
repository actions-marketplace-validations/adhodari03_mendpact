# GitHub Action

MendPact is packaged as a composite GitHub Action in the repository root. Existing scan users
remain on `mode: scan` by default. Authorization preflights use `mode: auth` without a credential.
Guard users select `mode: guard` and provide a committed scan baseline, plus an optional
scenario/replay pair. Model-release checks use `mode: compare-models` with two completed behavior
reports and make no network request.
Semantic-grader checks use `mode: calibrate-grader` with reviewed human labels and saved scores.
Bounded tool-selection runs use `mode: evaluate` with replay data or one explicit live provider.

The Action installs the MendPact version contained in the referenced Git revision. The first
alpha reference was `v0.1.0`; PR-native feedback is introduced in `v0.2.0`. GitHub recommends
pinning third-party actions to a full commit SHA when an immutable reference is required. Use
`main` only for deliberate pre-release testing.

Every authorization, scan, evaluation, guard, and model-comparison run writes a Markdown result to
the GitHub job summary and emits bounded workflow annotations for findings, failed behavior trials,
contract changes, compatibility regressions, and report errors. These presentation steps do not
change MendPact's configured pass/fail thresholds. The JSON report remains the complete,
machine-readable source of truth.

Offline scan rechecks use `mode: recheck` with `source-report`. This mode reapplies current
deterministic rules to a saved capability graph and labels the derived report with its exact source
digest and freshness boundary. See the [offline recheck guide](RECHECK.md).

The immutable `v0.1.0` tag predates PR-native summaries. Use `v0.2.0` or a later release for this
feedback.

Policy-as-code support is introduced in `v0.3.0`. When `policy` is configured, the reviewed TOML
file owns scan and contract thresholds plus target-network allowances. See the
[policy reference](POLICY.md).

## Generate a scan workflow

From the root of a consuming repository, generate a secure starting workflow and policy:

```bash
mendpact init --target https://api.example.com/mcp
```

The generated workflow uses `v0.3.0` in scan mode, uploads the machine report for 14 days, and
grants only read access to repository contents. The initializer remains offline: it creates an
empty baseline directory, an ignored local candidate directory, and a labeled example scenario but
does not contact the target, invent a baseline, or enable guard mode. Use `--force` only after
reviewing the generated-file collisions reported by the command.

## Authenticated target

Keep a bearer token in GitHub Actions secrets and pass it to the Action only through the named
environment variable referenced by policy:

```yaml
- id: mendpact
  uses: adhodari03/mendpact@v0.3.0
  env:
    MENDPACT_ACCESS_TOKEN: ${{ secrets.MENDPACT_ACCESS_TOKEN }}
  with:
    target: https://api.example.com/mcp
    policy: mendpact.toml
    output: mendpact-report.json
```

For runs without policy, add `auth-token-env: MENDPACT_ACCESS_TOKEN`. The Action passes only that
name to the CLI. The secret value stays in the environment and is never constructed as a command
argument. See [authenticated targets](AUTHENTICATION.md) for OAuth metadata checks and limitations.

## Authorization preflight mode

Audit the public OAuth discovery chain before provisioning a token. This mode deliberately rejects
`auth-token-env` and never loads a credential:

```yaml
name: MCP authorization metadata

on:
  pull_request:

permissions:
  contents: read

jobs:
  mendpact-auth:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-python@v6
        with:
          python-version: "3.13"
      - id: mendpact-auth
        uses: adhodari03/mendpact@v0.3.0
        with:
          mode: auth
          target: https://api.example.com/mcp
          policy: mendpact.toml
          output: mendpact-authorization-report.json
      - if: always()
        uses: actions/upload-artifact@v6
        with:
          name: mendpact-authorization-report
          path: mendpact-authorization-report.json
          if-no-files-found: ignore
          retention-days: 14
```

The Action publishes a dedicated authorization summary, bounded findings, and the report path.
See [`examples/github-actions/mendpact-auth.yml`](../examples/github-actions/mendpact-auth.yml) for
the copy-ready workflow.

## Scan mode

```yaml
name: MCP reliability

on:
  pull_request:

permissions:
  contents: read

jobs:
  mendpact:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-python@v6
        with:
          python-version: "3.13"
      - id: mendpact
        uses: adhodari03/mendpact@v0.2.0
        with:
          target: https://your-server.example/mcp
          fail-on: high
          output: mendpact-report.json
      - if: always()
        uses: actions/upload-artifact@v6
        with:
          name: mendpact-report
          path: mendpact-report.json
          if-no-files-found: ignore
```

## Guard mode

The baseline, scenario suite, and replay plan live in the consuming repository and are available
after `actions/checkout`.

```yaml
name: MCP contract guard

on:
  pull_request:

permissions:
  contents: read

jobs:
  mendpact:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-python@v6
        with:
          python-version: "3.13"
      - id: mendpact
        uses: adhodari03/mendpact@v0.2.0
        with:
          mode: guard
          target: https://your-server.example/mcp
          baseline: mendpact/baseline-scan.json
          scenario: mendpact/scenarios.json
          replay: mendpact/replay.json
          scan-fail-on: high
          contract-fail-on: breaking
          output: mendpact-guard-report.json
          save-scan: mendpact-candidate-scan.json
      - if: always()
        uses: actions/upload-artifact@v6
        with:
          name: mendpact-guard-report
          path: mendpact-guard-report.json
          if-no-files-found: ignore
```

The Action returns the configured paths as `report` and `candidate-scan` outputs. The examples
use the fixed configured path for `if: always()` artifact upload so a failure report can still be
collected. The Action deliberately does not upload artifacts itself, allowing the consuming
workflow to choose retention, permissions, and naming policy.

`save-scan` is a candidate artifact, not an automatically trusted baseline. Download it, run
`mendpact baseline inspect`, review its target, scan ID, status, capabilities, and digest, then use
`mendpact baseline promote` in a separate change. See [contract baseline lifecycle](BASELINES.md).

## Offline scan recheck mode

Re-evaluate a committed or downloaded complete scan after MendPact rules change, without accessing
the MCP target or loading credentials:

```yaml
name: Recheck saved MCP evidence

on:
  pull_request:

permissions:
  contents: read

jobs:
  recheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-python@v6
        with:
          python-version: "3.13"
      - id: mendpact-recheck
        uses: adhodari03/mendpact@main
        with:
          mode: recheck
          source-report: mendpact/baselines/baseline-scan.json
          policy: mendpact.toml
          output: mendpact-rechecked-scan.json
      - if: always()
        uses: actions/upload-artifact@v6
        with:
          name: mendpact-rechecked-scan
          path: mendpact-rechecked-scan.json
          if-no-files-found: ignore
          retention-days: 14
```

Use `main` only while reviewing an unreleased feature; pin the resulting release tag or full commit
SHA afterward. The Action rejects target, authentication, and target-network allowance inputs in
this mode. Its job summary shows introduced, resolved, severity-reclassified, and unchanged
deterministic finding pairs. It preserves unrefreshed authorization findings and cannot prove that
the saved graph still matches the deployed endpoint.

## Bounded model evaluation mode

Use `mode: evaluate` to create a behavior report from a deterministic replay or an explicit live
provider. Replay is the default driver and remains appropriate for routine pull requests. A live
run installs only its selected provider SDK and requires an explicit model:

```yaml
name: Small Anthropic routing check

on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  model-routing:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-python@v6
        with:
          python-version: "3.13"
      - id: mendpact-evaluate
        uses: adhodari03/mendpact@v0.3.0
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        with:
          mode: evaluate
          target: https://your-server.example/mcp
          scenario: mendpact/scenarios.json
          driver: anthropic
          model: your-reviewed-claude-model
          repetitions: "1"
          max-trials: "10"
          output: mendpact-behavior.json
          save-replay: mendpact/provider-replay.json
      - if: always()
        uses: actions/upload-artifact@v6
        with:
          name: mendpact-behavior
          path: |
            mendpact-behavior.json
            mendpact/provider-replay.json
          if-no-files-found: ignore
          retention-days: 14
```

Use `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `GEMINI_API_KEY` as an environment secret matching
the selected driver. Provider credentials are deliberately not Action inputs and are never added
to the MendPact command line. The `max-trials` input defaults to 10 and is enforced as scenario
count multiplied by repetitions before the driver is configured. Increase it only in a reviewed
workflow after estimating cost. The `saved-replay` output exposes the configured replay path; the
consumer still controls upload and retention.

Live evaluation sends scenario tasks and discovered tool metadata to the selected provider. It
does not execute the returned MCP tool. Prefer `workflow_dispatch`, protected environments, and
synthetic scenarios. Pull requests from forks do not receive ordinary repository secrets, and
workflows must not use `pull_request_target` to run untrusted scenario or Action code with a
provider key.

For a provider-free standalone evaluation, omit `model`, keep `driver: replay`, and supply
`replay:`. This mode still connects to the configured MCP endpoint to discover its current tool
catalog, but it makes no model-provider request.

## Offline model comparison mode

Use two reviewed `mendpact.behavior.v1` artifacts to block a model change that exceeds an allowed
overall or per-scenario pass-rate drop:

```yaml
name: Model behavior compatibility

on:
  pull_request:

permissions:
  contents: read

jobs:
  model-compatibility:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-python@v6
        with:
          python-version: "3.13"
      - id: mendpact-model-comparison
        uses: adhodari03/mendpact@v0.3.0
        with:
          mode: compare-models
          reference-report: mendpact/reference-behavior.json
          candidate-report: mendpact/candidate-behavior.json
          policy: mendpact.toml
          output: mendpact-model-comparison.json
      - if: always()
        uses: actions/upload-artifact@v6
        with:
          name: mendpact-model-comparison
          path: mendpact-model-comparison.json
          if-no-files-found: ignore
          retention-days: 14
```

`target` is intentionally optional in Action metadata and remains required at runtime for auth,
scan, and guard modes. Comparison mode instead requires `reference-report` and `candidate-report`.
It rejects target, authentication, and target-network allowance inputs because it only reads local
JSON. A `mendpact.policy.v2` file can own the comparison gates. Without policy, the individual
threshold inputs retain their original defaults. Do not combine policy with those inputs; new
confusion pairs fail by default. Run separate Action steps when one reference must be compared with
several candidates, or use the CLI's multi-candidate form.

The Action summary includes the configured thresholds, both model snapshots, the signed pass-rate
delta, token and latency observations, and bounded compatibility annotations. It returns the JSON
path through the existing `report` output.

## Offline semantic calibration mode

Calibrate one exact semantic-grader version and enforce its independent validation quality:

```yaml
name: Semantic grader calibration

on:
  pull_request:

permissions:
  contents: read

jobs:
  semantic-calibration:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-python@v6
        with:
          python-version: "3.13"
      - id: mendpact-calibration
        uses: adhodari03/mendpact@v0.3.0
        with:
          mode: calibrate-grader
          semantic-labels: mendpact/semantic-labels.json
          policy: mendpact.toml
          output: mendpact-semantic-calibration.json
      - if: always()
        uses: actions/upload-artifact@v6
        with:
          name: mendpact-semantic-calibration
          path: mendpact-semantic-calibration.json
          if-no-files-found: ignore
          retention-days: 14
```

Calibration mode requires `semantic-labels` and rejects target, authentication, and target-network
allowance inputs. A `mendpact.policy.v2` file can own the evidence and quality gates; otherwise,
use the individual calibration inputs. It reads local JSON and does not contact the semantic
grader, an MCP endpoint, or a model provider. The summary shows the selected threshold, quality
policy, calibration and validation metrics, findings, and bounded human/grader disagreements. See
[semantic grader calibration](SEMANTIC_CALIBRATION.md) for the input contract and limitations.

Private and insecure HTTP targets remain blocked by default. `allow-private` and
`allow-insecure-http` exist only for deliberate test environments, usually on a self-hosted
runner that can reach the endpoint.

GitHub's [action metadata reference](https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax)
defines composite inputs and outputs. Its
[composite Action guide](https://docs.github.com/en/actions/tutorials/create-actions/create-a-composite-action)
also recommends consuming an Action through an explicit repository revision.

## Publishing an Action release

1. Merge the release change only after its local `uses: ./` CI smoke test passes.
2. Create a GitHub release from the merged commit with a tag matching the package version, such
   as `v0.2.0`, and title it `MendPact v0.2.0`.
3. Keep the release notes explicit that this is an alpha supporting Streamable HTTP MCP targets.
4. If publishing to GitHub Marketplace, open the root `action.yml`, select the Marketplace
   release banner, accept the Marketplace Developer Agreement if prompted, and publish the same
   release. GitHub will validate the Action name and metadata in that flow.
5. Test the immutable tag from a release-smoke workflow before announcing it.
6. Record the release commit's full SHA so security-conscious users can pin it immutably.

The repository must remain public and keep a single root Action metadata file for Marketplace
publication. Publishing the GitHub Action does not require a PyPI release because the composite
Action installs MendPact directly from its referenced repository revision.
