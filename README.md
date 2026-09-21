# MendPact

MendPact is a protocol-native reliability scanner for AI agents. The first release connects to
a remote Model Context Protocol (MCP) endpoint, inventories its capabilities, builds a graph of
the exposed surface, runs deterministic safety checks, and emits a CI-friendly report.

> **Status:** early development. MendPact reports observable risks and compatibility signals;
> it does not certify that an agent is safe.

The static project website is maintained in `site/`. See the
[website guide](docs/WEBSITE.md) for local preview and GitHub Pages deployment.

## Why start here?

Remote MCP discovery gives maintainers value without asking them to install an SDK in their
application or give MendPact source-code access. The deterministic core also provides a stable
baseline before probabilistic, model-driven evaluations are added.

## Quick start

MendPact requires Python 3.12 or newer.

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
mendpact scan https://example.com/mcp --output report.json
```

Local endpoints are blocked by default. To scan a development server deliberately:

```bash
python -m uvicorn examples.fixture_server:app --host 127.0.0.1 --port 8000

mendpact scan http://127.0.0.1:8000/mcp \
  --allow-private \
  --allow-insecure-http \
  --output report.json
```

The fixture intentionally exposes a destructive-looking tool, so this scan exits with code `1`
and demonstrates the CI failure path.

### Recheck a saved scan with current rules

When MendPact's deterministic rules change, re-evaluate a complete saved scan without contacting
the MCP server or a model provider:

```bash
mendpact recheck reports/original-scan.json \
  --policy mendpact.toml \
  --output reports/rechecked-scan.json
```

The output preserves the original capture identity and graph while recording the source-file
digest, recheck time, and installed MendPact version. Authorization findings are preserved but not
refreshed. A rule-impact delta identifies findings introduced, resolved, or severity-reclassified
by the installed rules, and the command cannot replace its source or another existing file. See the
[offline recheck guide](docs/RECHECK.md) for the trust boundary and GitHub Action mode.

For a repository or validation workspace with several original scans, process up to 100 reports in
one bounded offline run:

```bash
mendpact recheck-batch reports/original-scans \
  --policy mendpact.toml \
  --output-dir reports/recheck-2026-09-11
```

The new output directory contains numbered rechecked reports and `batch-manifest.json`. The
manifest records aggregate outcomes, current policy identity, source-file digests, and rule-delta
counts without retaining input filenames or targets. Valid inputs continue when another input is
invalid; any input error makes the command exit `2`, while policy failures without input errors
exit `1`. The manifest is an operational artifact, not a privacy-minimized public export.

For authorized tests against independently developed servers, follow the
[real-world validation playbook](docs/REAL_WORLD_VALIDATION.md). It includes an offline workspace
setup script, strict policy selection, reproducibility notes, and a finding-review template.
Preparing a workspace does not run a scan or call a model provider.

After recording actual owner permission in the ignored local `authorization.json`, verify the
workspace without network access and deliberately start its bounded capture:

```bash
mendpact validation preflight reports/validation/2026-09-13-server-a
mendpact validation run reports/validation/2026-09-13-server-a \
  --acknowledge-authorized
mendpact validation summarize reports/validation/2026-09-13-server-a
```

The runner performs at most two sequential metadata scans, never retries or overwrites, stops on
an operational error, and records exact report digests in a local session manifest. It does not
load credentials, execute MCP tools, call a model provider, publish, or upload. The offline summary
verifies those private bytes and records only aggregate capability, finding, and repeat-capture
contract counts. Summary export success does not mean that the recorded scans passed policy. Read
the [guarded validation-session guide](docs/VALIDATION_SESSION.md) before using the network command.

## Initialize a repository

Create a production-safe policy and GitHub scan workflow in an application repository:

```bash
mendpact init --target https://api.example.com/mcp
```

The command creates `mendpact.toml`, `.github/workflows/mendpact.yml`, an empty baseline directory,
an ignored local candidate directory, and a clearly labeled example scenario. It refuses plaintext
HTTP, URL credentials, query strings, and fragments because the target is committed to the
workflow. Existing generated files are never replaced unless `--force` is supplied.

The generated workflow starts in deterministic scan mode and uses production policy defaults.
MendPact does not invent a baseline or activate the example behavior scenario. Capture the first
scan as a candidate, inspect its exact identity, deliberately promote it into
`mendpact/baselines/baseline-scan.json`, replace the example with real behavior, and then upgrade
the workflow to guard mode.

### Authenticated production targets

MendPact can load a pre-issued bearer token from a named environment variable. The token value is
never accepted as a CLI argument, policy value, URL parameter, or Action input:

```bash
export MENDPACT_ACCESS_TOKEN='your-short-lived-token'
mendpact scan https://api.example.com/mcp \
  --auth-token-env MENDPACT_ACCESS_TOKEN \
  --output mendpact-scan-report.json
```

Before provisioning a credential, audit the endpoint's public OAuth discovery chain:

```bash
mendpact auth-check https://api.example.com/mcp \
  --output mendpact-authorization-report.json
```

This credential-free preflight checks the unauthenticated Bearer challenge, RFC 9728
protected-resource metadata, authorization-server discovery, exact resource and issuer binding,
HTTPS endpoints, and PKCE `S256` advertisement. It emits a versioned
`mendpact.authorization.v1` report and never loads or transmits a bearer token.

Authenticated scans also inspect RFC 9728 protected-resource metadata and the advertised OAuth or
OpenID authorization-server metadata without sending the token to those endpoints. See the
[authenticated-target guide](docs/AUTHENTICATION.md) for policy, GitHub secret, discovery, and
security details.

## Behavioral evaluation

MendPact can also test whether a model decision chose the intended MCP tool and produced valid
arguments. Replay mode is deterministic and free to run, while optional OpenAI, Anthropic, and
Gemini drivers ask a live model to select a tool. No driver executes the selected tool.

With the fixture server running, evaluate the included scenario and recorded decision:

```bash
mendpact evaluate http://127.0.0.1:8000/mcp \
  --scenario examples/scenarios/read-status.json \
  --replay examples/replays/read-status.json \
  --allow-private \
  --allow-insecure-http \
  --output behavior-report.json
```

A scenario states a natural-language task, the expected tool and arguments, and any forbidden
tools. MendPact checks the replayed choice against the discovered tool catalog, validates its
arguments with the tool's JSON Schema, and reports repeated wrong-tool choices as confusion
edges. The provider-neutral trace format makes results from supported providers comparable. A full
report records the selected tool, arguments, resolved model, response ID, latency, and token counts
without storing the API key or raw provider response.

String comparison remains case-sensitive, and normalization is disabled by default. A scenario
can explicitly normalize only string fields whose server contract treats formatting or letter
case as equivalent. Exact versus subset comparison remains controlled by `argument_match`.
Paths use JSON Pointer syntax, and raw model arguments remain unchanged in reports:

```json
"argument_normalization": {
  "/component": ["trim", "casefold"]
}
```

### Live provider evaluation

Install only the provider SDKs that you need:

```bash
python -m pip install -e '.[openai,anthropic,gemini]'
```

Set the corresponding API key outside the repository:

```bash
export OPENAI_API_KEY='your-key'
export ANTHROPIC_API_KEY='your-key'
export GEMINI_API_KEY='your-key'
```

Choose one provider and an explicit model. This makes paid API requests but still does not execute
any MCP tool:

```bash
mendpact evaluate http://127.0.0.1:8000/mcp \
  --scenario examples/scenarios/read-status.json \
  --driver openai \
  --model gpt-5.6-luna \
  --allow-private \
  --allow-insecure-http \
  --output behavior-report.json \
  --save-replay replay.json
```

The saved replay file can reproduce the decisions later without another model call. MendPact
uses each provider's function or tool-calling interface and normalizes the result into the same
report format. Replace `openai` and the model in the example with `anthropic` and a Claude model,
or `gemini` and a Gemini model, to select another installed driver.

### Regression baselines

Save a reviewed behavior run as the expected result for later changes:

```bash
mendpact evaluate http://127.0.0.1:8000/mcp \
  --scenario examples/scenarios/read-status.json \
  --replay examples/replays/read-status.json \
  --allow-private \
  --allow-insecure-http \
  --save-baseline behavior-baseline.json \
  --min-pass-rate 0.95 \
  --max-pass-rate-drop 0.02
```

Then compare every candidate change with that versioned baseline:

```bash
mendpact evaluate http://127.0.0.1:8000/mcp \
  --scenario examples/scenarios/read-status.json \
  --replay examples/replays/read-status.json \
  --baseline behavior-baseline.json \
  --allow-private \
  --allow-insecure-http \
  --output behavior-report.json
```

The baseline stores the scenario set, sample size, pass rate, failed-trial allowance, known
wrong-tool confusions, driver, model, and CI thresholds. A comparison fails when quality drops
beyond policy or the sample is no longer comparable. Driver and model changes are visible
warnings by default because testing a new model is a normal use case. The report also includes
a one-sided proportion-test p-value as supporting statistical context; predictable thresholds
remain the source of the CI exit code. See the included
[`read-status` baseline](examples/baselines/read-status.json) for the JSON format.

### Compare model runs offline

Use saved behavior reports to decide whether a candidate model or model version preserves the
reference model's tool-routing behavior:

```bash
mendpact compare-models \
  reports/reference.json \
  reports/candidate-a.json \
  reports/candidate-b.json \
  --max-overall-pass-rate-drop 0.02 \
  --max-scenario-pass-rate-drop 0.05 \
  --output model-comparison.json
```

The first report is the reference; every remaining report is compared with it. MendPact requires
the same target, suite, scenario definitions, repetitions, and tool catalog so the result does not
mix unrelated experiments. It reports overall and per-scenario pass-rate changes, selected-tool
distributions, new wrong-tool confusion patterns, provider-resolved model names, token usage, and
average measured latency. This command reads existing artifacts only: it does not connect to an
MCP server, call a model provider, execute a tool, or incur provider cost. See the
[model comparison guide](docs/MODEL_COMPARISON.md) for the validation rules and CI policy.

### Calibrate semantic grading against human labels

Before trusting a semantic grader's score in CI, fit its threshold on reviewed calibration labels
and measure it on a separate validation split:

```bash
mendpact calibrate-grader examples/calibration/semantic-labels.example.json \
  --output semantic-calibration.json
```

MendPact selects the threshold without looking at validation labels, then reports balanced
accuracy, false-accept rate, false rejects, and every human/grader disagreement. Minimum sample
sizes and validation-quality limits produce CI exit code `1` when unmet. The report binds its
results to a formatting-independent dataset digest and the exact grader name and version.

The command consumes saved scores; it does not call an LLM judge or claim the included example is
a production benchmark. It is an offline reliability check for a separately operated semantic
grader. See the [semantic calibration guide](docs/SEMANTIC_CALIBRATION.md) for the data contract,
selection rule, trust boundary, and CI policy.

## MCP contract diff

MendPact can compare two versioned scan reports without reconnecting to either MCP server. It
classifies capability and JSON Schema changes as `compatible`, `risky`, or `breaking`, then maps
changed tools to behavior scenarios that may need retesting.

```bash
mendpact diff \
  examples/contracts/baseline-scan.json \
  examples/contracts/candidate-scan.json \
  --scenario examples/scenarios/read-status.json \
  --fail-on risky \
  --output contract-diff.json
```

The default CI threshold is `breaking`. Use `--fail-on risky` when description changes, newly
added tools, relaxed schemas, or other model-routing risks should also block a change. Reports
include stable rule IDs, before-and-after evidence, JSON Pointer paths, and affected scenario
IDs. The example intentionally exits with code `1` under the strict `risky` threshold because
the tool description changed. The command is deterministic and makes no model-provider or MCP
network request. See the [contract-diff rule reference](docs/CONTRACT_DIFF.md) for the complete
classification policy.

### Contract baseline lifecycle

Treat a newly captured scan as a candidate until its exact identity and target have been reviewed:

```bash
mendpact baseline inspect mendpact/candidates/candidate-scan.json

mendpact baseline promote \
  mendpact/candidates/candidate-scan.json \
  mendpact/baselines/baseline-scan.json \
  --accept-scan-id "paste-the-reviewed-scan-id" \
  --expected-target https://api.example.com/mcp
```

Promotion requires a complete MCP capability graph, refuses accidental replacement and symlink
destinations, and writes a canonical baseline atomically. A scan that failed its own policy needs
the additional `--accept-failed-scan` acknowledgement. See the
[baseline lifecycle guide](docs/BASELINES.md) for initial capture and controlled replacement.

## Unified CI guard

`mendpact guard` combines the routine pull-request workflow into one command. It scans the
current endpoint once, compares it with a committed contract baseline, calculates the behavior
blast radius, and replays only affected scenarios against the discovered tool catalog.

```bash
mendpact guard http://127.0.0.1:8000/mcp \
  --baseline examples/guard/baseline-scan.json \
  --scenario examples/scenarios/read-status.json \
  --replay examples/replays/read-status.json \
  --scan-fail-on critical \
  --allow-private \
  --allow-insecure-http \
  --output guard-report.json
```

The resulting `mendpact.guard.v1` report embeds scan, contract, and replay evidence under one CI
status. The workflow does not execute MCP tools or contact a model provider, so it is
deterministic and free to run. See the [guard reference](docs/GUARD.md) for its stage and exit-code
policy.

## Shareable evidence summaries

Turn a saved scan, behavior, or guard report into a self-contained HTML summary without making
network requests or publishing the source report:

```bash
mkdir -p reports
mendpact export-report guard-report.json --output reports/evidence.html
```

Open the HTML file locally and review it before sharing. The export omits targets, capability
names, prompts, arguments, provider metadata, raw errors, and waiver identities. It retains
aggregate counts, recorded outcomes, failure thresholds, the source timestamp, and a SHA-256 of
the original file. Missing guard stages are explicitly marked as skipped. A passed result does
not imply an absence of findings or a safety certification.

Use `--format json --output reports/evidence.json` for a versioned evidence summary. Current scan
and guard exports use `mendpact.evidence.v2`; behavior-only exports remain compatible with v1.
Existing output files are never overwritten. Export success is not a CI reliability gate: a
failed source report can be exported successfully while retaining its failed status. See the
[evidence export guide](docs/EVIDENCE_EXPORT.md) for validation, privacy boundaries, and CI usage.

## Local run history

Keep a private local index of minimized evidence, then compare two imports without reconnecting
to an MCP server or calling a model:

```bash
mkdir -p reports
mendpact history add examples/contracts/baseline-scan.json
mendpact history add examples/contracts/candidate-scan.json
mendpact history list
mendpact history compare 1 2 --output reports/history-comparison.json
```

Use the IDs printed by `history add`; `1` and `2` assume a fresh database. The default store is
`reports/history.sqlite`. Reimporting identical source bytes returns the existing ID without
resetting its age. History keeps minimized summaries and comparison fingerprints, not raw
reports, prompts, arguments, or credentials. It remains private local data, not an encrypted or
authenticated evidence store.

Comparisons reject different targets or report types, flag changed policies and model identities,
and withhold numeric deltas for missing/incomplete stages or changed behavior setups and contract
baselines. They are descriptive, not CI regression verdicts. Keep `guard` or `compare-models` as
the reliability gate.

Run `mendpact history prune` to preview entries imported at least 14 days ago. Add `--apply` to
delete eligible rows; original report files remain unchanged. Cleanup is explicit, not scheduled.
See the [local history guide](docs/HISTORY.md) for storage, retention, and comparison limits.

## Review evidence before sharing

Prepare a fixed-content ZIP containing only minimized HTML, summary JSON, and an integrity
manifest. The raw report is not included:

```bash
mkdir -p reports
mendpact share prepare guard-report.json --output reports/review-package.zip
mendpact share inspect reports/review-package.zip
```

Review `index.html` inside the ZIP and the inspection output. To record a local acknowledgement
for the exact package, paste its reviewed fingerprint:

```bash
mendpact share approve reports/review-package.zip \
  --accept-sha256 REVIEWED_PACKAGE_SHA256 \
  --acknowledge-public \
  --output reports/sharing-approval.json

mendpact share verify reports/review-package.zip \
  --approval reports/sharing-approval.json
```

After that exact package is acknowledged, prepare and verify static files for a separate GitHub
Pages workflow:

```bash
mendpact share prepare-site reports/review-package.zip \
  --approval reports/sharing-approval.json \
  --output reports/public-evidence

mendpact share verify-site reports/public-evidence \
  --package reports/review-package.zip \
  --approval reports/sharing-approval.json
```

Approval lasts seven days by default and at most 14 days. These commands do not upload, push, or
publish anything. An unsigned acknowledgement is not proof of reviewer identity, a live provider
call, or safety. Verification does not change the source report's failed/error outcome. See the
[reviewed sharing guide](docs/SHARING.md) and [static evidence guide](docs/PUBLIC_EVIDENCE.md) for
exact-byte checks, expiry, and publication limits.

## GitHub Action

MendPact can run as a composite GitHub Action. Scan mode remains the default for backward
compatibility, `auth` mode performs a credential-free OAuth preflight, guard mode runs the
complete scan, contract, and affected-replay workflow, and `compare-models` evaluates saved
behavior reports entirely offline. `calibrate-grader` checks saved semantic scores against
human-labelled calibration and validation examples. `evaluate` runs bounded replay or live
provider tool-selection checks and never executes the selected MCP tool.

```yaml
- id: mendpact
  uses: adhodari03/mendpact@v0.2.0
  with:
    mode: guard
    target: https://your-server.example/mcp
    baseline: mendpact/baseline-scan.json
    scenario: mendpact/scenarios.json
    replay: mendpact/replay.json
    output: mendpact-guard-report.json
```

The `v0.2.0` Action writes a Markdown job summary and bounded workflow annotations while keeping
the JSON report as its complete machine-readable output. It also exposes the report and
candidate-scan paths so the consuming workflow controls artifact upload and retention. Pin an
exact full commit SHA when an immutable reference with stronger supply-chain guarantees is
required. See the [GitHub Action guide](docs/GITHUB_ACTION.md) for complete authorization, scan,
and guard workflows.

To block a model upgrade that regresses saved behavior evidence:

```yaml
- id: mendpact-model-comparison
  uses: adhodari03/mendpact@v0.3.0
  with:
    mode: compare-models
    reference-report: mendpact/reference-behavior.json
    candidate-report: mendpact/candidate-behavior.json
    max-overall-pass-rate-drop: "0.02"
    max-scenario-pass-rate-drop: "0.05"
    output: mendpact-model-comparison.json
```

This mode does not accept or require a target, credential, or network allowance. Supply a
`mendpact.policy.v2` file to own its thresholds, or use the individual inputs shown above. Its job
summary displays the applied policy, reference and candidate metrics, and compatibility findings.
The JSON report remains the complete evidence artifact.

To collect a small live-provider sample, pass the provider key as an environment secret rather
than an Action input. The default `max-trials: "10"` ceiling is checked before provider requests:

```yaml
- id: mendpact-live-evaluation
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
    save-replay: mendpact/replay.json
```

Only the selected provider SDK is installed. Review provider pricing and the scenario/tool
metadata being shared before enabling this mode. Routine pull requests should continue using
saved replays and offline comparisons.

Semantic calibration can run through the same Action:

```yaml
- uses: adhodari03/mendpact@v0.3.0
  with:
    mode: calibrate-grader
    semantic-labels: mendpact/semantic-labels.json
    policy: mendpact.toml
    output: mendpact-semantic-calibration.json
```

## Policy as code

MendPact can load reviewed production or local settings from a versioned TOML policy. Policy v2
owns scan, contract, model-comparison, and semantic-calibration gates. Production policies cannot
enable private targets, plaintext HTTP, permissive model regressions, new confusion pairs, or weak
semantic-calibration evidence.

```bash
mendpact guard https://api.example/mcp \
  --baseline mendpact/baseline-scan.json \
  --policy mendpact.toml \
  --output mendpact-guard-report.json
```

The resolved policy is embedded in the report and GitHub job summary. See the
[policy reference](docs/POLICY.md) for profiles, controlled 14-day waivers, Action configuration,
and exit behavior.

## MCP conformance

MendPact also wraps the official MCP server conformance framework, pinned to version `0.1.16`.
This command requires Node.js 22 or newer because the upstream runner is distributed through npm.
The pinned release supports the `active`, `all`, and `pending` server suites.

The default runs only the initialization scenario:

```bash
mendpact conformance http://127.0.0.1:8000/mcp \
  --allow-private \
  --allow-insecure-http \
  --output conformance-report.json
```

Broader scenarios may invoke MCP tools and must only target an isolated test server. MendPact
requires an explicit acknowledgement:

```bash
mendpact conformance http://127.0.0.1:8000/mcp \
  --suite active \
  --allow-tool-calls \
  --allow-private \
  --allow-insecure-http
```

The wrapper uses the upstream exit code, retains the runner output, and normalizes every
`checks.json` artifact into a versioned MendPact conformance report. The upstream framework is
still marked unstable, which is why MendPact pins rather than silently following its latest
release.

Exit codes are designed for CI:

- `0`: the command completed and all configured checks passed;
- `1`: the command completed and a scan, conformance check, or behavior trial failed;
- `2`: validation, discovery, setup, replay data, comparison input, or report writing failed.

## Current checks

- missing or weak tool descriptions;
- schemas that accept arbitrary arguments;
- names and descriptions suggesting mutating, destructive, credential, execution, or financial
  behavior;
- explicit code/command execution tools identified by their normalized name and input fields;
- low-severity visibility when a server negotiates the legacy MCP `2024-11-05` revision;
- tool descriptions containing prompt-injection-like instructions;
- overly large tool catalogs;
- insecure HTTP transport;
- missing or unsafe OAuth protected-resource and authorization-server metadata;
- exact resource or issuer mismatches, unsafe OAuth endpoints, and missing PKCE `S256` signaling.

These checks are intentionally conservative heuristics. Every finding includes its rule ID and
evidence so a maintainer can review it rather than accepting a mysterious score.

## Development

```bash
python -m ruff check .
python -m mypy src
python -m pytest
```

CI also starts the isolated fixture and runs the pinned `server-initialize` conformance scenario.
The normalized conformance JSON is uploaded as a workflow artifact.

See [the architecture](docs/ARCHITECTURE.md), [security boundary](docs/SECURITY.md), and
[roadmap](docs/ROADMAP.md) for the technical direction. The [cost guide](docs/COSTS.md) explains
how to keep routine evaluation free and reserve small paid runs for provider validation.
Completed integration checks and their limitations are recorded in the
[validation report](docs/VALIDATION.md).

## License

MendPact is licensed under the [Apache License 2.0](LICENSE).
