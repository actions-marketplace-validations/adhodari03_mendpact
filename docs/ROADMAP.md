# Roadmap

## Milestone 0.1 — deterministic MCP scanner

- [x] Streamable HTTP target validation
- [x] MCP capability discovery
- [x] normalized capability graph
- [x] deterministic tool metadata and schema checks
- [x] JSON and terminal reports
- [x] CI exit codes and composite GitHub Action
- [x] exercise the CLI against an independently running fixture server
- [x] wrap the pinned official MCP conformance runner

## Milestone 0.2 — behavioral compatibility

- [x] provider-neutral `ModelDriver` and trace models
- [x] OpenAI Responses API driver
- [x] task-to-tool selection scenarios
- [x] JSON Schema argument grading
- [x] repetition, versioned baselines, and statistical regression thresholds
- [x] deterministic repetition and wrong-tool confusion summaries
- [x] trace replay without a live model call
- [x] export live decisions for deterministic replay

## Milestone 0.3 — contract intelligence

- [x] versioned MCP contract diff reports
- [x] capability addition, removal, and metadata classification
- [x] deterministic JSON Schema compatibility rules
- [x] behavior-scenario blast-radius mapping
- [x] CI thresholds and offline report comparison

## Milestone 0.4 — unified CI guard

- [x] single-scan guard orchestration
- [x] affected-scenario replay selection
- [x] versioned composite guard report
- [x] deterministic CI smoke workflow
- [x] backward-compatible scan and guard GitHub Action modes
- [x] report and candidate-scan Action outputs
- [x] PR-native GitHub job summaries and bounded annotations

## Milestone 0.5 — production adoption

- [x] versioned policy-as-code with production and local profiles
- [x] strict-policy negative CI test
- [x] controlled, expiring waivers with a 14-day maximum
- [x] one-command project initialization
- [x] authenticated production targets and OAuth metadata checks
- [x] credential-free OAuth deployment preflight and Action mode
- [x] reviewed contract baseline inspection and promotion lifecycle

## Milestone 0.6 — cross-provider matrix

- [x] Anthropic and Gemini drivers with mocked integration tests
- [x] bounded replay and live-provider evaluation mode for the composite GitHub Action
- [x] provider and model snapshots from complete behavior reports
- [x] semantic-score threshold calibration against human labels
- [x] offline compatibility comparison between model runs
- [x] offline model comparison mode for the composite GitHub Action
- [x] policy v2 gates for model comparison and semantic calibration

## Milestone 0.7 — hosted beta

The first slice prepares reviewed evidence for sharing without operating a hosted service.
Completed implementation is not equivalent to deployment or validation on customer workloads.

- [x] offline privacy-minimized HTML and versioned JSON evidence export for scan, behavior, and guard
- [x] explicit thresholds, skipped stages, source-file digests, and unsigned-evidence disclaimers
- [x] local minimized run-history store with deduplication and bounded listing
- [x] descriptive history comparison with target/setup checks and explicit 14-day cleanup
- [x] local sharing-package preparation, inspection, exact-byte acknowledgement, and expiry checks
- [x] offline current-rule rechecks with source provenance and explicit freshness limits
- [x] deterministic rule-impact deltas for introduced, resolved, and reclassified findings
- [x] bounded directory rechecks with one policy load and a versioned batch manifest
- [x] review-gated static evidence-site preparation and pre-publish verification
- [x] guarded real-world validation sessions with offline preflight and a two-scan ceiling
- [x] integrity-checked privacy-minimized summaries for completed validation sessions
- [ ] authenticated publisher with hosted deletion, expiry, and revocation controls
- [ ] projects, authentication, and encrypted bring-your-own-key storage
- [ ] scheduled scans and GitHub checks
- [ ] PostgreSQL persistence and object storage
- [ ] signed passports with a documented issuer and verification trust model
- [ ] opt-in compatibility index

### Recommended implementation sequence

1. Run the [real-world validation playbook](REAL_WORLD_VALIDATION.md) on explicitly authorized,
   independently developed targets. The offline setup and first local third-party runs are done;
   hosted/external validation remains pending explicit owner permission.
   The guarded session runner is ready to enforce a local approval record, clean revision, strict
   policy, retention window, and two-scan ceiling before the next live capture.
   Collect feedback on locally exported summaries using fixture or explicitly approved evidence.
   The [first validation set](REAL_WORLD_RESULTS.md) covers two local third-party implementations;
   broader target and authenticated-deployment coverage remains pending.
2. Exercise the local history and descriptive comparison workflow on approved real-world evidence;
   gather feedback before choosing hosted storage.
3. Design authenticated projects, report access controls, deletion, and retention; request review
   before introducing hosted infrastructure or credential custody.
   The local authenticated API design is deferred until validation informs that scope.
4. Integrate the reviewed-package acknowledgement with an authenticated publisher. Define hosted
   expiry, deletion and revocation before introducing a public evidence index. Local unsigned
   receipts alone do not establish reviewer identity or provide remote access control.

Signing cannot certify safety or prove that an API call happened. Its scope, issuer identity,
expiry, and revocation model need review before implementation. No hosting costs or live provider
tests are implied by this sequence.
