# Unified MCP guard

`mendpact guard` is the provider-free pull-request workflow. It turns a committed scan artifact,
a current MCP endpoint, and optional replay data into one CI decision.

## Execution order

1. Validate and scan the current endpoint once.
2. Compare the new capability graph with the committed baseline.
3. Map changed tools and server instructions to affected behavior scenarios.
4. Replay only those affected scenarios against the graph already discovered in step 1.
5. Combine the scan, contract, and behavior outcomes into `mendpact.guard.v1` JSON.

No tool is executed and no model provider is contacted. Replay decisions are committed test
fixtures, so routine pull-request checks remain deterministic and free.

## Command

```bash
mendpact guard http://127.0.0.1:8000/mcp \
  --baseline examples/guard/baseline-scan.json \
  --scenario examples/scenarios/read-status.json \
  --replay examples/replays/read-status.json \
  --scan-fail-on critical \
  --allow-private \
  --allow-insecure-http \
  --output guard-report.json \
  --save-scan candidate-scan.json
```

`--scenario` and `--replay` must be provided together. They may both be omitted when only scan
and contract checks are wanted. The default scan threshold is `high`, and the default contract
threshold is `breaking`.

## Exit codes

- `0`: every configured stage passed;
- `1`: at least one scan, contract, or behavior policy failed;
- `2`: configuration, discovery, replay, or report generation errored.

The report embeds the complete scan, contract diff, and behavior evidence. `--save-scan` also
writes the current scan separately so a reviewed artifact can become the next committed
baseline. Use `mendpact baseline inspect` and `mendpact baseline promote` rather than copying that
artifact directly; the [baseline lifecycle guide](BASELINES.md) explains the review boundary.
