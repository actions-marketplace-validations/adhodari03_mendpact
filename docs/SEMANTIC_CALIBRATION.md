# Semantic grader calibration

Semantic graders return a score, but an untested score threshold is not reliable evidence. MendPact
calibrates that threshold against human decisions and then measures it on a separate validation
split. The process is provider-neutral, deterministic, and offline.

## Input contract

The input uses schema `mendpact.semantic-labels.v1`. Each example contains:

- a stable example and scenario ID;
- a `calibration` or `validation` split;
- the task, expected behavior, and observed behavior reviewed by a human;
- the human's `accept` or `reject` label;
- a semantic score from `0` to `1`, where higher means more acceptable;
- an optional review rationale.

The grader name and version apply to every score in the file. Do not mix scores from different
grader prompts, models, or implementations. Treat a changed prompt as a new grader version.
MendPact rejects duplicate example IDs and requires both accepted and rejected labels in each
split. See the deliberately small
[`semantic-labels.example.json`](../examples/calibration/semantic-labels.example.json) fixture.

The example dataset demonstrates the file format and test path; its labels and scores are not a
production benchmark. Commit only reviewed, sanitized evidence that is safe for repository
readers. Keep sensitive production examples in appropriately protected storage.

## Threshold selection

Run:

```bash
mendpact calibrate-grader labels.json \
  --min-calibration-examples 20 \
  --min-validation-examples 20 \
  --min-validation-balanced-accuracy 0.90 \
  --max-validation-false-accept-rate 0.02 \
  --output semantic-calibration.json
```

MendPact chooses the score threshold using only the calibration split. It maximizes balanced
accuracy and resolves ties by preferring fewer false accepts, then higher accuracy, then the more
conservative threshold. The validation split never influences threshold selection.

The selected threshold is then evaluated on the untouched validation examples. The report stores
the confusion matrix, accuracy, balanced accuracy, precision, recall, specificity, false-accept
rate, every human/grader disagreement, the applied CI policy, and a formatting-independent SHA-256
digest of the complete labelled dataset.

## CI rules

| Rule | Failure condition |
| --- | --- |
| `MP-CAL-001` | Calibration split is smaller than the configured minimum. |
| `MP-CAL-002` | Validation split is smaller than the configured minimum. |
| `MP-CAL-003` | Validation balanced accuracy is below the configured minimum. |
| `MP-CAL-004` | Validation false-accept rate is above the configured maximum. |

Exit code `0` means the saved scores meet every configured requirement, `1` means the calibration
report was produced but failed policy, and `2` means the input or command was invalid.

Use `--policy mendpact.toml` to load these gates from the `[semantic_calibration]` section of a
`mendpact.policy.v2` file. The calibration report retains the resolved source policy and its
SHA-256. Policy v1 is rejected because it has no semantic-calibration contract, and individual
threshold options cannot be combined with policy.

## Trust boundary

This command does not generate semantic scores or claim that a grader is universally correct. It
tests one exact grader version against the supplied human labels. The score-generating system must
be run separately and consistently, and its model, prompt, rubric, and version should be reviewed.
Recalibrate whenever any of those inputs change or the evaluation population materially shifts.

Calibration validates a probabilistic judge; it does not override MendPact's deterministic safety
checks for missing tools, forbidden tools, multiple calls, invalid JSON, or schema-invalid
arguments. No MCP endpoint, model provider, tool, credential, or network connection is used by the
calibration command.
