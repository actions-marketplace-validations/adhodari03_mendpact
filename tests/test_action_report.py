from __future__ import annotations

from pathlib import Path

from mendpact.action_report import (
    Annotation,
    format_annotation,
    render_action_report,
    render_report_file,
)


def _scan_payload() -> dict[str, object]:
    return {
        "schema_version": "mendpact.scan.v1",
        "status": "failed",
        "target": "https://user:secret@example.com/mcp?token=hidden#fragment",
        "policy": {
            "schema_version": "mendpact.policy.v1",
            "source_sha256": "0" * 64,
            "name": "production",
            "profile": "production",
            "scan_fail_on": "high",
            "contract_fail_on": "risky",
            "allow_private": False,
            "allow_insecure_http": False,
        },
        "summary": {
            "tool_count": 2,
            "resource_count": 1,
            "prompt_count": 0,
            "finding_count": 1,
        },
        "findings": [
            {
                "severity": "high",
                "rule_id": "MP-MCP-004",
                "subject": "tool:delete|project",
                "message": "Delete <everything>\nafter approval.",
            }
        ],
        "errors": [],
    }


def test_renders_scan_summary_without_leaking_target_secrets() -> None:
    rendered = render_action_report(_scan_payload(), "reports/scan report.json")

    assert "## MendPact Scan" in rendered.summary
    assert "https://example.com/mcp" in rendered.summary
    assert "secret" not in rendered.summary
    assert "token=hidden" not in rendered.summary
    assert "tool:delete&#124;project" in rendered.summary
    assert "Delete &lt;everything&gt;<br>after approval." in rendered.summary
    assert "### Applied policy" in rendered.summary
    assert "production" in rendered.summary
    assert "blocked" in rendered.summary
    assert rendered.annotations[0].level == "error"
    assert rendered.annotations[1].level == "warning"


def test_renders_offline_recheck_provenance() -> None:
    payload = _scan_payload()
    payload["recheck"] = {
        "source_sha256": "a" * 64,
        "source_status": "passed",
        "rechecked_at": "2026-09-08T12:00:00Z",
        "mendpact_version": "0.2.0",
        "authorization_refreshed": False,
    }

    rendered = render_action_report(payload, "recheck.json")

    assert "## MendPact Scan Recheck" in rendered.summary
    assert "### Offline recheck provenance" in rendered.summary
    assert "a" * 64 in rendered.summary
    assert "Authorization refreshed" in rendered.summary
    assert "No" in rendered.summary


def test_renders_offline_recheck_rule_impact() -> None:
    payload = _scan_payload()
    payload["recheck"] = {
        "source_sha256": "a" * 64,
        "source_status": "passed",
        "rechecked_at": "2026-09-08T12:00:00Z",
        "mendpact_version": "0.2.0",
        "authorization_refreshed": False,
        "rule_delta": {
            "schema_version": "mendpact.scan-rule-delta.v1",
            "introduced_count": 1,
            "resolved_count": 1,
            "reclassified_count": 1,
            "unchanged_count": 2,
            "changes": [
                {
                    "kind": "introduced",
                    "rule_id": "MP-MCP-007",
                    "subject": "tool:execute",
                    "before_severity": None,
                    "after_severity": "critical",
                },
                {
                    "kind": "resolved",
                    "rule_id": "MP-OLD-001",
                    "subject": None,
                    "before_severity": "low",
                    "after_severity": None,
                },
                {
                    "kind": "reclassified",
                    "rule_id": "MP-MCP-004",
                    "subject": "tool:delete_project",
                    "before_severity": "medium",
                    "after_severity": "high",
                },
            ],
        },
    }

    rendered = render_action_report(payload, "recheck.json")

    assert "#### Rule impact" in rendered.summary
    assert "| 1 | 1 | 1 | 2 |" in rendered.summary
    assert "#### Deterministic rule changes" in rendered.summary
    assert "INTRODUCED" in rendered.summary
    assert "RESOLVED" in rendered.summary
    assert "RECLASSIFIED" in rendered.summary
    assert "MP-MCP-007" in rendered.summary
    assert "tool:delete_project" in rendered.summary


def test_renders_guard_stages_contract_changes_and_failed_trials() -> None:
    payload: dict[str, object] = {
        "schema_version": "mendpact.guard.v1",
        "status": "failed",
        "target": "https://example.com/mcp",
        "summary": {
            "scan_status": "passed",
            "contract_status": "failed",
            "behavior_status": "failed",
            "affected_scenario_count": 1,
            "evaluated_scenario_count": 1,
        },
        "contract_diff": {
            "summary": {
                "change_count": 1,
                "changes_by_impact": {"compatible": 0, "risky": 0, "breaking": 1},
            },
            "changes": [
                {
                    "impact": "breaking",
                    "rule_id": "MP-DIFF-002",
                    "subject": "tool:read_status",
                    "message": "Required argument added.",
                    "affected_scenarios": ["read-status"],
                }
            ],
        },
        "behavior": {
            "status": "failed",
            "summary": {
                "trial_count": 1,
                "passed_trials": 0,
                "failed_trials": 1,
                "pass_rate": 0.0,
            },
            "trials": [
                {
                    "scenario": {"id": "read-status"},
                    "trace": {"selected_tool": "delete_project"},
                    "grade": {"passed": False, "reasons": ["wrong tool"]},
                }
            ],
        },
        "scan": {
            "status": "passed",
            "summary": {
                "tool_count": 2,
                "resource_count": 0,
                "prompt_count": 0,
                "finding_count": 0,
            },
            "findings": [],
        },
        "errors": [],
    }

    rendered = render_action_report(payload, "guard.json")

    assert "## MendPact Guard" in rendered.summary
    assert "### Guard stages" in rendered.summary
    assert "### Contract changes" in rendered.summary
    assert "BREAKING" in rendered.summary
    assert "read-status" in rendered.summary
    assert "delete_project" in rendered.summary
    assert "wrong tool" in rendered.summary


def test_renders_standalone_behavior_evaluation() -> None:
    payload: dict[str, object] = {
        "schema_version": "mendpact.behavior.v1",
        "status": "failed",
        "target": "https://example.com/mcp",
        "driver": "anthropic",
        "model": "claude-test-model",
        "repetitions": 1,
        "summary": {
            "scenario_count": 2,
            "trial_count": 2,
            "passed_trials": 1,
            "failed_trials": 1,
            "pass_rate": 0.5,
            "total_tokens": 80,
            "total_latency_ms": 50,
        },
        "trials": [
            {
                "scenario": {"id": "read-status"},
                "trace": {"attempt": 1, "selected_tool": "delete_project"},
                "grade": {"passed": False, "reasons": ["wrong tool"]},
            }
        ],
        "errors": [],
    }

    rendered = render_action_report(payload, "behavior.json")

    assert "## MendPact Behavior" in rendered.summary
    assert "### Model tool-selection evaluation" in rendered.summary
    assert "anthropic / claude-test-model" in rendered.summary
    assert "50.0%" in rendered.summary
    assert "80" in rendered.summary
    assert "25 ms" in rendered.summary
    assert "read-status" in rendered.summary
    assert "delete_project" in rendered.summary
    assert "wrong tool" in rendered.summary
    assert rendered.annotations[0].level == "error"
    assert rendered.annotations[1].level == "warning"


def test_escapes_github_workflow_annotation_commands() -> None:
    command = format_annotation(
        Annotation(
            level="warning",
            title="Rule: risky, change",
            message="100% unsafe\r\nnext line",
        )
    )

    assert command == (
        "::warning title=Rule%3A risky%2C change::100%25 unsafe%0D%0Anext line"
    )


def test_missing_report_returns_non_failing_feedback(tmp_path: Path) -> None:
    report = tmp_path / "missing.json"

    rendered = render_report_file(report)

    assert "MendPact report unavailable" in rendered.summary
    assert rendered.annotations[0].level == "warning"
    assert str(report) in rendered.annotations[0].message


def test_renders_active_waiver_as_visible_notice() -> None:
    payload = _scan_payload()
    waiver = {
        "rule_id": "MP-MCP-004",
        "subject": "tool:delete|project",
        "reason": "Migration requires a temporary exception.",
        "approved_by": "security@example.com",
        "approved_on": "2026-08-01",
        "expires_on": "2026-08-15",
        "status": "active",
    }
    payload["status"] = "passed"
    policy = payload["policy"]
    assert isinstance(policy, dict)
    policy["waivers"] = [waiver]
    findings = payload["findings"]
    assert isinstance(findings, list)
    assert isinstance(findings[0], dict)
    findings[0]["waiver"] = waiver

    rendered = render_action_report(payload, "scan.json")

    assert "#### Policy waivers" in rendered.summary
    assert "ACTIVE" in rendered.summary
    assert "Waived until 2026-08-15" in rendered.summary
    assert "security@example.com" in rendered.summary
    assert rendered.annotations[0].level == "notice"
    assert "WAIVED" in rendered.annotations[0].title


def test_renders_oauth_metadata_without_a_credential_value() -> None:
    payload = _scan_payload()
    payload["authorization"] = {
        "status": "valid",
        "credential_source": "environment",
        "bearer_token_env": "MENDPACT_ACCESS_TOKEN",
        "protected_resource_metadata_url": (
            "https://api.example.com/.well-known/oauth-protected-resource"
        ),
        "authorization_servers": ["https://auth.example.com"],
        "scopes_supported": ["tools:read"],
    }

    rendered = render_action_report(payload, "scan.json")

    assert "### OAuth metadata" in rendered.summary
    assert "https://auth.example.com" in rendered.summary
    assert "tools:read" in rendered.summary
    assert "MENDPACT_ACCESS_TOKEN" not in rendered.summary


def test_renders_standalone_authorization_audit() -> None:
    payload: dict[str, object] = {
        "schema_version": "mendpact.authorization.v1",
        "status": "failed",
        "target": "https://api.example.com/mcp",
        "failure_threshold": "high",
        "metadata": {
            "status": "invalid",
            "credential_source": "none",
            "protected_resource_metadata_url": (
                "https://api.example.com/.well-known/oauth-protected-resource"
            ),
            "authorization_servers": ["https://auth.example.com"],
            "scopes_supported": ["tools:read"],
            "challenge_scopes": ["tools:read", "profile"],
            "warnings": ["OIDC fallback was used."],
        },
        "findings": [
            {
                "severity": "high",
                "rule_id": "MP-AUTH-005",
                "subject": "oauth:issuer:https://auth.example.com",
                "message": "Issuer did not match.",
            }
        ],
        "errors": [],
    }

    rendered = render_action_report(payload, "authorization.json")

    assert "## MendPact Authorization" in rendered.summary
    assert "### OAuth authorization audit" in rendered.summary
    assert "#### Authorization findings" in rendered.summary
    assert "MP-AUTH-005" in rendered.summary
    assert "OIDC fallback was used." in rendered.summary
    assert "HIGH" in rendered.summary
    assert "profile" in rendered.summary
    assert rendered.annotations[0].level == "error"


def test_renders_model_comparison_matrix_and_findings() -> None:
    payload: dict[str, object] = {
        "schema_version": "mendpact.model-comparison.v1",
        "status": "failed",
        "target": "https://api.example.com/mcp",
        "thresholds": {
            "max_overall_pass_rate_drop": 0.02,
            "max_scenario_pass_rate_drop": 0.05,
            "allow_new_confusions": False,
        },
        "reference": {
            "run_id": "reference-run",
            "driver": "openai",
            "model": "reference-model",
            "pass_rate": 1.0,
            "total_tokens": 100,
            "average_latency_ms": 25.0,
        },
        "candidates": [
            {
                "run_id": "candidate-run",
                "driver": "openai",
                "model": "candidate-model",
                "pass_rate": 0.5,
                "total_tokens": 80,
                "average_latency_ms": 20.0,
            }
        ],
        "comparisons": [
            {
                "candidate_run_id": "candidate-run",
                "status": "failed",
                "pass_rate_delta": -0.5,
                "findings": [
                    {
                        "rule_id": "MP-MATRIX-002",
                        "impact": "failure",
                        "scenario_id": "read-status",
                        "message": "Scenario pass rate dropped by 50.0%.",
                    }
                ],
            }
        ],
        "errors": [],
    }

    rendered = render_action_report(payload, "model-comparison.json")

    assert "## MendPact Model Comparison" in rendered.summary
    assert "### Comparison policy" in rendered.summary
    assert "### Model runs" in rendered.summary
    assert "reference-model" in rendered.summary
    assert "candidate-model" in rendered.summary
    assert "-50.0%" in rendered.summary
    assert "### Compatibility findings" in rendered.summary
    assert "MP-MATRIX-002" in rendered.summary
    assert rendered.annotations[0].level == "error"
    assert rendered.annotations[1].level == "warning"
    assert "read-status" in rendered.annotations[1].message


def test_renders_semantic_calibration_metrics_and_disagreements() -> None:
    metrics = {
        "example_count": 4,
        "accepted_labels": 2,
        "rejected_labels": 2,
        "true_accepts": 2,
        "true_rejects": 1,
        "false_accepts": 1,
        "false_rejects": 0,
        "accuracy": 0.75,
        "balanced_accuracy": 0.75,
        "precision": 2 / 3,
        "recall": 1.0,
        "specificity": 0.5,
        "false_accept_rate": 0.5,
    }
    payload: dict[str, object] = {
        "schema_version": "mendpact.semantic-calibration.v1",
        "status": "failed",
        "label_set_name": "Reviewed routing labels",
        "label_set_sha256": "a" * 64,
        "grader": "semantic-judge",
        "grader_version": "2026-09",
        "selected_threshold": 0.82,
        "policy": {
            "min_calibration_examples": 4,
            "min_validation_examples": 4,
            "min_validation_balanced_accuracy": 0.8,
            "max_validation_false_accept_rate": 0.1,
        },
        "calibration": {**metrics, "false_accepts": 0, "false_accept_rate": 0.0},
        "validation": metrics,
        "disagreements": [
            {
                "example_id": "val-dangerous-choice",
                "scenario_id": "read-status",
                "split": "validation",
                "semantic_score": 0.9,
                "human_label": "reject",
                "predicted_label": "accept",
            }
        ],
        "findings": [
            {
                "rule_id": "MP-CAL-004",
                "impact": "failure",
                "message": "Validation false-accept rate exceeds the configured maximum.",
                "observed_value": 0.5,
                "required_value": 0.1,
            }
        ],
        "errors": [],
    }

    rendered = render_action_report(payload, "semantic-calibration.json")

    assert "## MendPact Semantic Calibration" in rendered.summary
    assert "### Calibrated grader" in rendered.summary
    assert "semantic-judge" in rendered.summary
    assert "### Validation policy" in rendered.summary
    assert "### Calibration quality" in rendered.summary
    assert "50.0%" in rendered.summary
    assert "### Human/grader disagreements" in rendered.summary
    assert "val-dangerous-choice" in rendered.summary
    assert "### Applied policy" not in rendered.summary
    assert rendered.annotations[0].level == "error"
    assert rendered.annotations[1].level == "warning"
    assert "false-accept rate" in rendered.annotations[1].message

    payload["source_policy"] = {
        "schema_version": "mendpact.policy.v2",
        "name": "reviewed-reliability",
        "profile": "production",
        "scan_fail_on": "high",
        "contract_fail_on": "risky",
        "allow_private": False,
        "allow_insecure_http": False,
        "waivers": [],
    }
    with_policy = render_action_report(payload, "semantic-calibration.json")
    assert "### Applied policy" in with_policy.summary
    assert "reviewed-reliability" in with_policy.summary
    assert "mendpact.policy.v2" in with_policy.summary
