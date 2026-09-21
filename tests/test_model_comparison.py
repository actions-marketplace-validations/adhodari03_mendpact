from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mendpact.behavior import summarize_behavior
from mendpact.cli import app
from mendpact.domain import (
    BehaviorExpectation,
    BehaviorGrade,
    BehaviorReport,
    BehaviorScenario,
    BehaviorSuite,
    BehaviorTrial,
    ModelComparisonThresholds,
    RegressionImpact,
    ScanStatus,
    ToolCallTrace,
)
from mendpact.model_comparison import compare_behavior_reports

runner = CliRunner()


def _report(
    decisions: dict[str, list[str | None]],
    *,
    run_id: str,
    model: str,
    target: str = "https://api.example.com/mcp",
    tool_catalog: list[str] | None = None,
) -> BehaviorReport:
    tools = tool_catalog or ["delete_project", "read_status"]
    scenarios = [
        BehaviorScenario(
            id=scenario_id,
            name=scenario_id.replace("-", " ").title(),
            task=f"Perform {scenario_id}.",
            expectation=BehaviorExpectation(tool=scenario_id.replace("-", "_")),
        )
        for scenario_id in decisions
    ]
    repetitions = len(next(iter(decisions.values())))
    trials: list[BehaviorTrial] = []
    for scenario in scenarios:
        assert len(decisions[scenario.id]) == repetitions
        for attempt, selected_tool in enumerate(decisions[scenario.id], start=1):
            passed = selected_tool == scenario.expectation.tool
            trials.append(
                BehaviorTrial(
                    scenario=scenario,
                    trace=ToolCallTrace(
                        scenario_id=scenario.id,
                        attempt=attempt,
                        provider="openai",
                        model=f"{model}-resolved",
                        available_tools=sorted(tools),
                        selected_tool=selected_tool,
                        tool_call_count=1 if selected_tool is not None else 0,
                        latency_ms=float(attempt * 10),
                        input_tokens=5,
                        output_tokens=2,
                        total_tokens=7,
                    ),
                    grade=BehaviorGrade(
                        passed=passed,
                        tool_selected=selected_tool is not None,
                        single_tool_selected=selected_tool is not None,
                        tool_exists=selected_tool in tools,
                        expected_tool_selected=passed,
                        arguments_valid=True,
                        expected_arguments_match=True,
                        forbidden_tool_selected=False,
                        reasons=[] if passed else ["Wrong tool."],
                    ),
                )
            )
    suite = BehaviorSuite(name="Core routing", scenarios=scenarios)
    summary = summarize_behavior(suite, trials)
    return BehaviorReport(
        run_id=run_id,
        target=target,
        status=ScanStatus.PASSED if not summary.failed_trials else ScanStatus.FAILED,
        suite_name=suite.name,
        driver="openai",
        model=model,
        repetitions=repetitions,
        tool_catalog=sorted(tools),
        trials=trials,
        summary=summary,
    )


def test_compares_complete_runs_and_preserves_telemetry() -> None:
    reference = _report(
        {"read-status": ["read_status", "read_status"]},
        run_id="reference",
        model="model-a",
    )
    candidate = _report(
        {"read-status": ["read_status", "read_status"]},
        run_id="candidate",
        model="model-b",
    )

    report = compare_behavior_reports(reference, [candidate])

    assert report.schema_version == "mendpact.model-comparison.v1"
    assert report.status == ScanStatus.PASSED
    assert report.reference.resolved_models == ["model-a-resolved"]
    assert report.candidates[0].total_tokens == 14
    assert report.candidates[0].average_latency_ms == 15.0
    assert report.comparisons[0].pass_rate_delta == 0.0
    assert not report.comparisons[0].findings


def test_detects_overall_scenario_and_new_confusion_regressions() -> None:
    reference = _report(
        {"read-status": ["read_status", "read_status"]},
        run_id="reference",
        model="model-a",
    )
    candidate = _report(
        {"read-status": ["read_status", "delete_project"]},
        run_id="candidate",
        model="model-b",
    )

    report = compare_behavior_reports(reference, [candidate])

    assert report.status == ScanStatus.FAILED
    assert {finding.rule_id for finding in report.comparisons[0].findings} == {
        "MP-MATRIX-001",
        "MP-MATRIX-002",
        "MP-MATRIX-003",
    }
    assert report.comparisons[0].new_confusion_edges[0].selected_tool == (
        "delete_project"
    )


def test_per_scenario_guard_prevents_one_gain_from_hiding_another_drop() -> None:
    reference = _report(
        {
            "read-status": ["read_status"],
            "delete-project": ["read_status"],
        },
        run_id="reference",
        model="model-a",
    )
    candidate = _report(
        {
            "read-status": ["delete_project"],
            "delete-project": ["delete_project"],
        },
        run_id="candidate",
        model="model-b",
    )

    report = compare_behavior_reports(
        reference,
        [candidate],
        ModelComparisonThresholds(allow_new_confusions=True),
    )

    rules = [finding.rule_id for finding in report.comparisons[0].findings]
    assert "MP-MATRIX-001" not in rules
    assert "MP-MATRIX-002" in rules
    assert report.comparisons[0].pass_rate_delta == 0.0


def test_new_confusions_can_be_warnings_when_explicitly_allowed() -> None:
    reference = _report(
        {"read-status": ["read_status"]},
        run_id="reference",
        model="model-a",
    )
    candidate = _report(
        {"read-status": ["delete_project"]},
        run_id="candidate",
        model="model-b",
    )

    report = compare_behavior_reports(
        reference,
        [candidate],
        ModelComparisonThresholds(
            max_overall_pass_rate_drop=1.0,
            max_scenario_pass_rate_drop=1.0,
            allow_new_confusions=True,
        ),
    )

    assert report.status == ScanStatus.PASSED
    assert report.comparisons[0].findings[0].impact == RegressionImpact.WARNING


def test_compares_multiple_candidates_independently() -> None:
    reference = _report(
        {"read-status": ["read_status"]},
        run_id="reference",
        model="model-a",
    )
    unchanged = _report(
        {"read-status": ["read_status"]},
        run_id="unchanged",
        model="model-b",
    )
    regressed = _report(
        {"read-status": ["delete_project"]},
        run_id="regressed",
        model="model-c",
    )

    report = compare_behavior_reports(reference, [unchanged, regressed])

    assert [comparison.status for comparison in report.comparisons] == [
        ScanStatus.PASSED,
        ScanStatus.FAILED,
    ]
    assert report.status == ScanStatus.FAILED


def test_rejects_tampered_and_incomparable_reports() -> None:
    reference = _report(
        {"read-status": ["read_status"]},
        run_id="reference",
        model="model-a",
    )
    tampered = _report(
        {"read-status": ["read_status"]},
        run_id="candidate",
        model="model-b",
    )
    assert tampered.summary is not None
    tampered.summary.passed_trials = 0

    with pytest.raises(ValueError, match="summary does not match"):
        compare_behavior_reports(reference, [tampered])

    different_target = _report(
        {"read-status": ["read_status"]},
        run_id="other",
        model="model-b",
        target="https://other.example.com/mcp",
    )
    with pytest.raises(ValueError, match="mismatched: target"):
        compare_behavior_reports(reference, [different_target])


def test_rejects_attempt_and_grade_evidence_that_contradicts_the_run() -> None:
    reference = _report(
        {"read-status": ["read_status"]},
        run_id="reference",
        model="model-a",
    )
    bad_attempt = _report(
        {"read-status": ["read_status"]},
        run_id="bad-attempt",
        model="model-b",
    )
    bad_attempt.trials[0].trace.attempt = 2
    with pytest.raises(ValueError, match="exactly attempts"):
        compare_behavior_reports(reference, [bad_attempt])

    bad_grade = _report(
        {"read-status": ["read_status"]},
        run_id="bad-grade",
        model="model-b",
    )
    bad_grade.trials[0].grade.expected_tool_selected = False
    with pytest.raises(ValueError, match="grade that contradicts"):
        compare_behavior_reports(reference, [bad_grade])


def test_rejects_duplicate_run_identity() -> None:
    reference = _report(
        {"read-status": ["read_status"]},
        run_id="same-run",
        model="model-a",
    )
    candidate = reference.model_copy(deep=True)

    with pytest.raises(ValueError, match="unique run IDs"):
        compare_behavior_reports(reference, [candidate])


def test_cli_writes_failed_comparison_and_uses_ci_exit_code(tmp_path: Path) -> None:
    reference_path = tmp_path / "reference.json"
    candidate_path = tmp_path / "candidate.json"
    output_path = tmp_path / "comparison.json"
    reference_path.write_text(
        _report(
            {"read-status": ["read_status"]},
            run_id="reference",
            model="model-a",
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )
    candidate_path.write_text(
        _report(
            {"read-status": ["delete_project"]},
            run_id="candidate",
            model="model-b",
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "compare-models",
            str(reference_path),
            str(candidate_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 1
    assert "model comparison: FAILED" in result.stdout
    assert "model-b" in result.stdout
    assert "MP-MATRIX-001" in result.stdout
    assert json.loads(output_path.read_text(encoding="utf-8"))["status"] == "failed"


def test_cli_refuses_to_overwrite_an_input(tmp_path: Path) -> None:
    reference_path = tmp_path / "reference.json"
    candidate_path = tmp_path / "candidate.json"
    for path, run_id, model in (
        (reference_path, "reference", "model-a"),
        (candidate_path, "candidate", "model-b"),
    ):
        path.write_text(
            _report(
                {"read-status": ["read_status"]},
                run_id=run_id,
                model=model,
            ).model_dump_json(indent=2),
            encoding="utf-8",
        )

    result = runner.invoke(
        app,
        [
            "compare-models",
            str(reference_path),
            str(candidate_path),
            "--output",
            str(candidate_path),
        ],
    )

    assert result.exit_code == 2
    assert "cannot overwrite" in result.stdout


def test_cli_uses_v2_policy_for_model_comparison(tmp_path: Path) -> None:
    reference_path = tmp_path / "reference.json"
    candidate_path = tmp_path / "candidate.json"
    output_path = tmp_path / "comparison.json"
    policy_path = tmp_path / "mendpact.toml"
    reference_path.write_text(
        _report(
            {"read-status": ["read_status"]},
            run_id="reference",
            model="model-a",
        ).model_dump_json(),
        encoding="utf-8",
    )
    candidate_path.write_text(
        _report(
            {"read-status": ["delete_project"]},
            run_id="candidate",
            model="model-b",
        ).model_dump_json(),
        encoding="utf-8",
    )
    policy_path.write_text(
        '\n'.join(
            [
                'schema_version = "mendpact.policy.v2"',
                'name = "model-upgrade"',
                'profile = "local"',
                '',
                '[model_comparison]',
                'max_overall_pass_rate_drop = 1.0',
                'max_scenario_pass_rate_drop = 1.0',
                'allow_new_confusions = true',
            ]
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "compare-models",
            str(reference_path),
            str(candidate_path),
            "--policy",
            str(policy_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["policy"]["schema_version"] == "mendpact.policy.v2"
    assert payload["policy"]["name"] == "model-upgrade"
    assert payload["thresholds"]["max_overall_pass_rate_drop"] == 1.0
    assert payload["thresholds"]["allow_new_confusions"] is True


def test_cli_rejects_v1_or_explicit_overrides_for_model_policy(tmp_path: Path) -> None:
    reference_path = tmp_path / "reference.json"
    candidate_path = tmp_path / "candidate.json"
    for path, run_id, model in (
        (reference_path, "reference", "model-a"),
        (candidate_path, "candidate", "model-b"),
    ):
        path.write_text(
            _report(
                {"read-status": ["read_status"]},
                run_id=run_id,
                model=model,
            ).model_dump_json(),
            encoding="utf-8",
        )
    policy_path = tmp_path / "mendpact.toml"
    policy_path.write_text(
        'schema_version = "mendpact.policy.v1"\nname = "legacy"\nprofile = "local"\n',
        encoding="utf-8",
    )

    legacy = runner.invoke(
        app,
        [
            "compare-models",
            str(reference_path),
            str(candidate_path),
            "--policy",
            str(policy_path),
        ],
    )
    policy_path.write_text(
        'schema_version = "mendpact.policy.v2"\nname = "current"\nprofile = "local"\n',
        encoding="utf-8",
    )
    override = runner.invoke(
        app,
        [
            "compare-models",
            str(reference_path),
            str(candidate_path),
            "--policy",
            str(policy_path),
            "--max-overall-pass-rate-drop",
            "0.1",
        ],
    )

    assert legacy.exit_code == 2
    assert "requires schema_version" in legacy.stdout
    assert "mendpact.policy.v2" in legacy.stdout
    assert override.exit_code == 2
    assert "--policy cannot be combined" in override.stdout
    assert "--max-overall-pass-rate-drop" in override.stdout


def test_cli_model_comparison_does_not_overwrite_policy(tmp_path: Path) -> None:
    reference_path = tmp_path / "reference.json"
    candidate_path = tmp_path / "candidate.json"
    for path, run_id, model in (
        (reference_path, "reference", "model-a"),
        (candidate_path, "candidate", "model-b"),
    ):
        path.write_text(
            _report(
                {"read-status": ["read_status"]},
                run_id=run_id,
                model=model,
            ).model_dump_json(),
            encoding="utf-8",
        )
    policy_path = tmp_path / "mendpact.toml"
    source = (
        'schema_version = "mendpact.policy.v2"\n'
        'name = "current"\n'
        'profile = "local"\n'
    )
    policy_path.write_text(source, encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "compare-models",
            str(reference_path),
            str(candidate_path),
            "--policy",
            str(policy_path),
            "--output",
            str(policy_path),
        ],
    )

    assert result.exit_code == 2
    assert "cannot overwrite" in result.stdout
    assert policy_path.read_text(encoding="utf-8") == source
