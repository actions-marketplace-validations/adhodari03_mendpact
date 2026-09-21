"""Offline, provider-neutral comparison of complete behavior reports."""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

from mendpact.behavior import summarize_behavior
from mendpact.domain import (
    BehaviorReport,
    BehaviorScenario,
    BehaviorSuite,
    ConfusionEdge,
    ModelCandidateComparison,
    ModelComparisonFinding,
    ModelComparisonReport,
    ModelComparisonThresholds,
    ModelRunSnapshot,
    ModelScenarioDelta,
    ModelScenarioSnapshot,
    PolicySnapshot,
    RegressionImpact,
    ScanStatus,
)

_NO_TOOL = "<no-tool>"


def load_behavior_report(path: Path) -> BehaviorReport:
    """Load one versioned behavior report for offline comparison."""

    report = BehaviorReport.model_validate_json(path.read_text(encoding="utf-8"))
    if report.schema_version != "mendpact.behavior.v1":
        raise ValueError(
            f"Unsupported behavior schema '{report.schema_version}'; "
            "expected mendpact.behavior.v1."
        )
    return report


def validate_behavior_report(
    report: BehaviorReport,
    label: str,
) -> dict[str, BehaviorScenario]:
    """Validate that an artifact contains one internally consistent, complete run."""

    if report.status == ScanStatus.ERROR or report.errors or report.summary is None:
        raise ValueError(f"The {label} must contain a complete behavior run.")
    if not report.trials:
        raise ValueError(f"The {label} must contain a complete behavior run.")
    if not report.run_id.strip() or not report.driver.strip() or not report.model.strip():
        raise ValueError(f"The {label} has missing run, driver, or model identity.")
    if len(report.tool_catalog) != len(set(report.tool_catalog)):
        raise ValueError(f"The {label} contains duplicate tool names.")

    scenarios: dict[str, BehaviorScenario] = {}
    trials_by_scenario: dict[str, list[int]] = defaultdict(list)
    expected_catalog = sorted(report.tool_catalog)
    for trial in report.trials:
        scenario = scenarios.setdefault(trial.scenario.id, trial.scenario)
        if scenario != trial.scenario:
            raise ValueError(
                f"The {label} contains conflicting definitions for scenario "
                f"'{trial.scenario.id}'."
            )
        if trial.trace.scenario_id != trial.scenario.id:
            raise ValueError(
                f"The {label} has a trace assigned to the wrong scenario."
            )
        if trial.trace.provider != report.driver:
            raise ValueError(
                f"The {label} has trace provider metadata that does not match the report."
            )
        if sorted(trial.trace.available_tools) != expected_catalog:
            raise ValueError(
                f"The {label} has a trace tool catalog that does not match the report."
            )
        expected_grade_flags = (
            trial.trace.selected_tool is not None,
            trial.trace.tool_call_count == 1,
            trial.trace.selected_tool in report.tool_catalog
            if trial.trace.selected_tool is not None
            else False,
            trial.trace.selected_tool == trial.scenario.expectation.tool,
            trial.trace.selected_tool in trial.scenario.expectation.forbidden_tools,
        )
        actual_grade_flags = (
            trial.grade.tool_selected,
            trial.grade.single_tool_selected,
            trial.grade.tool_exists,
            trial.grade.expected_tool_selected,
            trial.grade.forbidden_tool_selected,
        )
        if actual_grade_flags != expected_grade_flags:
            raise ValueError(f"The {label} has a grade that contradicts its trace evidence.")
        expected_passed = all(
            (
                trial.grade.tool_selected,
                trial.grade.single_tool_selected,
                trial.grade.tool_exists,
                trial.grade.expected_tool_selected,
                trial.grade.arguments_valid,
                trial.grade.expected_arguments_match,
                not trial.grade.forbidden_tool_selected,
            )
        )
        if trial.grade.passed != expected_passed:
            raise ValueError(f"The {label} has inconsistent grade outcome fields.")
        trials_by_scenario[trial.scenario.id].append(trial.trace.attempt)

    expected_attempts = list(range(1, report.repetitions + 1))
    for scenario_id, attempts in trials_by_scenario.items():
        if sorted(attempts) != expected_attempts:
            raise ValueError(
                f"The {label} does not contain exactly attempts 1 through "
                f"{report.repetitions} for scenario '{scenario_id}'."
            )

    suite = BehaviorSuite(name=report.suite_name, scenarios=list(scenarios.values()))
    rebuilt_summary = summarize_behavior(suite, report.trials)
    if rebuilt_summary != report.summary:
        raise ValueError(f"The {label} summary does not match its trial evidence.")
    return scenarios


def _snapshot(
    report: BehaviorReport,
    scenarios: dict[str, BehaviorScenario],
) -> ModelRunSnapshot:
    assert report.summary is not None
    trials_by_scenario = {
        scenario_id: [
            trial for trial in report.trials if trial.scenario.id == scenario_id
        ]
        for scenario_id in scenarios
    }
    scenario_snapshots: list[ModelScenarioSnapshot] = []
    for scenario_id in sorted(scenarios):
        scenario = scenarios[scenario_id]
        trials = trials_by_scenario[scenario_id]
        passed = sum(trial.grade.passed for trial in trials)
        selections = Counter(
            trial.trace.selected_tool if trial.trace.selected_tool is not None else _NO_TOOL
            for trial in trials
        )
        scenario_snapshots.append(
            ModelScenarioSnapshot(
                scenario_id=scenario_id,
                scenario_name=scenario.name,
                expected_tool=scenario.expectation.tool,
                trial_count=len(trials),
                passed_trials=passed,
                failed_trials=len(trials) - passed,
                pass_rate=passed / len(trials),
                selection_counts=dict(sorted(selections.items())),
            )
        )

    measured_latencies = [
        trial.trace.latency_ms
        for trial in report.trials
        if trial.trace.latency_ms is not None
    ]
    return ModelRunSnapshot(
        run_id=report.run_id,
        generated_at=report.generated_at,
        driver=report.driver,
        model=report.model,
        resolved_models=sorted({trial.trace.model for trial in report.trials}),
        scenario_count=report.summary.scenario_count,
        trial_count=report.summary.trial_count,
        passed_trials=report.summary.passed_trials,
        failed_trials=report.summary.failed_trials,
        pass_rate=report.summary.pass_rate,
        input_tokens=report.summary.input_tokens,
        output_tokens=report.summary.output_tokens,
        total_tokens=report.summary.total_tokens,
        measured_latency_trials=len(measured_latencies),
        average_latency_ms=(
            sum(measured_latencies) / len(measured_latencies)
            if measured_latencies
            else None
        ),
        confusion_edges=report.summary.confusion_edges,
        scenarios=scenario_snapshots,
    )


def _ensure_comparable(
    reference: BehaviorReport,
    candidate: BehaviorReport,
    reference_scenarios: dict[str, BehaviorScenario],
    candidate_scenarios: dict[str, BehaviorScenario],
    label: str,
) -> None:
    differences: list[str] = []
    if candidate.target != reference.target:
        differences.append("target")
    if candidate.suite_name != reference.suite_name:
        differences.append("suite name")
    if candidate.repetitions != reference.repetitions:
        differences.append("repetitions")
    if sorted(candidate.tool_catalog) != sorted(reference.tool_catalog):
        differences.append("tool catalog")
    if candidate_scenarios != reference_scenarios:
        differences.append("scenario definitions")
    if differences:
        raise ValueError(
            f"The {label} is not comparable with the reference; mismatched: "
            + ", ".join(differences)
            + "."
        )


def _new_confusions(
    reference: ModelRunSnapshot,
    candidate: ModelRunSnapshot,
) -> list[ConfusionEdge]:
    reference_pairs = {
        (edge.intended_tool, edge.selected_tool) for edge in reference.confusion_edges
    }
    return [
        edge
        for edge in candidate.confusion_edges
        if (edge.intended_tool, edge.selected_tool) not in reference_pairs
    ]


def _compare_candidate(
    reference: ModelRunSnapshot,
    candidate: ModelRunSnapshot,
    thresholds: ModelComparisonThresholds,
) -> ModelCandidateComparison:
    findings: list[ModelComparisonFinding] = []
    overall_drop = reference.pass_rate - candidate.pass_rate
    if overall_drop > thresholds.max_overall_pass_rate_drop:
        findings.append(
            ModelComparisonFinding(
                rule_id="MP-MATRIX-001",
                impact=RegressionImpact.FAILURE,
                message=(
                    f"Overall pass rate dropped by {overall_drop:.1%}; allowed drop is "
                    f"{thresholds.max_overall_pass_rate_drop:.1%}."
                ),
                reference_value=reference.pass_rate,
                candidate_value=candidate.pass_rate,
            )
        )

    reference_scenarios = {
        scenario.scenario_id: scenario for scenario in reference.scenarios
    }
    candidate_scenarios = {
        scenario.scenario_id: scenario for scenario in candidate.scenarios
    }
    scenario_deltas: list[ModelScenarioDelta] = []
    for scenario_id in sorted(reference_scenarios):
        reference_scenario = reference_scenarios[scenario_id]
        candidate_scenario = candidate_scenarios[scenario_id]
        delta = candidate_scenario.pass_rate - reference_scenario.pass_rate
        scenario_deltas.append(
            ModelScenarioDelta(
                scenario_id=scenario_id,
                reference_pass_rate=reference_scenario.pass_rate,
                candidate_pass_rate=candidate_scenario.pass_rate,
                pass_rate_delta=delta,
                reference_selection_counts=reference_scenario.selection_counts,
                candidate_selection_counts=candidate_scenario.selection_counts,
            )
        )
        scenario_drop = -delta
        if scenario_drop > thresholds.max_scenario_pass_rate_drop:
            findings.append(
                ModelComparisonFinding(
                    rule_id="MP-MATRIX-002",
                    impact=RegressionImpact.FAILURE,
                    scenario_id=scenario_id,
                    message=(
                        f"Scenario '{scenario_id}' pass rate dropped by "
                        f"{scenario_drop:.1%}; allowed drop is "
                        f"{thresholds.max_scenario_pass_rate_drop:.1%}."
                    ),
                    reference_value=reference_scenario.pass_rate,
                    candidate_value=candidate_scenario.pass_rate,
                )
            )

    new_confusions = _new_confusions(reference, candidate)
    for edge in new_confusions:
        findings.append(
            ModelComparisonFinding(
                rule_id="MP-MATRIX-003",
                impact=(
                    RegressionImpact.WARNING
                    if thresholds.allow_new_confusions
                    else RegressionImpact.FAILURE
                ),
                message=(
                    f"New confusion: expected '{edge.intended_tool}' but selected "
                    f"'{edge.selected_tool}' in {edge.count} trial(s)."
                ),
                reference_value=0,
                candidate_value=edge.count,
            )
        )

    failed = any(finding.impact == RegressionImpact.FAILURE for finding in findings)
    return ModelCandidateComparison(
        reference_run_id=reference.run_id,
        candidate_run_id=candidate.run_id,
        status=ScanStatus.FAILED if failed else ScanStatus.PASSED,
        pass_rate_delta=candidate.pass_rate - reference.pass_rate,
        new_confusion_edges=new_confusions,
        scenarios=scenario_deltas,
        findings=findings,
    )


def compare_behavior_reports(
    reference: BehaviorReport,
    candidates: list[BehaviorReport],
    thresholds: ModelComparisonThresholds | None = None,
    *,
    policy: PolicySnapshot | None = None,
) -> ModelComparisonReport:
    """Compare complete reports without contacting any model provider or MCP target."""

    if not candidates:
        raise ValueError("At least one candidate behavior report is required.")
    all_reports = [reference, *candidates]
    run_ids = [report.run_id for report in all_reports]
    if len(run_ids) != len(set(run_ids)):
        raise ValueError("Reference and candidate reports must have unique run IDs.")

    reference_scenarios = validate_behavior_report(reference, "reference report")
    candidate_scenarios: list[dict[str, BehaviorScenario]] = []
    for index, candidate in enumerate(candidates, start=1):
        label = f"candidate report {index}"
        scenarios = validate_behavior_report(candidate, label)
        _ensure_comparable(
            reference,
            candidate,
            reference_scenarios,
            scenarios,
            label,
        )
        candidate_scenarios.append(scenarios)

    applied_thresholds = thresholds or ModelComparisonThresholds()
    reference_snapshot = _snapshot(reference, reference_scenarios)
    candidate_snapshots = [
        _snapshot(candidate, scenarios)
        for candidate, scenarios in zip(candidates, candidate_scenarios, strict=True)
    ]
    comparisons = [
        _compare_candidate(reference_snapshot, candidate, applied_thresholds)
        for candidate in candidate_snapshots
    ]
    failed = any(comparison.status == ScanStatus.FAILED for comparison in comparisons)
    return ModelComparisonReport(
        target=reference.target,
        suite_name=reference.suite_name,
        status=ScanStatus.FAILED if failed else ScanStatus.PASSED,
        policy=policy,
        thresholds=applied_thresholds,
        reference=reference_snapshot,
        candidates=candidate_snapshots,
        comparisons=comparisons,
    )
