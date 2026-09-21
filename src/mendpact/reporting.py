"""Human-readable and machine-readable scan reports."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.table import Table

from mendpact.baseline import BaselineInspection
from mendpact.domain import (
    AuthorizationAuditReport,
    BehaviorBaseline,
    BehaviorReport,
    ConformanceCheckStatus,
    ConformanceReport,
    ContractDiffReport,
    ContractImpact,
    GuardReport,
    ModelComparisonReport,
    RegressionImpact,
    ReplayPlan,
    ScanReport,
    ScanStatus,
    SemanticCalibrationReport,
)


def write_json_report(report: ScanReport, destination: Path) -> None:
    destination.write_text(report.model_dump_json(indent=2), encoding="utf-8")


def write_authorization_report(
    report: AuthorizationAuditReport,
    destination: Path,
) -> None:
    destination.write_text(report.model_dump_json(indent=2), encoding="utf-8")


def write_conformance_report(report: ConformanceReport, destination: Path) -> None:
    destination.write_text(report.model_dump_json(indent=2, by_alias=True), encoding="utf-8")


def write_behavior_report(report: BehaviorReport, destination: Path) -> None:
    destination.write_text(report.model_dump_json(indent=2), encoding="utf-8")


def write_contract_diff_report(report: ContractDiffReport, destination: Path) -> None:
    destination.write_text(report.model_dump_json(indent=2), encoding="utf-8")


def write_guard_report(report: GuardReport, destination: Path) -> None:
    destination.write_text(report.model_dump_json(indent=2), encoding="utf-8")


def write_model_comparison_report(
    report: ModelComparisonReport,
    destination: Path,
) -> None:
    destination.write_text(report.model_dump_json(indent=2), encoding="utf-8")


def write_semantic_calibration_report(
    report: SemanticCalibrationReport,
    destination: Path,
) -> None:
    destination.write_text(report.model_dump_json(indent=2), encoding="utf-8")


def write_behavior_baseline(baseline: BehaviorBaseline, destination: Path) -> None:
    destination.write_text(baseline.model_dump_json(indent=2), encoding="utf-8")


def write_replay_plan(plan: ReplayPlan, destination: Path) -> None:
    destination.write_text(plan.model_dump_json(indent=2), encoding="utf-8")


def render_baseline_inspection(
    inspection: BaselineInspection,
    console: Console,
) -> None:
    report = inspection.report
    console.print("MendPact contract baseline: [bold green]VALID[/]")
    console.print(f"Scan ID: {report.scan_id}")
    console.print(f"Target: {report.target}")
    console.print(f"Captured: {report.generated_at.isoformat()}")
    console.print(f"Scan status: {report.status.value.upper()}")
    if report.recheck:
        console.print(
            "Evidence mode: offline deterministic recheck | "
            f"Rechecked: {report.recheck.rechecked_at.isoformat()}"
        )
        console.print("Authorization evidence refreshed: no")
    console.print(f"Canonical SHA-256: {inspection.canonical_sha256}")
    if report.graph:
        console.print(
            f"Protocol: MCP {report.graph.protocol_version or 'unknown'} | "
            f"Tools: {inspection.tool_count} | "
            f"Resources: {inspection.resource_count} | "
            f"Prompts: {inspection.prompt_count}"
        )
    if inspection.requires_failed_scan_acceptance:
        console.print(
            "[yellow]Review required:[/] The scan failed its configured policy threshold."
        )


def render_report(report: ScanReport, console: Console) -> None:
    status_style = {
        ScanStatus.PASSED: "bold green",
        ScanStatus.FAILED: "bold red",
        ScanStatus.ERROR: "bold red",
    }[report.status]
    label = "scan recheck" if report.recheck else "scan"
    console.print(f"MendPact {label}: [{status_style}]{report.status.value.upper()}[/]")
    console.print(f"Scan ID: {report.scan_id}")
    console.print(f"Target: {report.target}")
    if report.recheck:
        console.print(
            "Evidence mode: offline deterministic recheck | "
            f"Source SHA-256: {report.recheck.source_sha256}"
        )
        console.print(
            f"Rechecked: {report.recheck.rechecked_at.isoformat()} | "
            f"MendPact: {report.recheck.mendpact_version} | "
            "Authorization evidence refreshed: no"
        )
        if report.recheck.rule_delta:
            delta = report.recheck.rule_delta
            console.print(
                f"Rule impact: Introduced: {delta.introduced_count} | "
                f"Resolved: {delta.resolved_count} | "
                f"Reclassified: {delta.reclassified_count} | "
                f"Unchanged: {delta.unchanged_count}"
            )
            if delta.changes:
                delta_table = Table(show_header=True, header_style="bold")
                delta_table.add_column("Change", width=14)
                delta_table.add_column("Rule", width=14)
                delta_table.add_column("Subject", overflow="fold")
                delta_table.add_column("Before", width=10)
                delta_table.add_column("After", width=10)
                for change in delta.changes:
                    delta_table.add_row(
                        change.kind.value.upper(),
                        change.rule_id,
                        change.subject or "-",
                        change.before_severity.value.upper()
                        if change.before_severity
                        else "-",
                        change.after_severity.value.upper()
                        if change.after_severity
                        else "-",
                    )
                console.print(delta_table)
    if report.policy:
        console.print(
            f"Policy: {report.policy.name} ({report.policy.profile.value}) | "
            f"Scan: {report.policy.scan_fail_on.value} | "
            f"Contract: {report.policy.contract_fail_on.value}"
        )
    if report.authorization:
        console.print(
            "OAuth metadata: "
            f"{report.authorization.status.value} | "
            f"Authorization servers: {len(report.authorization.authorization_servers)} | "
            "Credential source: environment"
        )

    if report.errors:
        for error in report.errors:
            console.print(f"[red]Error:[/] {error}")
        return

    if report.summary and report.graph:
        console.print(
            f"Protocol: MCP {report.graph.protocol_version or 'unknown'} | "
            f"Tools: {report.summary.tool_count} | "
            f"Resources: {report.summary.resource_count} | "
            f"Prompts: {report.summary.prompt_count}"
        )

    if not report.findings:
        console.print("[green]No deterministic findings.[/]")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity", width=10)
    table.add_column("Rule", width=12)
    table.add_column("Subject", overflow="fold")
    table.add_column("Finding", overflow="fold")
    table.add_column("Policy", overflow="fold")
    for finding in report.findings:
        table.add_row(
            finding.severity.value.upper(),
            finding.rule_id,
            finding.subject or "-",
            f"{finding.title}: {finding.message}",
            (
                f"waived until {finding.waiver.expires_on}"
                if finding.waiver
                else "enforced"
            ),
        )
    console.print(table)


def render_authorization_report(
    report: AuthorizationAuditReport,
    console: Console,
) -> None:
    status_style = {
        ScanStatus.PASSED: "bold green",
        ScanStatus.FAILED: "bold red",
        ScanStatus.ERROR: "bold red",
    }[report.status]
    console.print(
        f"MendPact authorization audit: [{status_style}]{report.status.value.upper()}[/]"
    )
    console.print(f"Target: {report.target}")
    console.print(f"Fails on: {report.failure_threshold.value}")
    if report.policy:
        console.print(
            f"Policy: {report.policy.name} ({report.policy.profile.value})"
        )
    if report.metadata:
        console.print(
            f"OAuth metadata: {report.metadata.status.value} | "
            f"Authorization servers: {len(report.metadata.authorization_servers)} | "
            f"Challenge scopes: {', '.join(report.metadata.challenge_scopes) or '-'}"
        )
        for warning in report.metadata.warnings:
            console.print(f"[yellow]Metadata warning:[/] {warning}")
    for error in report.errors:
        console.print(f"[red]Error:[/] {error}")
    if not report.findings:
        if not report.errors:
            console.print("[green]No authorization metadata findings.[/]")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity", width=10)
    table.add_column("Rule", width=12)
    table.add_column("Subject", overflow="fold")
    table.add_column("Finding", overflow="fold")
    table.add_column("Policy", overflow="fold")
    for finding in report.findings:
        table.add_row(
            finding.severity.value.upper(),
            finding.rule_id,
            finding.subject or "-",
            f"{finding.title}: {finding.message}",
            (
                f"waived until {finding.waiver.expires_on}"
                if finding.waiver
                else "enforced"
            ),
        )
    console.print(table)


def render_conformance_report(report: ConformanceReport, console: Console) -> None:
    status_style = {
        ScanStatus.PASSED: "bold green",
        ScanStatus.FAILED: "bold red",
        ScanStatus.ERROR: "bold red",
    }[report.status]
    console.print(f"MendPact conformance: [{status_style}]{report.status.value.upper()}[/]")
    console.print(f"Target: {report.target}")
    console.print(f"Runner: {report.runner_package}@{report.runner_version}")

    if report.errors:
        for error in report.errors:
            console.print(f"[red]Error:[/] {error}")

    if report.summary:
        counts = report.summary.checks_by_status
        console.print(
            f"Scenarios: {report.summary.scenario_count} | "
            f"Checks: {report.summary.check_count} | "
            f"Passed: {counts[ConformanceCheckStatus.SUCCESS.value]} | "
            f"Failed: {counts[ConformanceCheckStatus.FAILURE.value]} | "
            f"Skipped: {counts[ConformanceCheckStatus.SKIPPED.value]}"
        )

    failed_checks = [
        (scenario.name, check)
        for scenario in report.scenarios
        for check in scenario.checks
        if check.status == ConformanceCheckStatus.FAILURE
    ]
    if not failed_checks:
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Scenario", overflow="fold")
    table.add_column("Check", overflow="fold")
    table.add_column("Failure", overflow="fold")
    for scenario_name, check in failed_checks:
        table.add_row(
            scenario_name,
            check.id,
            check.error_message or check.description,
        )
    console.print(table)


def render_contract_diff_report(report: ContractDiffReport, console: Console) -> None:
    status_style = {
        ScanStatus.PASSED: "bold green",
        ScanStatus.FAILED: "bold red",
        ScanStatus.ERROR: "bold red",
    }[report.status]
    console.print(f"MendPact contract diff: [{status_style}]{report.status.value.upper()}[/]")
    console.print(f"Baseline: {report.baseline_target}")
    console.print(f"Candidate: {report.candidate_target}")
    counts = report.summary.changes_by_impact
    console.print(
        f"Changes: {report.summary.change_count} | "
        f"Breaking: {counts[ContractImpact.BREAKING.value]} | "
        f"Risky: {counts[ContractImpact.RISKY.value]} | "
        f"Compatible: {counts[ContractImpact.COMPATIBLE.value]} | "
        f"Waived: {report.summary.waived_change_count} | "
        f"Affected scenarios: {report.summary.affected_scenario_count}"
    )

    if not report.changes:
        console.print("[green]No contract changes.[/]")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Impact", width=11)
    table.add_column("Rule", width=12)
    table.add_column("Subject", overflow="fold")
    table.add_column("Change", overflow="fold")
    table.add_column("Scenarios", overflow="fold")
    table.add_column("Policy", overflow="fold")
    styles = {
        ContractImpact.BREAKING: "red",
        ContractImpact.RISKY: "yellow",
        ContractImpact.COMPATIBLE: "green",
    }
    for change in report.changes:
        table.add_row(
            f"[{styles[change.impact]}]{change.impact.value.upper()}[/]",
            change.rule_id,
            change.subject,
            change.message,
            ", ".join(change.affected_scenarios) or "-",
            (
                f"waived until {change.waiver.expires_on}"
                if change.waiver
                else "enforced"
            ),
        )
    console.print(table)


def render_guard_report(report: GuardReport, console: Console) -> None:
    status_style = {
        ScanStatus.PASSED: "bold green",
        ScanStatus.FAILED: "bold red",
        ScanStatus.ERROR: "bold red",
    }[report.status]
    summary = report.summary
    console.print(f"MendPact guard: [{status_style}]{report.status.value.upper()}[/]")
    console.print(f"Target: {report.target}")
    if report.policy:
        console.print(
            f"Policy: {report.policy.name} ({report.policy.profile.value}) | "
            f"Scan: {report.policy.scan_fail_on.value} | "
            f"Contract: {report.policy.contract_fail_on.value}"
        )
    console.print(
        f"Scan: {summary.scan_status.value} | "
        f"Contract: {summary.contract_status.value if summary.contract_status else 'skipped'} | "
        f"Behavior: {summary.behavior_status.value if summary.behavior_status else 'skipped'}"
    )
    console.print(
        f"Affected scenarios: {summary.affected_scenario_count} | "
        f"Evaluated scenarios: {summary.evaluated_scenario_count}"
    )
    if report.behavior_skipped_reason:
        console.print(f"Behavior replay: {report.behavior_skipped_reason}")
    for error in report.errors:
        console.print(f"[red]Error:[/] {error}")


def render_behavior_report(report: BehaviorReport, console: Console) -> None:
    status_style = {
        ScanStatus.PASSED: "bold green",
        ScanStatus.FAILED: "bold red",
        ScanStatus.ERROR: "bold red",
    }[report.status]
    console.print(f"MendPact behavior: [{status_style}]{report.status.value.upper()}[/]")
    console.print(f"Target: {report.target}")
    console.print(
        f"Suite: {report.suite_name} | Driver: {report.driver} | "
        f"Model: {report.model} | Repetitions: {report.repetitions}"
    )

    if report.errors:
        for error in report.errors:
            console.print(f"[red]Error:[/] {error}")

    if report.summary:
        console.print(
            f"Scenarios: {report.summary.scenario_count} | "
            f"Trials: {report.summary.trial_count} | "
            f"Passed: {report.summary.passed_trials} | "
            f"Failed: {report.summary.failed_trials} | "
            f"Pass rate: {report.summary.pass_rate:.1%}"
        )
        if report.summary.total_tokens or report.summary.total_latency_ms:
            console.print(
                f"Provider usage: {report.summary.total_tokens} tokens "
                f"({report.summary.input_tokens} input, "
                f"{report.summary.output_tokens} output) | "
                f"Latency: {report.summary.total_latency_ms:.0f} ms"
            )

    if report.regression:
        regression = report.regression
        statistics = ""
        if regression.one_sided_p_value is not None:
            statistics = f" | One-sided p: {regression.one_sided_p_value:.3f}"
        console.print(
            f"Baseline: {regression.baseline_pass_rate:.1%} | "
            f"Current: {regression.current_pass_rate:.1%} | "
            f"Drop: {regression.pass_rate_drop:.1%}{statistics}"
        )
        if regression.findings:
            regression_table = Table(show_header=True, header_style="bold")
            regression_table.add_column("Impact", width=9)
            regression_table.add_column("Rule", width=12)
            regression_table.add_column("Baseline difference", overflow="fold")
            for finding in regression.findings:
                style = "red" if finding.impact == RegressionImpact.FAILURE else "yellow"
                regression_table.add_row(
                    f"[{style}]{finding.impact.value.upper()}[/]",
                    finding.rule_id,
                    finding.message,
                )
            console.print(regression_table)

    failed_trials = [trial for trial in report.trials if not trial.grade.passed]
    if not failed_trials:
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Scenario", overflow="fold")
    table.add_column("Attempt", justify="right")
    table.add_column("Expected", overflow="fold")
    table.add_column("Selected", overflow="fold")
    table.add_column("Reason", overflow="fold")
    for trial in failed_trials:
        table.add_row(
            trial.scenario.id,
            str(trial.trace.attempt),
            trial.scenario.expectation.tool,
            trial.trace.selected_tool or "-",
            " ".join(trial.grade.reasons),
        )
    console.print(table)


def render_model_comparison_report(
    report: ModelComparisonReport,
    console: Console,
) -> None:
    """Render a compact model-by-model compatibility matrix."""

    status_style = {
        ScanStatus.PASSED: "bold green",
        ScanStatus.FAILED: "bold red",
        ScanStatus.ERROR: "bold red",
    }[report.status]
    console.print(
        f"MendPact model comparison: [{status_style}]{report.status.value.upper()}[/]"
    )
    console.print(f"Target: {report.target}")
    console.print(f"Suite: {report.suite_name}")
    if report.policy:
        console.print(
            f"Policy: {report.policy.name} ({report.policy.schema_version}, "
            f"{report.policy.profile.value})"
        )
    console.print(
        f"Reference: {report.reference.driver}/{report.reference.model} | "
        f"Pass rate: {report.reference.pass_rate:.1%} | "
        f"Trials: {report.reference.trial_count}"
    )

    table = Table(show_header=True, header_style="bold")
    table.add_column("Candidate", overflow="fold")
    table.add_column("Status", width=8)
    table.add_column("Pass rate", justify="right")
    table.add_column("Delta", justify="right")
    table.add_column("Tokens", justify="right")
    table.add_column("Avg latency", justify="right")
    for candidate, comparison in zip(
        report.candidates,
        report.comparisons,
        strict=True,
    ):
        style = "green" if comparison.status == ScanStatus.PASSED else "red"
        latency = (
            f"{candidate.average_latency_ms:.0f} ms"
            if candidate.average_latency_ms is not None
            else "-"
        )
        table.add_row(
            f"{candidate.driver}/{candidate.model}",
            f"[{style}]{comparison.status.value.upper()}[/]",
            f"{candidate.pass_rate:.1%}",
            f"{comparison.pass_rate_delta:+.1%}",
            str(candidate.total_tokens) if candidate.total_tokens else "-",
            latency,
        )
    console.print(table)

    findings = [
        (candidate, finding)
        for candidate, comparison in zip(
            report.candidates,
            report.comparisons,
            strict=True,
        )
        for finding in comparison.findings
    ]
    if not findings:
        console.print("[green]No model compatibility regressions.[/]")
        return

    findings_table = Table(show_header=True, header_style="bold")
    findings_table.add_column("Impact", width=9)
    findings_table.add_column("Rule", width=14)
    findings_table.add_column("Candidate", overflow="fold")
    findings_table.add_column("Finding", overflow="fold")
    for candidate, finding in findings:
        style = "red" if finding.impact == RegressionImpact.FAILURE else "yellow"
        findings_table.add_row(
            f"[{style}]{finding.impact.value.upper()}[/]",
            finding.rule_id,
            f"{candidate.driver}/{candidate.model}",
            finding.message,
        )
    console.print(findings_table)


def render_semantic_calibration_report(
    report: SemanticCalibrationReport,
    console: Console,
) -> None:
    """Render calibration and independent validation metrics for a semantic grader."""

    status_style = {
        ScanStatus.PASSED: "bold green",
        ScanStatus.FAILED: "bold red",
        ScanStatus.ERROR: "bold red",
    }[report.status]
    console.print(
        f"MendPact semantic calibration: [{status_style}]{report.status.value.upper()}[/]"
    )
    console.print(
        f"Label set: {report.label_set_name} | "
        f"Grader: {report.grader}/{report.grader_version}"
    )
    if report.source_policy:
        console.print(
            f"Policy: {report.source_policy.name} ({report.source_policy.schema_version}, "
            f"{report.source_policy.profile.value})"
        )
    console.print(
        f"Selected threshold: {report.selected_threshold:.3f} | "
        f"Dataset SHA-256: {report.label_set_sha256}"
    )

    table = Table(show_header=True, header_style="bold")
    table.add_column("Split")
    table.add_column("Examples", justify="right")
    table.add_column("Accuracy", justify="right")
    table.add_column("Balanced", justify="right")
    table.add_column("False accepts", justify="right")
    table.add_column("False rejects", justify="right")
    table.add_column("False-accept rate", justify="right")
    for name, metrics in (
        ("Calibration", report.calibration),
        ("Validation", report.validation),
    ):
        table.add_row(
            name,
            str(metrics.example_count),
            f"{metrics.accuracy:.1%}",
            f"{metrics.balanced_accuracy:.1%}",
            str(metrics.false_accepts),
            str(metrics.false_rejects),
            f"{metrics.false_accept_rate:.1%}",
        )
    console.print(table)

    if report.findings:
        findings = Table(show_header=True, header_style="bold")
        findings.add_column("Impact", width=9)
        findings.add_column("Rule", width=12)
        findings.add_column("Finding", overflow="fold")
        findings.add_column("Observed", justify="right")
        findings.add_column("Required", justify="right")
        for finding in report.findings:
            style = "red" if finding.impact == RegressionImpact.FAILURE else "yellow"
            findings.add_row(
                f"[{style}]{finding.impact.value.upper()}[/]",
                finding.rule_id,
                finding.message,
                str(finding.observed_value),
                str(finding.required_value),
            )
        console.print(findings)

    if report.disagreements:
        disagreements = Table(show_header=True, header_style="bold")
        disagreements.add_column("Example", overflow="fold")
        disagreements.add_column("Split")
        disagreements.add_column("Score", justify="right")
        disagreements.add_column("Human")
        disagreements.add_column("Predicted")
        for item in report.disagreements:
            disagreements.add_row(
                item.example_id,
                item.split.value,
                f"{item.semantic_score:.3f}",
                item.human_label.value,
                item.predicted_label.value,
            )
        console.print(disagreements)
