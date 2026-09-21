import json
from pathlib import Path

import pytest
from click import unstyle
from typer.testing import CliRunner

import mendpact.cli as cli_module
from mendpact.cli import app
from mendpact.domain import (
    CapabilityGraph,
    CapabilityNode,
    Finding,
    NodeKind,
    ScanReport,
    ScanStatus,
    Severity,
)

runner = CliRunner()


def test_help_lists_main_commands() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "conformance" in result.stdout
    assert "evaluate" in result.stdout
    assert "compare-models" in result.stdout
    assert "calibrate-grader" in result.stdout
    assert "diff" in result.stdout
    assert "guard" in result.stdout
    assert "init" in result.stdout
    assert "auth-check" in result.stdout
    assert "baseline" in result.stdout


def test_calibrate_grader_writes_passing_offline_report(tmp_path: Path) -> None:
    labels = (
        Path(__file__).parents[1]
        / "examples"
        / "calibration"
        / "semantic-labels.example.json"
    )
    output = tmp_path / "calibration.json"

    result = runner.invoke(
        app,
        ["calibrate-grader", str(labels), "--output", str(output)],
    )

    assert result.exit_code == 0
    assert "MendPact semantic calibration: PASSED" in result.stdout
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "mendpact.semantic-calibration.v1"
    assert payload["selected_threshold"] == 0.82
    assert payload["validation"]["false_accepts"] == 0


def test_calibrate_grader_uses_ci_exit_code_for_policy_failure(tmp_path: Path) -> None:
    labels = (
        Path(__file__).parents[1]
        / "examples"
        / "calibration"
        / "semantic-labels.example.json"
    )

    result = runner.invoke(
        app,
        [
            "calibrate-grader",
            str(labels),
            "--min-validation-balanced-accuracy",
            "1",
            "--max-validation-false-accept-rate",
            "0",
            "--min-validation-examples",
            "5",
        ],
    )

    assert result.exit_code == 1
    assert "MP-CAL-002" in result.stdout


def test_calibrate_grader_does_not_overwrite_labels() -> None:
    labels = (
        Path(__file__).parents[1]
        / "examples"
        / "calibration"
        / "semantic-labels.example.json"
    )

    result = runner.invoke(
        app,
        ["calibrate-grader", str(labels), "--output", str(labels)],
    )

    assert result.exit_code == 2
    assert "cannot overwrite" in result.stdout
    assert "semantic" in result.stdout


def test_calibrate_grader_uses_v2_policy_and_records_its_identity(tmp_path: Path) -> None:
    labels = (
        Path(__file__).parents[1]
        / "examples"
        / "calibration"
        / "semantic-labels.example.json"
    )
    policy = tmp_path / "mendpact.toml"
    output = tmp_path / "calibration.json"
    policy.write_text(
        '\n'.join(
            [
                'schema_version = "mendpact.policy.v2"',
                'name = "grader-review"',
                'profile = "local"',
                '',
                '[semantic_calibration]',
                'min_calibration_examples = 4',
                'min_validation_examples = 4',
                'min_validation_balanced_accuracy = 0.95',
                'max_validation_false_accept_rate = 0.0',
            ]
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "calibrate-grader",
            str(labels),
            "--policy",
            str(policy),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["source_policy"]["schema_version"] == "mendpact.policy.v2"
    assert payload["source_policy"]["name"] == "grader-review"
    assert payload["policy"]["min_validation_balanced_accuracy"] == 0.95
    assert payload["policy"]["max_validation_false_accept_rate"] == 0.0


def test_calibrate_grader_rejects_v1_or_explicit_policy_override(
    tmp_path: Path,
) -> None:
    labels = (
        Path(__file__).parents[1]
        / "examples"
        / "calibration"
        / "semantic-labels.example.json"
    )
    policy = tmp_path / "mendpact.toml"
    policy.write_text(
        'schema_version = "mendpact.policy.v1"\nname = "legacy"\nprofile = "local"\n',
        encoding="utf-8",
    )

    legacy = runner.invoke(
        app,
        ["calibrate-grader", str(labels), "--policy", str(policy)],
    )
    policy.write_text(
        'schema_version = "mendpact.policy.v2"\nname = "current"\nprofile = "local"\n',
        encoding="utf-8",
    )
    override = runner.invoke(
        app,
        [
            "calibrate-grader",
            str(labels),
            "--policy",
            str(policy),
            "--min-validation-examples",
            "6",
        ],
    )

    assert legacy.exit_code == 2
    assert "requires" in legacy.stdout
    assert "mendpact.policy.v2" in legacy.stdout
    assert override.exit_code == 2
    assert "--policy cannot be combined" in override.stdout
    assert "--min-validation-examples" in override.stdout


def test_calibrate_grader_does_not_overwrite_policy(tmp_path: Path) -> None:
    labels = (
        Path(__file__).parents[1]
        / "examples"
        / "calibration"
        / "semantic-labels.example.json"
    )
    policy = tmp_path / "mendpact.toml"
    source = (
        'schema_version = "mendpact.policy.v2"\n'
        'name = "current"\n'
        'profile = "local"\n'
    )
    policy.write_text(source, encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "calibrate-grader",
            str(labels),
            "--policy",
            str(policy),
            "--output",
            str(policy),
        ],
    )

    assert result.exit_code == 2
    assert "cannot overwrite" in result.stdout
    assert policy.read_text(encoding="utf-8") == source


def _write_contract_scan(
    path: Path,
    *,
    status: ScanStatus = ScanStatus.PASSED,
) -> ScanReport:
    report = ScanReport(
        scan_id="cli-reviewed-scan",
        target="https://api.example.com/mcp",
        status=status,
        failure_threshold=Severity.HIGH,
        findings=(
            [
                Finding(
                    rule_id="MP-TEST-001",
                    severity=Severity.HIGH,
                    title="Reviewed finding",
                    message="The candidate reached its policy threshold.",
                    subject="tool:read_status",
                )
            ]
            if status == ScanStatus.FAILED
            else []
        ),
        graph=CapabilityGraph(
            target="https://api.example.com/mcp",
            protocol_version="2026-07-28",
            server_name="fixture",
            nodes=[
                CapabilityNode(
                    id="server:fixture",
                    kind=NodeKind.SERVER,
                    name="fixture",
                ),
                CapabilityNode(
                    id="tool:read_status",
                    kind=NodeKind.TOOL,
                    name="read_status",
                ),
            ],
        ),
    )
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return report


def test_baseline_inspect_prints_review_identity(tmp_path: Path) -> None:
    artifact = tmp_path / "candidate.json"
    _write_contract_scan(artifact)

    result = runner.invoke(app, ["baseline", "inspect", str(artifact)])

    assert result.exit_code == 0
    assert "contract baseline: VALID" in result.stdout
    assert "cli-reviewed-scan" in result.stdout
    assert "Canonical SHA-256" in result.stdout
    assert "Tools: 1" in result.stdout


def test_baseline_inspect_surfaces_failed_candidate(tmp_path: Path) -> None:
    artifact = tmp_path / "candidate.json"
    _write_contract_scan(artifact, status=ScanStatus.FAILED)

    result = runner.invoke(app, ["baseline", "inspect", str(artifact)])

    assert result.exit_code == 1
    assert "Scan status: FAILED" in result.stdout
    assert "Review required" in result.stdout


def test_baseline_promote_requires_and_records_exact_review(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.json"
    _write_contract_scan(candidate)
    destination = tmp_path / "baseline.json"

    missing_acceptance = runner.invoke(
        app,
        ["baseline", "promote", str(candidate), str(destination)],
    )
    promoted = runner.invoke(
        app,
        [
            "baseline",
            "promote",
            str(candidate),
            str(destination),
            "--accept-scan-id",
            "cli-reviewed-scan",
            "--expected-target",
            "https://api.example.com/mcp",
        ],
    )

    assert missing_acceptance.exit_code == 2
    captured_output = unstyle(
        missing_acceptance.stdout + missing_acceptance.stderr
    )
    assert "--accept-scan-id" in captured_output
    assert promoted.exit_code == 0
    assert "Promoted baseline" in promoted.stdout
    assert json.loads(destination.read_text(encoding="utf-8"))["scan_id"] == (
        "cli-reviewed-scan"
    )


def test_init_creates_production_safe_scaffold(tmp_path: Path) -> None:
    project = tmp_path / "consumer"

    result = runner.invoke(
        app,
        ["init", str(project), "--target", "https://api.example.com/mcp"],
    )

    assert result.exit_code == 0
    policy = (project / "mendpact.toml").read_text(encoding="utf-8")
    workflow = (project / ".github/workflows/mendpact.yml").read_text(
        encoding="utf-8"
    )
    scenario = json.loads(
        (project / "mendpact/scenarios.example.json").read_text(encoding="utf-8")
    )
    assert 'schema_version = "mendpact.policy.v2"' in policy
    assert 'profile = "production"' in policy
    assert "allow_private = false" in policy
    assert "allow_insecure_http = false" in policy
    assert "[model_comparison]" in policy
    assert "[semantic_calibration]" in policy
    assert "max_validation_false_accept_rate = 0.02" in policy
    assert "adhodari03/mendpact@v0.3.0" in workflow
    assert 'target: "https://api.example.com/mcp"' in workflow
    assert "mode: scan" in workflow
    assert "retention-days: 14" in workflow
    assert "EXAMPLE" in scenario["name"]
    assert (project / "mendpact/baselines/.gitkeep").is_file()
    assert (project / "mendpact/candidates/.gitignore").read_text(
        encoding="utf-8"
    ) == "*\n!.gitignore\n"
    assert "Review the example scenario" in result.stdout
    assert "mendpact baseline inspect" in result.stdout
    assert "mendpact baseline promote" in result.stdout
    assert "--accept-scan-id" in result.stdout


def test_init_refuses_collisions_before_writing_any_file(tmp_path: Path) -> None:
    project = tmp_path / "consumer"
    project.mkdir()
    policy = project / "mendpact.toml"
    policy.write_text("owned by user\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["init", str(project), "--target", "https://api.example.com/mcp"],
    )

    assert result.exit_code == 2
    assert "Refusing to overwrite" in result.stdout
    assert policy.read_text(encoding="utf-8") == "owned by user\n"
    assert not (project / ".github/workflows/mendpact.yml").exists()


def test_init_force_replaces_only_generated_files_deterministically(tmp_path: Path) -> None:
    project = tmp_path / "consumer"
    project.mkdir()
    unrelated = project / "README.md"
    unrelated.write_text("keep me\n", encoding="utf-8")

    first = runner.invoke(
        app,
        ["init", str(project), "--target", "https://api.example.com/mcp"],
    )
    assert first.exit_code == 0
    expected = (project / "mendpact.toml").read_text(encoding="utf-8")
    (project / "mendpact.toml").write_text("changed\n", encoding="utf-8")

    second = runner.invoke(
        app,
        [
            "init",
            str(project),
            "--target",
            "https://api.example.com/mcp",
            "--force",
        ],
    )

    assert second.exit_code == 0
    assert (project / "mendpact.toml").read_text(encoding="utf-8") == expected
    assert unrelated.read_text(encoding="utf-8") == "keep me\n"


@pytest.mark.parametrize(
    ("target", "message"),
    [
        ("http://api.example.com/mcp", "requires a production"),
        ("https://user:secret@api.example.com/mcp", "must not be embedded"),
        ("https://api.example.com/mcp?token=secret", "query or fragment"),
        ("https://api.example.com/mcp#section", "query or fragment"),
        ("https://api.example.com:invalid/mcp", "invalid port"),
        ("https://api.example.com/a path", "cannot contain whitespace"),
    ],
)
def test_init_rejects_targets_unsafe_to_commit(
    tmp_path: Path,
    target: str,
    message: str,
) -> None:
    project = tmp_path / "consumer"

    result = runner.invoke(app, ["init", str(project), "--target", target])

    assert result.exit_code == 2
    assert message in result.stdout
    assert not project.exists()


def test_init_quotes_next_command_for_directory_with_spaces(tmp_path: Path) -> None:
    project = tmp_path / "consumer project"

    result = runner.invoke(
        app,
        ["init", str(project), "--target", "https://api.example.com/mcp"],
    )

    assert result.exit_code == 0
    assert f"cd '{project}'" in result.stdout


def test_init_rejects_structural_collision_before_writing(tmp_path: Path) -> None:
    project = tmp_path / "consumer"
    project.mkdir()
    (project / ".github").write_text("not a directory\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["init", str(project), "--target", "https://api.example.com/mcp"],
    )

    assert result.exit_code == 2
    assert "parent is not a directory" in result.stdout
    assert not (project / "mendpact.toml").exists()


def test_init_force_refuses_to_follow_generated_file_symlink(tmp_path: Path) -> None:
    project = tmp_path / "consumer"
    project.mkdir()
    outside = tmp_path / "outside.toml"
    outside.write_text("do not replace\n", encoding="utf-8")
    (project / "mendpact.toml").symlink_to(outside)

    result = runner.invoke(
        app,
        [
            "init",
            str(project),
            "--target",
            "https://api.example.com/mcp",
            "--force",
        ],
    )

    assert result.exit_code == 2
    assert "Refusing to overwrite symlink" in result.stdout
    assert outside.read_text(encoding="utf-8") == "do not replace\n"


def test_suite_requires_explicit_tool_call_authorization() -> None:
    result = runner.invoke(
        app,
        ["conformance", "https://example.com/mcp", "--suite", "active"],
    )

    assert result.exit_code == 2
    assert "allow-tool-calls" in result.stdout


def test_scenario_and_suite_are_mutually_exclusive() -> None:
    result = runner.invoke(
        app,
        [
            "conformance",
            "https://example.com/mcp",
            "--scenario",
            "server-initialize",
            "--suite",
            "active",
            "--allow-tool-calls",
        ],
    )

    assert result.exit_code == 2
    assert "--scenario and --suite" in result.stdout
    assert "cannot be used" in result.stdout


def _write_scenario(tmp_path: Path) -> Path:
    path = tmp_path / "scenario.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "mendpact.scenario.v1",
                "name": "CLI behavior",
                "scenarios": [
                    {
                        "id": "read-status",
                        "name": "Read status",
                        "task": "Read the status.",
                        "expectation": {"tool": "read_status"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _write_replay(tmp_path: Path) -> Path:
    path = tmp_path / "replay.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "mendpact.replay.v1",
                "model": "fixture-model",
                "decisions": [{"scenario_id": "read-status"}],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_replay_driver_requires_replay_file(tmp_path: Path) -> None:
    scenario = _write_scenario(tmp_path)

    result = runner.invoke(
        app,
        ["evaluate", "https://example.com/mcp", "--scenario", str(scenario)],
    )

    assert result.exit_code == 2
    assert "--replay is required" in result.stdout


@pytest.mark.parametrize("driver", ["openai", "anthropic", "gemini"])
def test_live_driver_requires_explicit_model(tmp_path: Path, driver: str) -> None:
    scenario = _write_scenario(tmp_path)

    result = runner.invoke(
        app,
        [
            "evaluate",
            "https://example.com/mcp",
            "--scenario",
            str(scenario),
            "--driver",
            driver,
        ],
    )

    assert result.exit_code == 2
    output = " ".join(unstyle(result.output).split())
    assert f"--model is required when --driver is {driver}" in output


@pytest.mark.parametrize(
    ("driver", "constructor_name"),
    [
        (cli_module.BehaviorDriver.OPENAI, "OpenAIResponsesDriver"),
        (cli_module.BehaviorDriver.ANTHROPIC, "AnthropicMessagesDriver"),
        (cli_module.BehaviorDriver.GEMINI, "GeminiGenerateContentDriver"),
    ],
)
def test_builds_selected_live_driver(
    monkeypatch: pytest.MonkeyPatch,
    driver: cli_module.BehaviorDriver,
    constructor_name: str,
) -> None:
    sentinel = object()
    received: dict[str, str] = {}

    def build_driver(*, model: str) -> object:
        received["model"] = model
        return sentinel

    monkeypatch.setattr(cli_module, constructor_name, build_driver)

    selected = cli_module._build_behavior_driver(
        driver,
        replay=None,
        model="provider-test-model",
    )

    assert selected is sentinel
    assert received == {"model": "provider-test-model"}


def test_max_trials_blocks_evaluation_before_driver_configuration(tmp_path: Path) -> None:
    scenario = _write_scenario(tmp_path)

    result = runner.invoke(
        app,
        [
            "evaluate",
            "https://example.com/mcp",
            "--scenario",
            str(scenario),
            "--driver",
            "openai",
            "--model",
            "provider-test-model",
            "--repetitions",
            "2",
            "--max-trials",
            "1",
        ],
    )

    assert result.exit_code == 2
    output = " ".join(unstyle(result.output).split())
    assert "requires 2 trials, exceeding --max-trials 1" in output
    assert "OPENAI_API_KEY" not in output


def test_behavior_threshold_requires_baseline_destination(tmp_path: Path) -> None:
    scenario = _write_scenario(tmp_path)
    replay = _write_replay(tmp_path)

    result = runner.invoke(
        app,
        [
            "evaluate",
            "https://example.com/mcp",
            "--scenario",
            str(scenario),
            "--replay",
            str(replay),
            "--min-pass-rate",
            "0.9",
        ],
    )

    assert result.exit_code == 2
    assert "Behavior thresholds require --baseline" in result.stdout
    assert "--save-baseline" in result.stdout


def _write_scan(
    tmp_path: Path,
    name: str,
    *,
    include_tool: bool,
) -> Path:
    nodes = (
        [
            CapabilityNode(
                id="tool:read_status",
                kind=NodeKind.TOOL,
                name="read_status",
                input_schema={"type": "object"},
            )
        ]
        if include_tool
        else []
    )
    report = ScanReport(
        target=f"https://{name}.example/mcp",
        status=ScanStatus.PASSED,
        failure_threshold=Severity.HIGH,
        graph=CapabilityGraph(target=name, nodes=nodes),
    )
    path = tmp_path / f"{name}.json"
    path.write_text(report.model_dump_json(), encoding="utf-8")
    return path


def test_contract_diff_command_writes_report_and_fails_on_breaking_change(
    tmp_path: Path,
) -> None:
    baseline = _write_scan(tmp_path, "baseline", include_tool=True)
    candidate = _write_scan(tmp_path, "candidate", include_tool=False)
    output = tmp_path / "diff.json"

    result = runner.invoke(
        app,
        ["diff", str(baseline), str(candidate), "--output", str(output)],
    )

    assert result.exit_code == 1
    assert "MendPact contract diff: FAILED" in result.stdout
    assert json.loads(output.read_text(encoding="utf-8"))["schema_version"] == (
        "mendpact.contract-diff.v1"
    )


def test_guard_requires_scenario_and_replay_together(tmp_path: Path) -> None:
    baseline = _write_scan(tmp_path, "baseline", include_tool=True)
    scenario = _write_scenario(tmp_path)

    result = runner.invoke(
        app,
        [
            "guard",
            "https://example.com/mcp",
            "--baseline",
            str(baseline),
            "--scenario",
            str(scenario),
        ],
    )

    assert result.exit_code == 2
    assert "--scenario and --replay must be supplied together" in result.stdout


def test_policy_cannot_be_weakened_by_scan_cli_options(tmp_path: Path) -> None:
    policy = tmp_path / "mendpact.toml"
    policy.write_text(
        '\n'.join(
            [
                'schema_version = "mendpact.policy.v1"',
                'name = "production"',
                'profile = "production"',
            ]
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "https://example.com/mcp",
            "--policy",
            str(policy),
            "--fail-on",
            "critical",
        ],
    )

    assert result.exit_code == 2
    assert "--policy cannot be combined" in result.stdout
    assert "--fail-on" in result.stdout


def test_scan_requires_named_bearer_environment_variable_to_exist() -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "https://example.com/mcp",
            "--auth-token-env",
            "MENDPACT_TEST_MISSING_TOKEN",
        ],
        env={"MENDPACT_TEST_MISSING_TOKEN": None},
    )

    assert result.exit_code == 2
    assert "is not set" in result.stdout


def test_scan_rejects_authentication_override_when_policy_is_used(
    tmp_path: Path,
) -> None:
    policy = tmp_path / "mendpact.toml"
    policy.write_text(
        '\n'.join(
            [
                'schema_version = "mendpact.policy.v1"',
                'name = "production"',
                'profile = "production"',
            ]
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "scan",
            "https://example.com/mcp",
            "--policy",
            str(policy),
            "--auth-token-env",
            "MENDPACT_TOKEN",
        ],
        env={"MENDPACT_TOKEN": "secret-token-value"},
    )

    assert result.exit_code == 2
    assert "--auth-token-env" in result.stdout
    assert "secret-token-value" not in result.stdout


def test_guard_does_not_overwrite_baseline(tmp_path: Path) -> None:
    baseline = _write_scan(tmp_path, "baseline", include_tool=True)

    result = runner.invoke(
        app,
        [
            "guard",
            "https://example.com/mcp",
            "--baseline",
            str(baseline),
            "--save-scan",
            str(baseline),
        ],
    )

    assert result.exit_code == 2
    assert "cannot overwrite a guard input file" in result.stdout
