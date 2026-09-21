from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "run-action.sh"
INSTALL_SCRIPT = Path(__file__).parents[1] / "scripts" / "install-action.sh"


def _run_action_script(
    tmp_path: Path,
    **inputs: str,
) -> subprocess.CompletedProcess[str]:
    executable = tmp_path / "mendpact"
    capture = tmp_path / "arguments.json"
    executable.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "Path(os.environ['CAPTURE']).write_text(json.dumps(sys.argv[1:]))\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    environment = {
        **os.environ,
        "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
        "CAPTURE": str(capture),
        **inputs,
    }
    return subprocess.run(
        ["bash", str(SCRIPT)],
        capture_output=True,
        check=False,
        encoding="utf-8",
        env=environment,
    )


def _arguments(tmp_path: Path) -> list[str]:
    return json.loads((tmp_path / "arguments.json").read_text(encoding="utf-8"))


def _run_install_script(
    tmp_path: Path,
    *,
    mode: str,
    driver: str,
) -> tuple[subprocess.CompletedProcess[str], list[str] | None]:
    executable = tmp_path / "python"
    capture = tmp_path / "install-arguments.json"
    executable.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "Path(os.environ['INSTALL_CAPTURE']).write_text(json.dumps(sys.argv[1:]))\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    result = subprocess.run(
        ["bash", str(INSTALL_SCRIPT)],
        capture_output=True,
        check=False,
        encoding="utf-8",
        env={
            **os.environ,
            "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
            "INSTALL_CAPTURE": str(capture),
            "MENDPACT_ACTION_PATH": "/action path/mendpact",
            "MENDPACT_MODE": mode,
            "MENDPACT_DRIVER": driver,
        },
    )
    arguments = (
        json.loads(capture.read_text(encoding="utf-8")) if capture.exists() else None
    )
    return result, arguments


def test_action_script_preserves_backward_compatible_scan_mode(tmp_path: Path) -> None:
    result = _run_action_script(
        tmp_path,
        MENDPACT_TARGET="https://example.com/mcp",
        MENDPACT_OUTPUT="scan report.json",
        MENDPACT_FAIL_ON="medium",
    )

    assert result.returncode == 0
    assert _arguments(tmp_path) == [
        "scan",
        "https://example.com/mcp",
        "--fail-on",
        "medium",
        "--output",
        "scan report.json",
    ]


def test_action_script_builds_offline_recheck(tmp_path: Path) -> None:
    result = _run_action_script(
        tmp_path,
        MENDPACT_MODE="recheck",
        MENDPACT_SOURCE_REPORT="reports/original scan.json",
        MENDPACT_FAIL_ON="medium",
        MENDPACT_OUTPUT="reports/current rules.json",
    )

    assert result.returncode == 0
    assert _arguments(tmp_path) == [
        "recheck",
        "reports/original scan.json",
        "--fail-on",
        "medium",
        "--output",
        "reports/current rules.json",
    ]


def test_action_script_lets_policy_own_recheck_threshold(tmp_path: Path) -> None:
    result = _run_action_script(
        tmp_path,
        MENDPACT_MODE="recheck",
        MENDPACT_SOURCE_REPORT="source.json",
        MENDPACT_POLICY="mendpact.toml",
        MENDPACT_OUTPUT="rechecked.json",
    )

    assert result.returncode == 0
    assert _arguments(tmp_path) == [
        "recheck",
        "source.json",
        "--policy",
        "mendpact.toml",
        "--output",
        "rechecked.json",
    ]


def test_action_script_validates_offline_recheck_inputs(tmp_path: Path) -> None:
    missing_source = _run_action_script(tmp_path, MENDPACT_MODE="recheck")
    live_target = _run_action_script(
        tmp_path,
        MENDPACT_MODE="recheck",
        MENDPACT_SOURCE_REPORT="source.json",
        MENDPACT_TARGET="https://example.com/mcp",
    )
    source_in_scan = _run_action_script(
        tmp_path,
        MENDPACT_SOURCE_REPORT="source.json",
        MENDPACT_TARGET="https://example.com/mcp",
    )

    assert missing_source.returncode == 2
    assert "source-report is required" in missing_source.stderr
    assert live_target.returncode == 2
    assert "recheck mode is offline" in live_target.stderr
    assert source_in_scan.returncode == 2
    assert "source-report can only be used" in source_in_scan.stderr


def test_action_installer_selects_only_requested_provider_extra(tmp_path: Path) -> None:
    for driver in ("openai", "anthropic", "gemini"):
        result, arguments = _run_install_script(
            tmp_path,
            mode="evaluate",
            driver=driver,
        )

        assert result.returncode == 0
        assert arguments == ["-m", "pip", "install", f"/action path/mendpact[{driver}]"]


def test_action_installer_keeps_base_install_for_offline_modes(tmp_path: Path) -> None:
    result, arguments = _run_install_script(
        tmp_path,
        mode="evaluate",
        driver="replay",
    )

    assert result.returncode == 0
    assert arguments == ["-m", "pip", "install", "/action path/mendpact"]


def test_action_installer_rejects_unknown_evaluate_driver(tmp_path: Path) -> None:
    result, arguments = _run_install_script(
        tmp_path,
        mode="evaluate",
        driver="other",
    )

    assert result.returncode == 2
    assert arguments is None
    assert "evaluate driver must be" in result.stderr


def test_action_script_builds_bounded_live_evaluation(tmp_path: Path) -> None:
    result = _run_action_script(
        tmp_path,
        MENDPACT_MODE="evaluate",
        MENDPACT_TARGET="https://example.com/mcp",
        MENDPACT_SCENARIO="scenarios/provider suite.json",
        MENDPACT_DRIVER="anthropic",
        MENDPACT_MODEL="claude-test-model",
        MENDPACT_REPETITIONS="2",
        MENDPACT_MAX_TRIALS="6",
        MENDPACT_OUTPUT="reports/anthropic evaluation.json",
        MENDPACT_SAVE_REPLAY="replays/anthropic decisions.json",
        MENDPACT_AUTH_TOKEN_ENV="MENDPACT_ACCESS_TOKEN",
        MENDPACT_ACCESS_TOKEN="secret-value-never-passed-as-an-argument",
    )

    assert result.returncode == 0
    arguments = _arguments(tmp_path)
    assert arguments == [
        "evaluate",
        "https://example.com/mcp",
        "--scenario",
        "scenarios/provider suite.json",
        "--driver",
        "anthropic",
        "--repetitions",
        "2",
        "--max-trials",
        "6",
        "--output",
        "reports/anthropic evaluation.json",
        "--model",
        "claude-test-model",
        "--save-replay",
        "replays/anthropic decisions.json",
        "--auth-token-env",
        "MENDPACT_ACCESS_TOKEN",
    ]
    assert "secret-value-never-passed-as-an-argument" not in arguments


def test_action_script_builds_bounded_replay_evaluation(tmp_path: Path) -> None:
    result = _run_action_script(
        tmp_path,
        MENDPACT_MODE="evaluate",
        MENDPACT_TARGET="https://example.com/mcp",
        MENDPACT_SCENARIO="scenarios/core.json",
        MENDPACT_REPLAY="replays/core.json",
        MENDPACT_OUTPUT="behavior.json",
    )

    assert result.returncode == 0
    assert _arguments(tmp_path) == [
        "evaluate",
        "https://example.com/mcp",
        "--scenario",
        "scenarios/core.json",
        "--driver",
        "replay",
        "--repetitions",
        "1",
        "--max-trials",
        "10",
        "--output",
        "behavior.json",
        "--replay",
        "replays/core.json",
    ]


def test_action_script_validates_evaluate_configuration(tmp_path: Path) -> None:
    missing_scenario = _run_action_script(
        tmp_path,
        MENDPACT_MODE="evaluate",
        MENDPACT_TARGET="https://example.com/mcp",
    )
    missing_model = _run_action_script(
        tmp_path,
        MENDPACT_MODE="evaluate",
        MENDPACT_TARGET="https://example.com/mcp",
        MENDPACT_SCENARIO="scenario.json",
        MENDPACT_DRIVER="gemini",
    )
    invalid_budget = _run_action_script(
        tmp_path,
        MENDPACT_MODE="evaluate",
        MENDPACT_TARGET="https://example.com/mcp",
        MENDPACT_SCENARIO="scenario.json",
        MENDPACT_REPLAY="replay.json",
        MENDPACT_MAX_TRIALS="unlimited",
    )

    assert missing_scenario.returncode == 2
    assert "scenario is required" in missing_scenario.stderr
    assert missing_model.returncode == 2
    assert "model is required" in missing_model.stderr
    assert invalid_budget.returncode == 2
    assert "max-trials must be a positive integer" in invalid_budget.stderr


def test_action_script_builds_guard_command_without_losing_spaces(tmp_path: Path) -> None:
    result = _run_action_script(
        tmp_path,
        MENDPACT_MODE="guard",
        MENDPACT_TARGET="http://127.0.0.1:8000/mcp",
        MENDPACT_BASELINE="contracts/reviewed baseline.json",
        MENDPACT_SCENARIO="scenarios/core suite.json",
        MENDPACT_REPLAY="replays/core decisions.json",
        MENDPACT_REPETITIONS="3",
        MENDPACT_SCAN_FAIL_ON="critical",
        MENDPACT_CONTRACT_FAIL_ON="risky",
        MENDPACT_OUTPUT="reports/guard report.json",
        MENDPACT_SAVE_SCAN="reports/candidate scan.json",
        MENDPACT_ALLOW_PRIVATE="true",
        MENDPACT_ALLOW_INSECURE_HTTP="true",
    )

    assert result.returncode == 0
    assert _arguments(tmp_path) == [
        "guard",
        "http://127.0.0.1:8000/mcp",
        "--baseline",
        "contracts/reviewed baseline.json",
        "--repetitions",
        "3",
        "--scan-fail-on",
        "critical",
        "--contract-fail-on",
        "risky",
        "--output",
        "reports/guard report.json",
        "--scenario",
        "scenarios/core suite.json",
        "--replay",
        "replays/core decisions.json",
        "--save-scan",
        "reports/candidate scan.json",
        "--allow-private",
        "--allow-insecure-http",
    ]


def test_action_script_builds_offline_model_comparison(tmp_path: Path) -> None:
    result = _run_action_script(
        tmp_path,
        MENDPACT_MODE="compare-models",
        MENDPACT_REFERENCE_REPORT="reports/reference model.json",
        MENDPACT_CANDIDATE_REPORT="reports/candidate model.json",
        MENDPACT_MAX_OVERALL_PASS_RATE_DROP="0.02",
        MENDPACT_MAX_SCENARIO_PASS_RATE_DROP="0.05",
        MENDPACT_ALLOW_NEW_CONFUSIONS="true",
        MENDPACT_OUTPUT="reports/model comparison.json",
    )

    assert result.returncode == 0
    assert _arguments(tmp_path) == [
        "compare-models",
        "reports/reference model.json",
        "reports/candidate model.json",
        "--max-overall-pass-rate-drop",
        "0.02",
        "--max-scenario-pass-rate-drop",
        "0.05",
        "--output",
        "reports/model comparison.json",
        "--allow-new-confusions",
    ]


def test_action_script_validates_model_comparison_inputs(tmp_path: Path) -> None:
    incomplete = _run_action_script(
        tmp_path,
        MENDPACT_MODE="compare-models",
        MENDPACT_REFERENCE_REPORT="reference.json",
    )
    target_input = _run_action_script(
        tmp_path,
        MENDPACT_MODE="compare-models",
        MENDPACT_REFERENCE_REPORT="reference.json",
        MENDPACT_CANDIDATE_REPORT="candidate.json",
        MENDPACT_TARGET="https://example.com/mcp",
    )

    assert incomplete.returncode == 2
    assert "reference-report and candidate-report are required" in incomplete.stderr
    assert target_input.returncode == 2
    assert "does not accept target" in target_input.stderr


def test_action_script_lets_v2_policy_own_model_comparison_gates(tmp_path: Path) -> None:
    result = _run_action_script(
        tmp_path,
        MENDPACT_MODE="compare-models",
        MENDPACT_REFERENCE_REPORT="reference.json",
        MENDPACT_CANDIDATE_REPORT="candidate.json",
        MENDPACT_POLICY="mendpact-v2.toml",
        MENDPACT_OUTPUT="comparison.json",
    )
    override = _run_action_script(
        tmp_path,
        MENDPACT_MODE="compare-models",
        MENDPACT_REFERENCE_REPORT="reference.json",
        MENDPACT_CANDIDATE_REPORT="candidate.json",
        MENDPACT_POLICY="mendpact-v2.toml",
        MENDPACT_MAX_SCENARIO_PASS_RATE_DROP="0.1",
    )
    boolean_override = _run_action_script(
        tmp_path,
        MENDPACT_MODE="compare-models",
        MENDPACT_REFERENCE_REPORT="reference.json",
        MENDPACT_CANDIDATE_REPORT="candidate.json",
        MENDPACT_POLICY="mendpact-v2.toml",
        MENDPACT_ALLOW_NEW_CONFUSIONS="false",
    )

    assert result.returncode == 0
    assert _arguments(tmp_path) == [
        "compare-models",
        "reference.json",
        "candidate.json",
        "--policy",
        "mendpact-v2.toml",
        "--output",
        "comparison.json",
    ]
    assert override.returncode == 2
    assert "cannot be combined with model-comparison threshold inputs" in override.stderr
    assert boolean_override.returncode == 2


def test_action_script_still_requires_target_for_network_modes(tmp_path: Path) -> None:
    for mode in ("auth", "scan", "evaluate", "guard"):
        result = _run_action_script(tmp_path, MENDPACT_MODE=mode)

        assert result.returncode == 2
        assert f"target is required in {mode} mode" in result.stderr


def test_action_script_builds_offline_semantic_calibration(tmp_path: Path) -> None:
    result = _run_action_script(
        tmp_path,
        MENDPACT_MODE="calibrate-grader",
        MENDPACT_SEMANTIC_LABELS="labels/human review.json",
        MENDPACT_MIN_CALIBRATION_EXAMPLES="20",
        MENDPACT_MIN_VALIDATION_EXAMPLES="30",
        MENDPACT_MIN_VALIDATION_BALANCED_ACCURACY="0.9",
        MENDPACT_MAX_VALIDATION_FALSE_ACCEPT_RATE="0.02",
        MENDPACT_OUTPUT="reports/calibration result.json",
    )

    assert result.returncode == 0
    assert _arguments(tmp_path) == [
        "calibrate-grader",
        "labels/human review.json",
        "--min-calibration-examples",
        "20",
        "--min-validation-examples",
        "30",
        "--min-validation-balanced-accuracy",
        "0.9",
        "--max-validation-false-accept-rate",
        "0.02",
        "--output",
        "reports/calibration result.json",
    ]


def test_action_script_validates_semantic_calibration_inputs(tmp_path: Path) -> None:
    missing_labels = _run_action_script(
        tmp_path,
        MENDPACT_MODE="calibrate-grader",
    )
    target_input = _run_action_script(
        tmp_path,
        MENDPACT_MODE="calibrate-grader",
        MENDPACT_SEMANTIC_LABELS="labels.json",
        MENDPACT_TARGET="https://example.com/mcp",
    )

    assert missing_labels.returncode == 2
    assert "semantic-labels is required" in missing_labels.stderr
    assert target_input.returncode == 2
    assert "does not accept target" in target_input.stderr


def test_action_script_lets_v2_policy_own_semantic_calibration_gates(
    tmp_path: Path,
) -> None:
    result = _run_action_script(
        tmp_path,
        MENDPACT_MODE="calibrate-grader",
        MENDPACT_SEMANTIC_LABELS="labels.json",
        MENDPACT_POLICY="mendpact-v2.toml",
        MENDPACT_OUTPUT="calibration.json",
    )
    override = _run_action_script(
        tmp_path,
        MENDPACT_MODE="calibrate-grader",
        MENDPACT_SEMANTIC_LABELS="labels.json",
        MENDPACT_POLICY="mendpact-v2.toml",
        MENDPACT_MIN_VALIDATION_EXAMPLES="30",
    )

    assert result.returncode == 0
    assert _arguments(tmp_path) == [
        "calibrate-grader",
        "labels.json",
        "--policy",
        "mendpact-v2.toml",
        "--output",
        "calibration.json",
    ]
    assert override.returncode == 2
    assert "cannot be combined with semantic-calibration threshold inputs" in override.stderr


def test_action_script_rejects_incomplete_guard_configuration(tmp_path: Path) -> None:
    result = _run_action_script(
        tmp_path,
        MENDPACT_MODE="guard",
        MENDPACT_TARGET="https://example.com/mcp",
        MENDPACT_BASELINE="baseline.json",
        MENDPACT_SCENARIO="scenario.json",
    )

    assert result.returncode == 2
    assert "scenario and replay must be supplied together" in result.stderr
    assert not (tmp_path / "arguments.json").exists()


def test_action_script_rejects_unknown_mode_and_boolean(tmp_path: Path) -> None:
    unknown_mode = _run_action_script(
        tmp_path,
        MENDPACT_MODE="publish",
        MENDPACT_TARGET="https://example.com/mcp",
    )
    invalid_boolean = _run_action_script(
        tmp_path,
        MENDPACT_TARGET="https://example.com/mcp",
        MENDPACT_ALLOW_PRIVATE="yes",
    )

    assert unknown_mode.returncode == 2
    assert (
        "mode must be 'auth', 'scan', 'recheck', 'evaluate', 'guard', "
        "'compare-models', or 'calibrate-grader'"
    ) in (
        unknown_mode.stderr
    )
    assert invalid_boolean.returncode == 2
    assert "must be 'true' or 'false'" in invalid_boolean.stderr


def test_action_script_lets_policy_own_guard_thresholds(tmp_path: Path) -> None:
    result = _run_action_script(
        tmp_path,
        MENDPACT_MODE="guard",
        MENDPACT_TARGET="https://example.com/mcp",
        MENDPACT_BASELINE="baseline.json",
        MENDPACT_POLICY="mendpact.toml",
        MENDPACT_OUTPUT="guard.json",
    )

    assert result.returncode == 0
    assert _arguments(tmp_path) == [
        "guard",
        "https://example.com/mcp",
        "--baseline",
        "baseline.json",
        "--repetitions",
        "1",
        "--output",
        "guard.json",
        "--policy",
        "mendpact.toml",
    ]


def test_action_script_rejects_policy_with_target_allowances(tmp_path: Path) -> None:
    result = _run_action_script(
        tmp_path,
        MENDPACT_TARGET="https://example.com/mcp",
        MENDPACT_POLICY="mendpact.toml",
        MENDPACT_ALLOW_PRIVATE="true",
    )

    assert result.returncode == 2
    assert "policy cannot be combined with target allowance inputs" in result.stderr


def test_action_script_passes_only_bearer_environment_variable_name(
    tmp_path: Path,
) -> None:
    result = _run_action_script(
        tmp_path,
        MENDPACT_TARGET="https://example.com/mcp",
        MENDPACT_AUTH_TOKEN_ENV="MENDPACT_ACCESS_TOKEN",
        MENDPACT_ACCESS_TOKEN="secret-value-never-passed-as-an-argument",
    )

    assert result.returncode == 0
    arguments = _arguments(tmp_path)
    assert arguments[-2:] == ["--auth-token-env", "MENDPACT_ACCESS_TOKEN"]
    assert "secret-value-never-passed-as-an-argument" not in arguments


def test_action_script_rejects_policy_with_authentication_input(tmp_path: Path) -> None:
    result = _run_action_script(
        tmp_path,
        MENDPACT_TARGET="https://example.com/mcp",
        MENDPACT_POLICY="mendpact.toml",
        MENDPACT_AUTH_TOKEN_ENV="MENDPACT_ACCESS_TOKEN",
    )

    assert result.returncode == 2
    assert "policy cannot be combined with auth-token-env" in result.stderr


def test_action_script_builds_credential_free_authorization_audit(
    tmp_path: Path,
) -> None:
    result = _run_action_script(
        tmp_path,
        MENDPACT_MODE="auth",
        MENDPACT_TARGET="https://example.com/mcp",
        MENDPACT_FAIL_ON="medium",
        MENDPACT_OUTPUT="oauth report.json",
    )

    assert result.returncode == 0
    assert _arguments(tmp_path) == [
        "auth-check",
        "https://example.com/mcp",
        "--fail-on",
        "medium",
        "--output",
        "oauth report.json",
    ]


def test_action_script_rejects_token_configuration_in_auth_mode(
    tmp_path: Path,
) -> None:
    result = _run_action_script(
        tmp_path,
        MENDPACT_MODE="auth",
        MENDPACT_TARGET="https://example.com/mcp",
        MENDPACT_AUTH_TOKEN_ENV="MENDPACT_ACCESS_TOKEN",
    )

    assert result.returncode == 2
    assert "auth mode never loads a token" in result.stderr


def test_action_script_lets_policy_own_authorization_threshold(
    tmp_path: Path,
) -> None:
    result = _run_action_script(
        tmp_path,
        MENDPACT_MODE="auth",
        MENDPACT_TARGET="https://example.com/mcp",
        MENDPACT_POLICY="mendpact.toml",
        MENDPACT_OUTPUT="authorization.json",
    )

    assert result.returncode == 0
    assert _arguments(tmp_path) == [
        "auth-check",
        "https://example.com/mcp",
        "--output",
        "authorization.json",
        "--policy",
        "mendpact.toml",
    ]
