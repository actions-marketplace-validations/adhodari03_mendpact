from __future__ import annotations

import json
import socket
import stat
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from mendpact import validation_session
from mendpact.cli import app
from mendpact.domain import (
    CapabilityGraph,
    CapabilityNode,
    Finding,
    NodeKind,
    ScanReport,
    ScanStatus,
    Severity,
    summarize,
)
from mendpact.validation_session import (
    SESSION_MANIFEST_NAME,
    SESSION_SUMMARY_NAME,
    ValidationSessionError,
    ValidationSessionManifest,
    ValidationSessionScan,
    ValidationSessionSummary,
    inspect_completed_validation_session,
    inspect_validation_session,
    run_validation_session,
    summarize_validation_session,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 9, 12, 12, tzinfo=UTC)
TARGET = "https://mcp.example.test/mcp"
runner = CliRunner()


def _private_write(path: Path, content: str | bytes) -> None:
    data = content.encode() if isinstance(content, str) else content
    path.write_bytes(data)
    path.chmod(0o600)


def _authorization(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "mendpact.validation-authorization.v1",
        "status": "approved",
        "target_alias": "server-a",
        "target_url": TARGET,
        "target_kind": "production_https",
        "approved_by": "owner@example.test",
        "permission_reference": "Local owner approval record 2026-09-12",
        "approved_at": (NOW - timedelta(hours=1)).isoformat(),
        "expires_at": (NOW + timedelta(days=1)).isoformat(),
        "max_discovery_scans": 2,
        "stop_conditions_acknowledged": True,
        "allow_authenticated": False,
        "allow_tool_execution": False,
        "allow_provider_calls": False,
    }
    value.update(updates)
    return value


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path.resolve() / "checkout"
    directory = root / "reports" / "validation" / "server-a"
    directory.mkdir(parents=True, mode=0o700)
    directory.chmod(0o700)
    for name in ("production.toml", "local-strict.toml"):
        _private_write(directory / name, (ROOT / "examples/policies" / name).read_bytes())
    _private_write(directory / "review.md", "# Local review\n")
    _private_write(
        directory / "authorization.json",
        json.dumps(_authorization(), indent=2) + "\n",
    )
    production = (directory / "production.toml").read_bytes()
    local = (directory / "local-strict.toml").read_bytes()
    manifest = {
        "schema_version": "mendpact.validation-workspace.v1",
        "status": "not-run",
        "created_at": (NOW - timedelta(days=1)).isoformat(),
        "review_or_delete_by": (NOW + timedelta(days=13)).isoformat(),
        "retention_note": "Manual cleanup reminder only; no automatic deletion.",
        "environment": {
            "revision": "a" * 40,
            "working_tree_dirty": False,
            "python": "3.13",
            "packages": {},
        },
        "template_sha256": {
            "production.toml": sha256(production).hexdigest(),
            "local-strict.toml": sha256(local).hexdigest(),
        },
        "boundaries": {
            "provider_calls": False,
            "tool_execution": False,
            "publishing": False,
        },
    }
    _private_write(directory / "manifest.json", json.dumps(manifest, indent=2) + "\n")
    monkeypatch.setattr(
        validation_session,
        "_git",
        lambda _root, *arguments: "a" * 40 if arguments[0] == "rev-parse" else "",
    )
    monkeypatch.setattr(validation_session, "_now", lambda: NOW)
    return directory


def _replace_json(path: Path, **updates: object) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    value.update(updates)
    _private_write(path, json.dumps(value, indent=2) + "\n")


def _report(index: int, status: ScanStatus) -> ScanReport:
    graph = CapabilityGraph(
        target=TARGET,
        protocol_version="2026-07-28",
        nodes=[CapabilityNode(id="server:mcp", kind=NodeKind.SERVER, name="mcp")],
    )
    findings = (
        [
            Finding(
                rule_id="MP-TEST-001",
                severity=Severity.HIGH,
                title="Fixture finding",
                message="Controlled test finding.",
            )
        ]
        if status == ScanStatus.FAILED
        else []
    )
    return ScanReport(
        scan_id=f"scan-{index}",
        generated_at=NOW + timedelta(seconds=index),
        target=TARGET,
        status=status,
        failure_threshold=Severity.HIGH,
        graph=graph if status != ScanStatus.ERROR else None,
        findings=findings,
        errors=["Controlled operational error"] if status == ScanStatus.ERROR else [],
        summary=summarize(graph, findings) if status != ScanStatus.ERROR else None,
    )


def test_preflight_is_offline_and_selects_strict_production_policy(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(socket, "socket", Mock(side_effect=AssertionError("network forbidden")))

    plan = inspect_validation_session(workspace, inspected_at=NOW)

    assert plan.authorization.target_alias == "server-a"
    assert plan.authorization.target_url == TARGET
    assert plan.authorization.max_discovery_scans == 2
    assert plan.policy.profile == "production"
    assert plan.policy.scan_fail_on == Severity.HIGH
    assert plan.policy.allow_private is False
    assert plan.policy.allow_insecure_http is False


def test_draft_authorization_blocks_preflight(workspace: Path) -> None:
    _replace_json(workspace / "authorization.json", status="draft")

    with pytest.raises(ValidationSessionError, match="remains draft"):
        inspect_validation_session(workspace, inspected_at=NOW)


@pytest.mark.parametrize(
    ("target_url", "target_kind"),
    [
        ("http://mcp.example.test/mcp", "production_https"),
        ("https://user:secret@mcp.example.test/mcp", "production_https"),
        ("https://mcp.example.test/mcp?token=secret", "production_https"),
        ("http://192.168.1.10/mcp", "isolated_loopback"),
    ],
)
def test_unsafe_or_mismatched_targets_are_blocked(
    workspace: Path,
    target_url: str,
    target_kind: str,
) -> None:
    _replace_json(
        workspace / "authorization.json",
        target_url=target_url,
        target_kind=target_kind,
    )

    with pytest.raises(ValidationSessionError, match="safe production or loopback"):
        inspect_validation_session(workspace, inspected_at=NOW)


def test_loopback_target_selects_local_strict_policy(workspace: Path) -> None:
    _replace_json(
        workspace / "authorization.json",
        target_url="http://127.0.0.1:8000/mcp",
        target_kind="isolated_loopback",
    )

    plan = inspect_validation_session(workspace, inspected_at=NOW)

    assert plan.policy.profile == "local"
    assert plan.policy.allow_private is True
    assert plan.policy.allow_insecure_http is True


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"expires_at": (NOW - timedelta(seconds=1)).isoformat()}, "not currently valid"),
        ({"approved_at": (NOW + timedelta(seconds=1)).isoformat()}, "not currently valid"),
        (
            {
                "approved_at": NOW.isoformat(),
                "expires_at": (NOW + timedelta(days=15)).isoformat(),
            },
            "invalid",
        ),
        ({"stop_conditions_acknowledged": False}, "invalid"),
        ({"allow_tool_execution": True}, "invalid"),
    ],
)
def test_invalid_approval_lifecycle_is_blocked(
    workspace: Path,
    updates: dict[str, object],
    message: str,
) -> None:
    _replace_json(workspace / "authorization.json", **updates)

    with pytest.raises(ValidationSessionError, match=message):
        inspect_validation_session(workspace, inspected_at=NOW)


def test_stale_checkout_or_policy_blocks_preflight(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        validation_session,
        "_git",
        lambda _root, *arguments: "b" * 40 if arguments[0] == "rev-parse" else "",
    )
    with pytest.raises(ValidationSessionError, match="stale, dirty, expired"):
        inspect_validation_session(workspace, inspected_at=NOW)

    monkeypatch.setattr(
        validation_session,
        "_git",
        lambda _root, *arguments: "a" * 40 if arguments[0] == "rev-parse" else "",
    )
    with (workspace / "production.toml").open("a", encoding="utf-8") as stream:
        stream.write("\n# changed after preparation\n")
    with pytest.raises(ValidationSessionError, match="stale, dirty, expired"):
        inspect_validation_session(workspace, inspected_at=NOW)


def test_existing_outputs_and_weak_permissions_are_blocked(workspace: Path) -> None:
    (workspace / "scan-01.json").write_text("keep", encoding="utf-8")
    with pytest.raises(ValidationSessionError, match="already exist"):
        inspect_validation_session(workspace, inspected_at=NOW)
    (workspace / "scan-01.json").unlink()

    (workspace / "authorization.json").chmod(0o644)
    with pytest.raises(ValidationSessionError, match="permissions 0600"):
        inspect_validation_session(workspace, inspected_at=NOW)


@pytest.mark.anyio
async def test_session_runs_two_scans_sequentially_and_writes_integrity_manifest(
    workspace: Path,
) -> None:
    calls: list[dict[str, object]] = []

    async def scanner(target: str, **kwargs: object) -> ScanReport:
        calls.append({"target": target, **kwargs})
        return _report(len(calls), ScanStatus.PASSED if len(calls) == 1 else ScanStatus.FAILED)

    result = await run_validation_session(workspace, scanner=scanner, started_at=NOW)

    assert len(calls) == 2
    assert all(call["target"] == TARGET for call in calls)
    assert all(call["authentication"] is None for call in calls)
    assert result.manifest.status == ScanStatus.FAILED
    assert result.manifest.completed_scan_count == 2
    assert result.manifest.stopped_early is False
    assert result.manifest.authenticated is False
    assert result.manifest.tool_execution is False
    assert result.manifest.provider_calls is False
    saved = ValidationSessionManifest.model_validate_json(
        (workspace / SESSION_MANIFEST_NAME).read_text(encoding="utf-8")
    )
    assert saved == result.manifest
    for capture in saved.scans:
        raw = (workspace / capture.report_file).read_bytes()
        assert capture.report_sha256 == sha256(raw).hexdigest()
    manifest_text = (workspace / SESSION_MANIFEST_NAME).read_text(encoding="utf-8")
    assert TARGET not in manifest_text
    assert "owner@example.test" not in manifest_text
    assert "Local owner approval" not in manifest_text


@pytest.mark.anyio
async def test_session_stops_after_first_operational_error(workspace: Path) -> None:
    calls = 0

    async def scanner(_target: str, **_kwargs: object) -> ScanReport:
        nonlocal calls
        calls += 1
        return _report(calls, ScanStatus.ERROR)

    result = await run_validation_session(workspace, scanner=scanner, started_at=NOW)

    assert calls == 1
    assert result.manifest.status == ScanStatus.ERROR
    assert result.manifest.completed_scan_count == 1
    assert result.manifest.stopped_early is True
    assert (workspace / "scan-01.json").exists()
    assert not (workspace / "scan-02.json").exists()


def test_manifest_rejects_inconsistent_stopped_early() -> None:
    scan = ValidationSessionScan(
        index=1,
        status=ScanStatus.PASSED,
        scan_id="scan-1",
        generated_at=NOW,
        report_file="scan-01.json",
        report_sha256="a" * 64,
    )

    with pytest.raises(ValueError, match="stopped_early"):
        ValidationSessionManifest(
            generated_at=NOW,
            status=ScanStatus.PASSED,
            target_alias="server-a",
            target_sha256="a" * 64,
            authorization_sha256="b" * 64,
            authorization_expires_at=NOW + timedelta(days=1),
            workspace_manifest_sha256="c" * 64,
            policy_source_sha256="d" * 64,
            planned_scan_count=2,
            completed_scan_count=1,
            stopped_early=False,
            scans=[scan],
        )


def test_cli_preflight_is_offline_and_does_not_print_target(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(socket, "socket", Mock(side_effect=AssertionError("network forbidden")))

    result = runner.invoke(app, ["validation", "preflight", str(workspace)])

    assert result.exit_code == 0
    assert "validation preflight: READY" in result.stdout
    assert "Discovery scan budget: 2" in result.stdout
    assert TARGET not in result.stdout
    assert not (workspace / SESSION_MANIFEST_NAME).exists()


def test_cli_run_requires_fresh_acknowledgement(workspace: Path) -> None:
    result = runner.invoke(app, ["validation", "run", str(workspace)])

    assert result.exit_code == 2
    assert "--acknowledge-authorized" in result.stdout
    assert not (workspace / "scan-01.json").exists()


def test_cli_run_uses_approved_file_and_conservative_exit(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    async def scanner(_target: str, **_kwargs: object) -> ScanReport:
        nonlocal calls
        calls += 1
        return _report(calls, ScanStatus.FAILED)

    monkeypatch.setattr(validation_session, "scan_mcp_url", scanner)

    result = runner.invoke(
        app,
        ["validation", "run", str(workspace), "--acknowledge-authorized"],
    )

    assert result.exit_code == 1
    assert calls == 2
    assert "Validation session: FAILED | Completed scans: 2/2" in result.stdout
    assert "No automatic retry" in result.stdout
    assert (workspace / SESSION_MANIFEST_NAME).exists()


@pytest.mark.anyio
async def test_completed_session_summary_verifies_sources_and_omits_private_values(
    workspace: Path,
) -> None:
    calls = 0

    async def scanner(_target: str, **kwargs: object) -> ScanReport:
        nonlocal calls
        calls += 1
        report = _report(calls, ScanStatus.PASSED if calls == 1 else ScanStatus.FAILED)
        report.policy = kwargs["applied_policy"]  # type: ignore[assignment]
        return report

    await run_validation_session(workspace, scanner=scanner, started_at=NOW)

    completed = inspect_completed_validation_session(
        workspace,
        inspected_at=NOW + timedelta(days=2),
    )
    summary = summarize_validation_session(
        workspace,
        summarized_at=NOW + timedelta(days=2),
    )

    assert len(completed.reports) == 2
    assert summary.recorded_status == ScanStatus.FAILED
    assert summary.completed_scan_count == 2
    assert summary.comparison.result == "stable"
    assert summary.comparison.change_count == 0
    assert summary.scans[1].finding_count == 1
    assert summary.scans[1].findings_by_severity["high"] == 1
    serialized = summary.model_dump_json()
    assert TARGET not in serialized
    assert "server-a" not in serialized
    assert "owner@example.test" not in serialized
    assert "Local owner approval" not in serialized
    assert "scan-1" not in serialized


@pytest.mark.anyio
async def test_summary_detects_contract_changes_between_complete_scans(
    workspace: Path,
) -> None:
    calls = 0

    async def scanner(_target: str, **kwargs: object) -> ScanReport:
        nonlocal calls
        calls += 1
        report = _report(calls, ScanStatus.PASSED)
        report.policy = kwargs["applied_policy"]  # type: ignore[assignment]
        if calls == 2 and report.graph is not None:
            report.graph.nodes.append(
                CapabilityNode(id="tool:weather", kind=NodeKind.TOOL, name="weather")
            )
            report.summary = summarize(report.graph, report.findings)
        return report

    await run_validation_session(workspace, scanner=scanner, started_at=NOW)
    summary = summarize_validation_session(
        workspace,
        summarized_at=NOW + timedelta(minutes=1),
    )

    assert summary.comparison.result == "changed"
    assert summary.comparison.change_count == 1
    assert summary.comparison.changes_by_impact["risky"] == 1
    assert summary.scans[1].tool_count == 1


@pytest.mark.anyio
async def test_completed_session_rejects_changed_report_bytes(workspace: Path) -> None:
    calls = 0

    async def scanner(_target: str, **kwargs: object) -> ScanReport:
        nonlocal calls
        calls += 1
        report = _report(calls, ScanStatus.PASSED)
        report.policy = kwargs["applied_policy"]  # type: ignore[assignment]
        return report

    await run_validation_session(workspace, scanner=scanner, started_at=NOW)
    with (workspace / "scan-01.json").open("a", encoding="utf-8") as stream:
        stream.write("\n")

    with pytest.raises(ValidationSessionError, match="does not match the session manifest"):
        inspect_completed_validation_session(
            workspace,
            inspected_at=NOW + timedelta(minutes=1),
        )


def test_cli_summarize_is_offline_private_and_does_not_overwrite(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    async def scanner(_target: str, **kwargs: object) -> ScanReport:
        nonlocal calls
        calls += 1
        report = _report(calls, ScanStatus.PASSED)
        report.policy = kwargs["applied_policy"]  # type: ignore[assignment]
        return report

    monkeypatch.setattr(validation_session, "scan_mcp_url", scanner)
    run_result = runner.invoke(
        app,
        ["validation", "run", str(workspace), "--acknowledge-authorized"],
    )
    assert run_result.exit_code == 0
    monkeypatch.setattr(socket, "socket", Mock(side_effect=AssertionError("network forbidden")))

    result = runner.invoke(app, ["validation", "summarize", str(workspace)])

    assert result.exit_code == 0
    assert "validation summary: EXPORTED" in result.stdout
    assert "Repeat-capture contract: STABLE" in result.stdout
    assert "Export success does not mean" in result.stdout
    assert TARGET not in result.stdout
    output = workspace / SESSION_SUMMARY_NAME
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    saved = ValidationSessionSummary.model_validate_json(output.read_text(encoding="utf-8"))
    assert saved.comparison.result == "stable"

    repeated = runner.invoke(app, ["validation", "summarize", str(workspace)])
    assert repeated.exit_code == 2
    assert "Cannot write export" in repeated.stdout


@pytest.mark.anyio
async def test_summary_marks_repeat_comparison_unavailable_after_operational_error(
    workspace: Path,
) -> None:
    async def scanner(_target: str, **kwargs: object) -> ScanReport:
        report = _report(1, ScanStatus.ERROR)
        report.policy = kwargs["applied_policy"]  # type: ignore[assignment]
        return report

    await run_validation_session(workspace, scanner=scanner, started_at=NOW)
    summary = summarize_validation_session(
        workspace,
        summarized_at=NOW + timedelta(minutes=1),
    )

    assert summary.recorded_status == ScanStatus.ERROR
    assert summary.stopped_early is True
    assert summary.comparison.result == "unavailable"
    assert summary.scans[0].recorded_error_count == 1
