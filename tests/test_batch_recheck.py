from __future__ import annotations

import json
import socket
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from mendpact import batch_recheck
from mendpact.batch_recheck import (
    BATCH_MANIFEST_NAME,
    MAX_BATCH_FILES,
    BatchRecheckError,
    BatchRecheckItem,
    BatchRecheckManifest,
    discover_scan_reports,
    recheck_scan_directory,
)
from mendpact.cli import app
from mendpact.domain import (
    CapabilityGraph,
    CapabilityNode,
    NodeKind,
    ScanReport,
    ScanStatus,
    Severity,
    summarize,
)
from mendpact.evidence import EvidenceExportError
from mendpact.policy import load_policy

NOW = datetime(2026, 9, 11, 12, tzinfo=UTC)
runner = CliRunner()


def _write_scan(path: Path, *, risky: bool = False) -> bytes:
    nodes = [CapabilityNode(id="server:mcp", kind=NodeKind.SERVER, name="mcp")]
    if risky:
        nodes.append(
            CapabilityNode(
                id="tool:execute",
                kind=NodeKind.TOOL,
                name="execute",
                description="Execute supplied code.",
                input_schema={
                    "type": "object",
                    "properties": {"code": {"type": "string"}},
                    "required": ["code"],
                    "additionalProperties": False,
                },
            )
        )
    graph = CapabilityGraph(
        target="https://example.com/mcp",
        protocol_version="2026-07-28",
        nodes=nodes,
    )
    report = ScanReport(
        scan_id=f"scan-{path.stem}",
        generated_at=datetime(2026, 9, 10, 12, tzinfo=UTC),
        target=graph.target,
        status=ScanStatus.PASSED,
        failure_threshold=Severity.HIGH,
        graph=graph,
        summary=summarize(graph, []),
    )
    raw = report.model_dump_json(indent=2).encode()
    path.write_bytes(raw)
    return raw


def test_discovers_only_direct_json_files_in_deterministic_order(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_scan(source / "B.json")
    _write_scan(source / "a.JSON")
    (source / "notes.txt").write_text("ignored", encoding="utf-8")
    nested = source / "nested"
    nested.mkdir()
    _write_scan(nested / "nested.json")

    discovered = discover_scan_reports(source)

    assert [path.name for path in discovered] == ["a.JSON", "B.json"]


def test_batch_rechecks_mixed_saved_scans_without_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    safe_raw = _write_scan(source / "a-safe.json")
    risky_raw = _write_scan(source / "b-risky.json", risky=True)
    output = tmp_path / "output"
    monkeypatch.setattr(socket, "socket", Mock(side_effect=AssertionError("network forbidden")))

    manifest = recheck_scan_directory(source, output, generated_at=NOW)

    assert manifest.status == ScanStatus.FAILED
    assert (manifest.source_count, manifest.passed_count, manifest.failed_count) == (2, 1, 1)
    assert manifest.error_count == 0
    assert manifest.authorization_refreshed is False
    assert manifest.items[0].source_sha256 == sha256(safe_raw).hexdigest()
    assert manifest.items[1].source_sha256 == sha256(risky_raw).hexdigest()
    assert manifest.items[1].rule_delta is not None
    assert manifest.items[1].rule_delta.introduced == 1
    assert sorted(path.name for path in output.iterdir()) == [
        BATCH_MANIFEST_NAME,
        "recheck-001.json",
        "recheck-002.json",
    ]
    saved = BatchRecheckManifest.model_validate_json(
        (output / BATCH_MANIFEST_NAME).read_text(encoding="utf-8")
    )
    assert saved == manifest
    manifest_text = (output / BATCH_MANIFEST_NAME).read_text(encoding="utf-8")
    assert "a-safe" not in manifest_text
    assert "b-risky" not in manifest_text
    assert "example.com" not in manifest_text


def test_invalid_input_is_recorded_and_valid_inputs_continue(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "a-customer-secret.json").write_text("not json", encoding="utf-8")
    _write_scan(source / "b-valid.json")
    output = tmp_path / "output"

    manifest = recheck_scan_directory(source, output, generated_at=NOW)

    assert manifest.status == ScanStatus.ERROR
    assert manifest.error_count == 1
    assert manifest.passed_count == 1
    assert manifest.items[0] == BatchRecheckItem(
        input_index=1,
        status=ScanStatus.ERROR,
        error_code="invalid_source",
    )
    assert manifest.items[1].output_file == "recheck-002.json"
    assert not (output / "recheck-001.json").exists()
    assert (output / "recheck-002.json").is_file()
    assert "customer-secret" not in (output / BATCH_MANIFEST_NAME).read_text(encoding="utf-8")


def test_batch_uses_one_loaded_policy_for_every_report(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_scan(source / "safe.json")
    policy_file = tmp_path / "mendpact.toml"
    policy_file.write_text(
        'schema_version = "mendpact.policy.v1"\n'
        'name = "batch local"\n'
        'profile = "local"\n'
        'scan_fail_on = "critical"\n',
        encoding="utf-8",
    )
    policy = load_policy(policy_file)

    manifest = recheck_scan_directory(
        source,
        tmp_path / "output",
        policy=policy,
        generated_at=NOW,
    )

    assert manifest.failure_threshold == Severity.CRITICAL
    assert manifest.policy_source_sha256 == policy.source_sha256
    payload = json.loads((tmp_path / "output/recheck-001.json").read_text(encoding="utf-8"))
    assert payload["policy"]["source_sha256"] == policy.source_sha256


@pytest.mark.parametrize("count", [0, MAX_BATCH_FILES + 1])
def test_batch_rejects_empty_and_oversized_sources(tmp_path: Path, count: int) -> None:
    source = tmp_path / "source"
    source.mkdir()
    for index in range(count):
        (source / f"{index:03}.json").write_text("{}", encoding="utf-8")

    with pytest.raises(BatchRecheckError):
        recheck_scan_directory(source, tmp_path / "output", generated_at=NOW)

    assert not (tmp_path / "output").exists()


def test_batch_rejects_linked_inputs_and_existing_output(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    original = tmp_path / "original.json"
    _write_scan(original)
    (source / "linked.json").symlink_to(original)

    with pytest.raises(BatchRecheckError, match="regular files"):
        recheck_scan_directory(source, tmp_path / "output", generated_at=NOW)

    (source / "linked.json").unlink()
    _write_scan(source / "source.json")
    output = tmp_path / "output"
    output.mkdir()
    (output / "keep.txt").write_text("keep", encoding="utf-8")
    with pytest.raises(BatchRecheckError, match="new directory"):
        recheck_scan_directory(source, output, generated_at=NOW)
    assert (output / "keep.txt").read_text(encoding="utf-8") == "keep"


def test_write_failure_removes_only_batch_created_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_scan(source / "source.json")
    output = tmp_path / "output"
    original_write = batch_recheck.write_new_evidence_file
    calls = 0

    def fail_manifest(destination: Path, content: str) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise EvidenceExportError("simulated")
        original_write(destination, content)

    monkeypatch.setattr(batch_recheck, "write_new_evidence_file", fail_manifest)

    with pytest.raises(BatchRecheckError, match="no completed batch"):
        recheck_scan_directory(source, output, generated_at=NOW)

    assert not output.exists()


def test_batch_manifest_rejects_inconsistent_counts() -> None:
    item = BatchRecheckItem(
        input_index=1,
        status=ScanStatus.ERROR,
        error_code="invalid_source",
    )

    with pytest.raises(ValueError, match="status counts"):
        BatchRecheckManifest(
            generated_at=NOW,
            mendpact_version="0.2.0",
            status=ScanStatus.ERROR,
            failure_threshold=Severity.HIGH,
            source_count=1,
            passed_count=1,
            failed_count=0,
            error_count=0,
            items=[item],
        )


def test_cli_help_lists_batch_recheck() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "recheck-batch" in result.stdout


def test_cli_batch_returns_failed_policy_exit_and_writes_summary(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_scan(source / "risky.json", risky=True)
    output = tmp_path / "output"

    result = runner.invoke(
        app,
        ["recheck-batch", str(source), "--output-dir", str(output)],
    )

    assert result.exit_code == 1
    assert "MendPact batch recheck: FAILED" in result.stdout
    assert "Inputs: 1 | Passed: 0 | Failed: 1 | Errors: 0" in result.stdout
    assert "recheck-001.json" in result.stdout
    assert "Authorization evidence was preserved, not refreshed" in result.stdout


def test_cli_batch_returns_operational_exit_without_disclosing_filename(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "customer-secret-name.json").write_text("not json", encoding="utf-8")

    result = runner.invoke(
        app,
        ["recheck-batch", str(source), "--output-dir", str(tmp_path / "output")],
    )

    assert result.exit_code == 2
    assert "MendPact batch recheck: ERROR" in result.stdout
    assert "customer-secret-name" not in result.stdout
    assert "Errors: 1" in result.stdout


def test_cli_batch_policy_rejects_fail_on_override(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_scan(source / "safe.json")
    policy = tmp_path / "mendpact.toml"
    policy.write_text(
        'schema_version = "mendpact.policy.v1"\nname = "local"\nprofile = "local"\n',
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "recheck-batch",
            str(source),
            "--output-dir",
            str(tmp_path / "output"),
            "--policy",
            str(policy),
            "--fail-on",
            "critical",
        ],
    )

    assert result.exit_code == 2
    assert "--policy cannot be combined" in result.stdout
    assert not (tmp_path / "output").exists()


def test_cli_batch_passes_safe_saved_scans(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _write_scan(source / "safe.json")

    result = runner.invoke(
        app,
        ["recheck-batch", str(source), "--output-dir", str(tmp_path / "output")],
    )

    assert result.exit_code == 0
    assert "MendPact batch recheck: PASSED" in result.stdout
