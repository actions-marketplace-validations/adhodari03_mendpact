from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

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

runner = CliRunner()


def test_main_help_lists_recheck_command() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "recheck" in result.stdout


def _write_scan(path: Path, *, risky: bool = True) -> bytes:
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
                },
            )
        )
    graph = CapabilityGraph(
        target="https://example.com/mcp",
        protocol_version="2026-07-28",
        nodes=nodes,
    )
    report = ScanReport(
        scan_id="original-scan",
        target=graph.target,
        status=ScanStatus.PASSED,
        failure_threshold=Severity.HIGH,
        graph=graph,
        summary=summarize(graph, []),
    )
    raw = report.model_dump_json(indent=2).encode()
    path.write_bytes(raw)
    return raw


def test_cli_recheck_writes_provenanced_report_and_returns_policy_exit_code(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.json"
    before = _write_scan(source)
    output = tmp_path / "rechecked.json"

    result = runner.invoke(app, ["recheck", str(source), "--output", str(output)])

    assert result.exit_code == 1
    assert source.read_bytes() == before
    assert "MendPact scan recheck: FAILED" in result.stdout
    assert "deterministic metadata rules were refreshed" in result.stdout
    assert "evidence was preserved but not refreshed" in result.stdout
    assert "Rule impact: Introduced: 1" in result.stdout
    assert "INTRODUCED" in result.stdout
    assert "MP-MCP-007" in result.stdout
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["scan_id"] == "original-scan"
    assert payload["recheck"]["source_sha256"]
    assert payload["recheck"]["authorization_refreshed"] is False
    assert payload["recheck"]["rule_delta"]["introduced_count"] == 1
    assert payload["recheck"]["rule_delta"]["resolved_count"] == 0
    assert [finding["rule_id"] for finding in payload["findings"]] == ["MP-MCP-007"]


def test_cli_recheck_passes_safe_saved_graph(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    _write_scan(source, risky=False)
    output = tmp_path / "rechecked.json"

    result = runner.invoke(app, ["recheck", str(source), "-o", str(output)])

    assert result.exit_code == 0
    assert "MendPact scan recheck: PASSED" in result.stdout


def test_cli_recheck_refuses_output_overwrite(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    _write_scan(source, risky=False)
    output = tmp_path / "existing.json"
    output.write_text("keep me\n", encoding="utf-8")

    result = runner.invoke(app, ["recheck", str(source), "-o", str(output)])

    assert result.exit_code == 2
    assert "use a new output filename" in result.stdout
    assert output.read_text(encoding="utf-8") == "keep me\n"


def test_cli_recheck_policy_owns_failure_threshold(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    _write_scan(source, risky=False)
    policy = tmp_path / "mendpact.toml"
    policy.write_text(
        'schema_version = "mendpact.policy.v1"\nname = "local"\nprofile = "local"\n',
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "recheck",
            str(source),
            "--output",
            str(tmp_path / "output.json"),
            "--policy",
            str(policy),
            "--fail-on",
            "critical",
        ],
    )

    assert result.exit_code == 2
    assert "--policy cannot be combined" in result.stdout
    assert "--fail-on" in result.stdout


def test_cli_recheck_does_not_disclose_invalid_source_filename(tmp_path: Path) -> None:
    source = tmp_path / "customer-secret-name.json"
    source.write_text("not json", encoding="utf-8")

    result = runner.invoke(
        app,
        ["recheck", str(source), "--output", str(tmp_path / "output.json")],
    )

    assert result.exit_code == 2
    assert "source is unreadable or invalid" in result.stdout
    assert "customer-secret-name" not in result.stdout
