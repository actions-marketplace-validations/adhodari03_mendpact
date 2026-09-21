import json
import os
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from mendpact import evidence
from mendpact.cli import app
from mendpact.contract_diff import diff_scan_reports
from mendpact.domain import (
    BehaviorReport,
    Finding,
    GuardReport,
    GuardSummary,
    ScanReport,
    ScanStatus,
    Severity,
)
from mendpact.evidence import (
    EvidenceExportError,
    export_evidence,
    load_evidence_summary,
    render_evidence_html,
)

ROOT = Path(__file__).resolve().parents[1]
SECRET = "PRIVATE-SENTINEL-DO-NOT-PUBLISH"


@pytest.fixture
def scan() -> ScanReport:
    return ScanReport.model_validate_json(
        (ROOT / "examples/contracts/candidate-scan.json").read_text()
    )


@pytest.fixture
def behavior() -> BehaviorReport:
    return BehaviorReport.model_validate_json(
        (ROOT / "examples/model-comparison/reference-behavior.json").read_text()
    )


def save(tmp_path: Path, report: ScanReport | BehaviorReport | GuardReport) -> Path:
    source = tmp_path / "input.json"
    source.write_text(report.model_dump_json())
    return source


def test_scan_export_minimizes_data_and_rebuilds_counts(tmp_path: Path, scan: ScanReport) -> None:
    scan.target = SECRET
    scan.scan_id = SECRET
    assert scan.graph is not None
    scan.graph.target = SECRET
    scan.graph.server_name = SECRET
    scan.graph.instructions = SECRET
    scan.graph.nodes[0].metadata = {"token": SECRET, "html": "<script>alert(1)</script>"}
    scan.findings = [Finding(
        rule_id=SECRET, severity=Severity.HIGH, title=SECRET, message=SECRET,
        subject=SECRET, evidence={"token": SECRET},
    )]
    scan.failure_threshold = Severity.CRITICAL
    assert scan.summary is not None
    scan.summary.finding_count = 999
    source = save(tmp_path, scan)
    summary = load_evidence_summary(source)
    assert summary.source_sha256 == sha256(source.read_bytes()).hexdigest()
    assert summary.recorded_status == ScanStatus.PASSED
    assert summary.sections[0].metrics["Findings"] == 1
    assert summary.sections[0].metrics["High findings"] == 1
    assert summary.sections[0].metrics["Fails on severity"] == "critical"
    for output in (summary.model_dump_json(), render_evidence_html(summary)):
        assert SECRET not in output
        assert "<script>" not in output
        assert "not a safety certification" in output


@pytest.mark.parametrize("driver", ["replay", "openai", "anthropic", "gemini"])
def test_behavior_export_omits_tasks_arguments_and_provider_metadata(
    tmp_path: Path, behavior: BehaviorReport, driver: str,
) -> None:
    behavior.target = SECRET
    behavior.model = SECRET
    behavior.suite_name = SECRET
    behavior.driver = driver
    for trial in behavior.trials:
        trial.trace.provider = driver
        trial.scenario.task = SECRET
        trial.trace.arguments = {"private": SECRET}
        trial.trace.message = SECRET
        trial.trace.response_id = SECRET
        trial.trace.model = SECRET
    summary = load_evidence_summary(save(tmp_path, behavior))
    assert SECRET not in summary.model_dump_json()
    assert summary.sections[0].metrics["Recorded trials"] == len(behavior.trials)
    expected = "Recorded replay" if driver == "replay" else "not authenticated"
    assert expected in str(summary.sections[0].metrics["Evidence mode"])


def test_guard_marks_missing_stages_skipped(tmp_path: Path, scan: ScanReport) -> None:
    report = GuardReport(
        target=scan.target, status=scan.status, scan=scan,
        summary=GuardSummary(scan_status=scan.status), behavior_skipped_reason=SECRET,
    )
    summary = load_evidence_summary(save(tmp_path, report))
    assert [section.status for section in summary.sections] == ["passed", "skipped", "skipped"]
    assert SECRET not in render_evidence_html(summary)


def test_full_guard_export_keeps_contract_and_behavior_evidence(
    tmp_path: Path, scan: ScanReport, behavior: BehaviorReport,
) -> None:
    baseline = ScanReport.model_validate_json(
        (ROOT / "examples/contracts/baseline-scan.json").read_text()
    )
    difference = diff_scan_reports(baseline, scan)
    behavior.target = scan.target
    report = GuardReport(
        target=scan.target, status=ScanStatus.PASSED, scan=scan,
        contract_diff=difference, behavior=behavior,
        summary=GuardSummary(
            scan_status=scan.status, contract_status=difference.status,
            behavior_status=behavior.status,
        ),
    )
    summary = load_evidence_summary(save(tmp_path, report))
    assert len(summary.sections) == 3
    assert summary.sections[1].metrics["Changes"] == len(difference.changes)
    assert summary.sections[1].metrics["Fails on impact"] == "breaking"
    assert summary.sections[2].status == "passed"


def test_guard_behavior_setup_error_is_not_skipped(tmp_path: Path, scan: ScanReport) -> None:
    report = GuardReport(
        target=scan.target, status=ScanStatus.ERROR, scan=scan, errors=[SECRET],
        summary=GuardSummary(scan_status=scan.status, behavior_status=ScanStatus.ERROR),
    )
    summary = load_evidence_summary(save(tmp_path, report))
    assert summary.sections[2].status == "error"


@pytest.mark.parametrize("kind", ["scan", "behavior", "guard"])
def test_error_reports_stay_errors_without_leaking_details(
    tmp_path: Path, scan: ScanReport, behavior: BehaviorReport, kind: str,
) -> None:
    scan.status = ScanStatus.ERROR
    scan.errors = [SECRET]
    scan.graph = None
    scan.summary = None
    behavior.status = ScanStatus.ERROR
    behavior.errors = [SECRET]
    behavior.trials = []
    behavior.summary = None
    report = {"scan": scan, "behavior": behavior, "guard": GuardReport(
        target=scan.target, status=ScanStatus.ERROR, scan=scan,
        summary=GuardSummary(scan_status=ScanStatus.ERROR), errors=[SECRET],
    )}[kind]
    summary = load_evidence_summary(save(tmp_path, report))
    assert summary.recorded_status == ScanStatus.ERROR
    assert SECRET not in summary.model_dump_json()
    assert SECRET not in render_evidence_html(summary)


@pytest.mark.parametrize("field", ["schema_version", "generated_at", "status"])
def test_requires_explicit_source_header(tmp_path: Path, scan: ScanReport, field: str) -> None:
    source = save(tmp_path, scan)
    payload = json.loads(source.read_text())
    del payload[field]
    source.write_text(json.dumps(payload))
    with pytest.raises(EvidenceExportError):
        load_evidence_summary(source)


@pytest.mark.parametrize("payload", [
    "[]", "{", "null", '{"schema_version": "secret-unknown"}',
    '{"status":"passed","status":"failed"}', '{"a": NaN}', '{"a": Infinity}',
    '{"a": 1e999}',
])
def test_invalid_and_ambiguous_json_rejected(tmp_path: Path, payload: str) -> None:
    source = tmp_path / "input.json"
    source.write_text(payload)
    with pytest.raises(EvidenceExportError):
        load_evidence_summary(source)


def test_rejects_inconsistent_scan_status(tmp_path: Path, scan: ScanReport) -> None:
    scan.status = ScanStatus.FAILED
    with pytest.raises(EvidenceExportError):
        load_evidence_summary(save(tmp_path, scan))


def test_rejects_inconsistent_behavior_summary(tmp_path: Path, behavior: BehaviorReport) -> None:
    assert behavior.summary is not None
    behavior.summary.passed_trials += 100
    with pytest.raises(EvidenceExportError):
        load_evidence_summary(save(tmp_path, behavior))


def test_rejects_inconsistent_guard_stage(tmp_path: Path, scan: ScanReport) -> None:
    report = GuardReport(
        target=scan.target, status=ScanStatus.PASSED, scan=scan,
        summary=GuardSummary(scan_status=ScanStatus.FAILED),
    )
    with pytest.raises(EvidenceExportError):
        load_evidence_summary(save(tmp_path, report))


def test_export_is_offline(
    tmp_path: Path, scan: ScanReport, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("Offline export attempted a network request")

    monkeypatch.setattr("socket.socket.connect", forbidden)
    monkeypatch.setattr("socket.getaddrinfo", forbidden)
    source = save(tmp_path, scan)
    output = tmp_path / "evidence.html"
    export_evidence(source, output, format="html")
    html = output.read_text()
    assert "Content-Security-Policy" in html
    assert "default-src 'none'" in html
    assert "<script" not in html
    assert "src=" not in html
    assert "href=" not in html
    assert output.stat().st_mode & 0o777 == 0o600


def test_renderer_escapes_all_display_fields(tmp_path: Path, scan: ScanReport) -> None:
    summary = load_evidence_summary(save(tmp_path, scan))
    summary.sections[0].metrics["<img src=x onerror=alert(1)>"] = "<script>x</script>"
    html = render_evidence_html(summary)
    assert "<img" not in html
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


@pytest.mark.parametrize("destination_kind", ["source", "existing", "symlink", "directory"])
def test_export_never_overwrites(
    tmp_path: Path, scan: ScanReport, destination_kind: str,
) -> None:
    source = save(tmp_path, scan)
    original = source.read_bytes()
    output = tmp_path / "evidence.html"
    if destination_kind == "source":
        output = source
    elif destination_kind == "existing":
        output.write_text(SECRET)
    elif destination_kind == "symlink":
        output.symlink_to(source)
    else:
        output.mkdir()
    with pytest.raises(EvidenceExportError):
        export_evidence(source, output, format="html")
    assert source.read_bytes() == original
    if destination_kind == "existing":
        assert output.read_text() == SECRET
    assert not list(tmp_path.glob(".mendpact-evidence-*"))


def test_rejects_output_symlink_parent(tmp_path: Path, scan: ScanReport) -> None:
    source = save(tmp_path, scan)
    alias = tmp_path / "alias"
    alias.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(EvidenceExportError):
        export_evidence(source, alias / "output.html", format="html")
    assert not (tmp_path / "output.html").exists()


def test_rejects_symlink_input(tmp_path: Path, scan: ScanReport) -> None:
    source = save(tmp_path, scan)
    alias = tmp_path / "alias.json"
    alias.symlink_to(source)
    with pytest.raises(EvidenceExportError):
        load_evidence_summary(alias)


def test_rejects_fifo_without_blocking(tmp_path: Path) -> None:
    source = tmp_path / "fifo"
    os.mkfifo(source)
    with pytest.raises(EvidenceExportError):
        load_evidence_summary(source)


def test_limits_file_size(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(evidence, "MAX_REPORT_BYTES", 10)
    source = tmp_path / "input.json"
    source.write_text("x" * 11)
    with pytest.raises(EvidenceExportError, match="limit"):
        load_evidence_summary(source)


@pytest.mark.parametrize("format", ["html", "json"])
def test_cli_exports_failed_evidence_successfully(
    tmp_path: Path, scan: ScanReport, format: str,
) -> None:
    scan.findings = [Finding(
        rule_id="MP-MCP-004", severity=Severity.HIGH, title=SECRET, message=SECRET,
    )]
    scan.status = ScanStatus.FAILED
    source = save(tmp_path, scan)
    output = tmp_path / f"output.{format}"
    result = CliRunner().invoke(app, [
        "export-report", str(source), "--output", str(output), "--format", format,
    ])
    assert result.exit_code == 0, result.output
    assert "does not mean the source checks passed" in result.output
    assert SECRET not in output.read_text()
    if format == "json":
        payload = json.loads(output.read_text())
        assert payload["schema_version"] == "mendpact.evidence.v2"
        assert payload["recorded_status"] == "failed"


def test_cli_sanitizes_validation_errors(tmp_path: Path, scan: ScanReport) -> None:
    source = save(tmp_path, scan)
    payload = json.loads(source.read_text())
    payload["status"] = SECRET
    source.write_text(json.dumps(payload))
    result = CliRunner().invoke(app, [
        "export-report", str(source), "--output", str(tmp_path / "output.html"),
    ])
    assert result.exit_code == 2
    assert SECRET not in result.output
    assert "Traceback" not in result.output
    assert not (tmp_path / "output.html").exists()
