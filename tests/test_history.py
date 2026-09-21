import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from mendpact import history
from mendpact.cli import app
from mendpact.contract_diff import diff_scan_reports
from mendpact.domain import BehaviorReport, GuardReport, GuardSummary, ScanReport, ScanStatus
from mendpact.evidence import EvidenceExportError
from mendpact.history import HistoryError, add_history, compare_history, list_history, prune_history

ROOT = Path(__file__).resolve().parents[1]
SECRET = "HISTORY-PRIVATE-SENTINEL"
NOW = datetime(2026, 9, 6, 12, tzinfo=UTC)


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


@pytest.fixture
def database(tmp_path: Path) -> Path:
    return tmp_path / "history.sqlite"


def save(tmp_path: Path, report: ScanReport | BehaviorReport | GuardReport) -> Path:
    source = tmp_path / "source.json"
    source.write_text(report.model_dump_json())
    return source


def pair(tmp_path: Path, database: Path, a: Any, b: Any) -> tuple[int, int]:
    left, _ = add_history(save(tmp_path, a), database)
    right, _ = add_history(save(tmp_path, b), database)
    return left.id, right.id


def test_import_duplicate_is_idempotent_and_does_not_refresh_retention(
    tmp_path: Path,
    database: Path,
    scan: ScanReport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(history, "_now", lambda: NOW)
    source = save(tmp_path, scan)
    first, created = add_history(source, database)
    monkeypatch.setattr(history, "_now", lambda: NOW + timedelta(days=15))
    second, duplicate_created = add_history(source, database)
    assert created and not duplicate_created
    assert first == second
    assert second.record.imported_at == NOW
    assert len(list_history(database)) == 1
    assert prune_history(database) == 1
    assert database.stat().st_mode & 0o777 == 0o600


def test_source_is_read_once_and_minimized(
    tmp_path: Path,
    database: Path,
    behavior: BehaviorReport,
) -> None:
    behavior.target = SECRET
    behavior.run_id = SECRET
    behavior.model = SECRET
    behavior.suite_name = SECRET
    for trial in behavior.trials:
        trial.scenario.task = SECRET
        trial.scenario.name = SECRET
        trial.trace.arguments = {"token": SECRET}
        trial.trace.message = SECRET
        trial.trace.response_id = SECRET
        trial.trace.model = SECRET
    source = save(tmp_path, behavior)
    original = source.read_bytes()
    entry, _ = add_history(source, database)
    assert source.read_bytes() == original
    assert SECRET not in entry.model_dump_json()
    assert SECRET.encode() not in database.read_bytes()
    assert str(source).encode() not in database.read_bytes()
    assert len(entry.record.context.target) == 64


def test_history_import_and_reads_are_offline(
    tmp_path: Path,
    database: Path,
    scan: ScanReport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("History attempted networking")

    monkeypatch.setattr("socket.socket.connect", forbidden)
    monkeypatch.setattr("socket.getaddrinfo", forbidden)
    a, b = pair(tmp_path, database, scan, scan.model_copy(update={"scan_id": "second"}))
    assert compare_history(database, a, b).stages[0].comparable
    assert len(list_history(database)) == 2
    assert prune_history(database) == 0


def test_list_is_paginated_by_import_order_without_writes(
    tmp_path: Path,
    database: Path,
    scan: ScanReport,
) -> None:
    ids = []
    for index in range(3):
        scan.scan_id = str(index)
        scan.generated_at -= timedelta(days=1)
        entry, _ = add_history(save(tmp_path, scan), database)
        ids.append(entry.id)
    before = database.read_bytes()
    assert [e.id for e in list_history(database, limit=2)] == ids[::-1][:2]
    assert [e.id for e in list_history(database, before_id=ids[1])] == [ids[0]]
    assert database.read_bytes() == before


@pytest.mark.parametrize("limit,before", [(0, None), (101, None), (1, 0)])
def test_list_validates_limits(database: Path, limit: int, before: int | None) -> None:
    with pytest.raises(HistoryError):
        list_history(database, limit=limit, before_id=before)
    assert not database.exists()


def test_invalid_source_does_not_create_database(tmp_path: Path, database: Path) -> None:
    source = tmp_path / "source.json"
    source.write_text('{"status":"' + SECRET + '"}')
    with pytest.raises(EvidenceExportError):
        add_history(source, database)
    assert not database.exists()


@pytest.mark.parametrize("operation", ["list", "compare", "prune"])
def test_missing_database_is_not_created_by_reads(database: Path, operation: str) -> None:
    with pytest.raises(HistoryError):
        if operation == "list":
            list_history(database)
        elif operation == "compare":
            compare_history(database, 1, 2)
        else:
            prune_history(database)
    assert not database.exists()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "directory", "fifo", "public"])
def test_unsafe_store_is_rejected(
    tmp_path: Path,
    database: Path,
    scan: ScanReport,
    kind: str,
) -> None:
    source = save(tmp_path, scan)
    if kind in ("symlink", "hardlink"):
        original = tmp_path / "original"
        original.write_text(SECRET)
        original.chmod(0o600)
        if kind == "symlink":
            database.symlink_to(original)
        else:
            os.link(original, database)
    elif kind == "directory":
        database.mkdir()
    elif kind == "fifo":
        os.mkfifo(database)
    else:
        database.write_text(SECRET)
        database.chmod(0o644)
    with pytest.raises(HistoryError):
        add_history(source, database)
    if kind in ("symlink", "hardlink"):
        assert original.read_text() == SECRET


def test_symlink_store_parent_is_rejected(tmp_path: Path, scan: ScanReport) -> None:
    alias = tmp_path / "alias"
    alias.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(HistoryError):
        add_history(save(tmp_path, scan), alias / "history.sqlite")
    assert not (tmp_path / "history.sqlite").exists()


def test_unknown_sqlite_database_is_not_migrated(
    tmp_path: Path,
    database: Path,
    scan: ScanReport,
) -> None:
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("CREATE TABLE private (value TEXT)")
        connection.execute("INSERT INTO private VALUES (?)", (SECRET,))
    database.chmod(0o600)
    original = database.read_bytes()
    with pytest.raises(HistoryError):
        add_history(save(tmp_path, scan), database)
    assert database.read_bytes() == original


def test_corrupt_record_errors_do_not_echo_its_contents(
    tmp_path: Path,
    database: Path,
    scan: ScanReport,
) -> None:
    add_history(save(tmp_path, scan), database)
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("UPDATE runs SET record_json = ?", ('{"private":"' + SECRET + '"}',))
    result = CliRunner().invoke(app, ["history", "list", "--database", str(database)])
    assert result.exit_code == 2
    assert SECRET not in result.output
    assert "Traceback" not in result.output


def test_compare_policy_change_is_visible(
    tmp_path: Path,
    database: Path,
    scan: ScanReport,
) -> None:
    from mendpact.domain import Severity

    updated = scan.model_copy(update={"failure_threshold": Severity.CRITICAL})
    a, b = pair(tmp_path, database, scan, updated)
    result = compare_history(database, a, b)
    assert any("Policy" in warning for warning in result.warnings)
    assert result.reference_status == result.candidate_status == "passed"
    assert result.stages[0].comparable
    assert "not a regression gate" in result.notice


def test_compare_refuses_different_targets(
    tmp_path: Path, database: Path, scan: ScanReport
) -> None:
    updated = scan.model_copy(deep=True)
    updated.target = "https://different.example/mcp"
    assert updated.graph is not None
    updated.graph.target = updated.target
    a, b = pair(tmp_path, database, scan, updated)
    with pytest.raises(HistoryError, match="different targets"):
        compare_history(database, a, b)


def test_compare_refuses_different_report_types(
    tmp_path: Path,
    database: Path,
    scan: ScanReport,
    behavior: BehaviorReport,
) -> None:
    behavior.target = scan.target
    a, b = pair(tmp_path, database, scan, behavior)
    with pytest.raises(HistoryError, match="report types"):
        compare_history(database, a, b)


@pytest.mark.parametrize("a,b", [(0, 1), (1, 1), (1, 999)])
def test_compare_requires_existing_distinct_ids(
    tmp_path: Path,
    database: Path,
    scan: ScanReport,
    a: int,
    b: int,
) -> None:
    add_history(save(tmp_path, scan), database)
    with pytest.raises(HistoryError):
        compare_history(database, a, b)


@pytest.mark.parametrize("change", ["task", "model", "order"])
def test_behavior_comparison_setup_binding(
    tmp_path: Path,
    database: Path,
    behavior: BehaviorReport,
    change: str,
) -> None:
    updated = behavior.model_copy(deep=True)
    updated.run_id = "second"
    if change == "task":
        for trial in updated.trials:
            trial.scenario.task = SECRET
    elif change == "model":
        updated.model = SECRET
        for trial in updated.trials:
            trial.trace.model = SECRET
    else:
        updated.trials.reverse()
        updated.tool_catalog.reverse()
    a, b = pair(tmp_path, database, behavior, updated)
    result = compare_history(database, a, b)
    assert SECRET not in result.model_dump_json()
    assert result.stages[0].comparable == (change != "task")
    if change == "task":
        assert all(metric.delta is None for metric in result.stages[0].metrics)
        assert any("Behavior setup" in w for w in result.warnings)
    elif change == "model":
        assert any("model identity" in w for w in result.warnings)
    else:
        assert not result.warnings


def test_guard_changed_baseline_withholds_contract_deltas(
    tmp_path: Path,
    database: Path,
    scan: ScanReport,
) -> None:
    baseline = ScanReport.model_validate_json(
        (ROOT / "examples/contracts/baseline-scan.json").read_text()
    )
    difference = diff_scan_reports(baseline, scan)
    guard = GuardReport(
        target=scan.target,
        scan=scan,
        contract_diff=difference,
        status=ScanStatus.PASSED,
        summary=GuardSummary(scan_status=scan.status, contract_status=difference.status),
    )
    updated = guard.model_copy(deep=True)
    assert updated.contract_diff is not None
    updated.contract_diff.baseline_scan_id = SECRET
    a, b = pair(tmp_path, database, guard, updated)
    result = compare_history(database, a, b)
    assert result.stages[0].comparable
    assert not result.stages[1].comparable
    assert not result.stages[2].comparable
    assert all(m.delta is None for m in result.stages[1].metrics)
    assert SECRET not in result.model_dump_json()


def test_error_run_has_no_numeric_deltas(tmp_path: Path, database: Path, scan: ScanReport) -> None:
    updated = scan.model_copy(update={"status": ScanStatus.ERROR, "errors": [SECRET]})
    a, b = pair(tmp_path, database, scan, updated)
    result = compare_history(database, a, b)
    assert not result.stages[0].comparable
    assert all(m.delta is None for m in result.stages[0].metrics)
    assert result.candidate_status == "error"
    assert SECRET not in result.model_dump_json()


@pytest.mark.parametrize("naive", [True, False])
def test_comparison_warns_about_chronology(
    tmp_path: Path,
    database: Path,
    scan: ScanReport,
    naive: bool,
) -> None:
    changed = scan.model_copy(
        update={
            "generated_at": scan.generated_at.replace(tzinfo=None)
            if naive
            else scan.generated_at - timedelta(days=1),
        }
    )
    a, b = pair(tmp_path, database, scan, changed)
    assert compare_history(database, a, b).warnings


def test_pruning_exact_boundary_is_preview_first_and_keeps_sources(
    tmp_path: Path,
    database: Path,
    scan: ScanReport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(history, "_now", lambda: NOW - timedelta(days=14))
    first, _ = add_history(save(tmp_path, scan), database)
    monkeypatch.setattr(history, "_now", lambda: NOW - timedelta(days=14) + timedelta(seconds=1))
    scan.scan_id = "newer"
    source = save(tmp_path, scan)
    second, _ = add_history(source, database)
    original_source = source.read_bytes()
    monkeypatch.setattr(history, "_now", lambda: NOW)
    original_database = database.read_bytes()
    assert prune_history(database) == 1
    assert database.read_bytes() == original_database
    assert prune_history(database, apply=True) == 1
    assert [entry.id for entry in list_history(database)] == [second.id]
    with pytest.raises(HistoryError):
        compare_history(database, first.id, second.id)
    assert source.read_bytes() == original_source


def test_concurrent_duplicate_imports_share_one_entry(
    tmp_path: Path,
    database: Path,
    scan: ScanReport,
) -> None:
    source = save(tmp_path, scan)
    first, _ = add_history(source, database)
    with ThreadPoolExecutor(max_workers=4) as executor:
        entries = list(executor.map(lambda _: add_history(source, database), range(8)))
    assert all(entry.id == first.id and not created for entry, created in entries)
    assert len(list_history(database)) == 1


def test_cli_workflow_and_no_overwrite(tmp_path: Path, database: Path, scan: ScanReport) -> None:
    runner = CliRunner()
    source = save(tmp_path, scan)
    args = ["--database", str(database)]
    imported = runner.invoke(app, ["history", "add", str(source), *args])
    assert imported.exit_code == 0, imported.output
    assert "history ID 1" in imported.output
    assert runner.invoke(app, ["history", "add", str(source), *args]).exit_code == 0
    scan.scan_id = "second"
    second, _ = add_history(save(tmp_path, scan), database)
    listed = runner.invoke(app, ["history", "list", *args])
    assert listed.exit_code == 0, listed.output
    output = tmp_path / "comparison.json"
    compared = runner.invoke(
        app,
        [
            "history",
            "compare",
            "1",
            str(second.id),
            *args,
            "--output",
            str(output),
        ],
    )
    assert compared.exit_code == 0, compared.output
    payload = json.loads(output.read_text())
    assert payload["schema_version"] == "mendpact.history-comparison.v1"
    assert "context" not in payload
    assert "target" not in payload
    before = output.read_bytes()
    assert (
        runner.invoke(
            app,
            [
                "history",
                "compare",
                "1",
                str(second.id),
                *args,
                "--output",
                str(output),
            ],
        ).exit_code
        == 2
    )
    assert output.read_bytes() == before
    preview = runner.invoke(app, ["history", "prune", *args])
    assert preview.exit_code == 0
    assert "Dry run" in preview.output
    assert "No changes made" in preview.output
    applied = runner.invoke(app, ["history", "prune", *args, "--apply"])
    assert applied.exit_code == 0
    assert "Deleted 0" in applied.output
