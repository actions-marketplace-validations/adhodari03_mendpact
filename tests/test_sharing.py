import json
import os
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile, ZipInfo

import pytest
from typer.testing import CliRunner

from mendpact import sharing
from mendpact.cli import app
from mendpact.contract_diff import diff_scan_reports
from mendpact.domain import BehaviorReport, GuardReport, GuardSummary, ScanReport, ScanStatus
from mendpact.evidence import EvidenceExportError
from mendpact.sharing import (
    DISCLOSURE,
    SharingError,
    approve_package,
    inspect_package,
    prepare_package,
    verify_approval,
)

ROOT = Path(__file__).resolve().parents[1]
SECRET = "DO-NOT-SHARE-PRIVATE-SENTINEL"
NOW = datetime(2026, 9, 6, 12, tzinfo=UTC)


@pytest.fixture
def source(tmp_path: Path) -> Path:
    report = ScanReport.model_validate_json(
        (ROOT / "examples/contracts/candidate-scan.json").read_text()
    )
    report.target = SECRET
    report.scan_id = SECRET
    assert report.graph is not None
    report.graph.target = SECRET
    report.graph.server_name = SECRET
    report.graph.instructions = SECRET
    report.graph.nodes[0].metadata = {"credential": SECRET}
    source = tmp_path / "source.json"
    source.write_text(report.model_dump_json())
    return source


@pytest.fixture
def package(tmp_path: Path, source: Path) -> Path:
    package = tmp_path / "package.zip"
    prepare_package(source, package)
    return package


def approve(tmp_path: Path, package: Path) -> Path:
    receipt = tmp_path / "approval.json"
    approve_package(
        package,
        receipt,
        accepted_sha256=inspect_package(package).package_sha256,
        acknowledge_public=True,
    )
    return receipt


def contents(package: Path) -> dict[str, bytes]:
    with ZipFile(package) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def replace_zip(package: Path, members: dict[str, bytes], *, compression: int = ZIP_STORED) -> None:
    with ZipFile(package, "w", compression=compression) as archive:
        for name, value in members.items():
            archive.writestr(name, value)


def test_package_is_deterministic_minimized_and_private(
    tmp_path: Path,
    source: Path,
    package: Path,
) -> None:
    original = source.read_bytes()
    second = tmp_path / "second.zip"
    inspection = prepare_package(source, second)
    assert package.read_bytes() == second.read_bytes()
    assert inspection == inspect_package(package)
    assert inspection.package_sha256 == sha256(package.read_bytes()).hexdigest()
    assert source.read_bytes() == original
    assert set(contents(package)) == {"index.html", "summary.json", "manifest.json"}
    for member in contents(package).values():
        assert SECRET.encode() not in member
    assert package.stat().st_mode & 0o777 == 0o600
    assert not (tmp_path / "approval.json").exists()


@pytest.mark.parametrize("kind", ["behavior", "guard"])
def test_prepares_other_supported_report_types(tmp_path: Path, source: Path, kind: str) -> None:
    if kind == "behavior":
        report: BehaviorReport | GuardReport = BehaviorReport.model_validate_json(
            (ROOT / "examples/model-comparison/reference-behavior.json").read_text()
        )
    else:
        scan = ScanReport.model_validate_json(source.read_text())
        report = GuardReport(
            target=scan.target,
            scan=scan,
            status=scan.status,
            summary=GuardSummary(scan_status=scan.status),
        )
    source.write_text(report.model_dump_json())
    package = tmp_path / "other.zip"
    prepare_package(source, package)
    assert inspect_package(package).summary.source_schema == f"mendpact.{kind}.v1"


def test_complete_guard_package_includes_contract_and_behavior(tmp_path: Path) -> None:
    baseline = ScanReport.model_validate_json(
        (ROOT / "examples/contracts/baseline-scan.json").read_text()
    )
    scan = ScanReport.model_validate_json(
        (ROOT / "examples/contracts/candidate-scan.json").read_text()
    )
    difference = diff_scan_reports(baseline, scan)
    behavior = BehaviorReport.model_validate_json(
        (ROOT / "examples/model-comparison/reference-behavior.json").read_text()
    )
    behavior.target = scan.target
    report = GuardReport(
        target=scan.target,
        scan=scan,
        contract_diff=difference,
        behavior=behavior,
        status=ScanStatus.PASSED,
        summary=GuardSummary(
            scan_status=scan.status,
            contract_status=difference.status,
            behavior_status=behavior.status,
        ),
    )
    source = tmp_path / "guard.json"
    source.write_text(report.model_dump_json())
    package = tmp_path / "guard.zip"
    prepare_package(source, package)
    assert len(inspect_package(package).summary.sections) == 3


def test_approval_requires_explicit_acknowledgement(tmp_path: Path, package: Path) -> None:
    output = tmp_path / "approval.json"
    with pytest.raises(SharingError, match="acknowledge-public"):
        approve_package(package, output, accepted_sha256=inspect_package(package).package_sha256)
    assert not output.exists()


def test_approval_binds_exact_reviewed_fingerprint(tmp_path: Path, package: Path) -> None:
    output = tmp_path / "approval.json"
    with pytest.raises(SharingError, match="accept-sha256"):
        approve_package(package, output, accepted_sha256="0" * 64, acknowledge_public=True)
    assert not output.exists()


@pytest.mark.parametrize("days", [0, 15, 90])
def test_rejects_invalid_approval_duration(tmp_path: Path, package: Path, days: int) -> None:
    with pytest.raises(SharingError, match="14 days"):
        approve_package(
            package,
            tmp_path / "approval.json",
            accepted_sha256=inspect_package(package).package_sha256,
            acknowledge_public=True,
            valid_for_days=days,
        )


def test_valid_receipt_is_unsigned_and_has_no_private_text(
    tmp_path: Path,
    package: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sharing, "_now", lambda: NOW)
    receipt = approve(tmp_path, package)
    value = verify_approval(package, receipt)
    assert value.approved_at == NOW
    assert value.expires_at == NOW + timedelta(days=7)
    assert value.disclosure == DISCLOSURE
    assert SECRET not in receipt.read_text()
    assert receipt.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("offset", [-1, 7 * 86400, 8 * 86400])
def test_verification_rejects_future_or_expired_receipts(
    tmp_path: Path,
    package: Path,
    monkeypatch: pytest.MonkeyPatch,
    offset: int,
) -> None:
    monkeypatch.setattr(sharing, "_now", lambda: NOW)
    receipt = approve(tmp_path, package)
    monkeypatch.setattr(sharing, "_now", lambda: NOW + timedelta(seconds=offset))
    with pytest.raises(SharingError, match="expired or not yet valid"):
        verify_approval(package, receipt)


@pytest.mark.parametrize("change", ["long", "naive", "inverted", "false", "disclosure", "digest"])
def test_invalid_receipts_are_rejected(
    tmp_path: Path,
    package: Path,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    monkeypatch.setattr(sharing, "_now", lambda: NOW)
    receipt = approve(tmp_path, package)
    payload = json.loads(receipt.read_text())
    if change == "long":
        payload["expires_at"] = (NOW + timedelta(days=15)).isoformat()
    elif change == "naive":
        payload["approved_at"] = NOW.replace(tzinfo=None).isoformat()
    elif change == "inverted":
        payload["expires_at"] = (NOW - timedelta(days=1)).isoformat()
    elif change == "false":
        payload["acknowledged_public"] = False
    elif change == "disclosure":
        payload["disclosure"] = SECRET
    else:
        payload["source_sha256"] = "0" * 64
    receipt.write_text(json.dumps(payload))
    with pytest.raises(SharingError) as error:
        verify_approval(package, receipt)
    assert SECRET not in str(error.value)


def test_valid_approval_does_not_apply_to_another_package(
    tmp_path: Path,
    source: Path,
    package: Path,
) -> None:
    receipt = approve(tmp_path, package)
    payload = json.loads(source.read_text())
    payload["generated_at"] = "2026-09-01T00:00:00Z"
    source.write_text(json.dumps(payload))
    other = tmp_path / "other.zip"
    prepare_package(source, other)
    with pytest.raises(SharingError):
        verify_approval(other, receipt)


@pytest.mark.parametrize("member", ["extra.txt", "../outside", "/absolute", "raw-report.json"])
def test_unexpected_archive_entries_rejected(package: Path, member: str) -> None:
    data = contents(package)
    data[member] = SECRET.encode()
    replace_zip(package, data)
    with pytest.raises(SharingError) as error:
        inspect_package(package)
    assert member not in str(error.value)


def test_duplicate_zip_entries_rejected(package: Path) -> None:
    with pytest.warns(UserWarning), ZipFile(package, "a") as archive:
        archive.writestr("index.html", SECRET)
    with pytest.raises(SharingError):
        inspect_package(package)


def test_archive_symlink_rejected(package: Path) -> None:
    data = contents(package)
    with ZipFile(package, "w") as archive:
        for name, value in data.items():
            info = ZipInfo(name)
            info.external_attr = 0o120777 << 16
            archive.writestr(info, value)
    with pytest.raises(SharingError):
        inspect_package(package)


def test_compressed_archives_rejected(package: Path) -> None:
    replace_zip(package, contents(package), compression=ZIP_DEFLATED)
    with pytest.raises(SharingError):
        inspect_package(package)


@pytest.mark.parametrize("change", ["html", "manifest", "trailing", "missing", "corrupt"])
def test_modified_packages_rejected(package: Path, change: str) -> None:
    data = contents(package)
    if change == "trailing":
        package.write_bytes(package.read_bytes() + SECRET.encode())
    elif change == "corrupt":
        package.write_bytes(b"not a zip")
    else:
        if change == "html":
            data["index.html"] = b"<script>alert(1)</script>"
        elif change == "manifest":
            data["manifest.json"] = b'{"secret":"' + SECRET.encode() + b'"}'
        else:
            del data["summary.json"]
        replace_zip(package, data)
    with pytest.raises(SharingError):
        inspect_package(package)


def test_new_html_and_matching_manifest_still_cannot_add_scripts(package: Path) -> None:
    data = contents(package)
    data["index.html"] += b"<script>alert(1)</script>"
    manifest = json.loads(data["manifest.json"])
    manifest["artifacts"]["index.html"] = sha256(data["index.html"]).hexdigest()
    data["manifest.json"] = json.dumps(manifest).encode()
    replace_zip(package, data)
    with pytest.raises(SharingError):
        inspect_package(package)


@pytest.mark.parametrize(
    "change", ["unknown_metric", "private_value", "notice", "negative", "missing"]
)
def test_summary_allowlist_blocks_arbitrary_text(package: Path, change: str) -> None:
    summary = inspect_package(package).summary
    if change == "unknown_metric":
        summary.sections[0].metrics[SECRET] = 1
    elif change == "private_value":
        summary.sections[0].metrics["Fails on severity"] = SECRET
    elif change == "notice":
        summary.notice = SECRET
    elif change == "negative":
        summary.sections[0].metrics["Findings"] = -1
    else:
        summary.sections[0].metrics.pop("Findings")
    with pytest.raises(SharingError):
        sharing._package_bytes(summary)


def test_package_reader_size_limits_and_no_extraction(
    tmp_path: Path,
    package: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = set(tmp_path.iterdir())
    monkeypatch.setattr(sharing, "MAX_PACKAGE_BYTES", 10)
    with pytest.raises(SharingError):
        inspect_package(package)
    assert set(tmp_path.iterdir()) == before


@pytest.mark.parametrize("kind", ["symlink", "fifo", "missing"])
def test_unsafe_package_inputs_fail_without_blocking(
    tmp_path: Path, package: Path, kind: str
) -> None:
    other = tmp_path / "other"
    if kind == "symlink":
        other.symlink_to(package)
    elif kind == "fifo":
        os.mkfifo(other)
    with pytest.raises(SharingError):
        inspect_package(other)


def test_outputs_never_overwrite_source_package_or_receipt(
    tmp_path: Path,
    source: Path,
    package: Path,
) -> None:
    original_source = source.read_bytes()
    original_package = package.read_bytes()
    with pytest.raises(EvidenceExportError):
        prepare_package(source, source)
    with pytest.raises(EvidenceExportError):
        prepare_package(source, package)
    receipt = approve(tmp_path, package)
    original_receipt = receipt.read_bytes()
    with pytest.raises(EvidenceExportError):
        approve(tmp_path, package)
    assert source.read_bytes() == original_source
    assert package.read_bytes() == original_package
    assert receipt.read_bytes() == original_receipt


def test_cli_workflow_is_offline(
    tmp_path: Path,
    source: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("Sharing attempted a network connection")

    monkeypatch.setattr("socket.socket.connect", forbidden)
    monkeypatch.setattr("socket.getaddrinfo", forbidden)
    runner = CliRunner()
    package = tmp_path / "cli.zip"
    receipt = tmp_path / "cli-approval.json"
    prepared = runner.invoke(app, ["share", "prepare", str(source), "--output", str(package)])
    assert prepared.exit_code == 0, prepared.output
    assert "not approved or published" in prepared.output
    inspected = runner.invoke(app, ["share", "inspect", str(package)])
    assert inspected.exit_code == 0, inspected.output
    digest = inspect_package(package).package_sha256
    args = ["share", "approve", str(package), "--accept-sha256", digest, "--output", str(receipt)]
    rejected = runner.invoke(app, args)
    assert rejected.exit_code == 2
    assert not receipt.exists()
    approved = runner.invoke(app, [*args, "--acknowledge-public"])
    assert approved.exit_code == 0, approved.output
    verified = runner.invoke(app, ["share", "verify", str(package), "--approval", str(receipt)])
    assert verified.exit_code == 0, verified.output
    assert "No files uploaded" in verified.output
    assert SECRET not in prepared.output + inspected.output + approved.output + verified.output


def test_error_evidence_remains_error_when_approved(tmp_path: Path, source: Path) -> None:
    scan = ScanReport.model_validate_json(source.read_text())
    scan.status = ScanStatus.ERROR
    scan.errors = [SECRET]
    source.write_text(scan.model_dump_json())
    package = tmp_path / "failed.zip"
    prepare_package(source, package)
    receipt = approve(tmp_path, package)
    verify_approval(package, receipt)
    assert inspect_package(package).summary.recorded_status == "error"


def test_cli_sanitizes_malformed_approval_errors(tmp_path: Path, package: Path) -> None:
    receipt = tmp_path / "bad.json"
    receipt.write_text('{"approved_at": "' + SECRET + '"}')
    result = CliRunner().invoke(app, ["share", "verify", str(package), "--approval", str(receipt)])
    assert result.exit_code == 2
    assert SECRET not in result.output
    assert "Traceback" not in result.output


def test_duplicate_receipt_keys_are_rejected(tmp_path: Path, package: Path) -> None:
    receipt = approve(tmp_path, package)
    receipt.write_text(
        receipt.read_text().replace(
            '"acknowledged_public": true',
            '"acknowledged_public": false, "acknowledged_public": true',
        )
    )
    with pytest.raises(SharingError):
        verify_approval(package, receipt)


@pytest.mark.parametrize("value", [1, "true"])
def test_receipt_acknowledgement_must_be_boolean(
    tmp_path: Path,
    package: Path,
    value: int | str,
) -> None:
    receipt = approve(tmp_path, package)
    payload = json.loads(receipt.read_text())
    payload["acknowledged_public"] = value
    receipt.write_text(json.dumps(payload))
    with pytest.raises(SharingError):
        verify_approval(package, receipt)
