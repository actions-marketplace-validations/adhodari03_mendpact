import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from mendpact import publication, sharing
from mendpact.cli import app
from mendpact.domain import ScanReport
from mendpact.publication import (
    PUBLICATION_FILES,
    PublicationError,
    inspect_publication_site,
    prepare_publication_site,
)
from mendpact.sharing import approve_package, inspect_package, prepare_package

ROOT = Path(__file__).resolve().parents[1]
SECRET = "DO-NOT-PUBLISH-PRIVATE-SENTINEL"
NOW = datetime(2026, 9, 10, 12, tzinfo=UTC)


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
    source = tmp_path / "private-report.json"
    source.write_text(report.model_dump_json(), encoding="utf-8")
    return source


@pytest.fixture
def reviewed(
    tmp_path: Path,
    source: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path]:
    monkeypatch.setattr(sharing, "_now", lambda: NOW)
    monkeypatch.setattr(publication, "_now", lambda: NOW + timedelta(seconds=1))
    package = tmp_path / "review-package.zip"
    approval = tmp_path / "approval.json"
    prepare_package(source, package)
    approve_package(
        package,
        approval,
        accepted_sha256=inspect_package(package).package_sha256,
        acknowledge_public=True,
    )
    return package, approval


def test_prepares_minimized_static_site_bound_to_reviewed_package(
    tmp_path: Path,
    reviewed: tuple[Path, Path],
) -> None:
    package, approval = reviewed
    output = tmp_path / "public-evidence"

    prepared = prepare_publication_site(package, approval, output)
    inspected = inspect_publication_site(output, package, approval)

    assert prepared == inspected
    assert {path.name for path in output.iterdir()} == PUBLICATION_FILES
    assert prepared.manifest.schema_version == "mendpact.public-evidence.v1"
    assert prepared.manifest.package_sha256 == inspect_package(package).package_sha256
    assert prepared.manifest.approval_expires_at == NOW + timedelta(days=7)
    assert prepared.manifest.prepared_at == NOW + timedelta(seconds=1)
    assert SECRET not in "".join(
        path.read_text(encoding="utf-8") for path in output.iterdir()
    )
    assert output.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in output.iterdir())


def test_refuses_existing_or_symlink_output_directory(
    tmp_path: Path,
    reviewed: tuple[Path, Path],
) -> None:
    package, approval = reviewed
    existing = tmp_path / "existing"
    existing.mkdir()
    marker = existing / "keep.txt"
    marker.write_text("keep", encoding="utf-8")
    linked = tmp_path / "linked"
    linked.symlink_to(existing, target_is_directory=True)

    for output in (existing, linked):
        with pytest.raises(PublicationError):
            prepare_publication_site(package, approval, output)

    assert marker.read_text(encoding="utf-8") == "keep"


@pytest.mark.parametrize(
    "change",
    [
        "index",
        "summary",
        "manifest",
        "duplicate",
        "nojekyll",
        "extra",
        "symlink",
        "hardlink",
    ],
)
def test_verification_rejects_altered_or_unsafe_static_site(
    tmp_path: Path,
    reviewed: tuple[Path, Path],
    change: str,
) -> None:
    package, approval = reviewed
    output = tmp_path / "public-evidence"
    prepare_publication_site(package, approval, output)
    if change == "index":
        (output / "index.html").write_text("<script>unsafe</script>", encoding="utf-8")
    elif change == "summary":
        (output / "summary.json").write_text('{"private":true}', encoding="utf-8")
    elif change == "manifest":
        payload = json.loads((output / "publication.json").read_text())
        payload["package_sha256"] = "0" * 64
        (output / "publication.json").write_text(json.dumps(payload), encoding="utf-8")
    elif change == "duplicate":
        manifest = (output / "publication.json").read_text(encoding="utf-8")
        (output / "publication.json").write_text(
            manifest.replace(
                "{",
                '{"schema_version":"mendpact.public-evidence.v1",',
                1,
            ),
            encoding="utf-8",
        )
    elif change == "nojekyll":
        (output / ".nojekyll").write_text("unexpected", encoding="utf-8")
    elif change == "extra":
        (output / "raw-report.json").write_text(SECRET, encoding="utf-8")
    elif change == "symlink":
        external = tmp_path / "external.json"
        external.write_text("{}", encoding="utf-8")
        (output / "summary.json").unlink()
        (output / "summary.json").symlink_to(external)
    else:
        summary = output / "summary.json"
        external = tmp_path / "external.json"
        external.write_bytes(summary.read_bytes())
        summary.unlink()
        os.link(external, summary)

    with pytest.raises(PublicationError):
        inspect_publication_site(output, package, approval)


def test_verification_rejects_expired_acknowledgement(
    tmp_path: Path,
    reviewed: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, approval = reviewed
    output = tmp_path / "public-evidence"
    prepare_publication_site(package, approval, output)
    monkeypatch.setattr(sharing, "_now", lambda: NOW + timedelta(days=8))

    with pytest.raises(sharing.SharingError, match="expired"):
        inspect_publication_site(output, package, approval)


def test_preparation_rejects_package_changed_between_validation_reads(
    tmp_path: Path,
    reviewed: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, approval = reviewed
    other_source = tmp_path / "other.json"
    report = ScanReport.model_validate_json(
        (ROOT / "examples/contracts/candidate-scan.json").read_text()
    )
    report.generated_at += timedelta(seconds=1)
    other_source.write_text(report.model_dump_json(), encoding="utf-8")
    other_package = tmp_path / "other.zip"
    prepare_package(other_source, other_package)
    other_inspection = inspect_package(other_package)
    monkeypatch.setattr(publication, "inspect_package", lambda _: other_inspection)

    with pytest.raises(PublicationError):
        prepare_publication_site(package, approval, tmp_path / "public-evidence")


def test_verification_bounds_every_publication_file(
    tmp_path: Path,
    reviewed: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, approval = reviewed
    output = tmp_path / "public-evidence"
    prepare_publication_site(package, approval, output)
    monkeypatch.setattr(publication, "MAX_PUBLICATION_MEMBER_BYTES", 10)

    with pytest.raises(PublicationError):
        inspect_publication_site(output, package, approval)


def test_cli_publication_workflow_is_offline(
    tmp_path: Path,
    reviewed: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("Evidence publication preparation attempted a network connection")

    monkeypatch.setattr("socket.socket.connect", forbidden)
    monkeypatch.setattr("socket.getaddrinfo", forbidden)
    package, approval = reviewed
    output = tmp_path / "public-evidence"
    runner = CliRunner()

    prepared = runner.invoke(
        app,
        [
            "share",
            "prepare-site",
            str(package),
            "--approval",
            str(approval),
            "--output",
            str(output),
        ],
    )
    verified = runner.invoke(
        app,
        [
            "share",
            "verify-site",
            str(output),
            "--package",
            str(package),
            "--approval",
            str(approval),
        ],
    )

    assert prepared.exit_code == 0, prepared.output
    assert verified.exit_code == 0, verified.output
    assert "Nothing was uploaded" in prepared.output
    assert "No identity, live call, safety claim" in verified.output
    assert SECRET not in prepared.output + verified.output


def test_cli_publication_error_does_not_disclose_input_path(
    tmp_path: Path,
    reviewed: tuple[Path, Path],
) -> None:
    package, approval = reviewed
    secret_path = tmp_path / SECRET
    secret_path.mkdir()

    result = CliRunner().invoke(
        app,
        [
            "share",
            "prepare-site",
            str(package),
            "--approval",
            str(approval),
            "--output",
            str(secret_path),
        ],
    )

    assert result.exit_code == 2
    assert SECRET not in result.output
    assert "Traceback" not in result.output


def test_output_failure_cleans_up_a_new_partial_directory(
    tmp_path: Path,
    reviewed: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, approval = reviewed
    output = tmp_path / "public-evidence"
    original_open = os.open
    calls = 0

    def fail_second_write(path: Any, flags: int, mode: int = 0o777) -> int:
        nonlocal calls
        if flags & os.O_WRONLY:
            calls += 1
            if calls == 2:
                raise OSError("simulated output failure")
        return original_open(path, flags, mode)

    monkeypatch.setattr(publication.os, "open", fail_second_write)

    with pytest.raises(PublicationError, match="Cannot prepare"):
        prepare_publication_site(package, approval, output)
    assert not output.exists()
