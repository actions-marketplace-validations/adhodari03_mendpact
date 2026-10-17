import json
import socket
from datetime import datetime, timedelta
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

import mendpact.validation_cli as validation_cli
import mendpact.validation_setup as setup
from mendpact.cli import app
from mendpact.policy import load_policy
from mendpact.registry import RegistryRecord, validation_candidate_from_record
from mendpact.validation_session import ValidationSessionError, inspect_validation_session

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def checkout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    # macOS /var is a symlink; use its resolved real path for the safety checks.
    root = tmp_path.resolve()
    for source in setup.TEMPLATES.values():
        destination = root / source
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / source).read_bytes())
    monkeypatch.setattr(setup, "environment_record", lambda _: {"revision": "fixture"})
    return root


def test_offline_private_workspace_preserves_strict_policies(
    checkout: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(socket, "socket", Mock(side_effect=AssertionError("Network forbidden")))
    monkeypatch.setenv("OPENAI_API_KEY", "SECRET-DO-NOT-COPY")
    destination = setup.prepare_workspace(checkout, "server-a")
    manifest = json.loads((destination / "manifest.json").read_text())
    assert manifest["status"] == "not-run"
    authorization = json.loads((destination / "authorization.json").read_text())
    assert authorization["status"] == "draft"
    assert authorization["allow_authenticated"] is False
    assert authorization["allow_tool_execution"] is False
    assert authorization["allow_provider_calls"] is False
    assert datetime.fromisoformat(manifest["review_or_delete_by"]) - datetime.fromisoformat(
        manifest["created_at"]
    ) == timedelta(days=14)
    assert destination.stat().st_mode & 0o777 == 0o700
    for path in destination.iterdir():
        assert path.stat().st_mode & 0o777 == 0o600
        assert b"SECRET-DO-NOT-COPY" not in path.read_bytes()
    for name, digest in manifest["template_sha256"].items():
        assert sha256((destination / name).read_bytes()).hexdigest() == digest
    production = load_policy(destination / "production.toml")
    local = load_policy(destination / "local-strict.toml")
    for policy in (production, local):
        assert policy.scan_fail_on == "high"
        assert policy.contract_fail_on == "risky"
        assert policy.bearer_token_env is None
        assert policy.waivers == []
    assert production.allow_private is production.allow_insecure_http is False
    assert local.allow_private is local.allow_insecure_http is True
    assert not list(destination.glob("scan*.json"))


def test_existing_workspace_is_never_overwritten(checkout: Path) -> None:
    destination = setup.prepare_workspace(checkout, "server-a")
    (destination / "review.md").write_text("User's reviewed evidence")
    before = {p.name: p.read_bytes() for p in destination.iterdir()}
    with pytest.raises(FileExistsError):
        setup.prepare_workspace(checkout, "server-a")
    assert {p.name: p.read_bytes() for p in destination.iterdir()} == before


@pytest.mark.parametrize("label", ["", "../escape", "/absolute", "a/b", "a b", "-a", "A", "a" * 49])
def test_bad_labels_do_not_write(checkout: Path, label: str) -> None:
    with pytest.raises(ValueError):
        setup.prepare_workspace(checkout, label)
    assert not (checkout / "reports").exists()


@pytest.mark.parametrize("linked_part", ["reports", "reports/validation"])
def test_symlink_ancestors_rejected(checkout: Path, linked_part: str) -> None:
    outside = checkout / "outside"
    outside.mkdir()
    link = checkout / linked_part
    link.parent.mkdir(exist_ok=True)
    link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        setup.prepare_workspace(checkout, "server-a")
    assert list(outside.iterdir()) == []


def test_missing_template_leaves_no_workspace(checkout: Path) -> None:
    (checkout / setup.TEMPLATES["review.md"]).unlink()
    with pytest.raises(FileNotFoundError):
        setup.prepare_workspace(checkout, "server-a")
    assert not (checkout / "reports").exists()


def test_environment_is_allowlisted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        setup, "git_value", lambda _, *args: "fixture" if args[0] == "rev-parse" else ""
    )
    monkeypatch.setattr(setup, "version", lambda name: "0.2.0" if name == "mendpact" else "fixture")
    monkeypatch.setenv("MENDPACT_ACCESS_TOKEN", "SECRET-TOKEN")
    record = setup.environment_record(ROOT)
    assert set(record) == {"revision", "working_tree_dirty", "python", "packages"}
    assert record["working_tree_dirty"] is False
    assert set(record["packages"]) == {"mendpact", *setup.PACKAGES}
    assert "SECRET-TOKEN" not in json.dumps(record)


@pytest.mark.parametrize("installed", ["0.1.0", None])
def test_environment_rejects_stale_or_missing_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    installed: str | None,
) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.2.0"\n')
    monkeypatch.setattr(setup, "git_value", lambda *_: "fixture")

    def installed_version(name: str) -> str:
        if name == "mendpact":
            if installed is None:
                raise setup.PackageNotFoundError(name)
            return installed
        return "fixture"

    monkeypatch.setattr(setup, "version", installed_version)
    with pytest.raises(ValueError, match=r"installed|Installed"):
        setup.environment_record(tmp_path)


def test_environment_rejects_same_version_from_another_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.2.0"\n')
    monkeypatch.setattr(setup, "version", lambda _: "0.2.0")
    monkeypatch.setattr(
        setup,
        "find_spec",
        lambda _: SimpleNamespace(origin="/another/checkout/mendpact/__init__.py"),
    )

    with pytest.raises(ValueError, match="source checkout"):
        setup.environment_record(tmp_path)


def test_documented_offline_analysis_with_committed_fixtures(
    checkout: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(socket, "socket", Mock(side_effect=AssertionError("Network forbidden")))
    destination = setup.prepare_workspace(checkout, "offline-fixture")
    reference = ROOT / "examples/contracts/baseline-scan.json"
    candidate = ROOT / "examples/contracts/candidate-scan.json"
    runner = CliRunner()
    diff = runner.invoke(
        app,
        [
            "diff",
            str(reference),
            str(candidate),
            "--fail-on",
            "risky",
            "--output",
            str(destination / "contract-diff.json"),
        ],
    )
    assert diff.exit_code == 1, diff.output
    report = json.loads((destination / "contract-diff.json").read_text())
    assert report["status"] == "failed"
    for command in (
        ["export-report", str(reference), "--output", str(destination / "evidence.html")],
        ["history", "add", str(reference), "--database", str(destination / "history.sqlite")],
    ):
        result = runner.invoke(app, command)
        assert result.exit_code == 0, result.output
    # Analysis of synthetic fixtures does not turn setup provenance into external validation.
    assert json.loads((destination / "manifest.json").read_text())["status"] == "not-run"


def _candidate_file(tmp_path: Path) -> Path:
    record = RegistryRecord.model_validate(
        {
            "server": {
                "name": "io.github.acme/video-editor",
                "version": "2.1.0",
                "repository": {"url": "https://github.com/acme/video-editor"},
                "remotes": [
                    {
                        "type": "streamable-http",
                        "url": "https://video.acme.test/mcp",
                    }
                ],
            },
            "_meta": {
                "io.modelcontextprotocol.registry/official": {
                    "status": "active",
                    "isLatest": True,
                }
            },
        }
    )
    candidate = validation_candidate_from_record(
        record,
        remote_url="https://video.acme.test/mcp",
    )
    path = tmp_path / "candidate.json"
    path.write_text(candidate.model_dump_json(indent=2), encoding="utf-8")
    return path


def test_registry_candidate_prepares_only_a_bound_draft_workspace(
    checkout: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(socket, "socket", Mock(side_effect=AssertionError("Network forbidden")))
    candidate_path = _candidate_file(tmp_path)

    destination = setup.prepare_workspace(
        checkout,
        "video-review",
        candidate_path=candidate_path,
    )

    authorization = json.loads((destination / "authorization.json").read_text())
    manifest = json.loads((destination / "manifest.json").read_text())
    copied = destination / setup.REGISTRY_CANDIDATE_NAME
    assert authorization["status"] == "draft"
    assert authorization["target_alias"] == "video-review"
    assert authorization["target_url"] == "https://video.acme.test/mcp"
    assert authorization["approved_by"] == ""
    assert authorization["permission_reference"] == ""
    assert manifest["registry_candidate"]["sha256"] == sha256(copied.read_bytes()).hexdigest()
    assert manifest["registry_candidate"]["server_version"] == "2.1.0"
    assert copied.stat().st_mode & 0o777 == 0o600


def test_registry_candidate_with_duplicate_keys_is_rejected_before_workspace_creation(
    checkout: Path,
    tmp_path: Path,
) -> None:
    candidate = _candidate_file(tmp_path)
    ambiguous = candidate.read_text(encoding="utf-8").replace(
        '"server_name":',
        '"server_name": "io.github.attacker/server",\n  "server_name":',
        1,
    )
    candidate.write_text(ambiguous, encoding="utf-8")

    with pytest.raises(ValueError, match="unreadable or invalid"):
        setup.prepare_workspace(
            checkout,
            "video-review",
            candidate_path=candidate,
        )
    assert not (checkout / "reports").exists()


@pytest.mark.parametrize("link_kind", ["symbolic", "hard"])
def test_registry_candidate_links_are_rejected_before_workspace_creation(
    checkout: Path,
    tmp_path: Path,
    link_kind: str,
) -> None:
    candidate = _candidate_file(tmp_path)
    linked = tmp_path / "linked-candidate.json"
    if link_kind == "symbolic":
        linked.symlink_to(candidate)
    else:
        linked.hardlink_to(candidate)

    with pytest.raises(ValueError, match="unreadable or invalid"):
        setup.prepare_workspace(
            checkout,
            "video-review",
            candidate_path=linked,
        )
    assert not (checkout / "reports").exists()


def test_tampered_registry_candidate_blocks_workspace_inspection(
    checkout: Path,
    tmp_path: Path,
) -> None:
    destination = setup.prepare_workspace(
        checkout,
        "video-review",
        candidate_path=_candidate_file(tmp_path),
    )
    copied = destination / setup.REGISTRY_CANDIDATE_NAME
    copied.write_text(copied.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    copied.chmod(0o600)

    with pytest.raises(ValidationSessionError, match="candidate provenance"):
        inspect_validation_session(destination)


def test_validation_prepare_cli_creates_draft_without_network(
    checkout: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(validation_cli, "repository_root", lambda _: checkout)
    monkeypatch.setattr(socket, "socket", Mock(side_effect=AssertionError("Network forbidden")))
    candidate = _candidate_file(tmp_path)

    result = CliRunner().invoke(
        app,
        [
            "validation",
            "prepare",
            "video-review",
            "--candidate",
            str(candidate),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "DRAFT" in result.stdout
    assert "No target was contacted" in result.stdout
    assert (checkout / "reports/validation/video-review/registry-candidate.json").exists()
