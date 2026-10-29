import json
from pathlib import Path

from typer.testing import CliRunner

import mendpact.cli as cli_module
from mendpact.cli import app
from mendpact.registry import (
    RegistryDiscoveryReport,
    RegistryError,
    RegistryRecord,
    RegistryValidationCandidate,
    validation_candidate_from_record,
)

runner = CliRunner()


def _record() -> RegistryRecord:
    return RegistryRecord.model_validate(
        {
            "server": {
                "name": "io.github.acme/video-editor",
                "title": "Acme Video Editor",
                "description": "Edit captions and scenes.",
                "version": "2.1.0",
                "repository": {
                    "url": "https://github.com/acme/video-editor",
                    "source": "github",
                },
                "remotes": [
                    {
                        "type": "streamable-http",
                        "url": "https://video.acme.test/mcp",
                    }
                ],
                "packages": [
                    {
                        "registryType": "npm",
                        "identifier": "@acme/video-editor",
                        "runtimeHint": "npx",
                        "transport": {"type": "stdio"},
                        "environmentVariables": [
                            {
                                "name": "ACME_TOKEN",
                                "isRequired": True,
                                "isSecret": True,
                                "value": "never-print-this",
                            }
                        ],
                    }
                ],
            },
            "_meta": {
                "io.modelcontextprotocol.registry/official": {
                    "status": "active",
                    "publishedAt": "2026-10-01T00:00:00Z",
                    "updatedAt": "2026-10-02T00:00:00Z",
                    "isLatest": True,
                }
            },
        }
    )


def _report() -> RegistryDiscoveryReport:
    return RegistryDiscoveryReport(
        query="video editing",
        registry_queries=["video", "editing", "edit"],
        result_count=1,
        results=[
            {
                "name": "io.github.acme/video-editor",
                "title": "Acme Video Editor",
                "description": "Edit captions and scenes.",
                "version": "2.1.0",
                "status": "active",
                "identity": "GitHub namespace: acme",
                "delivery": ["package:npx", "remote:streamable-http"],
                "required_secret_names": ["ACME_TOKEN"],
            }
        ],
    )


def test_root_help_lists_registry_discovery_commands() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "discover" in result.stdout
    assert "registry" in result.stdout


def test_discover_renders_results_and_writes_new_json(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def fake_search(query: str, *, limit: int) -> RegistryDiscoveryReport:
        assert query == "video editing"
        assert limit == 3
        return _report()

    monkeypatch.setattr(cli_module, "search_registry", fake_search)
    output = tmp_path / "registry-search.json"

    result = runner.invoke(
        app,
        [
            "discover",
            "video editing",
            "--limit",
            "3",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Acme Video" in result.stdout
    assert "Registry" in result.stdout
    assert "identity" in result.stdout
    assert "active" in result.stdout
    assert "not server" in result.stdout
    assert "safety" in result.stdout
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "mendpact.registry-discovery.v1"
    assert payload["result_count"] == 1
    assert payload["results"][0]["name"] == "io.github.acme/video-editor"
    assert payload["execution_boundary"].startswith("Registry metadata only")


def test_discover_never_overwrites_output(monkeypatch, tmp_path: Path) -> None:
    async def fake_search(query: str, *, limit: int) -> RegistryDiscoveryReport:
        return _report()

    monkeypatch.setattr(cli_module, "search_registry", fake_search)
    output = tmp_path / "existing.json"
    output.write_text("keep", encoding="utf-8")

    result = runner.invoke(app, ["discover", "video", "--output", str(output)])

    assert result.exit_code == 2
    assert "new output filename" in result.stdout
    assert output.read_text(encoding="utf-8") == "keep"


def test_registry_inspect_shows_metadata_but_not_secret_values(monkeypatch) -> None:
    async def fake_inspect(server_name: str, *, version: str) -> RegistryRecord:
        assert server_name == "io.github.acme/video-editor"
        assert version == "2.1.0"
        return _record()

    monkeypatch.setattr(cli_module, "inspect_registry_server", fake_inspect)

    result = runner.invoke(
        app,
        [
            "registry",
            "inspect",
            "io.github.acme/video-editor",
            "--version",
            "2.1.0",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Acme Video Editor" in result.stdout
    assert "ACME_TOKEN" in result.stdout
    assert "never-print-this" not in result.stdout
    assert "did not contact the MCP endpoint" in result.stdout
    assert "not a safety" in result.stdout
    assert "certification" in result.stdout


def test_registry_errors_are_configuration_exit_code_two(monkeypatch) -> None:
    async def fake_search(query: str, *, limit: int) -> RegistryDiscoveryReport:
        raise RegistryError("registry unavailable")

    async def fake_inspect(server_name: str, *, version: str) -> RegistryRecord:
        raise RegistryError("entry unavailable")

    monkeypatch.setattr(cli_module, "search_registry", fake_search)
    monkeypatch.setattr(cli_module, "inspect_registry_server", fake_inspect)

    search = runner.invoke(app, ["discover", "video"])
    inspect = runner.invoke(app, ["registry", "inspect", "com.example/video"])

    assert search.exit_code == 2
    assert "registry unavailable" in search.stdout
    assert inspect.exit_code == 2
    assert "entry unavailable" in inspect.stdout


def test_registry_prepare_writes_provenance_bound_candidate(
    monkeypatch,
    tmp_path: Path,
) -> None:
    async def fake_prepare(
        server_name: str,
        *,
        version: str,
        remote_url: str,
    ) -> RegistryValidationCandidate:
        assert server_name == "io.github.acme/video-editor"
        assert version == "2.1.0"
        assert remote_url == "https://video.acme.test/mcp"
        return validation_candidate_from_record(_record(), remote_url=remote_url)

    monkeypatch.setattr(cli_module, "prepare_registry_validation_candidate", fake_prepare)
    output = tmp_path / "candidate.json"
    result = runner.invoke(
        app,
        [
            "registry",
            "prepare",
            "io.github.acme/video-editor",
            "--version",
            "2.1.0",
            "--remote-url",
            "https://video.acme.test/mcp",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Candidate only" in result.stdout
    assert "not establish server safety" in result.stdout
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "mendpact.registry-validation-candidate.v1"
    assert payload["selected_remote"]["url"] == "https://video.acme.test/mcp"
    assert payload["source_record"]["required_package_secret_names"] == ["ACME_TOKEN"]
    assert "never-print-this" not in output.read_text(encoding="utf-8")


def test_registry_prepare_never_overwrites_candidate(monkeypatch, tmp_path: Path) -> None:
    async def fake_prepare(
        server_name: str,
        *,
        version: str,
        remote_url: str,
    ) -> RegistryValidationCandidate:
        return validation_candidate_from_record(_record(), remote_url=remote_url)

    monkeypatch.setattr(cli_module, "prepare_registry_validation_candidate", fake_prepare)
    output = tmp_path / "candidate.json"
    output.write_text("keep", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "registry",
            "prepare",
            "io.github.acme/video-editor",
            "--remote-url",
            "https://video.acme.test/mcp",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 2
    assert output.read_text(encoding="utf-8") == "keep"
