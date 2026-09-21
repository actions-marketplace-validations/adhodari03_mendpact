"""Create a secure, deterministic MendPact project scaffold."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_ACTION_REF = "adhodari03/mendpact@v0.3.0"


class ProjectInitializationError(ValueError):
    """Raised when a project scaffold cannot be created safely."""


@dataclass(frozen=True)
class ProjectFile:
    """One deterministic file in the generated project scaffold."""

    relative_path: Path
    content: str


def _validate_target(target: str) -> str:
    if "\n" in target or "\r" in target:
        raise ProjectInitializationError("Target URL cannot contain newlines.")
    if any(character.isspace() for character in target):
        raise ProjectInitializationError("Target URL cannot contain whitespace.")

    parsed = urlsplit(target)
    if parsed.scheme != "https":
        raise ProjectInitializationError(
            "Project initialization requires a production HTTPS MCP target."
        )
    if not parsed.hostname:
        raise ProjectInitializationError("Target URL must include a hostname.")
    if parsed.username or parsed.password:
        raise ProjectInitializationError(
            "Credentials must not be embedded in the target URL."
        )
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ProjectInitializationError("Target URL contains an invalid port.") from exc
    if parsed.query or parsed.fragment:
        raise ProjectInitializationError(
            "Target URL cannot contain a query or fragment because the URL is committed to CI."
        )
    return target


def _project_files(target: str) -> tuple[ProjectFile, ...]:
    yaml_target = json.dumps(target)
    policy = """schema_version = "mendpact.policy.v2"
name = "production"
profile = "production"

# Production-safe defaults. Tighten these thresholds if your project requires it.
scan_fail_on = "high"
contract_fail_on = "risky"
allow_private = false
allow_insecure_http = false

# For a protected target, store the token outside the repository and uncomment:
# bearer_token_env = "MENDPACT_ACCESS_TOKEN"

[model_comparison]
max_overall_pass_rate_drop = 0.02
max_scenario_pass_rate_drop = 0.05
allow_new_confusions = false

[semantic_calibration]
min_calibration_examples = 20
min_validation_examples = 20
min_validation_balanced_accuracy = 0.90
max_validation_false_accept_rate = 0.02
"""
    workflow = f"""name: MendPact MCP scan

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  mendpact:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-python@v6
        with:
          python-version: "3.13"
      - id: mendpact
        uses: {DEFAULT_ACTION_REF}
        with:
          mode: scan
          target: {yaml_target}
          policy: mendpact.toml
          output: mendpact-scan-report.json
      - if: always()
        uses: actions/upload-artifact@v6
        with:
          name: mendpact-scan-report
          path: mendpact-scan-report.json
          if-no-files-found: ignore
          retention-days: 14
"""
    scenario = json.dumps(
        {
            "schema_version": "mendpact.scenario.v1",
            "name": "EXAMPLE — replace with your reviewed MCP behavior",
            "scenarios": [
                {
                    "id": "replace-this-scenario",
                    "name": "Replace this example",
                    "task": "Describe one read-only task a user should be able to complete.",
                    "expectation": {
                        "tool": "replace_with_your_tool_name",
                        "argument_match": "exact",
                        "forbidden_tools": [],
                    },
                }
            ],
        },
        indent=2,
    ) + "\n"
    return (
        ProjectFile(Path("mendpact.toml"), policy),
        ProjectFile(Path(".github/workflows/mendpact.yml"), workflow),
        ProjectFile(Path("mendpact/scenarios.example.json"), scenario),
        ProjectFile(Path("mendpact/baselines/.gitkeep"), ""),
        ProjectFile(Path("mendpact/candidates/.gitignore"), "*\n!.gitignore\n"),
    )


def _validate_destination(root: Path, destination: Path) -> None:
    if root.is_symlink():
        raise ProjectInitializationError(f"Refusing to initialize through symlink: {root}")

    current = root
    parts = destination.relative_to(root).parts
    for part in parts[:-1]:
        current /= part
        if current.is_symlink():
            raise ProjectInitializationError(
                f"Refusing to initialize through symlink: {current.relative_to(root)}"
            )
        if current.exists() and not current.is_dir():
            raise ProjectInitializationError(
                f"Generated-file parent is not a directory: {current.relative_to(root)}"
            )

    if destination.is_symlink():
        raise ProjectInitializationError(
            f"Refusing to overwrite symlink: {destination.relative_to(root)}"
        )
    if destination.exists() and not destination.is_file():
        raise ProjectInitializationError(
            f"Generated-file destination is not a file: {destination.relative_to(root)}"
        )


def initialize_project(
    directory: Path,
    *,
    target: str,
    force: bool = False,
) -> tuple[Path, ...]:
    """Write the MendPact scaffold and return its generated paths."""

    safe_target = _validate_target(target)
    root = directory.expanduser().absolute()
    if root.exists() and not root.is_dir():
        raise ProjectInitializationError(f"Project destination is not a directory: {root}")

    project_files = _project_files(safe_target)
    destinations = tuple(root / item.relative_path for item in project_files)
    for destination in destinations:
        _validate_destination(root, destination)

    existing = [
        item.relative_path for item, destination in zip(project_files, destinations, strict=True)
        if destination.exists()
    ]
    if existing and not force:
        formatted = ", ".join(str(path) for path in existing)
        raise ProjectInitializationError(
            f"Refusing to overwrite existing generated files: {formatted}. "
            "Review them or rerun with --force."
        )

    root.mkdir(parents=True, exist_ok=True)
    for item, destination in zip(project_files, destinations, strict=True):
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(item.content, encoding="utf-8")
    return destinations
