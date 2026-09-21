"""Prepare a private, offline validation workspace; never run a scan or load credentials."""

from __future__ import annotations

import argparse
import json
import re
import stat
import subprocess
import tomllib
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from importlib.metadata import PackageNotFoundError, version
from importlib.util import find_spec
from pathlib import Path
from platform import python_version

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ("mcp", "httpx2", "pydantic", "typer", "rich")
TEMPLATES = {
    "production.toml": "examples/policies/production.toml",
    "local-strict.toml": "examples/policies/local-strict.toml",
    "authorization.json": "docs/templates/validation-authorization.json",
    "review.md": "docs/templates/validation-review.md",
}


def git_value(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        capture_output=True,
        text=True,
        check=True,
        timeout=5,
    )
    return result.stdout.strip()


def environment_record(root: Path) -> dict[str, object]:
    """Allowlist provenance; never record environment variables, remotes, or user identity."""
    try:
        project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        declared_version = project["version"]
    except (KeyError, TypeError) as exc:
        raise ValueError("pyproject.toml does not declare project.version") from exc
    if not isinstance(declared_version, str) or not declared_version:
        raise ValueError("pyproject.toml project.version must be a non-empty string")
    try:
        installed_version = version("mendpact")
    except PackageNotFoundError as exc:
        raise ValueError("MendPact is not installed in the active Python environment") from exc
    if installed_version != declared_version:
        raise ValueError(
            "Installed MendPact metadata does not match pyproject.toml; reinstall the project"
        )
    specification = find_spec("mendpact")
    expected_source = (root / "src" / "mendpact").resolve()
    if (
        specification is None
        or specification.origin is None
        or not Path(specification.origin).resolve().is_relative_to(expected_source)
    ):
        raise ValueError("Active MendPact installation does not use this source checkout")
    packages: dict[str, str] = {"mendpact": installed_version}
    for name in PACKAGES:
        try:
            packages[name] = version(name)
        except PackageNotFoundError:
            packages[name] = "not-installed"
    return {
        "revision": git_value(root, "rev-parse", "HEAD"),
        "working_tree_dirty": bool(git_value(root, "status", "--porcelain")),
        "python": python_version(),
        "packages": packages,
    }


def real_directory(path: Path) -> None:
    """Reject linked/non-directory ancestors rather than following them."""
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise ValueError("Workspace ancestors must be real directories, not symlinks.")


def prepare_workspace(root: Path, label: str) -> Path:
    if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,47}", label) is None:
        raise ValueError(
            "Use 1-48 lowercase letters, digits, or hyphens; start with a letter/digit."
        )
    root = root.absolute()
    for ancestor in (*reversed(root.parents), root):
        real_directory(ancestor)
    # Read all inputs before creating anything. No network or credential inspection.
    contents = {name: (root / source).read_bytes() for name, source in TEMPLATES.items()}
    created = datetime.now(UTC)
    manifest = {
        "schema_version": "mendpact.validation-workspace.v1",
        "status": "not-run",
        "created_at": created.isoformat(),
        "review_or_delete_by": (created + timedelta(days=14)).isoformat(),
        "retention_note": "Manual cleanup reminder only; no automatic deletion.",
        "environment": environment_record(root),
        "template_sha256": {name: sha256(data).hexdigest() for name, data in contents.items()},
        "boundaries": {"provider_calls": False, "tool_execution": False, "publishing": False},
    }
    contents["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    parent = root
    for part in ("reports", "validation"):
        parent /= part
        parent.mkdir(mode=0o700, exist_ok=True)
        real_directory(parent)
    destination = parent / label
    # Exclusive directory creation: retries must use a new label, never reuse evidence paths.
    destination.mkdir(mode=0o700)
    for name, data in contents.items():
        path = destination / name
        with path.open("xb") as stream:
            path.chmod(0o600)
            stream.write(data)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("label", help="Unique local run label, e.g. 2026-09-07-server-a")
    arguments = parser.parse_args()
    try:
        destination = prepare_workspace(ROOT, arguments.label)
    except (OSError, ValueError, subprocess.SubprocessError):
        parser.exit(
            2,
            "Could not prepare workspace. Activate the project environment and install it with "
            "`python -m pip install -e '.[dev]'`, then check the label, paths, and Git checkout. "
            "Existing files were not replaced; inspect any partial new directory.\n",
        )
    print(
        f"Prepared {destination}\nNo validation has run. Complete authorization.json, then "
        "follow docs/REAL_WORLD_VALIDATION.md."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
