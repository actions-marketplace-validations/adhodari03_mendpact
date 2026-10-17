"""Offline preparation of private, authorization-gated validation workspaces."""

from __future__ import annotations

import json
import os
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

from pydantic import ValidationError

from mendpact.registry import RegistryValidationCandidate

ROOT = Path(__file__).resolve().parents[2]
PACKAGES = ("mcp", "httpx2", "pydantic", "typer", "rich")
TEMPLATES = {
    "production.toml": "examples/policies/production.toml",
    "local-strict.toml": "examples/policies/local-strict.toml",
    "authorization.json": "docs/templates/validation-authorization.json",
    "review.md": "docs/templates/validation-review.md",
}
MAX_CANDIDATE_BYTES = 128 * 1024
REGISTRY_CANDIDATE_NAME = "registry-candidate.json"


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Registry candidate JSON contains duplicate keys.")
        result[key] = value
    return result


def git_value(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        capture_output=True,
        text=True,
        check=True,
        timeout=5,
    )
    return result.stdout.strip()


def repository_root(start: Path) -> Path:
    """Resolve the current source checkout without relying on a packaged template path."""

    root = Path(git_value(start, "rev-parse", "--show-toplevel")).resolve()
    if not root.is_dir():
        raise ValueError("Could not resolve the MendPact source checkout.")
    return root


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


def _load_candidate(path: Path) -> tuple[bytes, RegistryValidationCandidate]:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError
            raw = stream.read(MAX_CANDIDATE_BYTES + 1)
        if len(raw) > MAX_CANDIDATE_BYTES:
            raise ValueError
        value = json.loads(raw, object_pairs_hook=_unique_object)
        if not isinstance(value, dict):
            raise ValueError
        candidate = RegistryValidationCandidate.model_validate(value)
    except (OSError, ValidationError, ValueError) as exc:
        raise ValueError("Registry validation candidate is unreadable or invalid.") from exc
    return raw, candidate


def prepare_workspace(
    root: Path,
    label: str,
    *,
    candidate_path: Path | None = None,
) -> Path:
    """Create one private workspace without contacting a target or approving access."""

    if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,47}", label) is None:
        raise ValueError(
            "Use 1-48 lowercase letters, digits, or hyphens; start with a letter/digit."
        )
    root = root.absolute()
    for ancestor in (*reversed(root.parents), root):
        real_directory(ancestor)

    contents = {name: (root / source).read_bytes() for name, source in TEMPLATES.items()}
    candidate_binding: dict[str, str] | None = None
    if candidate_path is not None:
        candidate_raw, candidate = _load_candidate(candidate_path)
        authorization = json.loads(contents["authorization.json"])
        if not isinstance(authorization, dict):
            raise ValueError("Validation authorization template is invalid.")
        authorization.update(
            {
                "status": "draft",
                "target_alias": label,
                "target_url": candidate.selected_remote.url,
                "target_kind": "production_https",
            }
        )
        contents["authorization.json"] = (
            json.dumps(authorization, indent=2) + "\n"
        ).encode()
        contents[REGISTRY_CANDIDATE_NAME] = candidate_raw
        candidate_binding = {
            "file": REGISTRY_CANDIDATE_NAME,
            "sha256": sha256(candidate_raw).hexdigest(),
            "server_name": candidate.source_record.server_name,
            "server_version": candidate.source_record.server_version,
            "selected_remote_url": candidate.selected_remote.url,
        }

    created = datetime.now(UTC)
    manifest: dict[str, object] = {
        "schema_version": "mendpact.validation-workspace.v1",
        "status": "not-run",
        "created_at": created.isoformat(),
        "review_or_delete_by": (created + timedelta(days=14)).isoformat(),
        "retention_note": "Manual cleanup reminder only; no automatic deletion.",
        "environment": environment_record(root),
        "template_sha256": {
            name: sha256(data).hexdigest()
            for name, data in contents.items()
            if name in TEMPLATES
        },
        "boundaries": {
            "provider_calls": False,
            "tool_execution": False,
            "publishing": False,
        },
    }
    if candidate_binding is not None:
        manifest["registry_candidate"] = candidate_binding
    contents["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()

    parent = root
    for part in ("reports", "validation"):
        parent /= part
        parent.mkdir(mode=0o700, exist_ok=True)
        real_directory(parent)
    destination = parent / label
    destination.mkdir(mode=0o700)
    for name, data in contents.items():
        path = destination / name
        with path.open("xb") as stream:
            path.chmod(0o600)
            stream.write(data)
    return destination
