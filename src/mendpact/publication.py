"""Offline preparation and verification of review-gated static evidence sites."""

from __future__ import annotations

import json
import os
import stat
from contextlib import suppress
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mendpact.domain import ScanStatus
from mendpact.evidence import EvidenceSummary, render_evidence_html
from mendpact.sharing import (
    PackageInspection,
    SharingApproval,
    inspect_package,
    verify_approval,
)

MAX_PUBLICATION_MEMBER_BYTES = 256 * 1024
PUBLICATION_FILES = {".nojekyll", "index.html", "publication.json", "summary.json"}
PUBLICATION_DISCLOSURE = (
    "These static files were prepared from an exact locally acknowledged package. "
    "They are unsigned and do not verify reviewer identity, source freshness, live execution, "
    "or safety."
)
PublicationArtifactName = Literal["index.html", "summary.json"]
Sha256Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class PublicationError(ValueError):
    """Safe-to-display static publication failure without input paths or values."""


class PublicationManifest(BaseModel):
    """Public, versioned metadata binding static files to reviewed package bytes."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["mendpact.public-evidence.v1"] = (
        "mendpact.public-evidence.v1"
    )
    package_sha256: Sha256Digest
    source_sha256: Sha256Digest
    source_schema: Literal[
        "mendpact.scan.v1", "mendpact.behavior.v1", "mendpact.guard.v1"
    ]
    recorded_status: ScanStatus
    source_generated_at: datetime
    prepared_at: datetime
    approval_expires_at: datetime
    artifacts: dict[PublicationArtifactName, Sha256Digest]
    disclosure: str = PUBLICATION_DISCLOSURE


class PublicationInspection(BaseModel):
    """Validated local publication and its minimized evidence summary."""

    manifest: PublicationManifest
    summary: EvidenceSummary


def _now() -> datetime:
    return datetime.now(UTC)


def _fail() -> None:
    raise PublicationError(
        "Evidence site is incomplete, altered, or outside the supported publication format."
    )


def _require(condition: bool) -> None:
    if not condition:
        _fail()


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _publication_artifacts(
    summary: EvidenceSummary,
) -> dict[PublicationArtifactName, bytes]:
    return {
        "index.html": (render_evidence_html(summary) + "\n").encode(),
        "summary.json": (summary.model_dump_json(indent=2) + "\n").encode(),
    }


def _manifest_bytes(manifest: PublicationManifest) -> bytes:
    return (manifest.model_dump_json(indent=2) + "\n").encode()


def _safe_directory(path: Path, *, must_exist: bool) -> Path:
    absolute = path.absolute()
    _require(not any(item.is_symlink() for item in (absolute, *absolute.parents)))
    if must_exist:
        _require(absolute.is_dir())
    else:
        _require(not absolute.exists() and absolute.parent.is_dir())
    return absolute


def _write_new_directory(destination: Path, files: dict[str, bytes]) -> None:
    absolute = _safe_directory(destination, must_exist=False)
    created: list[Path] = []
    try:
        os.mkdir(absolute, 0o700)
        for name in ("index.html", "summary.json", ".nojekyll", "publication.json"):
            value = files[name]
            descriptor = os.open(
                absolute / name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            created.append(absolute / name)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
    except OSError as exc:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        with suppress(OSError):
            absolute.rmdir()
        raise PublicationError(
            "Cannot prepare evidence site; use a new directory in an existing writable location."
        ) from exc


def _read_publication_files(directory: Path) -> dict[str, bytes]:
    absolute = _safe_directory(directory, must_exist=True)
    contents: dict[str, bytes] = {}
    try:
        _require({path.name for path in absolute.iterdir()} == PUBLICATION_FILES)
        for name in PUBLICATION_FILES:
            path = absolute / name
            _require(not path.is_symlink())
            descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            with os.fdopen(descriptor, "rb") as stream:
                metadata = os.fstat(stream.fileno())
                _require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1)
                value = stream.read(MAX_PUBLICATION_MEMBER_BYTES + 1)
            _require(len(value) <= MAX_PUBLICATION_MEMBER_BYTES)
            contents[name] = value
        return contents
    except OSError as exc:
        raise PublicationError(
            "Evidence site could not be read as bounded regular files."
        ) from exc


def _validate_manifest(
    manifest: PublicationManifest,
    summary: EvidenceSummary,
    approval: SharingApproval,
    package_sha256: str,
) -> None:
    _require(manifest.disclosure == PUBLICATION_DISCLOSURE)
    _require(manifest.package_sha256 == package_sha256)
    _require(manifest.source_sha256 == summary.source_sha256 == approval.source_sha256)
    _require(manifest.source_schema == summary.source_schema)
    _require(manifest.recorded_status == summary.recorded_status)
    _require(manifest.source_generated_at == summary.source_generated_at)
    _require(manifest.approval_expires_at == approval.expires_at)
    _require(
        manifest.prepared_at.tzinfo is not None
        and manifest.approval_expires_at.tzinfo is not None
    )
    _require(
        approval.approved_at <= manifest.prepared_at < approval.expires_at
        and manifest.prepared_at <= _now()
    )


def _inspect_approved_package(
    package: Path,
    approval_file: Path,
) -> tuple[SharingApproval, PackageInspection]:
    approval = verify_approval(package, approval_file)
    inspection = inspect_package(package)
    _require(approval.package_sha256 == inspection.package_sha256)
    _require(approval.source_sha256 == inspection.summary.source_sha256)
    return approval, inspection


def prepare_publication_site(
    package: Path,
    approval_file: Path,
    destination: Path,
) -> PublicationInspection:
    """Prepare static files only after exact package acknowledgement verifies."""

    approval, inspection = _inspect_approved_package(package, approval_file)
    prepared_at = _now()
    if not approval.approved_at <= prepared_at < approval.expires_at:
        raise PublicationError("Approval expired while preparing the evidence site.")
    artifacts = _publication_artifacts(inspection.summary)
    manifest = PublicationManifest(
        package_sha256=inspection.package_sha256,
        source_sha256=inspection.summary.source_sha256,
        source_schema=inspection.summary.source_schema,
        recorded_status=inspection.summary.recorded_status,
        source_generated_at=inspection.summary.source_generated_at,
        prepared_at=prepared_at,
        approval_expires_at=approval.expires_at,
        artifacts={name: sha256(value).hexdigest() for name, value in artifacts.items()},
    )
    files: dict[str, bytes] = {name: value for name, value in artifacts.items()}
    files[".nojekyll"] = b""
    files["publication.json"] = _manifest_bytes(manifest)
    _write_new_directory(destination, files)
    return PublicationInspection(manifest=manifest, summary=inspection.summary)


def inspect_publication_site(
    directory: Path,
    package: Path,
    approval_file: Path,
) -> PublicationInspection:
    """Verify static files against an exact package and current acknowledgement."""

    approval, inspection = _inspect_approved_package(package, approval_file)
    contents = _read_publication_files(directory)
    try:
        parsed = json.loads(contents["publication.json"], object_pairs_hook=_unique)
        _require(isinstance(parsed, dict))
        manifest = PublicationManifest.model_validate_json(
            contents["publication.json"], strict=True
        )
        _validate_manifest(manifest, inspection.summary, approval, inspection.package_sha256)
        artifacts = _publication_artifacts(inspection.summary)
        _require(contents[".nojekyll"] == b"")
        _require(contents["publication.json"] == _manifest_bytes(manifest))
        _require(set(manifest.artifacts) == set(artifacts))
        for name, value in artifacts.items():
            _require(contents[name] == value)
            _require(manifest.artifacts[name] == sha256(value).hexdigest())
        return PublicationInspection(manifest=manifest, summary=inspection.summary)
    except PublicationError:
        raise
    except (TypeError, ValueError, ValidationError, RecursionError) as exc:
        raise PublicationError(
            "Evidence site metadata is invalid; no publication trust is established."
        ) from exc
