"""Local reviewed-sharing packages; no upload, signing, or identity verification."""

from __future__ import annotations

import io
import json
import os
import stat
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal
from zipfile import ZIP_STORED, BadZipFile, ZipFile, ZipInfo

from pydantic import BaseModel, ConfigDict, Field

from mendpact.evidence import (
    NOTICE,
    PRIVACY,
    EvidenceSummary,
    load_evidence_summary,
    render_evidence_html,
    write_new_evidence_bytes,
    write_new_evidence_file,
)

MAX_PACKAGE_BYTES = 1024 * 1024
MAX_MEMBER_BYTES = 256 * 1024
MAX_APPROVAL_BYTES = 16 * 1024
MAX_APPROVAL_DAYS = 14
MEMBERS = {"index.html", "summary.json", "manifest.json"}
DISCLOSURE = (
    "I acknowledge that this exact minimized package may be shared publicly. "
    "Counts, thresholds, outcomes, capture time and source digests remain visible. "
    "This acknowledgement is not a signature, identity verification or safety certification."
)


class SharingError(ValueError):
    """Safe error text, without private source values or archive member names."""


class SharingManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["mendpact.sharing-package.v1"]
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifacts: dict[Literal["index.html", "summary.json"], str]


class SharingApproval(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["mendpact.sharing-approval.v1"]
    package_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    approved_at: datetime
    expires_at: datetime
    acknowledged_public: Literal[True]
    disclosure: str


class PackageInspection(BaseModel):
    package_sha256: str
    summary: EvidenceSummary


def _require(condition: bool) -> None:
    if not condition:
        raise SharingError(
            "Package is malformed, altered, or outside the supported sharing format."
        )


def _read_file(path: Path, limit: int) -> bytes:
    try:
        absolute = path.absolute()
        _require(not any(p.is_symlink() for p in (absolute, *absolute.parents)))
        descriptor = os.open(absolute, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            _require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode))
            raw = stream.read(limit + 1)
        _require(len(raw) <= limit)
        return raw
    except OSError as exc:
        raise SharingError("Cannot read sharing input; use a readable regular file.") from exc


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _no_constant(value: str) -> None:
    raise SharingError("Non-finite JSON constants are not permitted.")


def _check_json(raw: bytes) -> Any:
    return json.loads(raw, object_pairs_hook=_unique, parse_constant=_no_constant)


def _validate_summary(summary: EvidenceSummary) -> None:
    """Reject arbitrary text/metrics in externally supplied minimized packages."""

    _require(summary.notice == NOTICE and summary.privacy == PRIVACY)
    if summary.schema_version == "mendpact.evidence.v2":
        _require(summary.source_schema in {"mendpact.scan.v1", "mendpact.guard.v1"})
    expected = {
        "mendpact.scan.v1": ["Capability scan"],
        "mendpact.behavior.v1": ["Behavior evaluation"],
        "mendpact.guard.v1": ["Capability scan", "Contract comparison", "Behavior evaluation"],
    }[summary.source_schema]
    _require([s.title for s in summary.sections] == expected)
    _require(summary.sections[0].status != "skipped")
    statuses = {s.status for s in summary.sections}
    if summary.source_schema != "mendpact.guard.v1":
        _require(summary.sections[0].status == summary.recorded_status)
    elif summary.recorded_status == "passed":
        _require(statuses <= {"passed", "skipped"})
    elif summary.recorded_status == "failed":
        _require("failed" in statuses and "error" not in statuses)
    for section in summary.sections:
        metrics = section.metrics
        if not metrics and section.status in ("error", "skipped"):
            continue
        _require(section.status != "skipped")
        choices: dict[str, set[str]] = {}
        optional: set[str] = set()
        if section.title == "Capability scan":
            required = {"Findings", "Waived findings", "Recorded errors (details withheld)"}
            severities = {f"{s} findings" for s in ("Info", "Low", "Medium", "High", "Critical")}
            required |= severities
            optional = {"Tools", "Resources", "Prompts"}
            _require(not (metrics.keys() & optional) or optional <= metrics.keys())
            delta_metrics = {
                "Introduced findings",
                "Resolved findings",
                "Reclassified findings",
                "Unchanged findings",
            }
            _require(not (metrics.keys() & delta_metrics) or delta_metrics <= metrics.keys())
            optional |= delta_metrics
            evidence_modes = {
                "Live metadata capture",
                "Offline deterministic recheck",
            }
            choices = {"Fails on severity": {"info", "low", "medium", "high", "critical"}}
            if summary.schema_version == "mendpact.evidence.v2":
                choices["Evidence mode"] = evidence_modes
            else:
                optional.add("Evidence mode")
                if "Evidence mode" in metrics:
                    _require(metrics["Evidence mode"] in evidence_modes)
        elif section.title == "Contract comparison":
            required = {
                "Changes",
                "Waived changes",
                "Affected scenarios",
                "Compatible changes",
                "Risky changes",
                "Breaking changes",
            }
            choices = {"Fails on impact": {"compatible", "risky", "breaking"}}
        else:
            required = {
                "Scenarios with trials",
                "Recorded trials",
                "Passed trials",
                "Failed trials",
                "Recorded errors (details withheld)",
            }
            choices = {
                "Evidence mode": {"Recorded replay", "Provider-labelled traces (not authenticated)"}
            }
            optional = {"Regression gate"}
            if "Regression gate" in metrics:
                _require(metrics["Regression gate"] in {"passed", "failed", "error"})
            passed, total = metrics.get("Passed trials"), metrics.get("Recorded trials")
            _require(type(passed) is int and type(total) is int)
            assert isinstance(passed, int) and isinstance(total, int)
            _require(total >= 0 and 0 <= passed <= total)
            choices["Pass rate"] = {f"{passed / total:.1%}" if total else "Not measured"}
        _require(required | choices.keys() <= metrics.keys())
        _require(metrics.keys() <= required | choices.keys() | optional)
        for label, values in choices.items():
            _require(metrics[label] in values)
        numeric_optional = {
            "Tools",
            "Resources",
            "Prompts",
            "Introduced findings",
            "Resolved findings",
            "Reclassified findings",
            "Unchanged findings",
        }
        for label in required | (optional & numeric_optional & metrics.keys()):
            value = metrics[label]
            _require(type(value) is int)
            _require(isinstance(value, int) and value >= 0)
        if section.title == "Capability scan":
            _require(sum(int(metrics[s]) for s in severities) == metrics["Findings"])
            _require(int(metrics["Waived findings"]) <= int(metrics["Findings"]))
        elif section.title == "Contract comparison":
            _require(
                sum(int(metrics[f"{s} changes"]) for s in ("Compatible", "Risky", "Breaking"))
                == metrics["Changes"]
            )
            _require(int(metrics["Waived changes"]) <= int(metrics["Changes"]))
        else:
            _require(
                int(metrics["Passed trials"]) + int(metrics["Failed trials"])
                == metrics["Recorded trials"]
            )
            _require(int(metrics["Scenarios with trials"]) <= int(metrics["Recorded trials"]))


def _package_bytes(summary: EvidenceSummary) -> bytes:
    _validate_summary(summary)
    artifacts = {
        "summary.json": (summary.model_dump_json(indent=2) + "\n").encode(),
        "index.html": (render_evidence_html(summary) + "\n").encode(),
    }
    manifest = SharingManifest(
        schema_version="mendpact.sharing-package.v1",
        source_sha256=summary.source_sha256,
        artifacts={
            "summary.json": sha256(artifacts["summary.json"]).hexdigest(),
            "index.html": sha256(artifacts["index.html"]).hexdigest(),
        },
    )
    artifacts["manifest.json"] = (manifest.model_dump_json(indent=2) + "\n").encode()
    stream = io.BytesIO()
    with ZipFile(stream, "w", compression=ZIP_STORED) as archive:
        for name in sorted(artifacts):
            _require(len(artifacts[name]) <= MAX_MEMBER_BYTES)
            info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o100600 << 16
            archive.writestr(info, artifacts[name])
    return stream.getvalue()


def prepare_package(source: Path, destination: Path) -> PackageInspection:
    """Create a local review ZIP from original evidence; never copy the raw report."""

    summary = load_evidence_summary(source)
    package = _package_bytes(summary)
    write_new_evidence_bytes(destination, package)
    return PackageInspection(package_sha256=sha256(package).hexdigest(), summary=summary)


def inspect_package(package: Path) -> PackageInspection:
    """Bound and validate every ZIP member without extracting anything."""

    raw = _read_file(package, MAX_PACKAGE_BYTES)
    try:
        with ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()
            _require(len(members) == len(MEMBERS) and {m.filename for m in members} == MEMBERS)
            for member in members:
                _require(not member.is_dir() and not member.flag_bits & 1)
                _require(member.compress_type == ZIP_STORED)
                _require(member.compress_size == member.file_size <= MAX_MEMBER_BYTES)
                _require(not stat.S_ISLNK(member.external_attr >> 16))
            content = {name: archive.read(name) for name in MEMBERS}
        _check_json(content["manifest.json"])
        _check_json(content["summary.json"])
        manifest = SharingManifest.model_validate_json(content["manifest.json"], strict=True)
        summary = EvidenceSummary.model_validate_json(content["summary.json"], strict=True)
        _validate_summary(summary)
        _require(set(manifest.artifacts) == {"summary.json", "index.html"})
        _require(manifest.source_sha256 == summary.source_sha256)
        for name, digest in manifest.artifacts.items():
            _require(digest == sha256(content[name]).hexdigest())
        _require(content["index.html"] == (render_evidence_html(summary) + "\n").encode())
        # Canonical bytes also exclude comments, extra fields, prepended/trailing payloads,
        # duplicate members and platform-dependent ZIP metadata from the reviewed artifact.
        _require(raw == _package_bytes(summary))
        return PackageInspection(package_sha256=sha256(raw).hexdigest(), summary=summary)
    except SharingError:
        raise
    except (ValueError, BadZipFile, KeyError, RuntimeError, RecursionError) as exc:
        raise SharingError(
            "Sharing package could not be validated; no files were extracted."
        ) from exc


def _now() -> datetime:
    return datetime.now(UTC)


def approve_package(
    package: Path,
    destination: Path,
    *,
    accepted_sha256: str,
    acknowledge_public: bool = False,
    valid_for_days: int = 7,
) -> SharingApproval:
    """Record an explicit, unsigned acknowledgement for the exact reviewed ZIP."""

    if acknowledge_public is not True:
        raise SharingError("Explicit --acknowledge-public is required; no approval was recorded.")
    if type(valid_for_days) is not int or not 1 <= valid_for_days <= MAX_APPROVAL_DAYS:
        raise SharingError("Approval validity must be between 1 and 14 days.")
    inspection = inspect_package(package)
    if accepted_sha256 != inspection.package_sha256:
        raise SharingError("--accept-sha256 does not match the inspected package.")
    now = _now()
    approval = SharingApproval(
        schema_version="mendpact.sharing-approval.v1",
        package_sha256=inspection.package_sha256,
        source_sha256=inspection.summary.source_sha256,
        approved_at=now,
        expires_at=now + timedelta(days=valid_for_days),
        acknowledged_public=True,
        disclosure=DISCLOSURE,
    )
    write_new_evidence_file(destination, approval.model_dump_json(indent=2))
    return approval


def verify_approval(package: Path, receipt: Path) -> SharingApproval:
    """Verify integrity and current acknowledgement, not an approver's identity."""

    inspection = inspect_package(package)
    try:
        raw = _read_file(receipt, MAX_APPROVAL_BYTES)
        payload = _check_json(raw)
        _require(isinstance(payload, dict) and payload.get("acknowledged_public") is True)
        approval = SharingApproval.model_validate_json(raw, strict=True)
        _require(approval.disclosure == DISCLOSURE)
        _require(approval.package_sha256 == inspection.package_sha256)
        _require(approval.source_sha256 == inspection.summary.source_sha256)
        _require(approval.approved_at.tzinfo is not None and approval.expires_at.tzinfo is not None)
        _require(timedelta(0) < approval.expires_at - approval.approved_at <= timedelta(days=14))
        if not approval.approved_at <= _now() < approval.expires_at:
            raise SharingError("Approval is expired or not yet valid. Inspect and approve again.")
        return approval
    except SharingError:
        raise
    except (ValueError, RecursionError) as exc:
        raise SharingError(
            "Approval receipt is invalid; no approval identity is verified."
        ) from exc
