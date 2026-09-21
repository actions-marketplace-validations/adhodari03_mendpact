"""Guarded, bounded capture sessions for authorized real-world MCP validation."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import stat
import subprocess
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    ValidationError,
    model_validator,
)

from mendpact.contract_diff import diff_scan_reports, validate_scan_contract
from mendpact.domain import (
    ContractImpact,
    PolicyProfile,
    PolicySnapshot,
    ScanReport,
    ScanStatus,
    Severity,
    summarize,
)
from mendpact.evidence import write_new_evidence_file
from mendpact.policy import load_policy, target_policy
from mendpact.scanner import scan_mcp_url

MAX_VALIDATION_FILE_BYTES = 128 * 1024
MAX_VALIDATION_REPORT_BYTES = 10 * 1024 * 1024
MAX_APPROVAL_DAYS = 14
SESSION_MANIFEST_NAME = "session.json"
SESSION_SUMMARY_NAME = "validation-summary.json"
SESSION_NOTICE = (
    "Bounded metadata discovery from an explicitly approved local authorization record. "
    "No MCP tool or model provider was called. A passed policy is not a security certification. "
    "Target hashes are linkable fingerprints, not anonymization or signatures."
)
SESSION_SUMMARY_NOTICE = (
    "This privacy-minimized summary describes locally supplied session evidence. It is not a "
    "security certification, proof of a live request, or a signature. Recorded policy outcomes "
    "and repeat-capture comparison must be reviewed with the private source files."
)
Scanner = Callable[..., Awaitable[ScanReport]]


class ValidationSessionError(ValueError):
    """Safe-to-display validation setup or session failure."""


class ValidationAuthorization(BaseModel):
    """Local authorization record that must be completed before any network operation."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["mendpact.validation-authorization.v1"] = (
        "mendpact.validation-authorization.v1"
    )
    status: Literal["draft", "approved"] = "draft"
    target_alias: str = Field(default="", max_length=48)
    target_url: str = Field(default="", max_length=2048)
    target_kind: Literal["production_https", "isolated_loopback"] = "production_https"
    approved_by: str = Field(default="", max_length=120)
    permission_reference: str = Field(default="", max_length=500)
    approved_at: datetime | None = None
    expires_at: datetime | None = None
    max_discovery_scans: int = Field(default=2, ge=1, le=2)
    stop_conditions_acknowledged: StrictBool = False
    allow_authenticated: StrictBool = False
    allow_tool_execution: StrictBool = False
    allow_provider_calls: StrictBool = False

    @model_validator(mode="after")
    def validate_approved_record(self) -> ValidationAuthorization:
        if self.status == "draft":
            return self
        if (
            re.fullmatch(r"[a-z0-9][a-z0-9-]{0,47}", self.target_alias) is None
            or not self.target_url
        ):
            raise ValueError("approved authorization requires a target alias and URL")
        if not self.approved_by.strip() or len(self.permission_reference.strip()) < 10:
            raise ValueError("approved authorization requires reviewer and permission evidence")
        if self.approved_at is None or self.expires_at is None:
            raise ValueError("approved authorization requires approval and expiry times")
        if self.approved_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("authorization times must include a UTC offset")
        if self.expires_at <= self.approved_at:
            raise ValueError("authorization expiry must follow approval")
        if self.expires_at - self.approved_at > timedelta(days=MAX_APPROVAL_DAYS):
            raise ValueError("authorization cannot exceed 14 days")
        if not self.stop_conditions_acknowledged:
            raise ValueError("validation stop conditions must be acknowledged")
        if self.allow_authenticated or self.allow_tool_execution or self.allow_provider_calls:
            raise ValueError("guarded validation cannot authorize expanded operations")
        return self


class ValidationSessionScan(BaseModel):
    """Integrity and outcome record for one sequential discovery scan."""

    model_config = ConfigDict(extra="forbid")

    index: int = Field(ge=1, le=2)
    status: ScanStatus
    scan_id: str = Field(min_length=1)
    generated_at: datetime
    report_file: str = Field(pattern=r"^scan-0[12]\.json$")
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ValidationSessionManifest(BaseModel):
    """Versioned local evidence for a bounded validation capture session."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["mendpact.validation-session.v1"] = (
        "mendpact.validation-session.v1"
    )
    generated_at: datetime
    status: ScanStatus
    target_alias: str = Field(min_length=1, max_length=48)
    target_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    authorization_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    authorization_expires_at: datetime
    workspace_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    planned_scan_count: int = Field(ge=1, le=2)
    completed_scan_count: int = Field(ge=1, le=2)
    stopped_early: bool
    authenticated: Literal[False] = False
    tool_execution: Literal[False] = False
    provider_calls: Literal[False] = False
    scans: list[ValidationSessionScan] = Field(min_length=1, max_length=2)
    notice: str = SESSION_NOTICE

    @model_validator(mode="after")
    def validate_session_outcome(self) -> ValidationSessionManifest:
        if self.notice != SESSION_NOTICE:
            raise ValueError("session notice does not match its schema")
        if self.generated_at.tzinfo is None or self.authorization_expires_at.tzinfo is None:
            raise ValueError("session times must include a UTC offset")
        if self.completed_scan_count != len(self.scans):
            raise ValueError("completed scan count does not match session scans")
        if [scan.index for scan in self.scans] != list(
            range(1, self.completed_scan_count + 1)
        ):
            raise ValueError("session scan indexes must be contiguous")
        if any(
            scan.report_file != f"scan-{scan.index:02}.json"
            or scan.generated_at.tzinfo is None
            for scan in self.scans
        ):
            raise ValueError("session scan files or times do not match their indexes")
        if len({scan.scan_id for scan in self.scans}) != len(self.scans):
            raise ValueError("session scan IDs must be unique")
        expected_status = (
            ScanStatus.ERROR
            if any(scan.status == ScanStatus.ERROR for scan in self.scans)
            else ScanStatus.FAILED
            if any(scan.status == ScanStatus.FAILED for scan in self.scans)
            else ScanStatus.PASSED
        )
        if self.status != expected_status:
            raise ValueError("session status does not match scan outcomes")
        if self.stopped_early != (self.completed_scan_count < self.planned_scan_count):
            raise ValueError("stopped_early does not match the scan counts")
        if self.stopped_early and self.scans[-1].status != ScanStatus.ERROR:
            raise ValueError("only an operational scan error can stop a session early")
        return self


class ValidationSessionScanSummary(BaseModel):
    """Allowlisted aggregate fields for one private session scan."""

    model_config = ConfigDict(extra="forbid")

    index: int = Field(ge=1, le=2)
    status: ScanStatus
    generated_at: datetime
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool_count: int = Field(ge=0)
    resource_count: int = Field(ge=0)
    prompt_count: int = Field(ge=0)
    finding_count: int = Field(ge=0)
    waived_finding_count: int = Field(ge=0)
    findings_by_severity: dict[str, int]
    recorded_error_count: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_severity_counts(self) -> ValidationSessionScanSummary:
        if set(self.findings_by_severity) != {severity.value for severity in Severity}:
            raise ValueError("scan summary must contain every supported severity")
        if any(count < 0 for count in self.findings_by_severity.values()):
            raise ValueError("scan summary severity counts cannot be negative")
        if sum(self.findings_by_severity.values()) != self.finding_count:
            raise ValueError("scan summary severity counts do not match finding count")
        if self.waived_finding_count > self.finding_count:
            raise ValueError("waived finding count cannot exceed finding count")
        return self


class ValidationSessionComparisonSummary(BaseModel):
    """Aggregate contract stability between two sequential discovery captures."""

    model_config = ConfigDict(extra="forbid")

    result: Literal["stable", "changed", "unavailable"]
    change_count: int = Field(ge=0)
    changes_by_impact: dict[str, int]

    @model_validator(mode="after")
    def validate_comparison_counts(self) -> ValidationSessionComparisonSummary:
        if set(self.changes_by_impact) != {impact.value for impact in ContractImpact}:
            raise ValueError("comparison must contain every supported impact")
        if any(count < 0 for count in self.changes_by_impact.values()):
            raise ValueError("comparison impact counts cannot be negative")
        if sum(self.changes_by_impact.values()) != self.change_count:
            raise ValueError("comparison impact counts do not match change count")
        if self.result == "stable" and self.change_count != 0:
            raise ValueError("a stable comparison cannot contain changes")
        if self.result == "changed" and self.change_count == 0:
            raise ValueError("a changed comparison must contain changes")
        if self.result == "unavailable" and self.change_count != 0:
            raise ValueError("an unavailable comparison cannot contain changes")
        return self


class ValidationSessionSummary(BaseModel):
    """Privacy-minimized, integrity-checked projection of a completed session."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["mendpact.validation-summary.v1"] = (
        "mendpact.validation-summary.v1"
    )
    generated_at: datetime
    recorded_status: ScanStatus
    session_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    planned_scan_count: int = Field(ge=1, le=2)
    completed_scan_count: int = Field(ge=1, le=2)
    stopped_early: bool
    scans: list[ValidationSessionScanSummary] = Field(min_length=1, max_length=2)
    comparison: ValidationSessionComparisonSummary
    authenticated: Literal[False] = False
    tool_execution: Literal[False] = False
    provider_calls: Literal[False] = False
    notice: str = SESSION_SUMMARY_NOTICE

    @model_validator(mode="after")
    def validate_summary_outcome(self) -> ValidationSessionSummary:
        if self.notice != SESSION_SUMMARY_NOTICE:
            raise ValueError("summary notice does not match its schema")
        if self.generated_at.tzinfo is None:
            raise ValueError("summary time must include a UTC offset")
        if self.completed_scan_count != len(self.scans):
            raise ValueError("completed scan count does not match summarized scans")
        if [scan.index for scan in self.scans] != list(
            range(1, self.completed_scan_count + 1)
        ):
            raise ValueError("summarized scan indexes must be contiguous")
        expected_status = (
            ScanStatus.ERROR
            if any(scan.status == ScanStatus.ERROR for scan in self.scans)
            else ScanStatus.FAILED
            if any(scan.status == ScanStatus.FAILED for scan in self.scans)
            else ScanStatus.PASSED
        )
        if self.recorded_status != expected_status:
            raise ValueError("summary status does not match scan outcomes")
        if self.stopped_early != (self.completed_scan_count < self.planned_scan_count):
            raise ValueError("summary stopped_early does not match scan counts")
        return self


@dataclass(frozen=True)
class ValidationSessionPlan:
    workspace: Path
    authorization: ValidationAuthorization
    authorization_sha256: str
    workspace_manifest_sha256: str
    policy: PolicySnapshot


@dataclass(frozen=True)
class ValidationSessionResult:
    manifest: ValidationSessionManifest
    reports: list[ScanReport]


@dataclass(frozen=True)
class CompletedValidationSession:
    manifest: ValidationSessionManifest
    manifest_sha256: str
    reports: list[ScanReport]


def _now() -> datetime:
    return datetime.now(UTC)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationSessionError("Validation JSON contains duplicate keys.")
        result[key] = value
    return result


def _read_private_file(
    path: Path,
    *,
    max_bytes: int = MAX_VALIDATION_FILE_BYTES,
) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_mode & 0o077
            ):
                raise ValidationSessionError(
                    "Validation inputs must be private regular files with permissions 0600."
                )
            raw = stream.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValidationSessionError("Validation input exceeds its size limit.")
        return raw
    except ValidationSessionError:
        raise
    except OSError as exc:
        raise ValidationSessionError("Validation input cannot be read safely.") from exc


def _read_json(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw = _read_private_file(path)
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
        if not isinstance(value, dict):
            raise ValueError
        return raw, value
    except ValidationSessionError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValidationSessionError("Validation JSON is unreadable or invalid.") from exc


def _reject_constant(_value: str) -> None:
    raise ValidationSessionError("Validation JSON contains a non-finite number.")


def _read_scan_report(path: Path) -> tuple[bytes, ScanReport]:
    raw = _read_private_file(path, max_bytes=MAX_VALIDATION_REPORT_BYTES)
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        if not isinstance(value, dict):
            raise ValueError
        report = ScanReport.model_validate(value)
        if report.schema_version != "mendpact.scan.v1" or report.recheck is not None:
            raise ValueError
        if report.status == ScanStatus.ERROR:
            if not report.errors or report.graph is not None or report.summary is not None:
                raise ValueError
            return raw, report
        graph = validate_scan_contract(report, "session")
        expected_summary = summarize(graph, report.findings)
        failed = any(
            finding.waiver is None
            and finding.severity.rank >= report.failure_threshold.rank
            for finding in report.findings
        )
        if (
            report.errors
            or graph.target != report.target
            or report.summary != expected_summary
            or report.status != (ScanStatus.FAILED if failed else ScanStatus.PASSED)
        ):
            raise ValueError
        return raw, report
    except ValidationSessionError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError) as exc:
        raise ValidationSessionError(
            "Session scan evidence is unreadable or internally inconsistent."
        ) from exc


def _safe_workspace(path: Path) -> Path:
    absolute = path.absolute()
    try:
        if any(item.is_symlink() for item in (absolute, *absolute.parents)):
            raise ValidationSessionError("Validation workspace paths must not contain symlinks.")
        metadata = absolute.stat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o077:
            raise ValidationSessionError(
                "Validation workspace must be a private directory with permissions 0700."
            )
        root = absolute.parents[2]
        if absolute.parent.name != "validation" or absolute.parent.parent.name != "reports":
            raise ValidationSessionError(
                "Use a workspace created under reports/validation by the preparation script."
            )
        if absolute != root / "reports" / "validation" / absolute.name:
            raise ValidationSessionError("Validation workspace location is invalid.")
        return absolute
    except ValidationSessionError:
        raise
    except (OSError, IndexError) as exc:
        raise ValidationSessionError("Validation workspace cannot be inspected safely.") from exc


def _git(root: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        return result.stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValidationSessionError("Validation checkout provenance cannot be verified.") from exc


def _validate_target(authorization: ValidationAuthorization) -> None:
    try:
        if any(character.isspace() for character in authorization.target_url):
            raise ValueError
        parts = urlsplit(authorization.target_url)
        if (
            parts.scheme not in {"http", "https"}
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
        ):
            raise ValueError
        _ = parts.port
        if authorization.target_kind == "production_https":
            if parts.scheme != "https":
                raise ValueError
            return
        if parts.scheme not in {"http", "https"}:
            raise ValueError
        hostname = parts.hostname.rstrip(".").lower()
        if hostname == "localhost":
            return
        if not ipaddress.ip_address(hostname).is_loopback:
            raise ValueError
    except ValueError as exc:
        raise ValidationSessionError(
            "Approved target URL does not match its safe production or loopback profile."
        ) from exc


def _validate_workspace_manifest(
    manifest: dict[str, Any],
    *,
    root: Path,
    policy_name: str,
    policy_sha256: str,
    now: datetime,
) -> None:
    try:
        environment = manifest["environment"]
        boundaries = manifest["boundaries"]
        created_at = datetime.fromisoformat(manifest["created_at"])
        delete_by = datetime.fromisoformat(manifest["review_or_delete_by"])
        if (
            manifest["schema_version"] != "mendpact.validation-workspace.v1"
            or manifest["status"] != "not-run"
            or not isinstance(environment, dict)
            or not isinstance(boundaries, dict)
            or environment.get("working_tree_dirty") is not False
            or environment.get("revision") != _git(root, "rev-parse", "HEAD")
            or _git(root, "status", "--porcelain")
            or boundaries
            != {"provider_calls": False, "tool_execution": False, "publishing": False}
            or manifest["template_sha256"][policy_name] != policy_sha256
            or created_at.tzinfo is None
            or delete_by.tzinfo is None
            or delete_by <= now
            or delete_by - created_at > timedelta(days=MAX_APPROVAL_DAYS)
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidationSessionError(
            "Workspace provenance is stale, dirty, expired, or inconsistent; prepare a fresh one."
        ) from exc


def inspect_validation_session(
    workspace: Path,
    *,
    inspected_at: datetime | None = None,
) -> ValidationSessionPlan:
    """Validate local approval, policies, checkout identity, retention, and output freshness."""

    current = inspected_at or _now()
    if current.tzinfo is None:
        raise ValidationSessionError("Validation inspection time must include a UTC offset.")
    directory = _safe_workspace(workspace)
    root = directory.parents[2]
    authorization_raw, authorization_value = _read_json(directory / "authorization.json")
    manifest_raw, manifest = _read_json(directory / "manifest.json")
    _read_private_file(directory / "review.md")
    try:
        authorization = ValidationAuthorization.model_validate(authorization_value)
    except ValidationError as exc:
        raise ValidationSessionError(
            "Authorization record is invalid; complete the generated template locally."
        ) from exc
    if authorization.status != "approved":
        raise ValidationSessionError(
            "Authorization remains draft; do not contact the target until it is approved."
        )
    if authorization.approved_at is None or authorization.expires_at is None:
        raise ValidationSessionError("Authorization record is incomplete.")
    if authorization.approved_at > current or authorization.expires_at <= current:
        raise ValidationSessionError("Authorization is not currently valid.")
    _validate_target(authorization)

    policy_name = (
        "production.toml"
        if authorization.target_kind == "production_https"
        else "local-strict.toml"
    )
    policy_path = directory / policy_name
    policy_raw = _read_private_file(policy_path)
    try:
        policy = load_policy(policy_path, today=current.date())
    except ValueError as exc:
        raise ValidationSessionError("Selected validation policy is invalid.") from exc
    if authorization.target_kind == "production_https":
        if (
            policy.profile != PolicyProfile.PRODUCTION
            or policy.allow_private
            or policy.allow_insecure_http
        ):
            raise ValidationSessionError("Production validation requires the strict HTTPS policy.")
    elif not policy.allow_private or not policy.allow_insecure_http:
        raise ValidationSessionError("Loopback validation requires the strict local policy.")
    if policy.bearer_token_env is not None:
        raise ValidationSessionError("Guarded validation does not accept credentials.")
    _validate_workspace_manifest(
        manifest,
        root=root,
        policy_name=policy_name,
        policy_sha256=sha256(policy_raw).hexdigest(),
        now=current,
    )
    delete_by = datetime.fromisoformat(manifest["review_or_delete_by"])
    if authorization.expires_at > delete_by:
        raise ValidationSessionError("Authorization cannot outlive the workspace retention date.")
    if (directory / SESSION_MANIFEST_NAME).exists() or list(directory.glob("scan-*.json")):
        raise ValidationSessionError(
            "Validation outputs already exist; prepare a fresh workspace instead of overwriting."
        )
    return ValidationSessionPlan(
        workspace=directory,
        authorization=authorization,
        authorization_sha256=sha256(authorization_raw).hexdigest(),
        workspace_manifest_sha256=sha256(manifest_raw).hexdigest(),
        policy=policy,
    )


def _validate_completed_workspace_manifest(
    manifest: dict[str, Any],
    *,
    policy_name: str,
    policy_sha256: str,
    now: datetime,
) -> tuple[datetime, datetime]:
    try:
        environment = manifest["environment"]
        boundaries = manifest["boundaries"]
        created_at = datetime.fromisoformat(manifest["created_at"])
        delete_by = datetime.fromisoformat(manifest["review_or_delete_by"])
        revision = environment["revision"]
        if (
            manifest["schema_version"] != "mendpact.validation-workspace.v1"
            or manifest["status"] != "not-run"
            or not isinstance(environment, dict)
            or not isinstance(boundaries, dict)
            or environment.get("working_tree_dirty") is not False
            or not isinstance(revision, str)
            or re.fullmatch(r"[0-9a-f]{40,64}", revision) is None
            or boundaries
            != {"provider_calls": False, "tool_execution": False, "publishing": False}
            or manifest["template_sha256"][policy_name] != policy_sha256
            or created_at.tzinfo is None
            or delete_by.tzinfo is None
            or delete_by <= now
            or delete_by - created_at > timedelta(days=MAX_APPROVAL_DAYS)
        ):
            raise ValueError
        return created_at, delete_by
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidationSessionError(
            "Completed workspace provenance is expired or internally inconsistent."
        ) from exc


def inspect_completed_validation_session(
    workspace: Path,
    *,
    inspected_at: datetime | None = None,
) -> CompletedValidationSession:
    """Verify a completed session and its exact private report bytes without network access."""

    current = inspected_at or _now()
    if current.tzinfo is None:
        raise ValidationSessionError("Validation inspection time must include a UTC offset.")
    directory = _safe_workspace(workspace)
    authorization_raw, authorization_value = _read_json(directory / "authorization.json")
    workspace_raw, workspace_value = _read_json(directory / "manifest.json")
    session_raw, session_value = _read_json(directory / SESSION_MANIFEST_NAME)
    _read_private_file(directory / "review.md")
    try:
        authorization = ValidationAuthorization.model_validate(authorization_value)
        manifest = ValidationSessionManifest.model_validate(session_value)
    except ValidationError as exc:
        raise ValidationSessionError(
            "Completed validation authorization or session manifest is invalid."
        ) from exc
    if authorization.status != "approved":
        raise ValidationSessionError("Completed validation authorization is not approved.")
    if authorization.approved_at is None or authorization.expires_at is None:
        raise ValidationSessionError("Completed validation authorization is incomplete.")
    _validate_target(authorization)

    policy_name = (
        "production.toml"
        if authorization.target_kind == "production_https"
        else "local-strict.toml"
    )
    policy_path = directory / policy_name
    policy_raw = _read_private_file(policy_path)
    try:
        policy = load_policy(policy_path, today=manifest.generated_at.date())
    except ValueError as exc:
        raise ValidationSessionError("Completed validation policy is invalid.") from exc
    if authorization.target_kind == "production_https":
        if (
            policy.profile != PolicyProfile.PRODUCTION
            or policy.allow_private
            or policy.allow_insecure_http
        ):
            raise ValidationSessionError(
                "Completed production validation does not use the strict HTTPS policy."
            )
    elif not policy.allow_private or not policy.allow_insecure_http:
        raise ValidationSessionError(
            "Completed loopback validation does not use the strict local policy."
        )
    if policy.bearer_token_env is not None:
        raise ValidationSessionError("Completed guarded validation cannot contain credentials.")
    _, delete_by = _validate_completed_workspace_manifest(
        workspace_value,
        policy_name=policy_name,
        policy_sha256=sha256(policy_raw).hexdigest(),
        now=current,
    )
    if (
        manifest.authorization_sha256 != sha256(authorization_raw).hexdigest()
        or manifest.workspace_manifest_sha256 != sha256(workspace_raw).hexdigest()
        or manifest.policy_source_sha256 != policy.source_sha256
        or manifest.target_alias != authorization.target_alias
        or manifest.target_sha256 != sha256(authorization.target_url.encode()).hexdigest()
        or manifest.authorization_expires_at != authorization.expires_at
        or manifest.planned_scan_count != authorization.max_discovery_scans
        or manifest.generated_at.tzinfo is None
        or manifest.generated_at < authorization.approved_at
        or manifest.generated_at >= authorization.expires_at
        or manifest.generated_at > delete_by
    ):
        raise ValidationSessionError(
            "Completed session does not match its authorization, policy, or workspace."
        )

    expected_files = {scan.report_file for scan in manifest.scans}
    actual_files = {path.name for path in directory.glob("scan-*.json")}
    if actual_files != expected_files:
        raise ValidationSessionError("Completed session scan files do not match its manifest.")
    reports: list[ScanReport] = []
    previous_generated_at = manifest.generated_at
    for recorded_scan in manifest.scans:
        raw, report = _read_scan_report(directory / recorded_scan.report_file)
        if (
            recorded_scan.report_sha256 != sha256(raw).hexdigest()
            or recorded_scan.scan_id != report.scan_id
            or recorded_scan.generated_at != report.generated_at
            or recorded_scan.status != report.status
            or report.target != authorization.target_url
            or report.generated_at.tzinfo is None
            or report.generated_at < previous_generated_at
            or report.generated_at >= authorization.expires_at
            or report.generated_at > delete_by
            or report.policy is None
            or report.policy != policy
        ):
            raise ValidationSessionError(
                "Completed scan evidence does not match the session manifest."
            )
        reports.append(report)
        previous_generated_at = report.generated_at
    return CompletedValidationSession(
        manifest=manifest,
        manifest_sha256=sha256(session_raw).hexdigest(),
        reports=reports,
    )


def summarize_validation_session(
    workspace: Path,
    *,
    summarized_at: datetime | None = None,
) -> ValidationSessionSummary:
    """Build an allowlisted session summary after verifying all private source evidence."""

    current = summarized_at or _now()
    if current.tzinfo is None:
        raise ValidationSessionError("Validation summary time must include a UTC offset.")
    completed = inspect_completed_validation_session(workspace, inspected_at=current)
    scans: list[ValidationSessionScanSummary] = []
    for index, (recorded, report) in enumerate(
        zip(completed.manifest.scans, completed.reports, strict=True),
        start=1,
    ):
        if report.summary is None:
            tools = resources = prompts = findings = waived = 0
            by_severity = {severity.value: 0 for severity in Severity}
        else:
            tools = report.summary.tool_count
            resources = report.summary.resource_count
            prompts = report.summary.prompt_count
            findings = report.summary.finding_count
            waived = report.summary.waived_finding_count
            by_severity = report.summary.findings_by_severity
        scans.append(
            ValidationSessionScanSummary(
                index=index,
                status=report.status,
                generated_at=report.generated_at,
                report_sha256=recorded.report_sha256,
                tool_count=tools,
                resource_count=resources,
                prompt_count=prompts,
                finding_count=findings,
                waived_finding_count=waived,
                findings_by_severity=by_severity,
                recorded_error_count=len(report.errors),
            )
        )

    impact_counts = {impact.value: 0 for impact in ContractImpact}
    if len(completed.reports) == 2 and all(
        report.status != ScanStatus.ERROR for report in completed.reports
    ):
        difference = diff_scan_reports(completed.reports[0], completed.reports[1])
        impact_counts = difference.summary.changes_by_impact
        comparison_result: Literal["stable", "changed", "unavailable"] = (
            "stable" if difference.summary.change_count == 0 else "changed"
        )
        change_count = difference.summary.change_count
    else:
        comparison_result = "unavailable"
        change_count = 0
    comparison = ValidationSessionComparisonSummary(
        result=comparison_result,
        change_count=change_count,
        changes_by_impact=impact_counts,
    )
    manifest = completed.manifest
    return ValidationSessionSummary(
        generated_at=current,
        recorded_status=manifest.status,
        session_manifest_sha256=completed.manifest_sha256,
        target_sha256=manifest.target_sha256,
        planned_scan_count=manifest.planned_scan_count,
        completed_scan_count=manifest.completed_scan_count,
        stopped_early=manifest.stopped_early,
        scans=scans,
        comparison=comparison,
    )


def write_validation_session_summary(
    workspace: Path,
    destination: Path | None = None,
    *,
    summarized_at: datetime | None = None,
) -> tuple[ValidationSessionSummary, Path]:
    """Write a new minimized summary without replacing an existing evidence file."""

    summary = summarize_validation_session(workspace, summarized_at=summarized_at)
    output = destination or workspace / SESSION_SUMMARY_NAME
    write_new_evidence_file(output, summary.model_dump_json(indent=2))
    return summary, output


async def run_validation_session(
    workspace: Path,
    *,
    scanner: Scanner | None = None,
    started_at: datetime | None = None,
) -> ValidationSessionResult:
    """Run one or two sequential metadata scans from an approved local record, without retries."""

    current = started_at or _now()
    plan = inspect_validation_session(workspace, inspected_at=current)
    execute_scan = scanner or scan_mcp_url
    reports: list[ScanReport] = []
    scans: list[ValidationSessionScan] = []
    for index in range(1, plan.authorization.max_discovery_scans + 1):
        report = await execute_scan(
            plan.authorization.target_url,
            failure_threshold=plan.policy.scan_fail_on,
            policy=target_policy(plan.policy),
            applied_policy=plan.policy,
            authentication=None,
        )
        if report.target != plan.authorization.target_url:
            raise ValidationSessionError("Scanner returned evidence for an unexpected target.")
        if report.status != ScanStatus.ERROR:
            graph = validate_scan_contract(report, "validation")
            if graph.target != plan.authorization.target_url:
                raise ValidationSessionError(
                    "Scanner returned a capability graph for an unexpected target."
                )
        report_file = f"scan-{index:02}.json"
        content = report.model_dump_json(indent=2)
        write_new_evidence_file(plan.workspace / report_file, content)
        reports.append(report)
        scans.append(
            ValidationSessionScan(
                index=index,
                status=report.status,
                scan_id=report.scan_id,
                generated_at=report.generated_at,
                report_file=report_file,
                report_sha256=sha256((content + "\n").encode()).hexdigest(),
            )
        )
        if report.status == ScanStatus.ERROR:
            break

    status = (
        ScanStatus.ERROR
        if any(scan.status == ScanStatus.ERROR for scan in scans)
        else ScanStatus.FAILED
        if any(scan.status == ScanStatus.FAILED for scan in scans)
        else ScanStatus.PASSED
    )
    if plan.authorization.expires_at is None:
        raise ValidationSessionError("Authorization record is incomplete.")
    manifest = ValidationSessionManifest(
        generated_at=current,
        status=status,
        target_alias=plan.authorization.target_alias,
        target_sha256=sha256(plan.authorization.target_url.encode()).hexdigest(),
        authorization_sha256=plan.authorization_sha256,
        authorization_expires_at=plan.authorization.expires_at,
        workspace_manifest_sha256=plan.workspace_manifest_sha256,
        policy_source_sha256=plan.policy.source_sha256,
        planned_scan_count=plan.authorization.max_discovery_scans,
        completed_scan_count=len(scans),
        stopped_early=len(scans) < plan.authorization.max_discovery_scans,
        scans=scans,
    )
    write_new_evidence_file(
        plan.workspace / SESSION_MANIFEST_NAME,
        manifest.model_dump_json(indent=2),
    )
    return ValidationSessionResult(manifest=manifest, reports=reports)
