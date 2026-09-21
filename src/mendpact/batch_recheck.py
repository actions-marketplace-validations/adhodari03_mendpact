"""Bounded offline rechecks for a directory of saved MCP scan reports."""

from __future__ import annotations

import os
import stat
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mendpact import __version__
from mendpact.domain import PolicySnapshot, ScanStatus, Severity
from mendpact.evidence import EvidenceExportError, write_new_evidence_file
from mendpact.recheck import ScanRecheckError, recheck_scan_report

MAX_BATCH_FILES = 100
BATCH_MANIFEST_NAME = "batch-manifest.json"
BATCH_NOTICE = (
    "Offline deterministic recheck of saved capability graphs. No endpoint, authorization "
    "metadata, provider response, or MCP tool execution was refreshed. This operational "
    "manifest is not a privacy-minimized public evidence export."
)


class BatchRecheckError(ValueError):
    """Safe-to-display failure while preparing a batch recheck."""


class BatchRuleDeltaCounts(BaseModel):
    """Aggregate rule changes for one rechecked scan without rule subjects."""

    model_config = ConfigDict(extra="forbid")

    introduced: int = Field(ge=0)
    resolved: int = Field(ge=0)
    reclassified: int = Field(ge=0)
    unchanged: int = Field(ge=0)


class BatchRecheckItem(BaseModel):
    """One bounded batch result, identified without retaining the input filename."""

    model_config = ConfigDict(extra="forbid")

    input_index: int = Field(ge=1)
    status: ScanStatus
    source_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    output_file: str | None = Field(default=None, pattern=r"^recheck-[0-9]{3}\.json$")
    finding_count: int | None = Field(default=None, ge=0)
    rule_delta: BatchRuleDeltaCounts | None = None
    error_code: Literal["invalid_source"] | None = None

    @model_validator(mode="after")
    def validate_result_shape(self) -> BatchRecheckItem:
        if self.status == ScanStatus.ERROR:
            if any(
                value is not None
                for value in (
                    self.source_sha256,
                    self.output_file,
                    self.finding_count,
                    self.rule_delta,
                )
            ) or self.error_code != "invalid_source":
                raise ValueError("batch error items must contain only a safe error code")
        elif (
            self.source_sha256 is None
            or self.output_file is None
            or self.finding_count is None
            or self.rule_delta is None
            or self.error_code is not None
        ):
            raise ValueError("successful batch items require complete recheck evidence")
        return self


class BatchRecheckManifest(BaseModel):
    """Versioned summary for one offline directory recheck."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["mendpact.batch-recheck.v1"] = (
        "mendpact.batch-recheck.v1"
    )
    generated_at: datetime
    mendpact_version: str = Field(min_length=1)
    status: ScanStatus
    failure_threshold: Severity
    policy_source_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    source_count: int = Field(ge=1, le=MAX_BATCH_FILES)
    passed_count: int = Field(ge=0)
    failed_count: int = Field(ge=0)
    error_count: int = Field(ge=0)
    authorization_refreshed: Literal[False] = False
    items: list[BatchRecheckItem] = Field(min_length=1, max_length=MAX_BATCH_FILES)
    notice: str = BATCH_NOTICE

    @model_validator(mode="after")
    def validate_counts_and_status(self) -> BatchRecheckManifest:
        counts = {
            ScanStatus.PASSED: self.passed_count,
            ScanStatus.FAILED: self.failed_count,
            ScanStatus.ERROR: self.error_count,
        }
        if self.source_count != len(self.items):
            raise ValueError("batch source count does not match its items")
        if any(
            sum(item.status == status for item in self.items) != count
            for status, count in counts.items()
        ):
            raise ValueError("batch status counts do not match its items")
        expected_status = (
            ScanStatus.ERROR
            if self.error_count
            else ScanStatus.FAILED
            if self.failed_count
            else ScanStatus.PASSED
        )
        if self.status != expected_status:
            raise ValueError("batch status does not match its item outcomes")
        if [item.input_index for item in self.items] != list(
            range(1, self.source_count + 1)
        ):
            raise ValueError("batch input indexes must be contiguous")
        return self


def _now() -> datetime:
    return datetime.now(UTC)


def discover_scan_reports(directory: Path) -> list[Path]:
    """Return at most 100 direct JSON children in a deterministic order."""

    absolute = directory.absolute()
    try:
        if any(item.is_symlink() for item in (absolute, *absolute.parents)):
            raise BatchRecheckError("Batch source paths must not contain symlinks.")
        if not absolute.is_dir():
            raise BatchRecheckError("Batch source must be an existing directory.")
        candidates = sorted(
            (item for item in absolute.iterdir() if item.suffix.lower() == ".json"),
            key=lambda item: (item.name.casefold(), item.name),
        )
        if not candidates:
            raise BatchRecheckError("Batch source contains no direct JSON files.")
        if len(candidates) > MAX_BATCH_FILES:
            raise BatchRecheckError(
                f"Batch source exceeds the {MAX_BATCH_FILES}-file safety limit."
            )
        if any(
            item.is_symlink() or not stat.S_ISREG(item.stat(follow_symlinks=False).st_mode)
            for item in candidates
        ):
            raise BatchRecheckError("Batch inputs must be regular files, not links or devices.")
        return candidates
    except BatchRecheckError:
        raise
    except OSError as exc:
        raise BatchRecheckError("Batch source directory cannot be read safely.") from exc


def _new_output_directory(destination: Path) -> Path:
    absolute = destination.absolute()
    try:
        if any(item.is_symlink() for item in (absolute, *absolute.parents)):
            raise BatchRecheckError("Batch output paths must not contain symlinks.")
        if absolute.exists() or not absolute.parent.is_dir():
            raise BatchRecheckError(
                "Batch output must be a new directory inside an existing directory."
            )
        os.mkdir(absolute, 0o700)
        return absolute
    except BatchRecheckError:
        raise
    except OSError as exc:
        raise BatchRecheckError(
            "Batch output directory cannot be created without overwriting data."
        ) from exc


def _cleanup_output(directory: Path, created: list[Path]) -> None:
    for path in reversed(created):
        with suppress(OSError):
            path.unlink()
    with suppress(OSError):
        directory.rmdir()


def recheck_scan_directory(
    source_directory: Path,
    output_directory: Path,
    *,
    failure_threshold: Severity = Severity.HIGH,
    policy: PolicySnapshot | None = None,
    generated_at: datetime | None = None,
) -> BatchRecheckManifest:
    """Recheck a bounded directory offline and write a versioned local manifest."""

    sources = discover_scan_reports(source_directory)
    output = _new_output_directory(output_directory)
    created: list[Path] = []
    timestamp = generated_at or _now()
    items: list[BatchRecheckItem] = []
    try:
        for index, source in enumerate(sources, start=1):
            output_name = f"recheck-{index:03}.json"
            try:
                report = recheck_scan_report(
                    source,
                    failure_threshold=failure_threshold,
                    policy=policy,
                    rechecked_at=timestamp,
                )
            except ScanRecheckError:
                items.append(
                    BatchRecheckItem(
                        input_index=index,
                        status=ScanStatus.ERROR,
                        error_code="invalid_source",
                    )
                )
                continue

            destination = output / output_name
            write_new_evidence_file(destination, report.model_dump_json(indent=2))
            created.append(destination)
            if report.recheck is None or report.recheck.rule_delta is None:
                raise BatchRecheckError("Rechecked report is missing required provenance.")
            delta = report.recheck.rule_delta
            items.append(
                BatchRecheckItem(
                    input_index=index,
                    status=report.status,
                    source_sha256=report.recheck.source_sha256,
                    output_file=output_name,
                    finding_count=len(report.findings),
                    rule_delta=BatchRuleDeltaCounts(
                        introduced=delta.introduced_count,
                        resolved=delta.resolved_count,
                        reclassified=delta.reclassified_count,
                        unchanged=delta.unchanged_count,
                    ),
                )
            )

        passed_count = sum(item.status == ScanStatus.PASSED for item in items)
        failed_count = sum(item.status == ScanStatus.FAILED for item in items)
        error_count = sum(item.status == ScanStatus.ERROR for item in items)
        status = (
            ScanStatus.ERROR
            if error_count
            else ScanStatus.FAILED
            if failed_count
            else ScanStatus.PASSED
        )
        manifest = BatchRecheckManifest(
            generated_at=timestamp,
            mendpact_version=__version__,
            status=status,
            failure_threshold=(policy.scan_fail_on if policy is not None else failure_threshold),
            policy_source_sha256=(policy.source_sha256 if policy is not None else None),
            source_count=len(sources),
            passed_count=passed_count,
            failed_count=failed_count,
            error_count=error_count,
            items=items,
        )
        manifest_path = output / BATCH_MANIFEST_NAME
        write_new_evidence_file(manifest_path, manifest.model_dump_json(indent=2))
        created.append(manifest_path)
        return manifest
    except (OSError, EvidenceExportError) as exc:
        _cleanup_output(output, created)
        raise BatchRecheckError(
            "Batch outputs could not be written safely; no completed batch was retained."
        ) from exc
    except Exception:
        _cleanup_output(output, created)
        raise
