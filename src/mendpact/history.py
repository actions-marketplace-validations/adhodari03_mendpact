"""Local-only minimized evidence history and descriptive comparisons."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from mendpact.domain import BehaviorReport, GuardReport, ScanReport
from mendpact.evidence import EvidenceSummary, load_evidence_source

RETENTION_DAYS = 14
APPLICATION_ID = 0x4D504854
SCHEMA_VERSION = 1
MAX_RECORD_BYTES = 128 * 1024
COMPARISON_NOTICE = (
    "Descriptive comparison of supplied evidence, not a regression gate or safety certificate. "
    "Counts do not identify which findings changed. A different policy can change the verdict "
    "without changing behavior. Missing or incompatible stages have no numeric deltas. "
    "Use guard or compare-models with original reports for CI decisions."
)


class HistoryError(ValueError):
    """Safe-to-display history error that does not echo private inputs."""


class HistoryContext(BaseModel):
    """Private correlation fingerprints; hashes are not anonymization or signatures."""

    model_config = ConfigDict(extra="forbid")

    target: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy: str = Field(pattern=r"^[0-9a-f]{64}$")
    behavior: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    producer: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    contract_baseline: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class HistoryRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["mendpact.history-entry.v1"] = "mendpact.history-entry.v1"
    imported_at: datetime
    evidence: EvidenceSummary
    context: HistoryContext


class HistoryEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: int = Field(ge=1)
    record: HistoryRecord


class HistoryMetricDelta(BaseModel):
    label: str
    reference: int | str | None
    candidate: int | str | None
    delta: int | None = None


class HistoryStageComparison(BaseModel):
    title: str
    reference_status: str
    candidate_status: str
    comparable: bool
    metrics: list[HistoryMetricDelta]


class HistoryComparison(BaseModel):
    schema_version: Literal["mendpact.history-comparison.v1"] = "mendpact.history-comparison.v1"
    reference_id: int
    candidate_id: int
    reference_sha256: str
    candidate_sha256: str
    reference_status: str
    candidate_status: str
    warnings: list[str]
    stages: list[HistoryStageComparison]
    notice: str = COMPARISON_NOTICE


def _fingerprint(value: Any) -> str:
    return sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def _context(report: ScanReport | BehaviorReport | GuardReport) -> HistoryContext:
    behavior = (
        report
        if isinstance(report, BehaviorReport)
        else (report.behavior if isinstance(report, GuardReport) else None)
    )
    policy: dict[str, Any] = {}
    if isinstance(report, ScanReport | GuardReport):
        scan = report.scan if isinstance(report, GuardReport) else report
        policy["scan"] = scan.failure_threshold.value
        policy["snapshot"] = report.policy.model_dump(mode="json") if report.policy else None
        policy["waivers"] = [f.waiver.model_dump(mode="json") for f in scan.findings if f.waiver]
    if isinstance(report, GuardReport) and report.contract_diff:
        policy["contract"] = report.contract_diff.failure_threshold.value
        policy["contract_waivers"] = [
            c.waiver.model_dump(mode="json") for c in report.contract_diff.changes if c.waiver
        ]
    if behavior and behavior.regression:
        policy["regression"] = behavior.regression.thresholds.model_dump(mode="json")
        policy["regression_baseline"] = behavior.regression.baseline_run_id
    context = HistoryContext(target=_fingerprint(report.target), policy=_fingerprint(policy))
    if behavior:
        scenarios = {t.scenario.id: t.scenario.model_dump(mode="json") for t in behavior.trials}
        context.behavior = _fingerprint(
            {
                "suite": behavior.suite_name,
                "scenarios": scenarios,
                "tool_catalog": sorted(behavior.tool_catalog),
                "repetitions": behavior.repetitions,
            }
        )
        context.producer = _fingerprint(
            {
                "driver": behavior.driver,
                "model": behavior.model,
                "resolved_models": sorted({t.trace.model for t in behavior.trials}),
            }
        )
    if isinstance(report, GuardReport) and report.contract_diff:
        context.contract_baseline = _fingerprint(
            {
                "scan_id": report.contract_diff.baseline_scan_id,
                "target": report.contract_diff.baseline_target,
            }
        )
    return context


def _now() -> datetime:
    return datetime.now(UTC)


@contextmanager
def _database(
    path: Path, *, writable: bool = False, create: bool = False
) -> Iterator[sqlite3.Connection]:
    connection: sqlite3.Connection | None = None
    try:
        absolute = path.absolute()
        if any(part.is_symlink() for part in (absolute, *absolute.parents)):
            raise HistoryError("History paths must not contain symlinks.")
        created = False
        if create:
            try:
                descriptor = os.open(absolute, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(descriptor)
                created = True
        info = absolute.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077:
            raise HistoryError("History must be a private regular file (permissions 0600).")
        mode = "rw" if writable else "ro"
        connection = sqlite3.connect(f"{absolute.as_uri()}?mode={mode}", uri=True, timeout=5)
        connection.execute("PRAGMA trusted_schema = OFF")
        if created:
            with connection:
                connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                connection.execute("""CREATE TABLE runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_sha256 TEXT NOT NULL UNIQUE,
                    imported_at TEXT NOT NULL,
                    record_json TEXT NOT NULL
                )""")
                connection.execute("CREATE INDEX runs_imported_at ON runs(imported_at)")
        if (
            connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID
            or connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION
        ):
            raise HistoryError(
                "Not a supported MendPact history database; no migration was attempted."
            )
        if writable:
            connection.execute("PRAGMA secure_delete = ON")
        yield connection
    except HistoryError:
        raise
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise HistoryError(
            "Cannot access history: check the file, permissions, schema, and parent directory."
        ) from exc
    finally:
        if connection is not None:
            connection.close()


def add_history(source: Path, database: Path) -> tuple[HistoryEntry, bool]:
    """Import one validated report, storing only minimized evidence and fingerprints."""

    summary, report = load_evidence_source(source)
    record = HistoryRecord(imported_at=_now(), evidence=summary, context=_context(report))
    content = record.model_dump_json()
    if len(content.encode()) > MAX_RECORD_BYTES:
        raise HistoryError("Minimized history record exceeds the size limit.")
    with _database(database, writable=True, create=True) as connection, connection:
        cursor = connection.execute(
            "INSERT OR IGNORE INTO runs(source_sha256, imported_at, record_json) VALUES (?, ?, ?)",
            (summary.source_sha256, record.imported_at.isoformat(), content),
        )
        added = cursor.rowcount == 1
        row = connection.execute(
            "SELECT id, source_sha256, imported_at, record_json FROM runs WHERE source_sha256 = ?",
            (summary.source_sha256,),
        ).fetchone()
        return _entry(row), added


def _entry(row: tuple[Any, ...] | None) -> HistoryEntry:
    if row is None:
        raise HistoryError("History entry was not found.")
    try:
        identifier, digest, imported_at, raw = row
        if len(raw.encode()) > MAX_RECORD_BYTES:
            raise ValueError("Oversize entry")
        record = HistoryRecord.model_validate_json(raw)
        if (
            record.evidence.source_sha256 != digest
            or record.imported_at.isoformat() != imported_at
            or record.imported_at.utcoffset() != timedelta(0)
        ):
            raise ValueError("Inconsistent entry")
        return HistoryEntry(id=identifier, record=record)
    except (ValueError, TypeError, AttributeError) as exc:
        raise HistoryError(
            "History contains an invalid entry; original reports were not modified."
        ) from exc


def list_history(
    database: Path, *, limit: int = 20, before_id: int | None = None
) -> list[HistoryEntry]:
    """Read a bounded page, newest import first; never create or mutate the store."""

    if not 1 <= limit <= 100 or (before_id is not None and before_id < 1):
        raise HistoryError("Use a limit from 1 to 100 and a positive before-ID.")
    with _database(database) as connection:
        rows = connection.execute(
            "SELECT id, source_sha256, imported_at, record_json FROM runs "
            "WHERE (? IS NULL OR id < ?) ORDER BY id DESC LIMIT ?",
            (before_id, before_id, limit),
        ).fetchall()
        return [_entry(row) for row in rows]


def compare_history(database: Path, reference_id: int, candidate_id: int) -> HistoryComparison:
    """Compare descriptive aggregates, withholding deltas for non-comparable stages."""

    if reference_id < 1 or candidate_id < 1 or reference_id == candidate_id:
        raise HistoryError("Choose two different positive history IDs.")
    with _database(database) as connection:
        # Keep both reads in one snapshot even if another process imports or prunes.
        connection.execute("BEGIN")
        entries = []
        for identifier in (reference_id, candidate_id):
            entries.append(
                _entry(
                    connection.execute(
                        "SELECT id, source_sha256, imported_at, record_json FROM runs WHERE id = ?",
                        (identifier,),
                    ).fetchone()
                )
            )
    left, right = [entry.record for entry in entries]
    if left.context.target != right.context.target:
        raise HistoryError("Cannot compare reports for different targets.")
    if left.evidence.source_schema != right.evidence.source_schema:
        raise HistoryError("Cannot compare different report types.")
    warnings = []
    if left.context.policy != right.context.policy:
        warnings.append("Policy or waiver evidence changed; verdicts may reflect different gates.")
    if left.context.producer != right.context.producer:
        warnings.append(
            "Provider or model identity changed; history does not validate model equivalence."
        )
    if left.context.behavior != right.context.behavior:
        warnings.append("Behavior setup changed; behavior numeric deltas are withheld.")
    if left.context.contract_baseline != right.context.contract_baseline:
        warnings.append("Contract baseline identity changed; contract numeric deltas are withheld.")
    for record in (left, right):
        captured = record.evidence.source_generated_at
        if captured.tzinfo is None:
            warnings.append("Source capture time has no timezone; chronology is not verified.")
            break
    else:
        if right.evidence.source_generated_at < left.evidence.source_generated_at:
            warnings.append(
                "Candidate capture time precedes the reference; order was explicitly chosen."
            )
    stages = []
    for title in ("Capability scan", "Contract comparison", "Behavior evaluation"):
        a = next((s for s in left.evidence.sections if s.title == title), None)
        b = next((s for s in right.evidence.sections if s.title == title), None)
        if a is None and b is None:
            continue
        comparable = bool(
            a
            and b
            and a.status not in ("skipped", "error")
            and b.status not in ("skipped", "error")
        )
        if title == "Behavior evaluation":
            comparable = comparable and left.context.behavior == right.context.behavior
        if title == "Contract comparison":
            comparable = (
                comparable and left.context.contract_baseline == right.context.contract_baseline
            )
        left_metrics = a.metrics if a else {}
        right_metrics = b.metrics if b else {}
        metrics = []
        for label in sorted(left_metrics.keys() | right_metrics.keys()):
            before = left_metrics.get(label)
            after = right_metrics.get(label)
            delta = (
                after - before
                if comparable and isinstance(before, int) and isinstance(after, int)
                else None
            )
            metrics.append(
                HistoryMetricDelta(
                    label=label,
                    reference=before,
                    candidate=after,
                    delta=delta,
                )
            )
        stages.append(
            HistoryStageComparison(
                title=title,
                reference_status=a.status if a else "skipped",
                candidate_status=b.status if b else "skipped",
                comparable=comparable,
                metrics=metrics,
            )
        )
    return HistoryComparison(
        reference_id=reference_id,
        candidate_id=candidate_id,
        reference_sha256=left.evidence.source_sha256,
        candidate_sha256=right.evidence.source_sha256,
        reference_status=left.evidence.recorded_status,
        candidate_status=right.evidence.recorded_status,
        warnings=warnings,
        stages=stages,
    )


def prune_history(database: Path, *, apply: bool = False) -> int:
    """Preview or logically delete entries imported at least 14 days ago."""

    cutoff = (_now() - timedelta(days=RETENTION_DAYS)).isoformat()
    with _database(database, writable=apply) as connection, connection:
        if apply:
            return connection.execute("DELETE FROM runs WHERE imported_at <= ?", (cutoff,)).rowcount
        return int(
            connection.execute(
                "SELECT COUNT(*) FROM runs WHERE imported_at <= ?",
                (cutoff,),
            ).fetchone()[0]
        )
