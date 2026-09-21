"""Offline, allowlisted evidence summaries; never publish the input report."""

from __future__ import annotations

import json
import math
import os
import stat
import tempfile
from datetime import datetime
from hashlib import sha256
from html import escape
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mendpact.contract_diff import validate_scan_contract
from mendpact.domain import (
    BehaviorReport,
    ContractDiffReport,
    ContractImpact,
    GuardReport,
    NodeKind,
    ScanReport,
    ScanStatus,
    Severity,
)
from mendpact.model_comparison import validate_behavior_report

MAX_REPORT_BYTES = 10 * 1024 * 1024
NOTICE = (
    "This is an unsigned summary of supplied evidence, not a safety certification or proof "
    "of a live API call. Passed means the recorded policy passed, not that no risks exist. "
    "Skipped stages provide no evidence. Review the original report privately."
)
PRIVACY = (
    "Targets, names and identifiers, prompts, arguments, tool descriptions, raw errors, "
    "provider metadata, and waiver identities are omitted. Counts, policy thresholds, "
    "the source timestamp and its SHA-256 remain. Review these before sharing."
)


class EvidenceExportError(ValueError):
    """A safe-to-display export failure without source report values."""


class EvidenceSection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: Literal["Capability scan", "Contract comparison", "Behavior evaluation"]
    status: ScanStatus | Literal["skipped"]
    metrics: dict[str, int | str] = Field(default_factory=dict)


class EvidenceSummary(BaseModel):
    """Public projection built only from explicitly selected aggregate fields."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["mendpact.evidence.v1", "mendpact.evidence.v2"] = (
        "mendpact.evidence.v1"
    )
    source_schema: Literal["mendpact.scan.v1", "mendpact.behavior.v1", "mendpact.guard.v1"]
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_generated_at: datetime
    recorded_status: ScanStatus
    sections: list[EvidenceSection]
    notice: str = NOTICE
    privacy: str = PRIVACY


def _assert(condition: bool) -> None:
    if not condition:
        raise EvidenceExportError("Report evidence is incomplete or internally inconsistent.")


def _scan_section(report: ScanReport) -> EvidenceSection:
    _assert(report.schema_version == "mendpact.scan.v1")
    if report.status != ScanStatus.ERROR:
        graph = validate_scan_contract(report, "source")
        _assert(graph.target == report.target and graph.protocol == "mcp")
        _assert(len(graph.nodes_of_kind(NodeKind.SERVER)) == 1)
        failed = any(
            f.waiver is None and f.severity.rank >= report.failure_threshold.rank
            for f in report.findings
        )
        _assert(report.status == (ScanStatus.FAILED if failed else ScanStatus.PASSED))
    metrics: dict[str, int | str] = {
        "Evidence mode": (
            "Offline deterministic recheck"
            if report.recheck is not None
            else "Live metadata capture"
        ),
        "Fails on severity": report.failure_threshold.value,
        "Findings": len(report.findings),
        "Waived findings": sum(f.waiver is not None for f in report.findings),
        "Recorded errors (details withheld)": len(report.errors),
    }
    for severity in Severity:
        metrics[f"{severity.value.title()} findings"] = sum(
            f.severity == severity for f in report.findings
        )
    if report.graph is not None:
        metrics.update({
            "Tools": len(report.graph.nodes_of_kind(NodeKind.TOOL)),
            "Resources": len(report.graph.nodes_of_kind(NodeKind.RESOURCE))
            + len(report.graph.nodes_of_kind(NodeKind.RESOURCE_TEMPLATE)),
            "Prompts": len(report.graph.nodes_of_kind(NodeKind.PROMPT)),
        })
    if report.recheck is not None and report.recheck.rule_delta is not None:
        delta = report.recheck.rule_delta
        metrics.update({
            "Introduced findings": delta.introduced_count,
            "Resolved findings": delta.resolved_count,
            "Reclassified findings": delta.reclassified_count,
            "Unchanged findings": delta.unchanged_count,
        })
    return EvidenceSection(title="Capability scan", status=report.status, metrics=metrics)


def _behavior_section(report: BehaviorReport) -> EvidenceSection:
    if report.status != ScanStatus.ERROR:
        validate_behavior_report(report, "source")
        failed = any(not trial.grade.passed for trial in report.trials)
        if report.regression:
            failed = failed or report.regression.status != ScanStatus.PASSED
        _assert(report.status == (ScanStatus.FAILED if failed else ScanStatus.PASSED))
    trials = len(report.trials)
    passed = sum(trial.grade.passed for trial in report.trials)
    metrics: dict[str, int | str] = {
        "Evidence mode": "Recorded replay" if report.driver == "replay"
        else "Provider-labelled traces (not authenticated)",
        "Scenarios with trials": len({trial.scenario.id for trial in report.trials}),
        "Recorded trials": trials,
        "Passed trials": passed,
        "Failed trials": trials - passed,
        "Pass rate": f"{passed / trials:.1%}" if trials else "Not measured",
        "Recorded errors (details withheld)": len(report.errors),
    }
    if report.regression:
        metrics["Regression gate"] = report.regression.status.value
    return EvidenceSection(title="Behavior evaluation", status=report.status, metrics=metrics)


def _contract_section(report: ContractDiffReport) -> EvidenceSection:
    if report.status != ScanStatus.ERROR:
        _assert(not report.errors)
        failed = any(
            c.waiver is None and c.impact.rank >= report.failure_threshold.rank
            for c in report.changes
        )
        _assert(report.status == (ScanStatus.FAILED if failed else ScanStatus.PASSED))
    metrics: dict[str, int | str] = {
        "Fails on impact": report.failure_threshold.value,
        "Changes": len(report.changes),
        "Waived changes": sum(c.waiver is not None for c in report.changes),
        "Affected scenarios": len({s for c in report.changes for s in c.affected_scenarios}),
    }
    for impact in ContractImpact:
        metrics[f"{impact.value.title()} changes"] = sum(
            c.impact == impact for c in report.changes
        )
    return EvidenceSection(title="Contract comparison", status=report.status, metrics=metrics)


def _guard_sections(report: GuardReport) -> list[EvidenceSection]:
    _assert(report.target == report.scan.target)
    _assert(report.summary.scan_status == report.scan.status)
    sections = [_scan_section(report.scan)]
    if report.contract_diff:
        _assert(report.contract_diff.candidate_target == report.target)
        _assert(report.contract_diff.candidate_scan_id == report.scan.scan_id)
        _assert(report.summary.contract_status == report.contract_diff.status)
        sections.append(_contract_section(report.contract_diff))
    else:
        _assert(report.summary.contract_status is None)
        sections.append(EvidenceSection(title="Contract comparison", status="skipped"))
    if report.behavior:
        _assert(report.behavior.target == report.target)
        _assert(report.summary.behavior_status == report.behavior.status)
        sections.append(_behavior_section(report.behavior))
    elif report.summary.behavior_status == ScanStatus.ERROR:
        _assert(report.status == ScanStatus.ERROR)
        sections.append(EvidenceSection(title="Behavior evaluation", status=ScanStatus.ERROR))
    else:
        _assert(report.summary.behavior_status is None)
        sections.append(EvidenceSection(title="Behavior evaluation", status="skipped"))
    statuses = {section.status for section in sections}
    expected = (
        ScanStatus.ERROR if report.errors or ScanStatus.ERROR in statuses
        else ScanStatus.FAILED if ScanStatus.FAILED in statuses else ScanStatus.PASSED
    )
    _assert(report.status == expected)
    return sections


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceExportError("Duplicate JSON keys are not supported.")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise EvidenceExportError("Non-finite JSON numbers are not supported.")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise EvidenceExportError("Non-finite JSON numbers are not supported.")
    return number


def load_evidence_summary(source: Path) -> EvidenceSummary:
    """Load a minimized summary while keeping the source report transient."""

    return load_evidence_source(source)[0]


def load_evidence_source(
    source: Path,
) -> tuple[EvidenceSummary, ScanReport | BehaviorReport | GuardReport]:
    """Read a bounded regular file once; never resolve target URLs or load secrets."""

    try:
        descriptor = os.open(source, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            _assert(stat.S_ISREG(os.fstat(stream.fileno()).st_mode))
            raw = stream.read(MAX_REPORT_BYTES + 1)
        if len(raw) > MAX_REPORT_BYTES:
            raise EvidenceExportError("Source report exceeds the 10 MiB export limit.")
        payload = json.loads(
            raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
        _assert(isinstance(payload, dict))
        _assert(all(key in payload for key in ("schema_version", "generated_at", "status")))
        schema = payload["schema_version"]
        report: ScanReport | BehaviorReport | GuardReport
        if schema == "mendpact.scan.v1":
            report = ScanReport.model_validate(payload)
            sections = [_scan_section(report)]
        elif schema == "mendpact.behavior.v1":
            report = BehaviorReport.model_validate(payload)
            sections = [_behavior_section(report)]
        elif schema == "mendpact.guard.v1":
            _assert(isinstance(payload.get("scan"), dict))
            _assert(payload["scan"].get("schema_version") == "mendpact.scan.v1")
            report = GuardReport.model_validate(payload)
            sections = _guard_sections(report)
        else:
            raise EvidenceExportError("Supported sources are scan.v1, behavior.v1 and guard.v1.")
        summary = EvidenceSummary(
            schema_version=(
                "mendpact.evidence.v2"
                if schema in {"mendpact.scan.v1", "mendpact.guard.v1"}
                else "mendpact.evidence.v1"
            ),
            source_schema=schema,
            source_sha256=sha256(raw).hexdigest(),
            source_generated_at=report.generated_at,
            recorded_status=report.status,
            sections=sections,
        )
        return summary, report
    except EvidenceExportError:
        raise
    except (OSError, ValueError, ValidationError, RecursionError) as exc:
        # Pydantic errors and filesystem paths can include private input values.
        raise EvidenceExportError("Cannot export: source is unreadable or invalid.") from exc


def render_evidence_html(summary: EvidenceSummary) -> str:
    """A self-contained, script-free report with no raw source data or external assets."""

    cards = []
    for section in summary.sections:
        rows = "".join(
            f"<tr><th scope='row'>{escape(label)}</th><td>{escape(str(value))}</td></tr>"
            for label, value in section.metrics.items()
        )
        body = f"<table><tbody>{rows}</tbody></table>" if rows else "<p>No evidence recorded.</p>"
        cards.append(
            f"<section><h2>{escape(section.title)}</h2>"
            f"<p class='status {escape(section.status)}'>{escape(section.status.upper())}</p>"
            f"{body}</section>"
        )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';
base-uri 'none'; form-action 'none'">
<title>MendPact evidence summary</title>
<style>
*{{box-sizing:border-box}}body{{margin:0;background:#f3f4ef;color:#182b25;
font:16px/1.6 system-ui,sans-serif}}main{{max-width:1000px;margin:auto;padding:40px 24px}}
h1{{font-size:clamp(2rem,6vw,3.4rem);line-height:1.1;margin:12px 0 24px}}
h2{{font-size:1.2rem;margin-top:0}}.eyebrow{{letter-spacing:.16em;font-size:.8rem}}
.notice{{background:#e4e9df;padding:20px;border-left:4px solid #314b3d}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,270px),1fr));
gap:20px;margin:28px 0}}section{{background:white;border:1px solid #cbd2c8;padding:22px;
border-radius:12px}}table{{width:100%;border-collapse:collapse;font-size:.9rem}}
th,td{{padding:10px 0;border-bottom:1px solid #e4e9df;text-align:left;vertical-align:top}}
th{{font-weight:500;padding-right:16px}}td{{text-align:right}}.status{{font-weight:700}}
.passed{{color:#236037}}.failed,.error{{color:#9c2525}}.skipped{{color:#5f6265}}
code{{overflow-wrap:anywhere;font-size:.85rem}}footer{{font-size:.85rem}}
@media print{{body{{background:white}}main{{padding:0}}section{{break-inside:avoid}}}}
</style></head><body><main>
<header><p class="eyebrow">MENDPACT / EVIDENCE SUMMARY</p>
<h1>Reliability evidence,<br>ready for review.</h1>
<p>Recorded result: <strong>{escape(summary.recorded_status.upper())}</strong></p>
<p>Source captured: {escape(summary.source_generated_at.isoformat())}</p></header>
<aside class="notice">{escape(summary.notice)}</aside>
<div class="grid">{''.join(cards)}</div>
<footer><h2>Sharing boundary</h2><p>{escape(summary.privacy)}</p>
<p>Summary schema: <code>{escape(summary.schema_version)}</code><br>
Source schema: <code>{escape(summary.source_schema)}</code></p>
<p>Original file SHA-256:<br><code>{escape(summary.source_sha256)}</code></p>
<p>The hash identifies the exact input bytes, including formatting. It is not a signature.</p>
</footer></main></body></html>
"""


def export_evidence(source: Path, destination: Path, *, format: Literal["html", "json"]) -> None:
    """Publish one local file atomically without overwriting any existing path."""

    summary = load_evidence_summary(source)
    content = (
        render_evidence_html(summary) if format == "html" else summary.model_dump_json(indent=2)
    )
    write_new_evidence_file(destination, content)


def write_new_evidence_file(destination: Path, content: str) -> None:
    """Write a completed evidence artifact atomically without replacing existing files."""

    write_new_evidence_bytes(destination, (content + "\n").encode("utf-8"))


def write_new_evidence_bytes(destination: Path, content: bytes) -> None:
    """Atomically create a local evidence file, including binary review bundles."""

    parent = destination.absolute().parent
    if any(path.is_symlink() for path in (parent, *parent.parents)):
        raise EvidenceExportError("Output directory must not contain symlinks.")
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=".mendpact-evidence-", dir=parent)
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        # A hard link atomically creates the destination and fails if it already exists.
        os.link(temporary, destination)
    except OSError as exc:
        raise EvidenceExportError(
            "Cannot write export: use a new output filename in an existing writable directory."
        ) from exc
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)
