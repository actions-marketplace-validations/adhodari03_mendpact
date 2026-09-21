"""Review and promotion lifecycle for MCP contract scan baselines."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from mendpact.contract_diff import load_scan_report, validate_scan_contract
from mendpact.domain import NodeKind, ScanReport, ScanStatus


class BaselineLifecycleError(ValueError):
    """Raised when a scan cannot be inspected or promoted safely."""


@dataclass(frozen=True)
class BaselineInspection:
    """Validated identity and capability counts for one scan artifact."""

    report: ScanReport
    canonical_sha256: str
    node_count: int
    tool_count: int
    resource_count: int
    prompt_count: int

    @property
    def requires_failed_scan_acceptance(self) -> bool:
        return self.report.status == ScanStatus.FAILED


def canonical_scan_bytes(report: ScanReport) -> bytes:
    """Serialize one scan deterministically for review and promotion."""

    return (report.model_dump_json(indent=2) + "\n").encode("utf-8")


def inspect_scan_baseline(path: Path, *, label: str = "baseline") -> BaselineInspection:
    """Load and structurally validate one contract baseline candidate."""

    try:
        report = load_scan_report(path)
        graph = validate_scan_contract(report, label)
    except (OSError, ValueError) as exc:
        raise BaselineLifecycleError(str(exc)) from exc

    if graph.target != report.target:
        raise BaselineLifecycleError(
            f"The {label} scan target does not match its capability graph target."
        )
    if graph.protocol != "mcp":
        raise BaselineLifecycleError(
            f"The {label} scan must contain an MCP capability graph."
        )
    if len(graph.nodes_of_kind(NodeKind.SERVER)) != 1:
        raise BaselineLifecycleError(f"The {label} scan must contain exactly one server node.")
    threshold_failed = any(
        finding.waiver is None
        and finding.severity.rank >= report.failure_threshold.rank
        for finding in report.findings
    )
    expected_status = ScanStatus.FAILED if threshold_failed else ScanStatus.PASSED
    if report.status != expected_status:
        raise BaselineLifecycleError(
            f"The {label} scan status is inconsistent with its findings and failure threshold."
        )

    canonical = canonical_scan_bytes(report)
    return BaselineInspection(
        report=report,
        canonical_sha256=sha256(canonical).hexdigest(),
        node_count=len(graph.nodes),
        tool_count=len(graph.nodes_of_kind(NodeKind.TOOL)),
        resource_count=len(graph.nodes_of_kind(NodeKind.RESOURCE))
        + len(graph.nodes_of_kind(NodeKind.RESOURCE_TEMPLATE)),
        prompt_count=len(graph.nodes_of_kind(NodeKind.PROMPT)),
    )


def _validate_promotion_destination(
    candidate: Path,
    destination: Path,
    *,
    replace: bool,
) -> None:
    if candidate.resolve() == destination.resolve():
        raise BaselineLifecycleError("Candidate and baseline destination must be different files.")
    if not destination.parent.exists():
        raise BaselineLifecycleError(
            f"Baseline destination directory does not exist: {destination.parent}"
        )
    if not destination.parent.is_dir():
        raise BaselineLifecycleError(
            f"Baseline destination parent is not a directory: {destination.parent}"
        )
    if destination.parent.is_symlink():
        raise BaselineLifecycleError(
            f"Refusing to promote through a symlink directory: {destination.parent}"
        )
    if destination.is_symlink():
        raise BaselineLifecycleError(f"Refusing to replace symlink: {destination}")
    if destination.exists() and not destination.is_file():
        raise BaselineLifecycleError(f"Baseline destination is not a file: {destination}")
    if destination.exists() and not replace:
        raise BaselineLifecycleError(
            f"Baseline already exists: {destination}. Rerun with --replace after review."
        )


def _atomic_write(destination: Path, content: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o644)
        os.replace(temporary, destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def promote_scan_baseline(
    candidate: Path,
    destination: Path,
    *,
    accepted_scan_id: str,
    expected_target: str | None = None,
    accept_failed_scan: bool = False,
    replace: bool = False,
) -> BaselineInspection:
    """Promote an exactly acknowledged complete scan to a contract baseline."""

    inspection = inspect_scan_baseline(candidate, label="candidate")
    report = inspection.report
    if accepted_scan_id != report.scan_id:
        raise BaselineLifecycleError(
            "--accept-scan-id does not match the candidate scan ID. "
            f"Expected {report.scan_id}."
        )
    if expected_target is not None and expected_target != report.target:
        raise BaselineLifecycleError(
            "--expected-target does not exactly match the candidate target."
        )
    if report.status == ScanStatus.FAILED and not accept_failed_scan:
        raise BaselineLifecycleError(
            "The candidate scan failed its policy threshold. Review its findings and rerun with "
            "--accept-failed-scan only when that result is deliberately approved."
        )

    _validate_promotion_destination(candidate, destination, replace=replace)
    try:
        _atomic_write(destination, canonical_scan_bytes(report))
        promoted = inspect_scan_baseline(destination)
    except OSError as exc:
        raise BaselineLifecycleError(f"Could not write baseline: {exc}") from exc
    if promoted.canonical_sha256 != inspection.canonical_sha256:
        raise BaselineLifecycleError("Promoted baseline digest did not match the candidate.")
    return promoted
