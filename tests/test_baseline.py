from __future__ import annotations

from pathlib import Path

import pytest

from mendpact.baseline import (
    BaselineLifecycleError,
    canonical_scan_bytes,
    inspect_scan_baseline,
    promote_scan_baseline,
)
from mendpact.domain import (
    CapabilityEdge,
    CapabilityGraph,
    CapabilityNode,
    Finding,
    NodeKind,
    ScanReport,
    ScanStatus,
    Severity,
)

TARGET = "https://api.example.com/mcp"


def _report(*, status: ScanStatus = ScanStatus.PASSED) -> ScanReport:
    server = CapabilityNode(id="server:fixture", kind=NodeKind.SERVER, name="fixture")
    tool = CapabilityNode(
        id="tool:read_status",
        kind=NodeKind.TOOL,
        name="read_status",
        description="Read service status.",
        input_schema={"type": "object", "additionalProperties": False},
    )
    return ScanReport(
        scan_id="review-this-scan-id",
        target=TARGET,
        status=status,
        failure_threshold=Severity.HIGH,
        findings=(
            [
                Finding(
                    rule_id="MP-TEST-001",
                    severity=Severity.HIGH,
                    title="Reviewed finding",
                    message="The failed scan retains its policy finding.",
                    subject="tool:read_status",
                )
            ]
            if status == ScanStatus.FAILED
            else []
        ),
        graph=CapabilityGraph(
            target=TARGET,
            protocol_version="2026-07-28",
            server_name="fixture",
            nodes=[server, tool],
            edges=[CapabilityEdge(source=server.id, target=tool.id)],
        ),
    )


def _write(path: Path, report: ScanReport, *, indent: int = 2) -> Path:
    path.write_text(report.model_dump_json(indent=indent), encoding="utf-8")
    return path


def test_inspection_has_stable_canonical_digest_and_counts(tmp_path: Path) -> None:
    report = _report()
    compact = inspect_scan_baseline(_write(tmp_path / "compact.json", report, indent=0))
    pretty = inspect_scan_baseline(_write(tmp_path / "pretty.json", report, indent=4))

    assert compact.canonical_sha256 == pretty.canonical_sha256
    assert compact.report.scan_id == "review-this-scan-id"
    assert compact.node_count == 2
    assert compact.tool_count == 1
    assert compact.resource_count == 0
    assert compact.prompt_count == 0
    assert compact.requires_failed_scan_acceptance is False


def test_inspection_rejects_error_or_incomplete_scan(tmp_path: Path) -> None:
    report = ScanReport(
        target=TARGET,
        status=ScanStatus.ERROR,
        failure_threshold=Severity.HIGH,
        errors=["discovery failed"],
    )

    with pytest.raises(BaselineLifecycleError, match="complete capability graph"):
        inspect_scan_baseline(_write(tmp_path / "error.json", report))


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("target", "target does not match"),
        ("protocol", "MCP capability graph"),
        ("server", "exactly one server"),
        ("duplicate_node", "duplicate capability node IDs"),
        ("dangling_edge", "dangling capability edge"),
        ("status", "status is inconsistent"),
    ],
)
def test_inspection_rejects_malformed_contract_graph(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    report = _report()
    assert report.graph is not None
    if mutation == "target":
        report.graph.target = "https://different.example.com/mcp"
    elif mutation == "protocol":
        report.graph.protocol = "other"
    elif mutation == "server":
        report.graph.nodes = [
            node for node in report.graph.nodes if node.kind != NodeKind.SERVER
        ]
        report.graph.edges = []
    elif mutation == "duplicate_node":
        report.graph.nodes.append(report.graph.nodes[-1].model_copy())
    elif mutation == "status":
        report.status = ScanStatus.FAILED
    else:
        report.graph.edges.append(
            CapabilityEdge(source="server:fixture", target="tool:missing")
        )

    with pytest.raises(BaselineLifecycleError, match=message):
        inspect_scan_baseline(_write(tmp_path / f"{mutation}.json", report))


def test_promotion_requires_exact_scan_id_and_expected_target(tmp_path: Path) -> None:
    candidate = _write(tmp_path / "candidate.json", _report())
    destination = tmp_path / "baseline.json"

    with pytest.raises(BaselineLifecycleError, match="does not match the candidate scan ID"):
        promote_scan_baseline(
            candidate,
            destination,
            accepted_scan_id="different-scan",
        )
    with pytest.raises(BaselineLifecycleError, match="does not exactly match"):
        promote_scan_baseline(
            candidate,
            destination,
            accepted_scan_id="review-this-scan-id",
            expected_target="https://staging.example.com/mcp",
        )

    assert not destination.exists()


def test_promotion_writes_canonical_validated_baseline(tmp_path: Path) -> None:
    report = _report()
    candidate = _write(tmp_path / "candidate.json", report, indent=4)
    destination = tmp_path / "baseline.json"

    promoted = promote_scan_baseline(
        candidate,
        destination,
        accepted_scan_id=report.scan_id,
        expected_target=TARGET,
    )

    assert destination.read_bytes() == canonical_scan_bytes(report)
    assert promoted.canonical_sha256 == inspect_scan_baseline(candidate).canonical_sha256


def test_failed_scan_requires_separate_explicit_acceptance(tmp_path: Path) -> None:
    report = _report(status=ScanStatus.FAILED)
    candidate = _write(tmp_path / "candidate.json", report)
    destination = tmp_path / "baseline.json"

    with pytest.raises(BaselineLifecycleError, match="--accept-failed-scan"):
        promote_scan_baseline(
            candidate,
            destination,
            accepted_scan_id=report.scan_id,
        )

    promoted = promote_scan_baseline(
        candidate,
        destination,
        accepted_scan_id=report.scan_id,
        accept_failed_scan=True,
    )

    assert promoted.report.status == ScanStatus.FAILED


def test_existing_baseline_requires_explicit_replace(tmp_path: Path) -> None:
    report = _report()
    candidate = _write(tmp_path / "candidate.json", report)
    destination = tmp_path / "baseline.json"
    destination.write_text("existing baseline\n", encoding="utf-8")

    with pytest.raises(BaselineLifecycleError, match="--replace"):
        promote_scan_baseline(
            candidate,
            destination,
            accepted_scan_id=report.scan_id,
        )

    promote_scan_baseline(
        candidate,
        destination,
        accepted_scan_id=report.scan_id,
        replace=True,
    )
    assert destination.read_bytes() == canonical_scan_bytes(report)


def test_promotion_refuses_symlink_destination(tmp_path: Path) -> None:
    report = _report()
    candidate = _write(tmp_path / "candidate.json", report)
    outside = tmp_path / "outside.json"
    outside.write_text("do not replace\n", encoding="utf-8")
    destination = tmp_path / "baseline.json"
    destination.symlink_to(outside)

    with pytest.raises(BaselineLifecycleError, match="Refusing to replace symlink"):
        promote_scan_baseline(
            candidate,
            destination,
            accepted_scan_id=report.scan_id,
            replace=True,
        )

    assert outside.read_text(encoding="utf-8") == "do not replace\n"


def test_promotion_requires_an_existing_real_destination_directory(
    tmp_path: Path,
) -> None:
    report = _report()
    candidate = _write(tmp_path / "candidate.json", report)

    with pytest.raises(BaselineLifecycleError, match="directory does not exist"):
        promote_scan_baseline(
            candidate,
            tmp_path / "missing" / "baseline.json",
            accepted_scan_id=report.scan_id,
        )
