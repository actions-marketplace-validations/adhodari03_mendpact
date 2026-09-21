import socket
from datetime import UTC, date, datetime
from hashlib import sha256
from pathlib import Path
from unittest.mock import Mock

import pytest

from mendpact.domain import (
    CapabilityGraph,
    CapabilityNode,
    Finding,
    NodeKind,
    RuleFindingChange,
    RuleFindingChangeKind,
    ScanRecheckEvidence,
    ScanReport,
    ScanRuleDelta,
    ScanStatus,
    Severity,
    summarize,
)
from mendpact.policy import load_policy
from mendpact.recheck import ScanRecheckError, compare_rule_findings, recheck_scan_report

TARGET = "https://example.com/mcp"
NOW = datetime(2026, 9, 8, 12, tzinfo=UTC)


def source_report() -> ScanReport:
    graph = CapabilityGraph(
        target=TARGET,
        protocol_version="2026-07-28",
        nodes=[
            CapabilityNode(id="server:mcp", kind=NodeKind.SERVER, name="mcp"),
            CapabilityNode(
                id="tool:execute",
                kind=NodeKind.TOOL,
                name="execute",
                description="Execute supplied JavaScript with an API client.",
                input_schema={
                    "type": "object",
                    "properties": {"code": {"type": "string"}},
                    "required": ["code"],
                    "additionalProperties": False,
                },
            ),
        ],
    )
    old = Finding(
        rule_id="MP-OLD-001",
        severity=Severity.LOW,
        title="Old rule",
        message="This deterministic finding should be replaced.",
    )
    authorization = Finding(
        rule_id="MP-AUTH-007",
        severity=Severity.MEDIUM,
        title="Authorization metadata warning",
        message="Network-derived evidence must remain visible but unrefreshed.",
    )
    findings = [old, authorization]
    return ScanReport(
        scan_id="source-scan",
        generated_at=datetime(2026, 9, 7, 12, tzinfo=UTC),
        target=TARGET,
        status=ScanStatus.PASSED,
        failure_threshold=Severity.HIGH,
        graph=graph,
        findings=findings,
        summary=summarize(graph, findings),
    )


def write_source(path: Path, report: ScanReport | None = None) -> bytes:
    raw = (report or source_report()).model_dump_json(indent=2).encode()
    path.write_bytes(raw)
    return raw


def test_rechecks_current_rules_with_exact_source_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.json"
    raw = write_source(source)
    before = source.read_bytes()
    monkeypatch.setattr(socket, "socket", Mock(side_effect=AssertionError("network forbidden")))

    result = recheck_scan_report(source, rechecked_at=NOW)

    assert source.read_bytes() == before
    assert result.scan_id == "source-scan"
    assert result.generated_at == datetime(2026, 9, 7, 12, tzinfo=UTC)
    assert result.status == ScanStatus.FAILED
    assert [finding.rule_id for finding in result.findings] == [
        "MP-MCP-007",
        "MP-AUTH-007",
    ]
    assert result.summary is not None
    assert result.summary.finding_count == 2
    assert result.recheck == ScanRecheckEvidence(
        source_sha256=sha256(raw).hexdigest(),
        rechecked_at=NOW,
        mendpact_version="0.2.0",
        source_status=ScanStatus.PASSED,
        preserved_authorization_finding_count=1,
        rule_delta=ScanRuleDelta(
            introduced_count=1,
            resolved_count=1,
            reclassified_count=0,
            unchanged_count=0,
            changes=[
                RuleFindingChange(
                    kind=RuleFindingChangeKind.INTRODUCED,
                    rule_id="MP-MCP-007",
                    subject="tool:execute",
                    after_severity=Severity.CRITICAL,
                ),
                RuleFindingChange(
                    kind=RuleFindingChangeKind.RESOLVED,
                    rule_id="MP-OLD-001",
                    before_severity=Severity.LOW,
                ),
            ],
        ),
    )


def test_compares_introduced_resolved_reclassified_and_unchanged_findings() -> None:
    previous = [
        Finding(rule_id="MP-A", severity=Severity.LOW, title="A", message="A"),
        Finding(rule_id="MP-B", severity=Severity.HIGH, title="B", message="B"),
        Finding(rule_id="MP-C", severity=Severity.MEDIUM, title="C", message="C"),
        Finding(rule_id="MP-C", severity=Severity.LOW, title="C duplicate", message="C"),
    ]
    current = [
        Finding(rule_id="MP-B", severity=Severity.CRITICAL, title="B", message="B"),
        Finding(rule_id="MP-C", severity=Severity.MEDIUM, title="C", message="C"),
        Finding(rule_id="MP-D", severity=Severity.HIGH, title="D", message="D"),
    ]

    delta = compare_rule_findings(previous, current)

    assert delta.introduced_count == 1
    assert delta.resolved_count == 1
    assert delta.reclassified_count == 1
    assert delta.unchanged_count == 1
    assert [(change.rule_id, change.kind) for change in delta.changes] == [
        ("MP-A", RuleFindingChangeKind.RESOLVED),
        ("MP-B", RuleFindingChangeKind.RECLASSIFIED),
        ("MP-D", RuleFindingChangeKind.INTRODUCED),
    ]
    assert delta.changes[1].before_severity == Severity.HIGH
    assert delta.changes[1].after_severity == Severity.CRITICAL


def test_scan_recheck_v1_without_rule_delta_remains_readable() -> None:
    evidence = ScanRecheckEvidence(
        source_sha256="0" * 64,
        mendpact_version="0.2.0",
        source_status=ScanStatus.PASSED,
        preserved_authorization_finding_count=0,
    )

    assert evidence.rule_delta is None


def test_rule_change_rejects_an_invalid_severity_transition() -> None:
    with pytest.raises(ValueError, match="invalid severity transition"):
        RuleFindingChange(
            kind=RuleFindingChangeKind.INTRODUCED,
            rule_id="MP-MCP-007",
            before_severity=Severity.LOW,
            after_severity=Severity.CRITICAL,
        )


def test_rule_delta_rejects_counts_that_do_not_match_changes() -> None:
    with pytest.raises(ValueError, match="counts do not match"):
        ScanRuleDelta(
            introduced_count=1,
            resolved_count=0,
            reclassified_count=0,
            unchanged_count=0,
        )


def test_rule_delta_rejects_duplicate_rule_subject_changes() -> None:
    change = RuleFindingChange(
        kind=RuleFindingChangeKind.INTRODUCED,
        rule_id="MP-MCP-007",
        subject="tool:execute",
        after_severity=Severity.CRITICAL,
    )

    with pytest.raises(ValueError, match="duplicate rule and subject"):
        ScanRuleDelta(
            introduced_count=2,
            resolved_count=0,
            reclassified_count=0,
            unchanged_count=0,
            changes=[change, change],
        )


def test_recheck_can_use_a_different_threshold(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    report = source_report()
    assert report.graph is not None
    report.graph.nodes = [report.graph.nodes[0]]
    report.findings = []
    report.summary = summarize(report.graph, [])
    write_source(source, report)

    result = recheck_scan_report(source, failure_threshold=Severity.CRITICAL, rechecked_at=NOW)

    assert result.status == ScanStatus.PASSED
    assert result.failure_threshold == Severity.CRITICAL
    assert result.policy is None


def test_recheck_applies_current_policy_threshold_and_waiver(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    report = source_report()
    assert report.graph is not None
    report.graph.nodes[1].id = "tool:delete_project"
    report.graph.nodes[1].name = "delete_project"
    report.graph.nodes[1].description = "Delete a project and all of its data."
    report.graph.nodes[1].input_schema = {"type": "object"}
    report.findings = []
    report.summary = summarize(report.graph, [])
    write_source(source, report)
    policy_file = tmp_path / "mendpact.toml"
    policy_file.write_text(
        """schema_version = "mendpact.policy.v1"
name = "reviewed local policy"
profile = "local"
scan_fail_on = "high"

[[waivers]]
rule_id = "MP-MCP-004"
subject = "tool:delete_project"
reason = "Deletion is isolated while the reviewed migration is completed."
approved_by = "security@example.com"
approved_on = 2026-09-01
expires_on = 2026-09-10
"""
    )
    policy = load_policy(policy_file, today=date(2026, 9, 8))

    result = recheck_scan_report(source, policy=policy, rechecked_at=NOW)

    assert result.status == ScanStatus.PASSED
    assert result.failure_threshold == Severity.HIGH
    assert result.policy == policy
    finding = next(item for item in result.findings if item.rule_id == "MP-MCP-004")
    assert finding.waiver is not None
    assert result.summary is not None
    assert result.summary.waived_finding_count == 1


def test_rejects_rechecked_source(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    write_source(source)
    result = recheck_scan_report(source, rechecked_at=NOW)
    write_source(source, result)

    with pytest.raises(ScanRecheckError, match="cannot be used"):
        recheck_scan_report(source)


def test_rejects_non_scan_and_incomplete_sources(tmp_path: Path) -> None:
    non_scan = tmp_path / "behavior.json"
    non_scan.write_text(
        '{"schema_version":"mendpact.behavior.v1","generated_at":"2026-09-08T12:00:00Z",'
        '"target":"fixture","status":"error","suite_name":"fixture","driver":"replay",'
        '"model":"fixture","repetitions":1}'
    )
    incomplete = tmp_path / "incomplete.json"
    report = source_report().model_copy(
        update={"status": ScanStatus.ERROR, "graph": None, "summary": None}
    )
    write_source(incomplete, report)

    for source in (non_scan, incomplete):
        with pytest.raises(ScanRecheckError, match=r"complete mendpact\.scan\.v1"):
            recheck_scan_report(source)


def test_invalid_source_uses_safe_error(tmp_path: Path) -> None:
    source = tmp_path / "customer-secret-name.json"
    source.write_text("not json")

    with pytest.raises(ScanRecheckError) as caught:
        recheck_scan_report(source)

    assert "customer-secret-name" not in str(caught.value)
