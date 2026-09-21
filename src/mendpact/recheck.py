"""Offline deterministic re-evaluation of a saved MCP capability scan."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from mendpact import __version__
from mendpact.checks.rules import run_deterministic_checks
from mendpact.contract_diff import validate_scan_contract
from mendpact.domain import (
    Finding,
    PolicySnapshot,
    RuleFindingChange,
    RuleFindingChangeKind,
    ScanRecheckEvidence,
    ScanReport,
    ScanRuleDelta,
    ScanStatus,
    Severity,
    summarize,
)
from mendpact.evidence import EvidenceExportError, load_evidence_source
from mendpact.policy import apply_finding_waivers

_AUTHORIZATION_RULE_PREFIX = "MP-AUTH-"


class ScanRecheckError(ValueError):
    """Safe-to-display failure while loading or re-evaluating a saved scan."""


def _finding_key(finding: Finding) -> tuple[int, str, str]:
    return (-finding.severity.rank, finding.rule_id, finding.subject or "")


def _severity_index(findings: list[Finding]) -> dict[tuple[str, str | None], Severity]:
    """Index distinct rule/subject pairs at their most conservative recorded severity."""

    result: dict[tuple[str, str | None], Severity] = {}
    for finding in findings:
        identity = (finding.rule_id, finding.subject)
        recorded = result.get(identity)
        if recorded is None or finding.severity.rank > recorded.rank:
            result[identity] = finding.severity
    return result


def compare_rule_findings(previous: list[Finding], current: list[Finding]) -> ScanRuleDelta:
    """Compare deterministic findings without treating waiver changes as rule changes."""

    before = _severity_index(previous)
    after = _severity_index(current)
    changes: list[RuleFindingChange] = []
    unchanged_count = 0
    identities = sorted(
        before.keys() | after.keys(),
        key=lambda item: (item[0], item[1] or ""),
    )
    for rule_id, subject in identities:
        before_severity = before.get((rule_id, subject))
        after_severity = after.get((rule_id, subject))
        if before_severity is None:
            changes.append(
                RuleFindingChange(
                    kind=RuleFindingChangeKind.INTRODUCED,
                    rule_id=rule_id,
                    subject=subject,
                    after_severity=after_severity,
                )
            )
        elif after_severity is None:
            changes.append(
                RuleFindingChange(
                    kind=RuleFindingChangeKind.RESOLVED,
                    rule_id=rule_id,
                    subject=subject,
                    before_severity=before_severity,
                )
            )
        elif before_severity != after_severity:
            changes.append(
                RuleFindingChange(
                    kind=RuleFindingChangeKind.RECLASSIFIED,
                    rule_id=rule_id,
                    subject=subject,
                    before_severity=before_severity,
                    after_severity=after_severity,
                )
            )
        else:
            unchanged_count += 1
    return ScanRuleDelta(
        introduced_count=sum(
            change.kind == RuleFindingChangeKind.INTRODUCED for change in changes
        ),
        resolved_count=sum(
            change.kind == RuleFindingChangeKind.RESOLVED for change in changes
        ),
        reclassified_count=sum(
            change.kind == RuleFindingChangeKind.RECLASSIFIED for change in changes
        ),
        unchanged_count=unchanged_count,
        changes=changes,
    )


def recheck_scan_report(
    source: Path,
    *,
    failure_threshold: Severity = Severity.HIGH,
    policy: PolicySnapshot | None = None,
    rechecked_at: datetime | None = None,
) -> ScanReport:
    """Apply current metadata rules to one complete saved scan without network access."""

    try:
        summary, loaded = load_evidence_source(source)
    except EvidenceExportError as exc:
        raise ScanRecheckError("Cannot recheck: source is unreadable or invalid.") from exc
    if not isinstance(loaded, ScanReport):
        raise ScanRecheckError("Only a complete mendpact.scan.v1 report can be rechecked.")
    if loaded.recheck is not None:
        raise ScanRecheckError("A rechecked report cannot be used as another recheck source.")
    try:
        graph = validate_scan_contract(loaded, "source")
    except ValueError as exc:
        raise ScanRecheckError("Only a complete mendpact.scan.v1 report can be rechecked.") from exc

    previous_deterministic = [
        finding
        for finding in loaded.findings
        if not finding.rule_id.startswith(_AUTHORIZATION_RULE_PREFIX)
    ]
    preserved_authorization = [
        finding.model_copy(update={"waiver": None})
        for finding in loaded.findings
        if finding.rule_id.startswith(_AUTHORIZATION_RULE_PREFIX)
    ]
    current_deterministic = run_deterministic_checks(graph)
    rule_delta = compare_rule_findings(previous_deterministic, current_deterministic)
    findings = apply_finding_waivers(
        [*preserved_authorization, *current_deterministic],
        policy,
    )
    findings.sort(key=_finding_key)
    threshold = policy.scan_fail_on if policy is not None else failure_threshold
    failed = any(
        finding.waiver is None and finding.severity.rank >= threshold.rank for finding in findings
    )
    return loaded.model_copy(
        update={
            "status": ScanStatus.FAILED if failed else ScanStatus.PASSED,
            "failure_threshold": threshold,
            "policy": policy,
            "findings": findings,
            "errors": [],
            "summary": summarize(graph, findings),
            "recheck": ScanRecheckEvidence(
                source_sha256=summary.source_sha256,
                rechecked_at=rechecked_at or datetime.now(UTC),
                mendpact_version=__version__,
                source_status=loaded.status,
                preserved_authorization_finding_count=len(preserved_authorization),
                rule_delta=rule_delta,
            ),
        }
    )
