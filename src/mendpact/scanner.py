"""Scan orchestration independent of the CLI and future hosted API."""

from __future__ import annotations

from typing import Any

from mendpact.adapters.mcp import discover_mcp_target
from mendpact.checks.rules import run_deterministic_checks
from mendpact.domain import (
    Finding,
    OAuthMetadataEvidence,
    PolicySnapshot,
    ScanReport,
    ScanStatus,
    Severity,
    summarize,
)
from mendpact.policy import apply_finding_waivers
from mendpact.security.auth import BearerAuthentication, render_exception
from mendpact.security.oauth_metadata import inspect_oauth_metadata
from mendpact.security.targets import TargetPolicy, validate_target_url


async def scan_mcp_url(
    target: str,
    *,
    failure_threshold: Severity = Severity.HIGH,
    policy: TargetPolicy | None = None,
    applied_policy: PolicySnapshot | None = None,
    authentication: BearerAuthentication | None = None,
) -> ScanReport:
    policy = policy or TargetPolicy()
    authorization: OAuthMetadataEvidence | None = None
    authorization_findings: list[Finding] = []
    try:
        await validate_target_url(target, policy)
        if authentication is not None:
            authorization, authorization_findings = await inspect_oauth_metadata(
                target,
                bearer_token_env=authentication.environment_variable,
                policy=policy,
            )
        graph = await discover_mcp_target(target, authentication=authentication)
    except Exception as exc:
        return ScanReport(
            target=target,
            status=ScanStatus.ERROR,
            failure_threshold=failure_threshold,
            policy=applied_policy,
            authorization=authorization,
            findings=authorization_findings,
            errors=[render_exception(exc, authentication)],
        )

    findings = apply_finding_waivers(
        [*authorization_findings, *run_deterministic_checks(graph)],
        applied_policy,
    )
    failed = any(
        finding.waiver is None and finding.severity.rank >= failure_threshold.rank
        for finding in findings
    )
    return ScanReport(
        target=target,
        status=ScanStatus.FAILED if failed else ScanStatus.PASSED,
        failure_threshold=failure_threshold,
        policy=applied_policy,
        graph=graph,
        authorization=authorization,
        findings=findings,
        summary=summarize(graph, findings),
    )

async def scan_mcp_target(
    target: Any,
    *,
    display_target: str = "in-memory-mcp",
    failure_threshold: Severity = Severity.HIGH,
) -> ScanReport:
    """Scan an in-memory target; used by tests and future embedded integrations."""

    try:
        graph = await discover_mcp_target(target, display_target=display_target)
    except Exception as exc:
        return ScanReport(
            target=display_target,
            status=ScanStatus.ERROR,
            failure_threshold=failure_threshold,
            errors=[render_exception(exc, None)],
        )

    findings = run_deterministic_checks(graph)
    failed = any(finding.severity.rank >= failure_threshold.rank for finding in findings)
    return ScanReport(
        target=display_target,
        status=ScanStatus.FAILED if failed else ScanStatus.PASSED,
        failure_threshold=failure_threshold,
        graph=graph,
        findings=findings,
        summary=summarize(graph, findings),
    )
