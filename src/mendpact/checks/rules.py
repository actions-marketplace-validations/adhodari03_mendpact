"""Transparent, deterministic rules for the first MendPact release."""

from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import urlsplit

from mendpact.domain import CapabilityGraph, CapabilityNode, Finding, NodeKind, Severity

_INJECTION_PATTERNS: dict[str, re.Pattern[str]] = {
    "ignore-instructions": re.compile(r"\bignore\b.{0,40}\b(previous|prior|system)\b", re.I),
    "concealment": re.compile(r"\b(do not|don't|never)\b.{0,30}\b(tell|reveal|mention)\b", re.I),
    "credential-access": re.compile(
        r"\b(api key|secret|credential|private key|access token)\b",
        re.I,
    ),
    "exfiltration": re.compile(r"\b(exfiltrat|send.{0,20}(secret|credential|token))", re.I),
}

_RISK_TERMS: dict[Severity, tuple[str, ...]] = {
    Severity.CRITICAL: ("shell", "execute_command", "run_command", "eval_code"),
    Severity.HIGH: ("delete", "destroy", "drop", "transfer", "payment", "purchase", "send_email"),
    Severity.MEDIUM: ("write", "update", "create", "upload", "publish", "admin", "credential"),
}

_EXECUTION_TOOL_NAMES = {
    "eval",
    "eval_code",
    "exec",
    "execute",
    "execute_code",
    "execute_command",
    "run_code",
    "run_command",
    "shell",
    "terminal",
}
_EXECUTION_ARGUMENT_NAMES = {"code", "command", "script", "shell_command"}
_LEGACY_PROTOCOL_VERSIONS = {"2024-11-05"}


def _finding(
    rule_id: str,
    severity: Severity,
    title: str,
    message: str,
    node: CapabilityNode | None = None,
    **evidence: object,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        message=message,
        subject=node.id if node else None,
        evidence=evidence,
    )


def _check_tool(tool: CapabilityNode) -> Iterable[Finding]:
    description = (tool.description or "").strip()
    if not description:
        yield _finding(
            "MP-MCP-001",
            Severity.MEDIUM,
            "Tool has no description",
            "Models cannot reliably choose or constrain a tool whose purpose is undocumented.",
            tool,
        )
    elif len(description) < 20:
        yield _finding(
            "MP-MCP-002",
            Severity.LOW,
            "Tool description is very short",
            "A short description may omit preconditions, side effects, or permission boundaries.",
            tool,
            description=description,
        )

    schema = tool.input_schema or {}
    properties = schema.get("properties") if isinstance(schema, dict) else None
    additional = schema.get("additionalProperties") if isinstance(schema, dict) else None
    if schema.get("type") == "object" and not properties and additional is not False:
        yield _finding(
            "MP-MCP-003",
            Severity.MEDIUM,
            "Tool accepts unbounded object arguments",
            "The input schema does not declare properties or reject additional properties.",
            tool,
            input_schema=schema,
        )

    property_names = (
        {str(name).lower().replace("-", "_") for name in properties}
        if isinstance(properties, dict)
        else set()
    )
    normalized_name = tool.name.lower().replace("-", "_")
    execution_arguments = sorted(property_names & _EXECUTION_ARGUMENT_NAMES)
    if normalized_name in _EXECUTION_TOOL_NAMES and execution_arguments:
        yield _finding(
            "MP-MCP-007",
            Severity.CRITICAL,
            "Tool accepts code or commands for execution",
            "The tool name and input schema advertise caller-controlled code or command "
            "execution, which requires isolation, least-privilege credentials, and explicit tests.",
            tool,
            tool_name=tool.name,
            execution_arguments=execution_arguments,
        )

    searchable = f"{tool.name} {description}".lower().replace("-", "_")
    for severity, terms in _RISK_TERMS.items():
        matches = sorted({term for term in terms if term in searchable})
        if matches:
            yield _finding(
                "MP-MCP-004",
                severity,
                "Tool may perform a consequential action",
                "The tool name or description suggests side effects that require "
                "explicit tests and policy.",
                tool,
                matched_terms=matches,
            )
            break

    for pattern_name, pattern in _INJECTION_PATTERNS.items():
        match = pattern.search(description)
        if match:
            yield _finding(
                "MP-MCP-005",
                Severity.CRITICAL,
                "Tool description contains injection-like instructions",
                "Tool metadata includes language that may manipulate a model beyond "
                "describing the tool.",
                tool,
                pattern=pattern_name,
                matched_text=match.group(0),
            )


def run_deterministic_checks(graph: CapabilityGraph) -> list[Finding]:
    findings: list[Finding] = []
    tools = graph.nodes_of_kind(NodeKind.TOOL)

    if urlsplit(graph.target).scheme == "http":
        findings.append(
            _finding(
                "MP-NET-001",
                Severity.MEDIUM,
                "Target uses plaintext HTTP",
                "Production MCP traffic should use TLS to protect tool metadata and "
                "session traffic.",
                target=graph.target,
            )
        )

    if graph.protocol_version in _LEGACY_PROTOCOL_VERSIONS:
        findings.append(
            _finding(
                "MP-MCP-008",
                Severity.LOW,
                "Server negotiated a legacy MCP revision",
                "The negotiated revision predates Streamable HTTP protocol revisions and may "
                "reduce interoperability with current clients.",
                protocol_version=graph.protocol_version,
            )
        )

    if len(tools) > 50:
        findings.append(
            _finding(
                "MP-MCP-006",
                Severity.LOW,
                "Large tool catalog",
                "Large catalogs increase selection ambiguity and should be tested with "
                "representative tasks.",
                tool_count=len(tools),
            )
        )

    for tool in tools:
        findings.extend(_check_tool(tool))

    return sorted(
        findings,
        key=lambda finding: (
            -finding.severity.rank,
            finding.rule_id,
            finding.subject or "",
        ),
    )
