"""Deterministic MCP contract comparison and behavioral blast-radius analysis."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, TypeGuard

from mendpact.domain import (
    BehaviorSuite,
    CapabilityEdge,
    CapabilityGraph,
    CapabilityNode,
    ContractChange,
    ContractChangeKind,
    ContractDiffReport,
    ContractDiffSummary,
    ContractImpact,
    NodeKind,
    PolicySnapshot,
    ScanReport,
    ScanStatus,
)
from mendpact.policy import apply_contract_waivers


def load_scan_report(path: Path) -> ScanReport:
    """Load one versioned MendPact scan artifact."""

    report = ScanReport.model_validate_json(path.read_text(encoding="utf-8"))
    if report.schema_version != "mendpact.scan.v1":
        raise ValueError(
            f"Unsupported scan schema '{report.schema_version}'; expected mendpact.scan.v1."
        )
    return report


def diff_scan_reports(
    baseline: ScanReport,
    candidate: ScanReport,
    *,
    suite: BehaviorSuite | None = None,
    failure_threshold: ContractImpact = ContractImpact.BREAKING,
    policy: PolicySnapshot | None = None,
) -> ContractDiffReport:
    """Compare two complete scan reports without contacting either target."""

    baseline_graph = validate_scan_contract(baseline, "baseline")
    candidate_graph = validate_scan_contract(candidate, "candidate")
    changes = apply_contract_waivers(
        _graph_changes(baseline_graph, candidate_graph, suite),
        policy,
    )
    changes.sort(
        key=lambda change: (
            -change.impact.rank,
            change.subject,
            change.path,
            change.rule_id,
        )
    )
    failed = any(
        change.waiver is None and change.impact.rank >= failure_threshold.rank
        for change in changes
    )
    counts = {impact.value: 0 for impact in ContractImpact}
    for change in changes:
        counts[change.impact.value] += 1
    affected_scenarios = {
        scenario_id
        for change in changes
        for scenario_id in change.affected_scenarios
    }
    return ContractDiffReport(
        baseline_scan_id=baseline.scan_id,
        candidate_scan_id=candidate.scan_id,
        baseline_target=baseline.target,
        candidate_target=candidate.target,
        status=ScanStatus.FAILED if failed else ScanStatus.PASSED,
        failure_threshold=failure_threshold,
        changes=changes,
        summary=ContractDiffSummary(
            change_count=len(changes),
            waived_change_count=sum(change.waiver is not None for change in changes),
            changes_by_impact=counts,
            affected_scenario_count=len(affected_scenarios),
        ),
    )


def validate_scan_contract(report: ScanReport, label: str) -> CapabilityGraph:
    """Return a structurally complete capability graph or reject the scan artifact."""

    if report.status == ScanStatus.ERROR or report.errors or report.graph is None:
        raise ValueError(f"The {label} scan must contain a complete capability graph.")
    node_ids = [node.id for node in report.graph.nodes]
    if len(node_ids) != len(set(node_ids)):
        raise ValueError(f"The {label} scan contains duplicate capability node IDs.")
    node_id_set = set(node_ids)
    edge_keys = [
        _edge_key(edge.source, edge.target, edge.relationship.value)
        for edge in report.graph.edges
    ]
    if len(edge_keys) != len(set(edge_keys)):
        raise ValueError(f"The {label} scan contains duplicate capability edges.")
    if any(
        edge.source not in node_id_set or edge.target not in node_id_set
        for edge in report.graph.edges
    ):
        raise ValueError(f"The {label} scan contains a dangling capability edge.")
    return report.graph


def _scenario_ids_for_tool(
    tool_name: str,
    suite: BehaviorSuite | None,
    *,
    added: bool = False,
) -> list[str]:
    if suite is None:
        return []
    if added:
        return sorted(scenario.id for scenario in suite.scenarios)
    return sorted(
        scenario.id
        for scenario in suite.scenarios
        if scenario.expectation.tool == tool_name
        or tool_name in scenario.expectation.forbidden_tools
    )


def _node_subject(node: CapabilityNode) -> str:
    return f"{node.kind.value}:{node.name}"


def _change(
    rule_id: str,
    impact: ContractImpact,
    kind: ContractChangeKind,
    subject: str,
    path: str,
    message: str,
    *,
    before: Any = None,
    after: Any = None,
    affected_scenarios: list[str] | None = None,
) -> ContractChange:
    return ContractChange(
        rule_id=rule_id,
        impact=impact,
        kind=kind,
        subject=subject,
        path=path,
        message=message,
        before=before,
        after=after,
        affected_scenarios=affected_scenarios or [],
    )


def _graph_changes(
    baseline: CapabilityGraph,
    candidate: CapabilityGraph,
    suite: BehaviorSuite | None,
) -> list[ContractChange]:
    changes = _server_changes(baseline, candidate, suite)
    baseline_nodes = {
        node.id: node for node in baseline.nodes if node.kind != NodeKind.SERVER
    }
    candidate_nodes = {
        node.id: node for node in candidate.nodes if node.kind != NodeKind.SERVER
    }

    for node_id in sorted(baseline_nodes.keys() - candidate_nodes.keys()):
        node = baseline_nodes[node_id]
        affected = (
            _scenario_ids_for_tool(node.name, suite)
            if node.kind == NodeKind.TOOL
            else []
        )
        changes.append(
            _change(
                "MP-DIFF-001",
                ContractImpact.BREAKING,
                ContractChangeKind.REMOVED,
                _node_subject(node),
                f"/nodes/{_pointer_token(node.id)}",
                "Capability was removed.",
                before=node.model_dump(mode="json"),
                affected_scenarios=affected,
            )
        )

    for node_id in sorted(candidate_nodes.keys() - baseline_nodes.keys()):
        node = candidate_nodes[node_id]
        is_tool = node.kind == NodeKind.TOOL
        affected = _scenario_ids_for_tool(node.name, suite, added=True) if is_tool else []
        changes.append(
            _change(
                "MP-DIFF-002",
                ContractImpact.RISKY if is_tool else ContractImpact.COMPATIBLE,
                ContractChangeKind.ADDED,
                _node_subject(node),
                f"/nodes/{_pointer_token(node.id)}",
                "Tool was added and may compete for model selection."
                if is_tool
                else "Capability was added.",
                after=node.model_dump(mode="json"),
                affected_scenarios=affected,
            )
        )

    for node_id in sorted(baseline_nodes.keys() & candidate_nodes.keys()):
        changes.extend(
            _node_changes(baseline_nodes[node_id], candidate_nodes[node_id], suite)
        )
    changes.extend(_edge_changes(baseline, candidate))
    return changes


def _edge_key(source: str, target: str, relationship: str) -> tuple[str, str, str]:
    return (source, target, relationship)


def _edge_changes(
    baseline: CapabilityGraph,
    candidate: CapabilityGraph,
) -> list[ContractChange]:
    baseline_edges = {
        _comparison_edge_key(baseline, edge): edge
        for edge in baseline.edges
    }
    candidate_edges = {
        _comparison_edge_key(candidate, edge): edge
        for edge in candidate.edges
    }
    changes: list[ContractChange] = []
    for key in sorted(baseline_edges.keys() - candidate_edges.keys()):
        edge = baseline_edges[key]
        changes.append(
            _change(
                "MP-DIFF-010",
                ContractImpact.BREAKING,
                ContractChangeKind.REMOVED,
                f"edge:{edge.source}->{edge.target}",
                f"/edges/{_pointer_token('|'.join(key))}",
                "Capability relationship was removed.",
                before=edge.model_dump(mode="json"),
            )
        )
    for key in sorted(candidate_edges.keys() - baseline_edges.keys()):
        edge = candidate_edges[key]
        changes.append(
            _change(
                "MP-DIFF-011",
                ContractImpact.COMPATIBLE,
                ContractChangeKind.ADDED,
                f"edge:{edge.source}->{edge.target}",
                f"/edges/{_pointer_token('|'.join(key))}",
                "Capability relationship was added.",
                after=edge.model_dump(mode="json"),
            )
        )
    return changes


def _comparison_edge_key(
    graph: CapabilityGraph,
    edge: CapabilityEdge,
) -> tuple[str, str, str]:
    nodes = {node.id: node for node in graph.nodes}
    source = nodes[edge.source]
    normalized_source = "server" if source.kind == NodeKind.SERVER else edge.source
    return _edge_key(normalized_source, edge.target, edge.relationship.value)


def _server_changes(
    baseline: CapabilityGraph,
    candidate: CapabilityGraph,
    suite: BehaviorSuite | None,
) -> list[ContractChange]:
    changes: list[ContractChange] = []
    pairs = [
        (
            "MP-DIFF-005",
            ContractImpact.RISKY,
            "/server/instructions",
            "Server instructions changed and may alter agent behavior.",
            baseline.instructions,
            candidate.instructions,
        ),
        (
            "MP-DIFF-006",
            ContractImpact.BREAKING,
            "/protocol",
            "Protocol identifier changed.",
            baseline.protocol,
            candidate.protocol,
        ),
        (
            "MP-DIFF-006",
            ContractImpact.BREAKING,
            "/protocol_version",
            "Negotiated MCP protocol version changed.",
            baseline.protocol_version,
            candidate.protocol_version,
        ),
        (
            "MP-DIFF-008",
            ContractImpact.RISKY,
            "/server/name",
            "Server identity changed.",
            baseline.server_name,
            candidate.server_name,
        ),
        (
            "MP-DIFF-009",
            ContractImpact.COMPATIBLE,
            "/server/version",
            "Server version changed.",
            baseline.server_version,
            candidate.server_version,
        ),
    ]
    for rule_id, impact, path, message, before, after in pairs:
        if before != after:
            affected = (
                sorted(scenario.id for scenario in suite.scenarios)
                if rule_id == "MP-DIFF-005" and suite is not None
                else []
            )
            changes.append(
                _change(
                    rule_id,
                    impact,
                    ContractChangeKind.MODIFIED,
                    "server",
                    path,
                    message,
                    before=before,
                    after=after,
                    affected_scenarios=affected,
                )
            )
    return changes


def _node_changes(
    baseline: CapabilityNode,
    candidate: CapabilityNode,
    suite: BehaviorSuite | None,
) -> list[ContractChange]:
    subject = _node_subject(candidate)
    node_path = f"/nodes/{_pointer_token(candidate.id)}"
    affected = (
        _scenario_ids_for_tool(candidate.name, suite)
        if candidate.kind == NodeKind.TOOL
        else []
    )
    changes: list[ContractChange] = []
    if (baseline.kind, baseline.name) != (candidate.kind, candidate.name):
        identity_affected = set(affected)
        if baseline.kind == NodeKind.TOOL:
            identity_affected.update(_scenario_ids_for_tool(baseline.name, suite))
        changes.append(
            _change(
                "MP-DIFF-004",
                ContractImpact.BREAKING,
                ContractChangeKind.MODIFIED,
                subject,
                f"{node_path}/identity",
                "Capability kind or name changed while its stable ID remained the same.",
                before={"kind": baseline.kind.value, "name": baseline.name},
                after={"kind": candidate.kind.value, "name": candidate.name},
                affected_scenarios=sorted(identity_affected),
            )
        )
    if (baseline.title, baseline.description) != (candidate.title, candidate.description):
        behavior_sensitive = candidate.kind in {NodeKind.TOOL, NodeKind.PROMPT}
        changes.append(
            _change(
                "MP-DIFF-003",
                ContractImpact.RISKY
                if behavior_sensitive
                else ContractImpact.COMPATIBLE,
                ContractChangeKind.MODIFIED,
                subject,
                f"{node_path}/description",
                "Capability title or description changed and may alter model selection."
                if behavior_sensitive
                else "Capability title or description changed.",
                before={"title": baseline.title, "description": baseline.description},
                after={"title": candidate.title, "description": candidate.description},
                affected_scenarios=affected,
            )
        )
    if baseline.input_schema != candidate.input_schema:
        changes.extend(
            _schema_changes(
                baseline.input_schema,
                candidate.input_schema,
                path=f"{node_path}/input_schema",
                subject=subject,
                affected_scenarios=affected,
            )
        )
    if baseline.metadata != candidate.metadata:
        impact = (
            ContractImpact.RISKY
            if candidate.kind == NodeKind.TOOL
            else ContractImpact.COMPATIBLE
        )
        changes.append(
            _change(
                "MP-DIFF-007",
                impact,
                ContractChangeKind.MODIFIED,
                subject,
                f"{node_path}/metadata",
                "Capability metadata changed.",
                before=baseline.metadata,
                after=candidate.metadata,
                affected_scenarios=affected,
            )
        )
    return changes


def _schema_changes(
    baseline: dict[str, Any] | None,
    candidate: dict[str, Any] | None,
    *,
    path: str,
    subject: str,
    affected_scenarios: list[str],
) -> list[ContractChange]:
    if baseline == candidate:
        return []
    if baseline is None:
        return [
            _change(
                "MP-DIFF-100",
                ContractImpact.BREAKING,
                ContractChangeKind.ADDED,
                subject,
                path,
                "An input schema was introduced and may reject previously accepted arguments.",
                after=candidate,
                affected_scenarios=affected_scenarios,
            )
        ]
    if candidate is None:
        return [
            _change(
                "MP-DIFF-100",
                ContractImpact.RISKY,
                ContractChangeKind.REMOVED,
                subject,
                path,
                "Input schema validation was removed.",
                before=baseline,
                affected_scenarios=affected_scenarios,
            )
        ]

    changes: list[ContractChange] = []
    baseline_type = baseline.get("type")
    candidate_type = candidate.get("type")
    if baseline_type != candidate_type:
        changes.append(
            _change(
                "MP-DIFF-101",
                ContractImpact.BREAKING,
                ContractChangeKind.MODIFIED,
                subject,
                f"{path}/type",
                "Input type changed.",
                before=baseline_type,
                after=candidate_type,
                affected_scenarios=affected_scenarios,
            )
        )

    changes.extend(
        _enum_changes(
            baseline.get("enum"),
            candidate.get("enum"),
            path=f"{path}/enum",
            subject=subject,
            affected_scenarios=affected_scenarios,
        )
    )
    changes.extend(
        _object_schema_changes(
            baseline,
            candidate,
            path=path,
            subject=subject,
            affected_scenarios=affected_scenarios,
        )
    )
    changes.extend(
        _constraint_changes(
            baseline,
            candidate,
            path=path,
            subject=subject,
            affected_scenarios=affected_scenarios,
        )
    )

    baseline_items = baseline.get("items")
    candidate_items = candidate.get("items")
    if isinstance(baseline_items, dict) or isinstance(candidate_items, dict):
        changes.extend(
            _schema_changes(
                baseline_items if isinstance(baseline_items, dict) else None,
                candidate_items if isinstance(candidate_items, dict) else None,
                path=f"{path}/items",
                subject=subject,
                affected_scenarios=affected_scenarios,
            )
        )

    for keyword in ("oneOf", "anyOf", "allOf", "not", "if", "then", "else"):
        if baseline.get(keyword) != candidate.get(keyword):
            changes.append(
                _change(
                    "MP-DIFF-198",
                    ContractImpact.RISKY,
                    ContractChangeKind.MODIFIED,
                    subject,
                    f"{path}/{keyword}",
                    f"JSON Schema '{keyword}' logic changed and requires review.",
                    before=baseline.get(keyword),
                    after=candidate.get(keyword),
                    affected_scenarios=affected_scenarios,
                )
            )

    if not changes:
        changes.append(
            _change(
                "MP-DIFF-199",
                ContractImpact.RISKY,
                ContractChangeKind.MODIFIED,
                subject,
                path,
                "Input schema changed in a way that requires review.",
                before=baseline,
                after=candidate,
                affected_scenarios=affected_scenarios,
            )
        )
    return changes


def _object_schema_changes(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    *,
    path: str,
    subject: str,
    affected_scenarios: list[str],
) -> list[ContractChange]:
    changes: list[ContractChange] = []
    baseline_properties = baseline.get("properties", {})
    candidate_properties = candidate.get("properties", {})
    if not isinstance(baseline_properties, dict):
        baseline_properties = {}
    if not isinstance(candidate_properties, dict):
        candidate_properties = {}
    baseline_required = _string_set(baseline.get("required"))
    candidate_required = _string_set(candidate.get("required"))

    for name in sorted(candidate_required - baseline_required):
        changes.append(
            _change(
                "MP-DIFF-102",
                ContractImpact.BREAKING,
                ContractChangeKind.MODIFIED,
                subject,
                f"{path}/required/{_pointer_token(name)}",
                f"Argument '{name}' became required.",
                before=False,
                after=True,
                affected_scenarios=affected_scenarios,
            )
        )
    for name in sorted(baseline_required - candidate_required):
        changes.append(
            _change(
                "MP-DIFF-107",
                ContractImpact.COMPATIBLE,
                ContractChangeKind.MODIFIED,
                subject,
                f"{path}/required/{_pointer_token(name)}",
                f"Argument '{name}' is no longer required.",
                before=True,
                after=False,
                affected_scenarios=affected_scenarios,
            )
        )
    for name in sorted(baseline_properties.keys() - candidate_properties.keys()):
        changes.append(
            _change(
                "MP-DIFF-103",
                ContractImpact.BREAKING,
                ContractChangeKind.REMOVED,
                subject,
                f"{path}/properties/{_pointer_token(name)}",
                f"Argument '{name}' was removed.",
                before=baseline_properties[name],
                affected_scenarios=affected_scenarios,
            )
        )
    for name in sorted(candidate_properties.keys() - baseline_properties.keys()):
        if name not in candidate_required:
            changes.append(
                _change(
                    "MP-DIFF-104",
                    ContractImpact.COMPATIBLE,
                    ContractChangeKind.ADDED,
                    subject,
                    f"{path}/properties/{_pointer_token(name)}",
                    f"Optional argument '{name}' was added.",
                    after=candidate_properties[name],
                    affected_scenarios=affected_scenarios,
                )
            )
    for name in sorted(baseline_properties.keys() & candidate_properties.keys()):
        baseline_property = baseline_properties[name]
        candidate_property = candidate_properties[name]
        if isinstance(baseline_property, dict) and isinstance(candidate_property, dict):
            changes.extend(
                _schema_changes(
                    baseline_property,
                    candidate_property,
                    path=f"{path}/properties/{_pointer_token(name)}",
                    subject=subject,
                    affected_scenarios=affected_scenarios,
                )
            )
        elif baseline_property != candidate_property:
            candidate_rejects_all = candidate_property is False
            baseline_rejects_all = baseline_property is False
            changes.append(
                _change(
                    "MP-DIFF-114",
                    ContractImpact.BREAKING
                    if candidate_rejects_all
                    else (
                        ContractImpact.COMPATIBLE
                        if baseline_rejects_all
                        else ContractImpact.RISKY
                    ),
                    ContractChangeKind.MODIFIED,
                    subject,
                    f"{path}/properties/{_pointer_token(name)}",
                    f"Argument '{name}' changed JSON Schema representation.",
                    before=baseline_property,
                    after=candidate_property,
                    affected_scenarios=affected_scenarios,
                )
            )

    baseline_additional = baseline.get("additionalProperties", True)
    candidate_additional = candidate.get("additionalProperties", True)
    if baseline_additional is not False and candidate_additional is False:
        changes.append(
            _change(
                "MP-DIFF-105",
                ContractImpact.BREAKING,
                ContractChangeKind.MODIFIED,
                subject,
                f"{path}/additionalProperties",
                "Unknown arguments are no longer accepted.",
                before=baseline_additional,
                after=candidate_additional,
                affected_scenarios=affected_scenarios,
            )
        )
    elif baseline_additional is False and candidate_additional is not False:
        changes.append(
            _change(
                "MP-DIFF-106",
                ContractImpact.RISKY,
                ContractChangeKind.MODIFIED,
                subject,
                f"{path}/additionalProperties",
                "Schema now accepts unknown arguments.",
                before=baseline_additional,
                after=candidate_additional,
                affected_scenarios=affected_scenarios,
            )
        )
    elif baseline_additional != candidate_additional:
        introduced_restriction = (
            baseline_additional is True
            and isinstance(candidate_additional, dict)
        )
        changes.append(
            _change(
                "MP-DIFF-115",
                ContractImpact.BREAKING
                if introduced_restriction
                else ContractImpact.RISKY,
                ContractChangeKind.MODIFIED,
                subject,
                f"{path}/additionalProperties",
                "Unknown-argument schema changed.",
                before=baseline_additional,
                after=candidate_additional,
                affected_scenarios=affected_scenarios,
            )
        )
    return changes


def _enum_changes(
    baseline: Any,
    candidate: Any,
    *,
    path: str,
    subject: str,
    affected_scenarios: list[str],
) -> list[ContractChange]:
    if baseline == candidate:
        return []
    if not isinstance(baseline, list) and isinstance(candidate, list):
        return [
            _change(
                "MP-DIFF-108",
                ContractImpact.BREAKING,
                ContractChangeKind.ADDED,
                subject,
                path,
                "An enum restriction was introduced.",
                before=baseline,
                after=candidate,
                affected_scenarios=affected_scenarios,
            )
        ]
    if isinstance(baseline, list) and not isinstance(candidate, list):
        return [
            _change(
                "MP-DIFF-109",
                ContractImpact.RISKY,
                ContractChangeKind.REMOVED,
                subject,
                path,
                "An enum restriction was removed.",
                before=baseline,
                after=candidate,
                affected_scenarios=affected_scenarios,
            )
        ]
    if not isinstance(baseline, list) or not isinstance(candidate, list):
        return []

    baseline_values = {_canonical(value): value for value in baseline}
    candidate_values = {_canonical(value): value for value in candidate}
    removed = [baseline_values[key] for key in sorted(baseline_values.keys() - candidate_values)]
    added = [candidate_values[key] for key in sorted(candidate_values.keys() - baseline_values)]
    changes: list[ContractChange] = []
    if removed:
        changes.append(
            _change(
                "MP-DIFF-108",
                ContractImpact.BREAKING,
                ContractChangeKind.MODIFIED,
                subject,
                path,
                "Allowed enum values were removed.",
                before=baseline,
                after=candidate,
                affected_scenarios=affected_scenarios,
            )
        )
    if added and not removed:
        changes.append(
            _change(
                "MP-DIFF-109",
                ContractImpact.COMPATIBLE,
                ContractChangeKind.MODIFIED,
                subject,
                path,
                "Allowed enum values were added.",
                before=baseline,
                after=candidate,
                affected_scenarios=affected_scenarios,
            )
        )
    return changes


def _constraint_changes(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    *,
    path: str,
    subject: str,
    affected_scenarios: list[str],
) -> list[ContractChange]:
    changes: list[ContractChange] = []
    lower_bounds = (
        "minimum",
        "exclusiveMinimum",
        "minLength",
        "minItems",
        "minProperties",
    )
    upper_bounds = (
        "maximum",
        "exclusiveMaximum",
        "maxLength",
        "maxItems",
        "maxProperties",
    )
    for keyword in lower_bounds + upper_bounds:
        before = baseline.get(keyword)
        after = candidate.get(keyword)
        if before == after:
            continue
        tightened = _bound_tightened(
            before,
            after,
            lower_bound=keyword in lower_bounds,
        )
        if tightened is None:
            changes.append(
                _change(
                    "MP-DIFF-113",
                    ContractImpact.RISKY,
                    ContractChangeKind.MODIFIED,
                    subject,
                    f"{path}/{keyword}",
                    f"Constraint '{keyword}' changed and requires review.",
                    before=before,
                    after=after,
                    affected_scenarios=affected_scenarios,
                )
            )
            continue
        changes.append(
            _change(
                "MP-DIFF-110" if tightened else "MP-DIFF-111",
                ContractImpact.BREAKING if tightened else ContractImpact.COMPATIBLE,
                ContractChangeKind.MODIFIED,
                subject,
                f"{path}/{keyword}",
                f"Constraint '{keyword}' was {'tightened' if tightened else 'relaxed'}.",
                before=before,
                after=after,
                affected_scenarios=affected_scenarios,
            )
        )
    for keyword in ("pattern", "format", "const", "multipleOf"):
        before = baseline.get(keyword)
        after = candidate.get(keyword)
        if before != after:
            changes.append(
                _change(
                    "MP-DIFF-112",
                    ContractImpact.BREAKING,
                    ContractChangeKind.MODIFIED,
                    subject,
                    f"{path}/{keyword}",
                    f"Constraint '{keyword}' changed.",
                    before=before,
                    after=after,
                    affected_scenarios=affected_scenarios,
                )
            )
    return changes


def _bound_tightened(
    before: Any,
    after: Any,
    *,
    lower_bound: bool,
) -> bool | None:
    if before is None:
        return True if _finite_real(after) else None
    if after is None:
        return False if _finite_real(before) else None
    if not _finite_real(before) or not _finite_real(after):
        return None
    return after > before if lower_bound else after < before


def _finite_real(value: Any) -> TypeGuard[int | float]:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, float) and math.isfinite(value)


def _string_set(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {item for item in value if isinstance(item, str)}


def _pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
