from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from mendpact.contract_diff import diff_scan_reports
from mendpact.domain import (
    CapabilityGraph,
    CapabilityNode,
    ContractChange,
    ContractChangeKind,
    ContractImpact,
    Finding,
    NodeKind,
    PolicyProfile,
    ScanReport,
    ScanStatus,
    Severity,
    WaiverStatus,
)
from mendpact.policy import (
    PolicyConfigurationError,
    apply_contract_waivers,
    apply_finding_waivers,
    load_policy,
    model_comparison_policy,
    semantic_calibration_policy,
    target_policy,
)
from mendpact.scanner import scan_mcp_url
from mendpact.security.targets import TargetPolicy


def _write_policy(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "mendpact.toml"
    path.write_text(content, encoding="utf-8")
    return path


def _waiver_policy(
    tmp_path: Path,
    *,
    rule_id: str = "MP-TEST-001",
    subject: str = "tool:delete_project",
    approved_on: str = "2026-08-01",
    expires_on: str = "2026-08-15",
) -> Path:
    return _write_policy(
        tmp_path,
        '\n'.join(
            [
                'schema_version = "mendpact.policy.v1"',
                'name = "production"',
                'profile = "production"',
                '',
                '[[waivers]]',
                f'rule_id = "{rule_id}"',
                f'subject = "{subject}"',
                'reason = "Temporary migration exception."',
                'approved_by = "security@example.com"',
                f'approved_on = {approved_on}',
                f'expires_on = {expires_on}',
            ]
        ),
    )


def test_production_profile_resolves_strict_defaults(tmp_path: Path) -> None:
    path = _write_policy(
        tmp_path,
        '\n'.join(
            [
                'schema_version = "mendpact.policy.v1"',
                'name = "production"',
                'profile = "production"',
            ]
        ),
    )

    policy = load_policy(path)

    assert policy.profile == PolicyProfile.PRODUCTION
    assert len(policy.source_sha256) == 64
    assert policy.scan_fail_on == Severity.HIGH
    assert policy.contract_fail_on == ContractImpact.RISKY
    assert policy.allow_private is False
    assert policy.allow_insecure_http is False
    assert policy.schema_version == "mendpact.policy.v1"
    assert policy.model_comparison is None
    assert policy.semantic_calibration is None


def test_v2_policy_resolves_provider_neutral_reliability_defaults(tmp_path: Path) -> None:
    path = _write_policy(
        tmp_path,
        '\n'.join(
            [
                'schema_version = "mendpact.policy.v2"',
                'name = "production-v2"',
                'profile = "production"',
            ]
        ),
    )

    policy = load_policy(path)

    assert policy.schema_version == "mendpact.policy.v2"
    comparison = model_comparison_policy(policy)
    assert comparison.max_overall_pass_rate_drop == 0.0
    assert comparison.max_scenario_pass_rate_drop == 0.0
    assert comparison.allow_new_confusions is False
    calibration = semantic_calibration_policy(policy)
    assert calibration.min_calibration_examples == 20
    assert calibration.min_validation_examples == 20
    assert calibration.min_validation_balanced_accuracy == 0.8
    assert calibration.max_validation_false_accept_rate == 0.05


def test_v2_policy_loads_reviewed_model_and_calibration_thresholds(tmp_path: Path) -> None:
    path = _write_policy(
        tmp_path,
        '\n'.join(
            [
                'schema_version = "mendpact.policy.v2"',
                'name = "reviewed-local"',
                'profile = "local"',
                '',
                '[model_comparison]',
                'max_overall_pass_rate_drop = 0.02',
                'max_scenario_pass_rate_drop = 0.05',
                'allow_new_confusions = true',
                '',
                '[semantic_calibration]',
                'min_calibration_examples = 6',
                'min_validation_examples = 8',
                'min_validation_balanced_accuracy = 0.9',
                'max_validation_false_accept_rate = 0.02',
            ]
        ),
    )

    policy = load_policy(path)

    assert model_comparison_policy(policy).max_overall_pass_rate_drop == 0.02
    assert model_comparison_policy(policy).allow_new_confusions is True
    assert semantic_calibration_policy(policy).min_validation_examples == 8
    assert semantic_calibration_policy(policy).max_validation_false_accept_rate == 0.02


def test_v1_policy_rejects_v2_sections_and_resolvers(tmp_path: Path) -> None:
    v1 = _write_policy(
        tmp_path,
        '\n'.join(
            [
                'schema_version = "mendpact.policy.v1"',
                'name = "legacy"',
                'profile = "local"',
            ]
        ),
    )
    snapshot = load_policy(v1)

    with pytest.raises(PolicyConfigurationError, match="requires schema_version"):
        model_comparison_policy(snapshot)
    with pytest.raises(PolicyConfigurationError, match="requires schema_version"):
        semantic_calibration_policy(snapshot)

    v1.write_text(
        v1.read_text(encoding="utf-8")
        + "\n[model_comparison]\nmax_overall_pass_rate_drop = 0.01\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyConfigurationError, match=r"require mendpact\.policy\.v2"):
        load_policy(v1)


def test_v2_policy_rejects_coerced_or_unknown_nested_settings(tmp_path: Path) -> None:
    quoted_boolean = _write_policy(
        tmp_path,
        '\n'.join(
            [
                'schema_version = "mendpact.policy.v2"',
                'name = "invalid"',
                'profile = "local"',
                '',
                '[model_comparison]',
                'allow_new_confusions = "false"',
            ]
        ),
    )
    with pytest.raises(PolicyConfigurationError, match="valid boolean"):
        load_policy(quoted_boolean)

    quoted_boolean.write_text(
        quoted_boolean.read_text(encoding="utf-8").replace(
            'allow_new_confusions = "false"',
            "unknown_gate = true",
        ),
        encoding="utf-8",
    )
    with pytest.raises(PolicyConfigurationError, match="Extra inputs are not permitted"):
        load_policy(quoted_boolean)


@pytest.mark.parametrize(
    ("section", "message"),
    [
        (
            "[model_comparison]\nmax_overall_pass_rate_drop = 0.06",
            "overall drop cannot exceed 0.05",
        ),
        (
            "[model_comparison]\nmax_scenario_pass_rate_drop = 0.11",
            "scenario drop cannot exceed 0.10",
        ),
        (
            "[model_comparison]\nallow_new_confusions = true",
            "cannot allow new confusion pairs",
        ),
        (
            "[semantic_calibration]\nmin_calibration_examples = 19",
            "at least 20 calibration examples",
        ),
        (
            "[semantic_calibration]\nmin_validation_examples = 19",
            "at least 20 validation examples",
        ),
        (
            "[semantic_calibration]\nmin_validation_balanced_accuracy = 0.79",
            "balanced accuracy cannot be below 0.80",
        ),
        (
            "[semantic_calibration]\nmax_validation_false_accept_rate = 0.06",
            "false-accept rate cannot exceed 0.05",
        ),
    ],
)
def test_v2_production_policy_rejects_weak_reliability_gates(
    tmp_path: Path,
    section: str,
    message: str,
) -> None:
    path = _write_policy(
        tmp_path,
        '\n'.join(
            [
                'schema_version = "mendpact.policy.v2"',
                'name = "weak-production"',
                'profile = "production"',
                '',
                section,
            ]
        ),
    )

    with pytest.raises(PolicyConfigurationError, match=message):
        load_policy(path)


def test_local_profile_requires_explicit_target_allowances(tmp_path: Path) -> None:
    default_path = _write_policy(
        tmp_path,
        '\n'.join(
            [
                'schema_version = "mendpact.policy.v1"',
                'name = "local"',
                'profile = "local"',
            ]
        ),
    )
    default = load_policy(default_path)
    assert default.allow_private is False
    assert default.allow_insecure_http is False

    explicit_path = tmp_path / "local-explicit.toml"
    explicit_path.write_text(
        default_path.read_text(encoding="utf-8")
        + '\nallow_private = true\nallow_insecure_http = true\n',
        encoding="utf-8",
    )
    explicit = load_policy(explicit_path)

    assert explicit.profile == PolicyProfile.LOCAL
    assert explicit.allow_private is True
    assert explicit.allow_insecure_http is True
    assert target_policy(explicit).allow_private is True


def test_policy_records_only_bearer_environment_variable_name(tmp_path: Path) -> None:
    path = _write_policy(
        tmp_path,
        '\n'.join(
            [
                'schema_version = "mendpact.policy.v1"',
                'name = "production"',
                'profile = "production"',
                'bearer_token_env = "MENDPACT_ACCESS_TOKEN"',
            ]
        ),
    )

    policy = load_policy(path)

    assert policy.bearer_token_env == "MENDPACT_ACCESS_TOKEN"
    assert "secret" not in policy.model_dump_json()


def test_policy_rejects_invalid_bearer_environment_variable_name(
    tmp_path: Path,
) -> None:
    path = _write_policy(
        tmp_path,
        '\n'.join(
            [
                'schema_version = "mendpact.policy.v1"',
                'name = "production"',
                'profile = "production"',
                'bearer_token_env = "not a valid name"',
            ]
        ),
    )

    with pytest.raises(PolicyConfigurationError, match="String should match pattern"):
        load_policy(path)


@pytest.mark.parametrize(
    ("setting", "message"),
    [
        ("allow_private = true", "cannot allow private targets"),
        ("allow_insecure_http = true", "cannot allow insecure HTTP"),
        ('scan_fail_on = "critical"', "cannot be weaker than high"),
        ('contract_fail_on = "breaking"', "cannot be weaker than risky"),
    ],
)
def test_production_profile_rejects_weak_settings(
    tmp_path: Path,
    setting: str,
    message: str,
) -> None:
    path = _write_policy(
        tmp_path,
        '\n'.join(
            [
                'schema_version = "mendpact.policy.v1"',
                'name = "production"',
                'profile = "production"',
                setting,
            ]
        ),
    )

    with pytest.raises(PolicyConfigurationError, match=message):
        load_policy(path)


def test_rejects_unknown_policy_fields(tmp_path: Path) -> None:
    path = _write_policy(
        tmp_path,
        '\n'.join(
            [
                'schema_version = "mendpact.policy.v1"',
                'name = "production"',
                'profile = "production"',
                'ignore_failures = true',
            ]
        ),
    )

    with pytest.raises(PolicyConfigurationError, match="Extra inputs are not permitted"):
        load_policy(path)


def test_resolves_active_14_day_exact_waiver(tmp_path: Path) -> None:
    policy = load_policy(_waiver_policy(tmp_path), today=date(2026, 8, 10))

    assert len(policy.waivers) == 1
    waiver = policy.waivers[0]
    assert waiver.status == WaiverStatus.ACTIVE
    assert waiver.rule_id == "MP-TEST-001"
    assert waiver.subject == "tool:delete_project"
    assert waiver.approved_by == "security@example.com"


def test_rejects_waiver_longer_than_14_days(tmp_path: Path) -> None:
    path = _waiver_policy(tmp_path, expires_on="2026-08-16")

    with pytest.raises(PolicyConfigurationError, match="cannot exceed 14 days"):
        load_policy(path, today=date(2026, 8, 10))


def test_rejects_future_approval_date(tmp_path: Path) -> None:
    path = _waiver_policy(
        tmp_path,
        approved_on="2026-08-11",
        expires_on="2026-08-12",
    )

    with pytest.raises(PolicyConfigurationError, match="future approved_on"):
        load_policy(path, today=date(2026, 8, 10))


def test_rejects_duplicate_rule_and_subject_waivers(tmp_path: Path) -> None:
    path = _waiver_policy(tmp_path)
    source = path.read_text(encoding="utf-8")
    duplicate = source[source.index("[[waivers]]") :]
    path.write_text(source + "\n" + duplicate, encoding="utf-8")

    with pytest.raises(PolicyConfigurationError, match="duplicate rule_id and subject"):
        load_policy(path, today=date(2026, 8, 10))


def test_expired_waiver_remains_visible_but_is_not_applied(tmp_path: Path) -> None:
    policy = load_policy(_waiver_policy(tmp_path), today=date(2026, 8, 15))
    finding = Finding(
        rule_id="MP-TEST-001",
        severity=Severity.HIGH,
        title="Risky tool",
        message="The tool is risky.",
        subject="tool:delete_project",
    )

    applied = apply_finding_waivers([finding], policy)

    assert policy.waivers[0].status == WaiverStatus.EXPIRED
    assert applied[0].waiver is None


def test_waiver_requires_exact_rule_and_subject_and_cannot_suppress_critical(
    tmp_path: Path,
) -> None:
    policy = load_policy(_waiver_policy(tmp_path), today=date(2026, 8, 10))
    exact = Finding(
        rule_id="MP-TEST-001",
        severity=Severity.HIGH,
        title="Risky tool",
        message="The tool is risky.",
        subject="tool:delete_project",
    )
    wrong_subject = exact.model_copy(update={"subject": "tool:delete_account"})
    critical = exact.model_copy(update={"severity": Severity.CRITICAL})

    applied = apply_finding_waivers([exact, wrong_subject, critical], policy)

    assert applied[0].waiver is not None
    assert applied[1].waiver is None
    assert applied[2].waiver is None


def test_waiver_cannot_suppress_breaking_contract_change(tmp_path: Path) -> None:
    policy = load_policy(_waiver_policy(tmp_path), today=date(2026, 8, 10))
    risky = ContractChange(
        rule_id="MP-TEST-001",
        impact=ContractImpact.RISKY,
        kind=ContractChangeKind.MODIFIED,
        subject="tool:delete_project",
        path="/description",
        message="Description changed.",
    )
    breaking = risky.model_copy(update={"impact": ContractImpact.BREAKING})

    applied = apply_contract_waivers([risky, breaking], policy)

    assert applied[0].waiver is not None
    assert applied[1].waiver is None


@pytest.mark.anyio
async def test_active_waiver_prevents_matching_high_finding_from_failing_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = load_policy(
        _waiver_policy(tmp_path, rule_id="MP-MCP-004"),
        today=date(2026, 8, 10),
    )
    graph = CapabilityGraph(
        target="https://example.com/mcp",
        nodes=[
            CapabilityNode(
                id="tool:delete_project",
                kind=NodeKind.TOOL,
                name="delete_project",
                description="Permanently delete one project after explicit authorization.",
                input_schema={
                    "type": "object",
                    "properties": {"project_id": {"type": "string"}},
                    "required": ["project_id"],
                    "additionalProperties": False,
                },
            )
        ],
    )

    async def fake_validate(*args: object, **kwargs: object) -> None:
        return None

    async def fake_discover(*args: object, **kwargs: object) -> CapabilityGraph:
        return graph

    monkeypatch.setattr("mendpact.scanner.validate_target_url", fake_validate)
    monkeypatch.setattr("mendpact.scanner.discover_mcp_target", fake_discover)

    report = await scan_mcp_url(
        graph.target,
        failure_threshold=Severity.HIGH,
        policy=TargetPolicy(),
        applied_policy=policy,
    )

    assert report.status == ScanStatus.PASSED
    assert report.summary is not None
    assert report.summary.waived_finding_count == 1
    assert report.findings[0].waiver is not None


def test_active_waiver_prevents_matching_risky_change_from_failing_diff(
    tmp_path: Path,
) -> None:
    policy = load_policy(
        _waiver_policy(
            tmp_path,
            rule_id="MP-DIFF-003",
            subject="tool:read_status",
        ),
        today=date(2026, 8, 10),
    )
    baseline_node = CapabilityNode(
        id="tool:read_status",
        kind=NodeKind.TOOL,
        name="read_status",
        description="Read status.",
        input_schema={"type": "object", "additionalProperties": False},
    )
    candidate_node = baseline_node.model_copy(
        update={"description": "Read current status."}
    )
    baseline = ScanReport(
        target="https://example.com/mcp",
        status=ScanStatus.PASSED,
        failure_threshold=Severity.HIGH,
        graph=CapabilityGraph(target="https://example.com/mcp", nodes=[baseline_node]),
    )
    candidate = baseline.model_copy(
        update={
            "scan_id": "candidate",
            "graph": CapabilityGraph(
                target="https://example.com/mcp",
                nodes=[candidate_node],
            ),
        }
    )

    report = diff_scan_reports(
        baseline,
        candidate,
        failure_threshold=ContractImpact.RISKY,
        policy=policy,
    )

    assert report.status == ScanStatus.PASSED
    assert report.summary.waived_change_count == 1
    assert report.changes[0].waiver is not None
