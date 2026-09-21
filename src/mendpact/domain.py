"""Core, provider-neutral data structures used by MendPact."""

from __future__ import annotations

from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mendpact.argument_matching import (
    ArgumentNormalizer,
    normalization_configuration_errors,
)


class NodeKind(StrEnum):
    SERVER = "server"
    TOOL = "tool"
    RESOURCE = "resource"
    RESOURCE_TEMPLATE = "resource_template"
    PROMPT = "prompt"


class Relationship(StrEnum):
    EXPOSES = "exposes"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class ScanStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"


class OAuthMetadataStatus(StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    NOT_FOUND = "not_found"


class PolicyProfile(StrEnum):
    """Security posture selected by a versioned MendPact policy."""

    PRODUCTION = "production"
    LOCAL = "local"


class WaiverStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"


class PolicyWaiver(BaseModel):
    """One exact, time-bounded exception retained as report evidence."""

    rule_id: str
    subject: str
    reason: str
    approved_by: str
    approved_on: date
    expires_on: date
    status: WaiverStatus


class RegressionImpact(StrEnum):
    """How a baseline comparison finding affects the evaluation result."""

    WARNING = "warning"
    FAILURE = "failure"


class ConformanceCheckStatus(StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    WARNING = "WARNING"
    SKIPPED = "SKIPPED"
    INFO = "INFO"


class ArgumentMatch(StrEnum):
    """How expected arguments are compared with a model-produced tool call."""

    SUBSET = "subset"
    EXACT = "exact"


class CalibrationSplit(StrEnum):
    """Dataset partition used to fit or independently validate a threshold."""

    CALIBRATION = "calibration"
    VALIDATION = "validation"


class HumanLabel(StrEnum):
    """Human judgment for one semantic-grading example."""

    ACCEPT = "accept"
    REJECT = "reject"


class CapabilityNode(BaseModel):
    id: str
    kind: NodeKind
    name: str
    title: str | None = None
    description: str | None = None
    input_schema: dict[str, Any] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CapabilityEdge(BaseModel):
    source: str
    target: str
    relationship: Relationship = Relationship.EXPOSES


class CapabilityGraph(BaseModel):
    target: str
    protocol: str = "mcp"
    protocol_version: str | None = None
    server_name: str | None = None
    server_version: str | None = None
    instructions: str | None = None
    nodes: list[CapabilityNode] = Field(default_factory=list)
    edges: list[CapabilityEdge] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    def nodes_of_kind(self, kind: NodeKind) -> list[CapabilityNode]:
        return [node for node in self.nodes if node.kind == kind]


class Finding(BaseModel):
    rule_id: str
    severity: Severity
    title: str
    message: str
    subject: str | None = None
    waiver: PolicyWaiver | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)


class ScanSummary(BaseModel):
    node_count: int
    tool_count: int
    resource_count: int
    prompt_count: int
    finding_count: int
    waived_finding_count: int = 0
    findings_by_severity: dict[str, int]


class AuthorizationServerEvidence(BaseModel):
    """Validated discovery evidence for one OAuth authorization server."""

    issuer: str
    metadata_url: str | None = None
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    code_challenge_methods_supported: list[str] = Field(default_factory=list)
    client_id_metadata_document_supported: bool = False


class OAuthMetadataEvidence(BaseModel):
    """Read-only authorization metadata inspection retained in a scan report."""

    status: OAuthMetadataStatus
    credential_source: Literal["none", "environment"] = "none"
    bearer_token_env: str | None = None
    challenge_metadata_url: str | None = None
    challenge_scopes: list[str] = Field(default_factory=list)
    protected_resource_metadata_url: str | None = None
    resource: str | None = None
    authorization_servers: list[str] = Field(default_factory=list)
    scopes_supported: list[str] = Field(default_factory=list)
    server_metadata: list[AuthorizationServerEvidence] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class RuleFindingChangeKind(StrEnum):
    """How one deterministic rule/subject pair changed during an offline recheck."""

    INTRODUCED = "introduced"
    RESOLVED = "resolved"
    RECLASSIFIED = "reclassified"


class RuleFindingChange(BaseModel):
    """One actionable difference between recorded and current deterministic findings."""

    kind: RuleFindingChangeKind
    rule_id: str
    subject: str | None = None
    before_severity: Severity | None = None
    after_severity: Severity | None = None

    @model_validator(mode="after")
    def validate_severity_transition(self) -> RuleFindingChange:
        if self.kind == RuleFindingChangeKind.INTRODUCED:
            valid = self.before_severity is None and self.after_severity is not None
        elif self.kind == RuleFindingChangeKind.RESOLVED:
            valid = self.before_severity is not None and self.after_severity is None
        else:
            valid = (
                self.before_severity is not None
                and self.after_severity is not None
                and self.before_severity != self.after_severity
            )
        if not valid:
            raise ValueError("rule finding change has an invalid severity transition")
        return self


class ScanRuleDelta(BaseModel):
    """Compact difference between old and current deterministic rule outcomes."""

    schema_version: Literal["mendpact.scan-rule-delta.v1"] = (
        "mendpact.scan-rule-delta.v1"
    )
    introduced_count: int = Field(ge=0)
    resolved_count: int = Field(ge=0)
    reclassified_count: int = Field(ge=0)
    unchanged_count: int = Field(ge=0)
    changes: list[RuleFindingChange] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_counts_and_unique_changes(self) -> ScanRuleDelta:
        expected = {
            RuleFindingChangeKind.INTRODUCED: self.introduced_count,
            RuleFindingChangeKind.RESOLVED: self.resolved_count,
            RuleFindingChangeKind.RECLASSIFIED: self.reclassified_count,
        }
        for kind, count in expected.items():
            if sum(change.kind == kind for change in self.changes) != count:
                raise ValueError("rule delta counts do not match its changes")
        identities = [(change.rule_id, change.subject) for change in self.changes]
        if len(identities) != len(set(identities)):
            raise ValueError("rule delta contains duplicate rule and subject changes")
        return self


class ScanRecheckEvidence(BaseModel):
    """Provenance for deterministic rules rerun against a saved capability graph."""

    schema_version: Literal["mendpact.scan-recheck.v1"] = "mendpact.scan-recheck.v1"
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    rechecked_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    mendpact_version: str = Field(min_length=1)
    source_status: ScanStatus
    preserved_authorization_finding_count: int = Field(ge=0)
    authorization_refreshed: Literal[False] = False
    rule_delta: ScanRuleDelta | None = None


class ScanReport(BaseModel):
    schema_version: str = "mendpact.scan.v1"
    scan_id: str = Field(default_factory=lambda: str(uuid4()))
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    target: str
    status: ScanStatus
    failure_threshold: Severity
    policy: PolicySnapshot | None = None
    graph: CapabilityGraph | None = None
    authorization: OAuthMetadataEvidence | None = None
    recheck: ScanRecheckEvidence | None = None
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    summary: ScanSummary | None = None


class AuthorizationAuditReport(BaseModel):
    """Versioned credential-free audit of MCP OAuth discovery metadata."""

    schema_version: Literal["mendpact.authorization.v1"] = (
        "mendpact.authorization.v1"
    )
    audit_id: str = Field(default_factory=lambda: str(uuid4()))
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    target: str
    status: ScanStatus
    failure_threshold: Severity
    policy: PolicySnapshot | None = None
    metadata: OAuthMetadataEvidence | None = None
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class ContractImpact(StrEnum):
    """Compatibility impact assigned to one contract change."""

    COMPATIBLE = "compatible"
    RISKY = "risky"
    BREAKING = "breaking"

    @property
    def rank(self) -> int:
        return {
            ContractImpact.COMPATIBLE: 0,
            ContractImpact.RISKY: 1,
            ContractImpact.BREAKING: 2,
        }[self]


class PolicySnapshot(BaseModel):
    """Resolved policy evidence embedded in scan and guard reports."""

    schema_version: Literal["mendpact.policy.v1", "mendpact.policy.v2"] = (
        "mendpact.policy.v1"
    )
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    name: str
    profile: PolicyProfile
    scan_fail_on: Severity
    contract_fail_on: ContractImpact
    allow_private: bool = False
    allow_insecure_http: bool = False
    bearer_token_env: str | None = None
    waivers: list[PolicyWaiver] = Field(default_factory=list)
    model_comparison: ModelComparisonThresholds | None = None
    semantic_calibration: SemanticCalibrationPolicy | None = None


class ContractChangeKind(StrEnum):
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"


class ContractChange(BaseModel):
    """One deterministic difference between two MCP capability graphs."""

    rule_id: str
    impact: ContractImpact
    kind: ContractChangeKind
    subject: str
    path: str
    message: str
    waiver: PolicyWaiver | None = None
    before: Any = None
    after: Any = None
    affected_scenarios: list[str] = Field(default_factory=list)


class ContractDiffSummary(BaseModel):
    change_count: int
    waived_change_count: int = 0
    changes_by_impact: dict[str, int]
    affected_scenario_count: int


class ContractDiffReport(BaseModel):
    """Versioned compatibility report for two scan artifacts."""

    schema_version: Literal["mendpact.contract-diff.v1"] = (
        "mendpact.contract-diff.v1"
    )
    diff_id: str = Field(default_factory=lambda: str(uuid4()))
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    baseline_scan_id: str
    candidate_scan_id: str
    baseline_target: str
    candidate_target: str
    status: ScanStatus
    failure_threshold: ContractImpact
    changes: list[ContractChange] = Field(default_factory=list)
    summary: ContractDiffSummary
    errors: list[str] = Field(default_factory=list)


class SpecReference(BaseModel):
    id: str
    url: str | None = None


class ConformanceCheck(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str
    description: str
    status: ConformanceCheckStatus
    timestamp: str | None = None
    spec_references: list[SpecReference] = Field(default_factory=list, alias="specReferences")
    details: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    error_message: str | None = Field(default=None, alias="errorMessage")
    logs: list[str] = Field(default_factory=list)


class ConformanceScenario(BaseModel):
    name: str
    artifact: str
    checks: list[ConformanceCheck] = Field(default_factory=list)


class ConformanceSummary(BaseModel):
    scenario_count: int
    check_count: int
    checks_by_status: dict[str, int]


class ConformanceReport(BaseModel):
    schema_version: str = "mendpact.conformance.v1"
    run_id: str = Field(default_factory=lambda: str(uuid4()))
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    target: str
    status: ScanStatus
    runner_package: str
    runner_version: str
    command: list[str] = Field(default_factory=list)
    exit_code: int | None = None
    scenarios: list[ConformanceScenario] = Field(default_factory=list)
    summary: ConformanceSummary | None = None
    stdout: str = ""
    stderr: str = ""
    errors: list[str] = Field(default_factory=list)


class BehaviorExpectation(BaseModel):
    """The observable tool decision required for a scenario to pass."""

    model_config = ConfigDict(extra="forbid")

    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    argument_match: ArgumentMatch = ArgumentMatch.SUBSET
    argument_normalization: dict[str, list[ArgumentNormalizer]] = Field(
        default_factory=dict
    )
    forbidden_tools: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_argument_normalization(self) -> BehaviorExpectation:
        errors = normalization_configuration_errors(
            self.arguments,
            self.argument_normalization,
        )
        if errors:
            raise ValueError(" ".join(errors))
        return self


class BehaviorScenario(BaseModel):
    """A natural-language task paired with a deterministic expectation."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, pattern=r"^[a-z0-9][a-z0-9_-]*$")
    name: str = Field(min_length=1)
    task: str = Field(min_length=1)
    expectation: BehaviorExpectation


class BehaviorSuite(BaseModel):
    """Portable collection of behavioral scenarios loaded by the CLI."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["mendpact.scenario.v1"] = "mendpact.scenario.v1"
    name: str = Field(min_length=1)
    scenarios: list[BehaviorScenario] = Field(min_length=1)


class ReplayDecision(BaseModel):
    """One recorded model decision used by the deterministic replay driver."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    attempt: int = Field(default=1, ge=1)
    selected_tool: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    message: str | None = None


class ReplayPlan(BaseModel):
    """Versioned replay input that stands in for a live model provider."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["mendpact.replay.v1"] = "mendpact.replay.v1"
    model: str = Field(min_length=1)
    decisions: list[ReplayDecision] = Field(min_length=1)


class ToolCallTrace(BaseModel):
    """Provider-neutral evidence describing one model tool-selection decision."""

    scenario_id: str
    attempt: int = Field(ge=1)
    provider: str
    model: str
    available_tools: list[str] = Field(default_factory=list)
    selected_tool: str | None = None
    provider_selected_tool: str | None = None
    tool_call_count: int = Field(default=1, ge=0)
    arguments: dict[str, Any] = Field(default_factory=dict)
    arguments_parse_error: str | None = None
    message: str | None = None
    response_id: str | None = None
    latency_ms: float | None = Field(default=None, ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)


class BehaviorGrade(BaseModel):
    """Deterministic checks applied to one tool-call trace."""

    passed: bool
    tool_selected: bool
    single_tool_selected: bool
    tool_exists: bool
    expected_tool_selected: bool
    arguments_valid: bool
    expected_arguments_match: bool
    forbidden_tool_selected: bool
    reasons: list[str] = Field(default_factory=list)


class BehaviorTrial(BaseModel):
    scenario: BehaviorScenario
    trace: ToolCallTrace
    grade: BehaviorGrade


class ConfusionEdge(BaseModel):
    intended_tool: str
    selected_tool: str
    count: int = Field(ge=1)


class BehaviorSummary(BaseModel):
    scenario_count: int
    trial_count: int
    passed_trials: int
    failed_trials: int
    pass_rate: float
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)
    total_latency_ms: float = Field(default=0, ge=0)
    confusion_edges: list[ConfusionEdge] = Field(default_factory=list)


class BehaviorThresholds(BaseModel):
    """CI policy stored with a behavior baseline."""

    model_config = ConfigDict(extra="forbid")

    min_pass_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    max_pass_rate_drop: float = Field(default=0.0, ge=0.0, le=1.0)
    max_failed_trials: int | None = Field(default=None, ge=0)
    allow_new_confusions: bool = False
    require_same_scenarios: bool = True
    require_same_trial_count: bool = True
    fail_on_driver_change: bool = False
    fail_on_model_change: bool = False


class BehaviorBaseline(BaseModel):
    """Versioned behavioral snapshot used to detect future regressions."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["mendpact.baseline.v1"] = "mendpact.baseline.v1"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source_run_id: str
    suite_name: str
    driver: str
    model: str
    repetitions: int = Field(ge=1)
    scenario_ids: list[str] = Field(min_length=1)
    trial_count: int = Field(ge=1)
    passed_trials: int = Field(ge=0)
    failed_trials: int = Field(ge=0)
    pass_rate: float = Field(ge=0.0, le=1.0)
    confusion_edges: list[ConfusionEdge] = Field(default_factory=list)
    thresholds: BehaviorThresholds = Field(default_factory=BehaviorThresholds)


class RegressionFinding(BaseModel):
    """One meaningful difference between a baseline and a current run."""

    rule_id: str
    impact: RegressionImpact
    message: str
    baseline_value: Any = None
    current_value: Any = None


class BehaviorRegression(BaseModel):
    """Result of comparing a behavior report with a saved baseline."""

    schema_version: Literal["mendpact.regression.v1"] = "mendpact.regression.v1"
    status: ScanStatus
    baseline_run_id: str
    baseline_pass_rate: float = Field(ge=0.0, le=1.0)
    current_pass_rate: float = Field(ge=0.0, le=1.0)
    pass_rate_drop: float = Field(ge=0.0, le=1.0)
    z_score: float | None = None
    one_sided_p_value: float | None = Field(default=None, ge=0.0, le=1.0)
    thresholds: BehaviorThresholds
    findings: list[RegressionFinding] = Field(default_factory=list)


class BehaviorReport(BaseModel):
    schema_version: Literal["mendpact.behavior.v1"] = "mendpact.behavior.v1"
    run_id: str = Field(default_factory=lambda: str(uuid4()))
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    target: str
    status: ScanStatus
    suite_name: str
    driver: str
    model: str
    repetitions: int = Field(ge=1)
    tool_catalog: list[str] = Field(default_factory=list)
    trials: list[BehaviorTrial] = Field(default_factory=list)
    summary: BehaviorSummary | None = None
    regression: BehaviorRegression | None = None
    errors: list[str] = Field(default_factory=list)


class ModelScenarioSnapshot(BaseModel):
    """Aggregated outcome for one scenario in one model run."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    scenario_name: str
    expected_tool: str
    trial_count: int = Field(ge=1)
    passed_trials: int = Field(ge=0)
    failed_trials: int = Field(ge=0)
    pass_rate: float = Field(ge=0.0, le=1.0)
    selection_counts: dict[str, int] = Field(default_factory=dict)


class ModelRunSnapshot(BaseModel):
    """Provider-neutral summary of one complete behavior report."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    generated_at: datetime
    driver: str
    model: str
    resolved_models: list[str] = Field(default_factory=list)
    scenario_count: int = Field(ge=1)
    trial_count: int = Field(ge=1)
    passed_trials: int = Field(ge=0)
    failed_trials: int = Field(ge=0)
    pass_rate: float = Field(ge=0.0, le=1.0)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)
    measured_latency_trials: int = Field(ge=0)
    average_latency_ms: float | None = Field(default=None, ge=0)
    confusion_edges: list[ConfusionEdge] = Field(default_factory=list)
    scenarios: list[ModelScenarioSnapshot] = Field(default_factory=list)


class ModelComparisonThresholds(BaseModel):
    """Deterministic failure policy for model-version comparisons."""

    model_config = ConfigDict(extra="forbid")

    max_overall_pass_rate_drop: float = Field(default=0.0, ge=0.0, le=1.0)
    max_scenario_pass_rate_drop: float = Field(default=0.0, ge=0.0, le=1.0)
    allow_new_confusions: bool = False


class ModelComparisonFinding(BaseModel):
    """One compatibility difference between a reference and candidate run."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    impact: RegressionImpact
    message: str
    scenario_id: str | None = None
    reference_value: Any = None
    candidate_value: Any = None


class ModelScenarioDelta(BaseModel):
    """Per-scenario quality change for one candidate model."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    reference_pass_rate: float = Field(ge=0.0, le=1.0)
    candidate_pass_rate: float = Field(ge=0.0, le=1.0)
    pass_rate_delta: float = Field(ge=-1.0, le=1.0)
    reference_selection_counts: dict[str, int] = Field(default_factory=dict)
    candidate_selection_counts: dict[str, int] = Field(default_factory=dict)


class ModelCandidateComparison(BaseModel):
    """Compatibility result for one candidate against the reference run."""

    model_config = ConfigDict(extra="forbid")

    reference_run_id: str
    candidate_run_id: str
    status: ScanStatus
    pass_rate_delta: float = Field(ge=-1.0, le=1.0)
    new_confusion_edges: list[ConfusionEdge] = Field(default_factory=list)
    scenarios: list[ModelScenarioDelta] = Field(default_factory=list)
    findings: list[ModelComparisonFinding] = Field(default_factory=list)


class ModelComparisonReport(BaseModel):
    """Versioned offline comparison of provider-neutral behavior reports."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["mendpact.model-comparison.v1"] = (
        "mendpact.model-comparison.v1"
    )
    comparison_id: str = Field(default_factory=lambda: str(uuid4()))
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    target: str
    suite_name: str
    status: ScanStatus
    policy: PolicySnapshot | None = None
    thresholds: ModelComparisonThresholds
    reference: ModelRunSnapshot
    candidates: list[ModelRunSnapshot] = Field(min_length=1)
    comparisons: list[ModelCandidateComparison] = Field(min_length=1)
    errors: list[str] = Field(default_factory=list)


class SemanticLabelExample(BaseModel):
    """One human-labelled example paired with a saved semantic-grader score."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, pattern=r"^[a-z0-9][a-z0-9_-]*$")
    scenario_id: str = Field(min_length=1)
    split: CalibrationSplit
    task: str = Field(min_length=1)
    expected_behavior: str = Field(min_length=1)
    observed_behavior: str = Field(min_length=1)
    human_label: HumanLabel
    semantic_score: float = Field(ge=0.0, le=1.0)
    rationale: str | None = Field(default=None, min_length=1)


class SemanticLabelSet(BaseModel):
    """Versioned human labels and provider-neutral semantic scores."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["mendpact.semantic-labels.v1"] = (
        "mendpact.semantic-labels.v1"
    )
    name: str = Field(min_length=1)
    grader: str = Field(min_length=1)
    grader_version: str = Field(min_length=1)
    examples: list[SemanticLabelExample] = Field(min_length=2)

    @model_validator(mode="after")
    def validate_unique_example_ids(self) -> SemanticLabelSet:
        identifiers = [example.id for example in self.examples]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("Semantic label example IDs must be unique.")
        return self


class SemanticCalibrationPolicy(BaseModel):
    """Minimum independent evidence required to trust a semantic grader."""

    model_config = ConfigDict(extra="forbid")

    min_calibration_examples: int = Field(default=4, ge=2)
    min_validation_examples: int = Field(default=4, ge=2)
    min_validation_balanced_accuracy: float = Field(default=0.8, ge=0.0, le=1.0)
    max_validation_false_accept_rate: float = Field(default=0.1, ge=0.0, le=1.0)


class SemanticCalibrationMetrics(BaseModel):
    """Confusion matrix and quality metrics for one dataset split."""

    model_config = ConfigDict(extra="forbid")

    example_count: int = Field(ge=0)
    accepted_labels: int = Field(ge=0)
    rejected_labels: int = Field(ge=0)
    true_accepts: int = Field(ge=0)
    true_rejects: int = Field(ge=0)
    false_accepts: int = Field(ge=0)
    false_rejects: int = Field(ge=0)
    accuracy: float = Field(ge=0.0, le=1.0)
    balanced_accuracy: float = Field(ge=0.0, le=1.0)
    precision: float = Field(ge=0.0, le=1.0)
    recall: float = Field(ge=0.0, le=1.0)
    specificity: float = Field(ge=0.0, le=1.0)
    false_accept_rate: float = Field(ge=0.0, le=1.0)


class SemanticCalibrationDisagreement(BaseModel):
    """Auditable example where the calibrated grader and a human differ."""

    model_config = ConfigDict(extra="forbid")

    example_id: str
    scenario_id: str
    split: CalibrationSplit
    semantic_score: float = Field(ge=0.0, le=1.0)
    human_label: HumanLabel
    predicted_label: HumanLabel
    rationale: str | None = None


class SemanticCalibrationFinding(BaseModel):
    """One policy result from independent semantic-grader validation."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    impact: RegressionImpact
    message: str
    observed_value: int | float
    required_value: int | float


class SemanticCalibrationReport(BaseModel):
    """Versioned evidence that calibrates and validates a semantic-score threshold."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["mendpact.semantic-calibration.v1"] = (
        "mendpact.semantic-calibration.v1"
    )
    calibration_id: str = Field(default_factory=lambda: str(uuid4()))
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    status: ScanStatus
    label_set_name: str
    label_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    grader: str
    grader_version: str
    selected_threshold: float = Field(ge=0.0, le=1.0)
    source_policy: PolicySnapshot | None = None
    policy: SemanticCalibrationPolicy
    calibration: SemanticCalibrationMetrics
    validation: SemanticCalibrationMetrics
    disagreements: list[SemanticCalibrationDisagreement] = Field(default_factory=list)
    findings: list[SemanticCalibrationFinding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class GuardSummary(BaseModel):
    """Stage-level outcome for one unified guard run."""

    scan_status: ScanStatus
    contract_status: ScanStatus | None = None
    behavior_status: ScanStatus | None = None
    affected_scenario_count: int = Field(default=0, ge=0)
    evaluated_scenario_count: int = Field(default=0, ge=0)


class GuardReport(BaseModel):
    """Versioned CI report combining scan, diff, and affected replays."""

    schema_version: Literal["mendpact.guard.v1"] = "mendpact.guard.v1"
    guard_id: str = Field(default_factory=lambda: str(uuid4()))
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    target: str
    status: ScanStatus
    policy: PolicySnapshot | None = None
    scan: ScanReport
    contract_diff: ContractDiffReport | None = None
    behavior: BehaviorReport | None = None
    behavior_skipped_reason: str | None = None
    summary: GuardSummary
    errors: list[str] = Field(default_factory=list)


def summarize(graph: CapabilityGraph, findings: list[Finding]) -> ScanSummary:
    counts = {severity.value: 0 for severity in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1

    return ScanSummary(
        node_count=len(graph.nodes),
        tool_count=len(graph.nodes_of_kind(NodeKind.TOOL)),
        resource_count=len(graph.nodes_of_kind(NodeKind.RESOURCE))
        + len(graph.nodes_of_kind(NodeKind.RESOURCE_TEMPLATE)),
        prompt_count=len(graph.nodes_of_kind(NodeKind.PROMPT)),
        finding_count=len(findings),
        waived_finding_count=sum(finding.waiver is not None for finding in findings),
        findings_by_severity=counts,
    )


def summarize_conformance(scenarios: list[ConformanceScenario]) -> ConformanceSummary:
    counts = {status.value: 0 for status in ConformanceCheckStatus}
    for scenario in scenarios:
        for check in scenario.checks:
            counts[check.status.value] += 1

    return ConformanceSummary(
        scenario_count=len(scenarios),
        check_count=sum(len(scenario.checks) for scenario in scenarios),
        checks_by_status=counts,
    )
