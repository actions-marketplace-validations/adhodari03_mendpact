"""Versioned policy-as-code loading and production safety validation."""

from __future__ import annotations

import tomllib
from datetime import UTC, date, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    ValidationError,
    model_validator,
)

from mendpact.domain import (
    ContractChange,
    ContractImpact,
    Finding,
    ModelComparisonThresholds,
    PolicyProfile,
    PolicySnapshot,
    PolicyWaiver,
    SemanticCalibrationPolicy,
    Severity,
    WaiverStatus,
)
from mendpact.security.targets import TargetPolicy


class PolicyConfigurationError(ValueError):
    """Raised when a policy file is invalid or weakens its selected profile."""


class _WaiverDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=1, pattern=r"^[A-Z][A-Z0-9-]+$")
    subject: str = Field(min_length=1, max_length=300)
    reason: str = Field(min_length=10, max_length=500)
    approved_by: str = Field(min_length=1, max_length=120)
    approved_on: date
    expires_on: date

    @model_validator(mode="after")
    def validate_duration(self) -> _WaiverDocument:
        duration = (self.expires_on - self.approved_on).days
        if duration < 1:
            raise ValueError("waiver expires_on must be after approved_on")
        if duration > 14:
            raise ValueError("waiver duration cannot exceed 14 days")
        return self


class _ModelComparisonDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_overall_pass_rate_drop: float = Field(default=0.0, ge=0.0, le=1.0)
    max_scenario_pass_rate_drop: float = Field(default=0.0, ge=0.0, le=1.0)
    allow_new_confusions: StrictBool = False


class _SemanticCalibrationDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    min_calibration_examples: int = Field(default=4, ge=2)
    min_validation_examples: int = Field(default=4, ge=2)
    min_validation_balanced_accuracy: float = Field(default=0.8, ge=0.0, le=1.0)
    max_validation_false_accept_rate: float = Field(default=0.1, ge=0.0, le=1.0)


def _resolved_semantic_calibration(
    configured: _SemanticCalibrationDocument | None,
    profile: PolicyProfile,
) -> SemanticCalibrationPolicy:
    defaults = (
        SemanticCalibrationPolicy(
            min_calibration_examples=20,
            min_validation_examples=20,
            min_validation_balanced_accuracy=0.8,
            max_validation_false_accept_rate=0.05,
        )
        if profile == PolicyProfile.PRODUCTION
        else SemanticCalibrationPolicy()
    )
    if configured is None:
        return defaults
    return defaults.model_copy(update=configured.model_dump(exclude_unset=True))


class _PolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["mendpact.policy.v1", "mendpact.policy.v2"]
    name: str = Field(min_length=1, max_length=80)
    profile: PolicyProfile
    scan_fail_on: Severity | None = None
    contract_fail_on: ContractImpact | None = None
    allow_private: StrictBool | None = None
    allow_insecure_http: StrictBool | None = None
    bearer_token_env: str | None = Field(
        default=None,
        min_length=1,
        max_length=120,
        pattern=r"^[A-Za-z_][A-Za-z0-9_]*$",
    )
    waivers: list[_WaiverDocument] = Field(default_factory=list)
    model_comparison: _ModelComparisonDocument | None = None
    semantic_calibration: _SemanticCalibrationDocument | None = None

    @model_validator(mode="after")
    def validate_production_boundaries(self) -> _PolicyDocument:
        keys = [(waiver.rule_id, waiver.subject) for waiver in self.waivers]
        if len(keys) != len(set(keys)):
            raise ValueError("policy contains duplicate rule_id and subject waivers")
        if self.schema_version == "mendpact.policy.v1" and (
            self.model_comparison is not None or self.semantic_calibration is not None
        ):
            raise ValueError(
                "model_comparison and semantic_calibration require mendpact.policy.v2"
            )
        if self.profile != PolicyProfile.PRODUCTION:
            return self
        if self.allow_private:
            raise ValueError("production policies cannot allow private targets")
        if self.allow_insecure_http:
            raise ValueError("production policies cannot allow insecure HTTP")
        if self.scan_fail_on is not None and self.scan_fail_on.rank > Severity.HIGH.rank:
            raise ValueError("production scan_fail_on cannot be weaker than high")
        if (
            self.contract_fail_on is not None
            and self.contract_fail_on.rank > ContractImpact.RISKY.rank
        ):
            raise ValueError("production contract_fail_on cannot be weaker than risky")
        if self.model_comparison is not None:
            if self.model_comparison.max_overall_pass_rate_drop > 0.05:
                raise ValueError(
                    "production model comparison overall drop cannot exceed 0.05"
                )
            if self.model_comparison.max_scenario_pass_rate_drop > 0.1:
                raise ValueError(
                    "production model comparison scenario drop cannot exceed 0.10"
                )
            if self.model_comparison.allow_new_confusions:
                raise ValueError(
                    "production model comparison cannot allow new confusion pairs"
                )
        if self.semantic_calibration is not None:
            semantic_calibration = _resolved_semantic_calibration(
                self.semantic_calibration,
                self.profile,
            )
            if semantic_calibration.min_calibration_examples < 20:
                raise ValueError(
                    "production semantic calibration requires at least 20 calibration examples"
                )
            if semantic_calibration.min_validation_examples < 20:
                raise ValueError(
                    "production semantic calibration requires at least 20 validation examples"
                )
            if semantic_calibration.min_validation_balanced_accuracy < 0.8:
                raise ValueError(
                    "production semantic calibration balanced accuracy cannot be below 0.80"
                )
            if semantic_calibration.max_validation_false_accept_rate > 0.05:
                raise ValueError(
                    "production semantic calibration false-accept rate cannot exceed 0.05"
                )
        return self


def _resolved(
    document: _PolicyDocument,
    *,
    source_sha256: str,
    today: date,
) -> PolicySnapshot:
    default_contract_threshold = (
        ContractImpact.RISKY
        if document.profile == PolicyProfile.PRODUCTION
        else ContractImpact.BREAKING
    )
    waivers: list[PolicyWaiver] = []
    for waiver in document.waivers:
        if waiver.approved_on > today:
            raise PolicyConfigurationError(
                f"waiver {waiver.rule_id} for {waiver.subject} has a future approved_on date"
            )
        waivers.append(
            PolicyWaiver(
                **waiver.model_dump(),
                status=(
                    WaiverStatus.EXPIRED
                    if waiver.expires_on <= today
                    else WaiverStatus.ACTIVE
                ),
            )
        )
    if document.schema_version == "mendpact.policy.v2":
        model_comparison = ModelComparisonThresholds.model_validate(
            document.model_comparison.model_dump()
            if document.model_comparison is not None
            else {}
        )
        semantic_calibration = _resolved_semantic_calibration(
            document.semantic_calibration,
            document.profile,
        )
    else:
        model_comparison = None
        semantic_calibration = None
    return PolicySnapshot(
        schema_version=document.schema_version,
        source_sha256=source_sha256,
        name=document.name,
        profile=document.profile,
        scan_fail_on=document.scan_fail_on or Severity.HIGH,
        contract_fail_on=document.contract_fail_on or default_contract_threshold,
        allow_private=(
            document.allow_private if document.allow_private is not None else False
        ),
        allow_insecure_http=(
            document.allow_insecure_http
            if document.allow_insecure_http is not None
            else False
        ),
        bearer_token_env=document.bearer_token_env,
        waivers=waivers,
        model_comparison=model_comparison,
        semantic_calibration=semantic_calibration,
    )


def load_policy(path: Path, *, today: date | None = None) -> PolicySnapshot:
    """Load, validate, and resolve a MendPact TOML policy."""
    try:
        source = path.read_text(encoding="utf-8")
        payload: dict[str, Any] = tomllib.loads(source)
        document = _PolicyDocument.model_validate(payload)
    except OSError as exc:
        raise PolicyConfigurationError(f"could not read policy: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise PolicyConfigurationError(f"invalid TOML: {exc}") from exc
    except ValidationError as exc:
        errors = "; ".join(error["msg"] for error in exc.errors())
        raise PolicyConfigurationError(errors) from exc
    resolved_today = today or datetime.now(UTC).date()
    return _resolved(
        document,
        source_sha256=sha256(source.encode("utf-8")).hexdigest(),
        today=resolved_today,
    )


def _active_waiver(
    snapshot: PolicySnapshot | None,
    *,
    rule_id: str,
    subject: str | None,
) -> PolicyWaiver | None:
    if snapshot is None or subject is None:
        return None
    return next(
        (
            waiver
            for waiver in snapshot.waivers
            if waiver.status == WaiverStatus.ACTIVE
            and waiver.rule_id == rule_id
            and waiver.subject == subject
        ),
        None,
    )


def apply_finding_waivers(
    findings: list[Finding],
    snapshot: PolicySnapshot | None,
) -> list[Finding]:
    """Attach active exact waivers except to critical findings."""
    return [
        finding.model_copy(
            update={
                "waiver": (
                    None
                    if finding.severity == Severity.CRITICAL
                    else _active_waiver(
                        snapshot,
                        rule_id=finding.rule_id,
                        subject=finding.subject,
                    )
                )
            }
        )
        for finding in findings
    ]


def apply_contract_waivers(
    changes: list[ContractChange],
    snapshot: PolicySnapshot | None,
) -> list[ContractChange]:
    """Attach active exact waivers except to breaking contract changes."""
    return [
        change.model_copy(
            update={
                "waiver": (
                    None
                    if change.impact == ContractImpact.BREAKING
                    else _active_waiver(
                        snapshot,
                        rule_id=change.rule_id,
                        subject=change.subject,
                    )
                )
            }
        )
        for change in changes
    ]


def target_policy(snapshot: PolicySnapshot) -> TargetPolicy:
    """Translate a resolved product policy into the network validation boundary."""
    return TargetPolicy(
        allow_private=snapshot.allow_private,
        allow_insecure_http=snapshot.allow_insecure_http,
    )


def model_comparison_policy(snapshot: PolicySnapshot) -> ModelComparisonThresholds:
    """Resolve model-comparison thresholds from a v2 reliability policy."""

    if snapshot.model_comparison is None:
        raise PolicyConfigurationError(
            "model comparison requires schema_version mendpact.policy.v2"
        )
    return snapshot.model_comparison


def semantic_calibration_policy(snapshot: PolicySnapshot) -> SemanticCalibrationPolicy:
    """Resolve semantic-calibration thresholds from a v2 reliability policy."""

    if snapshot.semantic_calibration is None:
        raise PolicyConfigurationError(
            "semantic calibration requires schema_version mendpact.policy.v2"
        )
    return snapshot.semantic_calibration
