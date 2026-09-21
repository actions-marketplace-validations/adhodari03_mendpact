"""Offline calibration of semantic-grader scores against human labels."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from mendpact.domain import (
    CalibrationSplit,
    HumanLabel,
    PolicySnapshot,
    RegressionImpact,
    ScanStatus,
    SemanticCalibrationDisagreement,
    SemanticCalibrationFinding,
    SemanticCalibrationMetrics,
    SemanticCalibrationPolicy,
    SemanticCalibrationReport,
    SemanticLabelExample,
    SemanticLabelSet,
)


def load_semantic_label_set(path: Path) -> SemanticLabelSet:
    """Load a versioned set of human labels and saved grader scores."""

    return SemanticLabelSet.model_validate_json(path.read_text(encoding="utf-8"))


def semantic_label_set_digest(label_set: SemanticLabelSet) -> str:
    """Return a formatting-independent digest of the complete labelled dataset."""

    canonical = json.dumps(
        label_set.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _split_examples(
    label_set: SemanticLabelSet,
    split: CalibrationSplit,
) -> list[SemanticLabelExample]:
    return [example for example in label_set.examples if example.split == split]


def _require_label_diversity(
    examples: list[SemanticLabelExample],
    split: CalibrationSplit,
) -> None:
    labels = {example.human_label for example in examples}
    if labels != {HumanLabel.ACCEPT, HumanLabel.REJECT}:
        raise ValueError(
            f"The {split.value} split must contain both accept and reject human labels."
        )


def _predicted_label(score: float, threshold: float) -> HumanLabel:
    return HumanLabel.ACCEPT if score >= threshold else HumanLabel.REJECT


def _safe_ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _metrics(
    examples: list[SemanticLabelExample],
    threshold: float,
) -> SemanticCalibrationMetrics:
    true_accepts = true_rejects = false_accepts = false_rejects = 0
    for example in examples:
        predicted = _predicted_label(example.semantic_score, threshold)
        if predicted == HumanLabel.ACCEPT and example.human_label == HumanLabel.ACCEPT:
            true_accepts += 1
        elif predicted == HumanLabel.REJECT and example.human_label == HumanLabel.REJECT:
            true_rejects += 1
        elif predicted == HumanLabel.ACCEPT:
            false_accepts += 1
        else:
            false_rejects += 1

    accepted = true_accepts + false_rejects
    rejected = true_rejects + false_accepts
    recall = _safe_ratio(true_accepts, accepted)
    specificity = _safe_ratio(true_rejects, rejected)
    return SemanticCalibrationMetrics(
        example_count=len(examples),
        accepted_labels=accepted,
        rejected_labels=rejected,
        true_accepts=true_accepts,
        true_rejects=true_rejects,
        false_accepts=false_accepts,
        false_rejects=false_rejects,
        accuracy=_safe_ratio(true_accepts + true_rejects, len(examples)),
        balanced_accuracy=(recall + specificity) / 2,
        precision=_safe_ratio(true_accepts, true_accepts + false_accepts),
        recall=recall,
        specificity=specificity,
        false_accept_rate=_safe_ratio(false_accepts, rejected),
    )


def _select_threshold(examples: list[SemanticLabelExample]) -> float:
    candidates = sorted({0.0, 1.0, *(example.semantic_score for example in examples)})

    def objective(threshold: float) -> tuple[float, float, float, float]:
        metrics = _metrics(examples, threshold)
        return (
            metrics.balanced_accuracy,
            -metrics.false_accept_rate,
            metrics.accuracy,
            threshold,
        )

    return max(candidates, key=objective)


def _disagreements(
    examples: list[SemanticLabelExample],
    threshold: float,
) -> list[SemanticCalibrationDisagreement]:
    disagreements: list[SemanticCalibrationDisagreement] = []
    for example in examples:
        predicted = _predicted_label(example.semantic_score, threshold)
        if predicted == example.human_label:
            continue
        disagreements.append(
            SemanticCalibrationDisagreement(
                example_id=example.id,
                scenario_id=example.scenario_id,
                split=example.split,
                semantic_score=example.semantic_score,
                human_label=example.human_label,
                predicted_label=predicted,
                rationale=example.rationale,
            )
        )
    return disagreements


def calibrate_semantic_grader(
    label_set: SemanticLabelSet,
    policy: SemanticCalibrationPolicy | None = None,
    *,
    source_policy: PolicySnapshot | None = None,
) -> SemanticCalibrationReport:
    """Fit on calibration labels and measure the selected threshold on validation labels."""

    applied_policy = policy or SemanticCalibrationPolicy()
    calibration_examples = _split_examples(label_set, CalibrationSplit.CALIBRATION)
    validation_examples = _split_examples(label_set, CalibrationSplit.VALIDATION)
    _require_label_diversity(calibration_examples, CalibrationSplit.CALIBRATION)
    _require_label_diversity(validation_examples, CalibrationSplit.VALIDATION)

    threshold = _select_threshold(calibration_examples)
    calibration_metrics = _metrics(calibration_examples, threshold)
    validation_metrics = _metrics(validation_examples, threshold)
    findings: list[SemanticCalibrationFinding] = []

    if len(calibration_examples) < applied_policy.min_calibration_examples:
        findings.append(
            SemanticCalibrationFinding(
                rule_id="MP-CAL-001",
                impact=RegressionImpact.FAILURE,
                message="Calibration split does not contain enough human-labelled examples.",
                observed_value=len(calibration_examples),
                required_value=applied_policy.min_calibration_examples,
            )
        )
    if len(validation_examples) < applied_policy.min_validation_examples:
        findings.append(
            SemanticCalibrationFinding(
                rule_id="MP-CAL-002",
                impact=RegressionImpact.FAILURE,
                message="Validation split does not contain enough independent examples.",
                observed_value=len(validation_examples),
                required_value=applied_policy.min_validation_examples,
            )
        )
    if (
        validation_metrics.balanced_accuracy
        < applied_policy.min_validation_balanced_accuracy
    ):
        findings.append(
            SemanticCalibrationFinding(
                rule_id="MP-CAL-003",
                impact=RegressionImpact.FAILURE,
                message="Validation balanced accuracy is below the configured minimum.",
                observed_value=validation_metrics.balanced_accuracy,
                required_value=applied_policy.min_validation_balanced_accuracy,
            )
        )
    if (
        validation_metrics.false_accept_rate
        > applied_policy.max_validation_false_accept_rate
    ):
        findings.append(
            SemanticCalibrationFinding(
                rule_id="MP-CAL-004",
                impact=RegressionImpact.FAILURE,
                message="Validation false-accept rate exceeds the configured maximum.",
                observed_value=validation_metrics.false_accept_rate,
                required_value=applied_policy.max_validation_false_accept_rate,
            )
        )

    all_examples = [*calibration_examples, *validation_examples]
    return SemanticCalibrationReport(
        status=ScanStatus.FAILED if findings else ScanStatus.PASSED,
        label_set_name=label_set.name,
        label_set_sha256=semantic_label_set_digest(label_set),
        grader=label_set.grader,
        grader_version=label_set.grader_version,
        selected_threshold=threshold,
        source_policy=source_policy,
        policy=applied_policy,
        calibration=calibration_metrics,
        validation=validation_metrics,
        disagreements=_disagreements(all_examples, threshold),
        findings=findings,
    )
