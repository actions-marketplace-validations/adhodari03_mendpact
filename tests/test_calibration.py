from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from mendpact.calibration import (
    calibrate_semantic_grader,
    semantic_label_set_digest,
)
from mendpact.domain import (
    CalibrationSplit,
    HumanLabel,
    ScanStatus,
    SemanticCalibrationPolicy,
    SemanticLabelExample,
    SemanticLabelSet,
)


def _example(
    identifier: str,
    split: CalibrationSplit,
    label: HumanLabel,
    score: float,
) -> SemanticLabelExample:
    return SemanticLabelExample(
        id=identifier,
        scenario_id="read-status",
        split=split,
        task="Read the API status.",
        expected_behavior="Select read_status for the API component.",
        observed_behavior="The candidate selected a tool and supplied arguments.",
        human_label=label,
        semantic_score=score,
        rationale="Reviewed fixture label.",
    )


def _label_set() -> SemanticLabelSet:
    return SemanticLabelSet(
        name="Fixture semantic labels",
        grader="fixture-grader",
        grader_version="1.0",
        examples=[
            _example("cal-accept-1", CalibrationSplit.CALIBRATION, HumanLabel.ACCEPT, 0.9),
            _example("cal-accept-2", CalibrationSplit.CALIBRATION, HumanLabel.ACCEPT, 0.8),
            _example("cal-reject-1", CalibrationSplit.CALIBRATION, HumanLabel.REJECT, 0.4),
            _example("cal-reject-2", CalibrationSplit.CALIBRATION, HumanLabel.REJECT, 0.2),
            _example("val-accept-1", CalibrationSplit.VALIDATION, HumanLabel.ACCEPT, 0.88),
            _example("val-accept-2", CalibrationSplit.VALIDATION, HumanLabel.ACCEPT, 0.82),
            _example("val-reject-1", CalibrationSplit.VALIDATION, HumanLabel.REJECT, 0.3),
            _example("val-reject-2", CalibrationSplit.VALIDATION, HumanLabel.REJECT, 0.1),
        ],
    )


def test_selects_threshold_on_calibration_split_and_passes_validation() -> None:
    report = calibrate_semantic_grader(_label_set())

    assert report.status == ScanStatus.PASSED
    assert report.selected_threshold == 0.8
    assert report.calibration.balanced_accuracy == 1.0
    assert report.validation.balanced_accuracy == 1.0
    assert report.validation.false_accept_rate == 0.0
    assert not report.disagreements
    assert not report.findings


def test_validation_labels_do_not_change_selected_threshold() -> None:
    labels = _label_set()
    baseline_threshold = calibrate_semantic_grader(labels).selected_threshold
    changed = labels.model_copy(deep=True)
    for example in changed.examples:
        if example.split == CalibrationSplit.VALIDATION:
            example.semantic_score = 1.0 - example.semantic_score

    report = calibrate_semantic_grader(changed)

    assert report.selected_threshold == baseline_threshold
    assert report.status == ScanStatus.FAILED
    assert report.disagreements


def test_equal_balanced_accuracy_prefers_lower_false_accept_rate() -> None:
    labels = _label_set()
    calibration_examples = [
        _example("cal-accept-high", CalibrationSplit.CALIBRATION, HumanLabel.ACCEPT, 0.9),
        _example("cal-accept-low", CalibrationSplit.CALIBRATION, HumanLabel.ACCEPT, 0.4),
        _example("cal-reject-high", CalibrationSplit.CALIBRATION, HumanLabel.REJECT, 0.8),
        _example("cal-reject-low", CalibrationSplit.CALIBRATION, HumanLabel.REJECT, 0.3),
    ]
    labels.examples = [
        *calibration_examples,
        *(example for example in labels.examples if example.split == CalibrationSplit.VALIDATION),
    ]

    report = calibrate_semantic_grader(labels)

    assert report.selected_threshold == 0.9
    assert report.calibration.balanced_accuracy == 0.75
    assert report.calibration.false_accept_rate == 0.0


def test_fails_policy_for_false_accepts_and_low_balanced_accuracy() -> None:
    labels = _label_set()
    labels.examples[-2].semantic_score = 0.95

    report = calibrate_semantic_grader(labels)

    assert report.status == ScanStatus.FAILED
    assert report.validation.false_accepts == 1
    assert report.validation.false_accept_rate == 0.5
    assert report.validation.balanced_accuracy == 0.75
    assert {finding.rule_id for finding in report.findings} == {
        "MP-CAL-003",
        "MP-CAL-004",
    }
    assert report.disagreements[0].example_id == "val-reject-1"


def test_fails_policy_when_splits_are_too_small() -> None:
    labels = _label_set().model_copy(
        update={"examples": _label_set().examples[::2]},
    )

    report = calibrate_semantic_grader(
        labels,
        SemanticCalibrationPolicy(
            min_calibration_examples=4,
            min_validation_examples=4,
            min_validation_balanced_accuracy=0.0,
        ),
    )

    assert report.status == ScanStatus.FAILED
    assert {finding.rule_id for finding in report.findings} == {
        "MP-CAL-001",
        "MP-CAL-002",
    }


def test_requires_both_human_labels_in_each_split() -> None:
    labels = _label_set()
    for example in labels.examples:
        if example.split == CalibrationSplit.VALIDATION:
            example.human_label = HumanLabel.ACCEPT

    with pytest.raises(ValueError, match="validation split must contain both"):
        calibrate_semantic_grader(labels)


def test_rejects_duplicate_example_ids() -> None:
    data = _label_set().model_dump(mode="json")
    data["examples"][1]["id"] = data["examples"][0]["id"]

    with pytest.raises(ValidationError, match="example IDs must be unique"):
        SemanticLabelSet.model_validate(data)


def test_dataset_digest_is_independent_of_json_formatting() -> None:
    labels = _label_set()
    compact = SemanticLabelSet.model_validate_json(labels.model_dump_json())
    pretty = SemanticLabelSet.model_validate_json(
        json.dumps(labels.model_dump(mode="json"), indent=4),
    )

    assert semantic_label_set_digest(compact) == semantic_label_set_digest(pretty)
