from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
from sklearn.metrics import accuracy_score, f1_score

from app.ml.cwe_ml_classifier import MLCWEClassifier, text_from_finding
from app.schemas import VulnerabilityFinding


@dataclass
class CalibrationResult:
    accuracy: float
    macro_f1: float
    brier_score_multiclass: float
    expected_calibration_error: float
    mean_confidence: float
    reliability_bins: list[dict[str, float | int]]
    examples: list[dict[str, Any]]


def _multiclass_brier(y_true: list[str], classes: list[str], prob_matrix: np.ndarray) -> float:
    class_index = {label: idx for idx, label in enumerate(classes)}
    one_hot = np.zeros_like(prob_matrix, dtype=float)
    for row_idx, label in enumerate(y_true):
        if label in class_index:
            one_hot[row_idx, class_index[label]] = 1.0
    return float(np.mean(np.sum((prob_matrix - one_hot) ** 2, axis=1)))


def _ece(confidences: np.ndarray, correctness: np.ndarray, n_bins: int) -> tuple[float, list[dict[str, float | int]]]:
    bins: list[dict[str, float | int]] = []
    ece = 0.0
    total = len(confidences)
    if total == 0:
        return 0.0, []

    for bin_idx in range(n_bins):
        low = bin_idx / n_bins
        high = (bin_idx + 1) / n_bins
        if bin_idx == n_bins - 1:
            mask = (confidences >= low) & (confidences <= high)
        else:
            mask = (confidences >= low) & (confidences < high)
        count = int(mask.sum())
        if count == 0:
            bins.append({"bin_low": round(low, 2), "bin_high": round(high, 2), "count": 0, "accuracy": 0.0, "confidence": 0.0, "gap": 0.0})
            continue
        bin_acc = float(correctness[mask].mean())
        bin_conf = float(confidences[mask].mean())
        gap = abs(bin_acc - bin_conf)
        ece += (count / total) * gap
        bins.append({
            "bin_low": round(low, 2),
            "bin_high": round(high, 2),
            "count": count,
            "accuracy": round(bin_acc, 4),
            "confidence": round(bin_conf, 4),
            "gap": round(gap, 4),
        })
    return float(ece), bins


def evaluate_cwe_calibration(
    classifier: MLCWEClassifier,
    findings: list[VulnerabilityFinding],
    labels_by_id: dict[str, str],
    n_bins: int = 10,
) -> CalibrationResult:
    if not findings:
        return CalibrationResult(0.0, 0.0, 0.0, 0.0, 0.0, [], [])

    x = [text_from_finding(finding) for finding in findings]
    y_true = [labels_by_id[finding.finding_id] for finding in findings if finding.finding_id in labels_by_id]
    filtered_x = [text_from_finding(finding) for finding in findings if finding.finding_id in labels_by_id]
    filtered_findings = [finding for finding in findings if finding.finding_id in labels_by_id]

    if not filtered_x:
        return CalibrationResult(0.0, 0.0, 0.0, 0.0, 0.0, [], [])

    model = classifier.model
    y_pred = list(model.predict(filtered_x))

    if not hasattr(model, "predict_proba"):
        confidences = np.array([0.5] * len(y_pred), dtype=float)
        classes = sorted(set(y_true) | set(y_pred))
        prob_matrix = np.zeros((len(y_pred), len(classes)))
        class_index = {label: idx for idx, label in enumerate(classes)}
        for idx, pred in enumerate(y_pred):
            prob_matrix[idx, class_index[pred]] = 0.5
    else:
        prob_matrix = np.asarray(model.predict_proba(filtered_x), dtype=float)
        classes = list(model.classes_)
        confidences = prob_matrix.max(axis=1)

    correctness = np.asarray([1.0 if p == t else 0.0 for p, t in zip(y_pred, y_true)], dtype=float)
    ece, bins = _ece(confidences, correctness, n_bins=n_bins)

    examples = []
    for finding, true, pred, conf, correct in zip(filtered_findings, y_true, y_pred, confidences, correctness):
        examples.append({
            "finding_id": finding.finding_id,
            "expected_cwe": true,
            "predicted_cwe": str(pred),
            "confidence": round(float(conf), 4),
            "correct": bool(correct),
        })

    return CalibrationResult(
        accuracy=round(float(accuracy_score(y_true, y_pred)), 4),
        macro_f1=round(float(f1_score(y_true, y_pred, average="macro", zero_division=0)), 4),
        brier_score_multiclass=round(_multiclass_brier(y_true, classes, prob_matrix), 4),
        expected_calibration_error=round(ece, 4),
        mean_confidence=round(float(confidences.mean()), 4),
        reliability_bins=bins,
        examples=examples,
    )
