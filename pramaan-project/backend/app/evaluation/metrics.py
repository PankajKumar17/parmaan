from collections import defaultdict

import numpy as np


def _binary_inputs(scores, truth):
    scores, truth = np.asarray(scores, dtype=float), np.asarray(truth)
    if scores.ndim != 1 or truth.shape != scores.shape:
        raise ValueError("Scores and truth must be matching one-dimensional arrays")
    if not np.isfinite(scores).all() or not np.isin(truth, [0, 1]).all():
        raise ValueError("Scores must be finite and truth binary")
    return scores, truth.astype(bool)


def _counts(predicted, affected):
    tp, fp, fn = len(predicted & affected), len(predicted - affected), len(affected - predicted)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall,
            "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0}


def per_detector_metrics(ground_truth, findings, detector_ids=()):
    """Unique flagged assets per detector; accepted/zero-support findings are negative.

    Truth is {affected: [ids], attack_type: str}, optionally with
    by_detector: {detector_id: {affected: [ids]}} for detector-specific surfaces.
    Pass detector_ids to include detectors producing no findings. IDs compare as
    strings, allowing synthetic row indices to match Finding.asset_id strings.
    """
    predictions = defaultdict(set)
    for detector in detector_ids:
        predictions[detector]
    for detector in ground_truth.get("by_detector", {}):
        predictions[detector]
    for finding in findings:
        detector = finding.provenance["detector_id"]
        predictions[detector]
        if finding.recommended_action.lower() != "accept" and finding.severity > 0 and finding.confidence > 0:
            predictions[detector].add(str(finding.asset_id))
    result = {}
    for detector in sorted(predictions):
        truth = ground_truth.get("by_detector", {}).get(detector, ground_truth)
        affected = set(map(str, truth["affected"]))
        result[detector] = _counts(predictions[detector], affected)
    return result


def roc_points(scores, truth):
    """Descending unique thresholds with a +infinity all-negative endpoint.

    Undefined TPR/FPR (no positives/negatives) are None, not invented rates.
    Tied scores enter together. Returned points are dictionaries.
    """
    scores, truth = _binary_inputs(scores, truth)
    positives, negatives = int(truth.sum()), int((~truth).sum())
    result = []
    for threshold in np.r_[np.inf, np.unique(scores)[::-1]]:
        predicted = scores >= threshold
        tp, fp = int((predicted & truth).sum()), int((predicted & ~truth).sum())
        result.append({"threshold": float(threshold), "tpr": tp / positives if positives else None,
                       "fpr": fp / negatives if negatives else None})
    return result


def pr_points(scores, truth):
    """Descending unique thresholds; precision=1 at the all-negative endpoint."""
    scores, truth = _binary_inputs(scores, truth)
    positives = int(truth.sum())
    result = []
    for threshold in np.r_[np.inf, np.unique(scores)[::-1]]:
        predicted = scores >= threshold
        tp, count = int((predicted & truth).sum()), int(predicted.sum())
        result.append({"threshold": float(threshold), "precision": tp / count if count else 1.0,
                       "recall": tp / positives if positives else None})
    return result
