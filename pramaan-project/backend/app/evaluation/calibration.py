from copy import deepcopy
from dataclasses import replace

import numpy as np

from app.evaluation.metrics import _binary_inputs


def _calibration_inputs(confidences, correctness):
    confidences, correctness = _binary_inputs(confidences, correctness)
    if not ((0 <= confidences) & (confidences <= 1)).all():
        raise ValueError("Confidences must be in [0, 1]")
    return confidences, correctness


def reliability_diagram(confidences, correctness, bins=10):
    """Equal-width bins [lower,upper), with confidence=1 in the final bin.

    Empty bins have count=0 and mean_confidence/accuracy=None.
    """
    confidences, correctness = _calibration_inputs(confidences, correctness)
    if not isinstance(bins, int) or isinstance(bins, bool) or bins < 1:
        raise ValueError("bins must be a positive integer")
    edges = np.linspace(0, 1, bins + 1)
    indices = np.minimum(np.searchsorted(edges, confidences, side="right") - 1, bins - 1)
    result = []
    for index in range(bins):
        selected = indices == index
        count = int(selected.sum())
        result.append({"lower": float(edges[index]), "upper": float(edges[index + 1]), "count": count,
                       "mean_confidence": float(confidences[selected].mean()) if count else None,
                       "accuracy": float(correctness[selected].mean()) if count else None})
    return result


def brier_score(confidences, correctness):
    """Mean squared confidence error; an empty evaluation is undefined (None)."""
    confidences, correctness = _calibration_inputs(confidences, correctness)
    return float(np.mean((confidences - correctness) ** 2)) if confidences.size else None


def apply_calibration(findings, mapping):
    """Copy findings using a serializable {raw_confidence: calibrated_confidence} map.

    Sorted knots interpolate linearly with endpoint clamping. Mapping must be
    nonempty, monotonic and within [0,1]. Provenance stores the mapping, raw
    confidence and calibration_applied=True. Reapplication uses the original raw
    confidence, so applying the same map twice is idempotent. Fit mappings on held-
    out ground truth; this function does not fit or claim generalization.
    """
    if not mapping:
        raise ValueError("A nonempty calibration mapping is required")
    knots = sorted((float(key), float(value)) for key, value in mapping.items())
    raw, calibrated = np.array(knots).T
    if not np.isfinite(knots).all() or not ((0 <= raw) & (raw <= 1)).all() or not ((0 <= calibrated) & (calibrated <= 1)).all():
        raise ValueError("Calibration knots must be finite and in [0, 1]")
    if (np.diff(raw) <= 0).any() or (np.diff(calibrated) < 0).any():
        raise ValueError("Calibration knots must be unique and monotonic")
    result = []
    for finding in findings:
        provenance = deepcopy(finding.provenance)
        confidence = provenance.get("uncalibrated_confidence", finding.confidence)
        if not 0 <= confidence <= 1:
            raise ValueError("Confidence must be finite and in [0, 1]")
        provenance.update(calibration_applied=True, uncalibrated_confidence=confidence,
                          calibration_mapping={str(key): value for key, value in knots})
        result.append(replace(finding, confidence=float(np.interp(confidence, raw, calibrated)),
                              provenance=provenance, evidence=list(finding.evidence),
                              counter_evidence=list(finding.counter_evidence)))
    return result
