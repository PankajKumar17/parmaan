import numpy as np


def optimize_trigger_against(detector_fn, trigger_init, predict_fn, iterations, seed):
    """Compatibility entry point for fixed-trigger assessment, NOT optimization.

    The trigger is copied unchanged. detector_fn(trigger) must return a nonempty
    scalar/vector of binary detections, one per evaluated case. predict_fn(trigger)
    is recorded without inferring attack success. iterations is validated but not
    used for search; seed is recorded. Detection rate is observed on these cases
    only, with no claim about held-out generalization or detector evasion.
    Returns (unchanged_trigger, report), explicitly optimized=False.
    """
    if not isinstance(iterations, int) or isinstance(iterations, bool) or iterations < 0:
        raise ValueError("iterations must be a nonnegative integer")
    np.random.default_rng(seed)
    trigger = np.array(trigger_init, dtype=float, copy=True)
    if not trigger.size or not np.isfinite(trigger).all():
        raise ValueError("Trigger must be nonempty and finite")
    prediction = np.asarray(predict_fn(trigger.copy()))
    detections = np.atleast_1d(np.asarray(detector_fn(trigger.copy())))
    if detections.ndim != 1 or not detections.size or not np.isin(detections, [0, 1]).all():
        raise ValueError("Detector must return nonempty binary detections")
    return trigger, {"detection_rate": float(detections.mean()), "evaluated_cases": int(detections.size),
                     "prediction": prediction.tolist(), "optimized": False, "iterations_run": 0, "seed": seed,
                     "limitation": "Fixed-trigger assessment only; no evasion optimization or attack-success claim."}
