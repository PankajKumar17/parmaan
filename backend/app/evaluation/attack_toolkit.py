"""In-memory synthetic fixtures; truth always has affected ids and attack_type.

Dataset ids are zero-based row indices; weight ids are flat indices; log ids are
zero-based record positions. 'affected' means actually changed, not merely selected.
No training, file replacement, or deployment is performed.
"""

from copy import deepcopy
from dataclasses import is_dataclass, replace

import numpy as np


def _indices(size, rate, seed):
    if not 0 <= rate <= 1:
        raise ValueError("rate must be finite and in [0, 1]")
    return np.sort(np.random.default_rng(seed).choice(size, int(size * rate), replace=False))


def poison_dataset(images, labels, rate, seed, mode="label_flip"):
    """Return ({images: ndarray, labels: ndarray}, truth) without mutating input.

    Duplicate flooding replaces selected rows with row zero; unchanged rows are
    excluded from truth. OOD fixtures are values beyond the observed numeric range.
    Label flips cycle through observed classes, requiring at least two classes.
    """
    images, labels = np.asarray(images), np.asarray(labels)
    if images.ndim < 2 or labels.ndim != 1 or len(images) != len(labels):
        raise ValueError("Expected image rows and matching one-dimensional labels")
    if not np.isfinite(images).all():
        raise ValueError("Images must be finite")
    if mode not in {"label_flip", "duplicate_flood", "ood_insert"}:
        raise ValueError("Unknown poison mode")
    selected = _indices(len(images), rate, seed)
    result_images, result_labels = images.copy(), labels.copy()
    if mode == "label_flip" and len(selected):
        classes = np.unique(labels)
        if len(classes) < 2:
            raise ValueError("Label flips require at least two classes")
        result_labels[selected] = classes[(np.searchsorted(classes, labels[selected]) + 1) % len(classes)]
    elif mode == "duplicate_flood" and len(selected):
        result_images[selected] = images[0]
        result_labels[selected] = labels[0]
    elif mode == "ood_insert" and len(selected):
        result_images = images.astype(float, copy=True)
        high, low = float(images.max()), float(images.min())
        result_images[selected] = high + max(high - low, 1.0) * np.random.default_rng(seed).uniform(
            2, 3, size=result_images[selected].shape)
        if not np.isfinite(result_images).all():
            raise ValueError("OOD fixture exceeds finite numeric range")
    changed = np.any(result_images != images, axis=tuple(range(1, images.ndim))) | (result_labels != labels)
    truth = {"affected": np.flatnonzero(changed).tolist(), "attack_type": mode,
             "selected": selected.tolist(), "universe": list(range(len(images)))}
    return {"images": result_images, "labels": result_labels}, truth


def backdoor_model(predict_fn, trigger_fn, target_class, rate, seed):
    """Return an in-memory synthetic predictor and mutable last-call truth.

    predict_fn accepts a batch and returns class labels (N,) or logits (N,C).
    trigger_fn accepts a copied row and returns a boolean indicating a fixed toy
    trigger's presence. Selected triggered rows receive the target output; truth
    describes the latest call only, with changed row indices and call history.
    Selection is reseeded per call, so identical batches have identical outputs.
    """
    _indices(0, rate, seed)
    if not isinstance(target_class, (int, np.integer)) or target_class < 0:
        raise ValueError("target_class must be a nonnegative integer")
    truth = {"affected": [], "attack_type": "synthetic_backdoor", "calls": []}

    def predict(samples):
        samples = np.asarray(samples)
        outputs = np.array(predict_fn(samples.copy()), copy=True)
        if outputs.ndim not in (1, 2) or len(outputs) != len(samples) or not np.isfinite(outputs).all():
            raise ValueError("Predictor must return finite batch labels or logits")
        if outputs.ndim == 2 and target_class >= outputs.shape[1]:
            raise ValueError("target_class exceeds output width")
        before = outputs.copy()
        for index in _indices(len(samples), rate, seed):
            present = trigger_fn(samples[index].copy())
            if not isinstance(present, (bool, np.bool_)):
                raise ValueError("trigger_fn must be a boolean presence predicate")
            if present:
                if outputs.ndim == 1:
                    outputs[index] = target_class
                else:
                    outputs[index] = 0
                    outputs[index, target_class] = 1
        changed = outputs != before
        if changed.ndim == 2:
            changed = changed.any(axis=1)
        truth["affected"] = np.flatnonzero(changed).tolist()
        truth["universe"] = list(range(len(samples)))
        truth["calls"].append({"affected": truth["affected"].copy(), "attack_type": truth["attack_type"]})
        return outputs

    return predict, truth


def substitute_model(base_weights, epsilon, seed):
    """Return bounded uniform perturbations to a copied numeric weight array."""
    weights = np.asarray(base_weights, dtype=float)
    if not np.isfinite(weights).all() or not np.isfinite(epsilon) or epsilon < 0:
        raise ValueError("Finite weights and finite nonnegative epsilon are required")
    perturbed = weights + np.random.default_rng(seed).uniform(-epsilon, epsilon, weights.shape)
    if not np.isfinite(perturbed).all():
        raise ValueError("Perturbed weights exceed finite range")
    return perturbed, {"affected": np.flatnonzero(perturbed.ravel() != weights.ravel()).tolist(),
                       "attack_type": "model_substitution", "shape": list(weights.shape)}


def tamper_log(records, index, seed):
    """Corrupt output_hash in a copied dict/dataclass record; retain its signature."""
    if not isinstance(index, (int, np.integer)) or not 0 <= index < len(records):
        raise ValueError("Record index out of bounds")
    result = deepcopy(list(records))
    record = result[index]
    value = np.random.default_rng(seed).bytes(32).hex()
    old = record.output_hash if is_dataclass(record) else record["output_hash"]
    if value == old:
        value = ("0" if value[0] != "0" else "1") + value[1:]
    result[index] = replace(record, output_hash=value) if is_dataclass(record) else dict(record, output_hash=value)
    return result, {"affected": [int(index)], "attack_type": "log_tampering", "field": "output_hash"}
