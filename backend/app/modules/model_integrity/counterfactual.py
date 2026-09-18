import numpy as np


def _predict(model, sample):
    if callable(model):
        output = model(sample)
    elif hasattr(model, "run") and hasattr(model, "get_inputs"):
        inputs = model.get_inputs()
        if len(inputs) != 1:
            raise ValueError("Counterfactual sessions must have one input; wrap other sessions in a callable")
        values = np.asarray(sample)
        shape = getattr(inputs[0], "shape", None)
        if shape is not None and len(shape) == values.ndim + 1:
            values = values[None, ...]
        output = model.run(None, {inputs[0].name: values})[0]
    else:
        raise TypeError("model must be callable or an ONNX session")
    logits = np.asarray(output, dtype=np.float64)
    if logits.ndim == 2 and logits.shape[0] == 1:
        logits = logits[0]
    if logits.ndim != 1 or not logits.size or not np.isfinite(logits).all():
        raise ValueError("model must return finite logits for exactly one sample")
    return logits


def test_counterfactual(model, sample, mask_fn):
    original = np.asarray(sample)
    if not original.size or not np.isfinite(original).all():
        raise ValueError("sample must be nonempty and finite")
    before = _predict(model, original.copy())
    masked = np.asarray(mask_fn(original.copy()))
    if masked.shape != original.shape or not np.isfinite(masked).all():
        raise ValueError("mask_fn must preserve sample shape and return finite values")
    after = _predict(model, masked)
    if before.shape != after.shape:
        raise ValueError("model output dimensions changed after masking")
    original_class, masked_class = int(before.argmax()), int(after.argmax())
    return {
        "behavior_persists": bool(original_class == masked_class),
        "details": {
            "original_class": original_class,
            "masked_class": masked_class,
            "original_logits": before.tolist(),
            "masked_logits": after.tolist(),
            "logit_delta_norm": float(np.linalg.norm(after - before)),
            "criterion": "Top predicted class is unchanged; this proxy does not establish causality.",
        },
    }


def mask_region(mask_value_box):
    if len(mask_value_box) == 4:
        value, box = 0, mask_value_box
    elif len(mask_value_box) == 2:
        value, box = mask_value_box
    else:
        raise ValueError("Use (x0, y0, x1, y1) or (value, (x0, y0, x1, y1))")
    if len(box) != 4 or any(not isinstance(item, (int, np.integer)) for item in box):
        raise ValueError("Region coordinates must be four integers")
    x0, y0, x1, y1 = box
    if x0 < 0 or y0 < 0 or x1 <= x0 or y1 <= y0 or not np.isfinite(value):
        raise ValueError("Region must have positive area and a finite fill value")

    def apply(sample):
        result = np.array(sample, copy=True)
        if result.ndim not in (2, 3) or y1 > result.shape[0] or x1 > result.shape[1]:
            raise ValueError("Region must lie within an HW or HWC image")
        result[y0:y1, x0:x1, ...] = value
        return result

    return apply


def mask_channels(neuron_indices, axis=-1):
    indices = list(neuron_indices)
    if any(not isinstance(index, (int, np.integer)) or index < 0 for index in indices):
        raise ValueError("Channel indices must be nonnegative integers")

    def apply(sample):
        result = np.array(sample, copy=True)
        if not result.ndim or not -result.ndim <= axis < result.ndim:
            raise ValueError("Invalid channel axis")
        if any(index >= result.shape[axis] for index in indices):
            raise ValueError("Channel index out of range")
        slices = [slice(None)] * result.ndim
        slices[axis] = indices
        result[tuple(slices)] = 0
        return result

    return apply
