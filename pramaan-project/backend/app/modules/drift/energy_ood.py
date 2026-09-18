import numpy as np


def energy_score(logits):
    values = np.asarray(logits, dtype=np.float64)
    if values.ndim not in (1, 2) or values.shape[-1] == 0 or not np.isfinite(values).all():
        raise ValueError("logits must be a finite class vector or N x C matrix")
    maximum = np.max(values, axis=-1)
    return -(maximum + np.log(np.exp(values - np.expand_dims(maximum, -1)).sum(axis=-1)))
