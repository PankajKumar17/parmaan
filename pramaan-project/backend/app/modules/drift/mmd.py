import numpy as np


def _matrix(values, name):
    matrix = np.asarray(values, dtype=np.float64)
    if matrix.ndim != 2 or min(matrix.shape) == 0 or not np.isfinite(matrix).all():
        raise ValueError(f"{name} must be a nonempty finite N x D matrix")
    return matrix


def mmd_rbf(X_ref, X_cur, gamma):
    reference = _matrix(X_ref, "X_ref")
    current = _matrix(X_cur, "X_cur")
    if reference.shape[1] != current.shape[1]:
        raise ValueError("Embedding dimensions must match")
    if min(len(reference), len(current)) < 2:
        raise ValueError("Unbiased MMD requires at least two samples in each batch")
    if not np.isfinite(gamma) or gamma <= 0:
        raise ValueError("gamma must be finite and positive")

    def kernel(first, second):
        distances = np.maximum(
            (first * first).sum(axis=1)[:, None]
            + (second * second).sum(axis=1)[None, :] - 2 * first @ second.T, 0
        )
        return np.exp(-gamma * distances)

    rr = kernel(reference, reference)
    cc = kernel(current, current)
    rc = kernel(reference, current)
    n, m = len(reference), len(current)
    return float((rr.sum() - np.trace(rr)) / (n * (n - 1))
                 + (cc.sum() - np.trace(cc)) / (m * (m - 1)) - 2 * rc.mean())


def kl_divergence_histogram(p, q, epsilon=1e-10):
    first = np.asarray(p, dtype=np.float64)
    second = np.asarray(q, dtype=np.float64)
    if first.ndim != 1 or first.size == 0 or first.shape != second.shape:
        raise ValueError("Histograms must be nonempty vectors with matching bins")
    if not np.isfinite(first).all() or not np.isfinite(second).all() or (first < 0).any() or (second < 0).any():
        raise ValueError("Histogram counts must be finite and nonnegative")
    if not np.isfinite(epsilon) or epsilon <= 0:
        raise ValueError("epsilon must be finite and positive")
    first = first / max(float(first.max()), 1.0) + epsilon
    second = second / max(float(second.max()), 1.0) + epsilon
    first /= first.sum()
    second /= second.sum()
    return float(max(0.0, np.sum(first * np.log(first / second))))
