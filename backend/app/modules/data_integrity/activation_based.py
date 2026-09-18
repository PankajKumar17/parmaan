import hashlib

import numpy as np

from app.core.evidence import EvidenceProvider, Finding, Modality
from app.manifests._common import digest


def _classes(asset):
    activations, labels = asset["activations"], asset["labels"]
    names = sorted(activations)
    if not names:
        return []
    vectors = [np.asarray(activations[name], dtype=np.float64) for name in names]
    if any(vector.ndim != 1 or not vector.size or not np.isfinite(vector).all() for vector in vectors):
        raise ValueError("Activations must be nonempty finite 1-D vectors")
    if any(vector.shape != vectors[0].shape for vector in vectors):
        raise ValueError("Activation dimensions must match")
    groups = {}
    for name, vector in zip(names, vectors):
        if name not in labels:
            raise ValueError(f"Missing class label for {name}")
        groups.setdefault(labels[name], []).append((name, vector))
    result = []
    for label, members in groups.items():
        class_names = [name for name, _ in members]
        matrix = np.stack([vector for _, vector in members])
        hashes = [hashlib.sha256(vector.astype("<f8").tobytes()).hexdigest() for _, vector in members]
        hashes.append(digest({"names": class_names, "label": label}))
        result.append((label, class_names, matrix, hashes))
    return result


def _finding(provider, asset, name, hashes, evidence, confidence):
    return Finding(
        asset_id=name, finding_type=provider.detector_id, severity=0.7, confidence=confidence,
        evidence=[evidence, "CANDIDATE evidence for poisoning, not proof."], modality=Modality.ACTIVATION,
        provenance=provider._create_provenance(hashes, asset["config_hash"]),
        recommended_action="review", quarantine_scope="sample", access_assumptions="gray_box",
        counter_evidence=["Rare legitimate subclasses, mislabeled examples, or natural multimodality can produce activation outliers. "
                          "Penultimate activations must come from a consistent model and preprocessing; confidence is uncalibrated."],
    )


class SpectralSignatureProvider(EvidenceProvider):
    def __init__(self, mad_threshold=5.0, min_class_samples=4):
        super().__init__("spectral_signature")
        if not np.isfinite(mad_threshold) or mad_threshold <= 0:
            raise ValueError("mad_threshold must be finite and positive")
        if not isinstance(min_class_samples, int) or min_class_samples < 3:
            raise ValueError("min_class_samples must be at least 3")
        self.mad_threshold = mad_threshold
        self.min_class_samples = min_class_samples

    def analyze(self, asset):
        findings = []
        for label, names, matrix, hashes in _classes(asset):
            if len(names) < self.min_class_samples:
                continue
            centered = matrix - matrix.mean(axis=0)
            covariance = centered.T @ centered / (len(names) - 1)
            _, singular_values, directions = np.linalg.svd(covariance, full_matrices=False)
            if singular_values[0] <= np.finfo(float).eps:
                continue
            projections = centered @ directions[0]
            deviations = np.abs(projections - np.median(projections))
            mad = float(np.median(deviations))
            scale = max(1.4826 * mad, 1e-12 * max(1.0, float(np.max(np.abs(projections)))))
            for index in np.flatnonzero(deviations > self.mad_threshold * scale):
                findings.append(_finding(
                    self, asset, names[index], hashes,
                    f"Tran et al. (2018) per-class spectral signature: class={label!r}, top covariance singular value={singular_values[0]:.6g}, "
                    f"absolute projection deviation={deviations[index]:.6g}, MAD-scaled score={deviations[index] / scale:.6g}, threshold={self.mad_threshold}.",
                    0.6,
                ))
        return findings


def _two_means(matrix):
    first = int(np.argmax(np.sum((matrix - np.median(matrix, axis=0)) ** 2, axis=1)))
    second = int(np.argmax(np.sum((matrix - matrix[first]) ** 2, axis=1)))
    centers = matrix[[first, second]].copy()
    assignments = np.zeros(len(matrix), dtype=int)
    for _ in range(100):
        distances = np.sum((matrix[:, None, :] - centers[None, :, :]) ** 2, axis=2)
        updated = distances.argmin(axis=1)
        counts = np.bincount(updated, minlength=2)
        if not counts.all():
            return None
        new_centers = np.stack([matrix[updated == group].mean(axis=0) for group in range(2)])
        stable = np.array_equal(assignments, updated)
        assignments, centers = updated, new_centers
        if stable:
            break
    return assignments, centers


class ActivationClusteringProvider(EvidenceProvider):
    def __init__(self, max_cluster_fraction=0.25, separation_threshold=0.7, min_class_samples=4):
        super().__init__("activation_clustering")
        if not 0 < max_cluster_fraction < 0.5:
            raise ValueError("max_cluster_fraction must be in (0, 0.5)")
        if not 0 < separation_threshold < 1:
            raise ValueError("separation_threshold must be in (0, 1)")
        if not isinstance(min_class_samples, int) or min_class_samples < 4:
            raise ValueError("min_class_samples must be at least 4")
        self.max_cluster_fraction = max_cluster_fraction
        self.separation_threshold = separation_threshold
        self.min_class_samples = min_class_samples

    def analyze(self, asset):
        findings = []
        for label, names, matrix, hashes in _classes(asset):
            if len(names) < self.min_class_samples:
                continue
            result = _two_means(matrix)
            if result is None:
                continue
            assignments, centers = result
            counts = np.bincount(assignments, minlength=2)
            minority = int(counts.argmin())
            fraction = float(counts[minority] / len(names))
            if fraction > self.max_cluster_fraction:
                continue
            within = np.linalg.norm(matrix - centers[assignments], axis=1)
            between = np.linalg.norm(matrix - centers[1 - assignments], axis=1)
            scores = (between - within) / np.maximum(np.maximum(within, between), 1e-12)
            separation = float(min(scores.mean(), scores[assignments == minority].mean()))
            if separation < self.separation_threshold:
                continue
            for index in np.flatnonzero(assignments == minority):
                findings.append(_finding(
                    self, asset, names[index], hashes,
                    f"Chen et al. (2018) per-class k=2 activation clustering: class={label!r}, secondary cluster share={fraction:.6g}, "
                    f"centroid silhouette-like separation={separation:.6g}; threshold={self.separation_threshold}. "
                    "Deterministic numpy k-means and a centroid separation proxy are used, not an exact silhouette test.",
                    0.6,
                ))
        return findings
