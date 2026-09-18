import numpy as np

from app.core.evidence import EvidenceProvider, Finding, Modality
from app.modules.data_integrity.mislabeling import sample_matrix


class OODDetector(EvidenceProvider):
    def __init__(self, distance_threshold=5.0, regularization=1e-6, min_class_samples=4):
        super().__init__("ood")
        if not np.isfinite(distance_threshold) or distance_threshold <= 0:
            raise ValueError("distance_threshold must be finite and positive")
        if not np.isfinite(regularization) or regularization <= 0:
            raise ValueError("regularization must be finite and positive")
        if not isinstance(min_class_samples, int) or min_class_samples < 3:
            raise ValueError("min_class_samples must be at least 3")
        self.distance_threshold = distance_threshold
        self.regularization = regularization
        self.min_class_samples = min_class_samples

    def analyze(self, dataset):
        names, matrix, labels, hashes = sample_matrix(dataset)
        provenance = self._create_provenance(hashes, dataset["config_hash"])
        findings = []
        for index, name in enumerate(names):
            peers = [item for item, label in enumerate(labels) if label == labels[index] and item != index]
            if len(peers) < self.min_class_samples - 1:
                continue
            reference = matrix[peers]
            centroid = reference.mean(axis=0)
            centered = reference - centroid
            covariance = centered.T @ centered / (len(peers) - 1)
            scale = max(float(np.trace(covariance) / matrix.shape[1]), 1.0)
            covariance += np.eye(matrix.shape[1]) * self.regularization * scale
            delta = matrix[index] - centroid
            distance = float(np.sqrt(max(0.0, delta @ np.linalg.solve(covariance, delta))))
            if distance <= self.distance_threshold:
                continue
            findings.append(Finding(
                asset_id=name, finding_type="out_of_distribution", severity=0.7,
                confidence=float(min(0.95, 0.5 + 0.45 * (1 - self.distance_threshold / distance))),
                evidence=[f"Leave-one-out class {labels[index]!r} centroid Mahalanobis distance="
                          f"{distance:.6g}; threshold={self.distance_threshold}; peers={len(peers)}.",
                          f"Empirical covariance uses diagonal regularization={self.regularization * scale:.6g}."],
                modality=Modality.EMBEDDING, provenance=provenance,
                recommended_action="review", quarantine_scope="sample",
                access_assumptions="black_box",
                counter_evidence=["Distance confidence is uncalibrated. Rare legitimate samples, "
                                  "non-Gaussian classes and singular covariance can cause false positives; "
                                  "contaminated peers can hide outliers. Small classes are not assessed."],
            ))
        return findings
