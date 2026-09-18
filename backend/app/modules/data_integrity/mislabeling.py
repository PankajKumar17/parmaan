import hashlib
from collections import Counter

import numpy as np

from app.core.evidence import EvidenceProvider, Finding, Modality
from app.manifests._common import digest


def feature_vector(image, bins=8):
    pixels = np.asarray(image.convert("RGB"), dtype=float) / 255
    means = pixels.mean(axis=(0, 1)).tolist()
    histograms = [np.histogram(pixels[:, :, channel], bins=bins, range=(0, 1))[0]
                  / (pixels.shape[0] * pixels.shape[1]) for channel in range(3)]
    return means + np.concatenate(histograms).tolist()


def sample_matrix(dataset):
    samples = dataset["samples"]
    num_classes = dataset["num_classes"]
    if isinstance(num_classes, bool) or not isinstance(num_classes, int) or num_classes < 1:
        raise ValueError("num_classes must be a positive integer")
    names = [str(name) for name, _, _ in samples]
    if len(set(names)) != len(names):
        raise ValueError("Sample names must be unique")
    labels = [label for _, _, label in samples]
    if any(not isinstance(label, (str, int)) or isinstance(label, bool) for label in labels):
        raise ValueError("Labels must be strings or integers")
    if len(set(labels)) > num_classes:
        raise ValueError("Observed labels exceed num_classes")
    matrix = np.asarray([features for _, features, _ in samples], dtype="<f8")
    if samples and (matrix.ndim != 2 or matrix.shape[1] == 0 or not np.isfinite(matrix).all()):
        raise ValueError("Features must be finite, nonempty vectors of equal length")
    hashes = [hashlib.sha256(row.tobytes()).hexdigest() for row in matrix]
    hashes.append(digest({"names": names, "labels": labels, "num_classes": num_classes}))
    return names, matrix, labels, hashes


class MislabelingDetector(EvidenceProvider):
    def __init__(self, k=5, confidence_threshold=0.8):
        super().__init__("mislabeling")
        if isinstance(k, bool) or not isinstance(k, int) or k < 1:
            raise ValueError("k must be a positive integer")
        if not 0.5 < confidence_threshold <= 1:
            raise ValueError("confidence_threshold must be in (0.5, 1]")
        self.k = k
        self.confidence_threshold = confidence_threshold

    def analyze(self, dataset):
        names, matrix, labels, hashes = sample_matrix(dataset)
        config_hash = dataset["config_hash"]
        if len(names) < 3:
            return []
        findings = []
        provenance = self._create_provenance(hashes, config_hash)
        for index, name in enumerate(names):
            distances = np.linalg.norm(matrix - matrix[index], axis=1)
            distances[index] = np.inf
            neighbors = np.argsort(distances, kind="stable")[:min(self.k, len(names) - 1)]
            predicted, count = Counter(labels[int(item)] for item in neighbors).most_common(1)[0]
            confidence = count / len(neighbors)
            if predicted == labels[index] or confidence < self.confidence_threshold:
                continue
            findings.append(Finding(
                asset_id=name, finding_type="label_disagreement", severity=0.65,
                confidence=float(confidence),
                evidence=[f"Leave-one-out k-NN predicts {predicted!r}, stated label={labels[index]!r}; "
                          f"{count}/{len(neighbors)} neighbors agree.",
                          f"Neighbor samples: {[names[int(item)] for item in neighbors]}"],
                modality=Modality.ANNOTATION, provenance=provenance,
                recommended_action="review", quarantine_scope="sample",
                access_assumptions="black_box",
                counter_evidence=["Neighbor vote fraction is uncalibrated; simple mean-RGB/histogram "
                                  "features may confuse legitimate classes. Corrupted neighbors, class "
                                  "imbalance, and feature scaling can cause confident false positives."],
            ))
        return findings
