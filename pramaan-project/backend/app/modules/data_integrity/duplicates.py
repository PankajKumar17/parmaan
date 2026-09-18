import hashlib

import numpy as np
from PIL import Image

from app.core.evidence import EvidenceProvider, Finding, Modality


class DuplicateDetector(EvidenceProvider):
    """Offline pHash and mean-RGB clustering; replace embedding_features with
    locally cached CLIP/ResNet embeddings later. RGB is not a semantic encoder.
    """

    def __init__(self, hamming_threshold=6, similarity_threshold=0.995):
        super().__init__("duplicates")
        if not isinstance(hamming_threshold, int) or not 0 <= hamming_threshold <= 63:
            raise ValueError("hamming_threshold must be an integer in [0, 63]")
        if not 0 < similarity_threshold <= 1:
            raise ValueError("similarity_threshold must be in (0, 1]")
        self.hamming_threshold = hamming_threshold
        self.similarity_threshold = similarity_threshold

    @staticmethod
    def phash(image):
        pixels = np.asarray(image.convert("L").resize((32, 32), Image.Resampling.LANCZOS), dtype=float)
        positions = np.arange(32) + 0.5
        basis = np.cos(np.pi * np.outer(np.arange(8), positions) / 32)
        basis[0] *= 1 / np.sqrt(2)
        coefficients = (basis @ pixels @ basis.T).ravel()[1:]
        coefficients[np.abs(coefficients) < 1e-8] = 0
        bits = coefficients > np.median(coefficients)
        return sum(int(bit) << index for index, bit in enumerate(bits))

    @staticmethod
    def embedding_features(image):
        return np.asarray(image.convert("RGB"), dtype=float).mean(axis=(0, 1)) / 255

    def analyze(self, dataset):
        images = dataset["images"]
        config_hash = dataset["config_hash"]
        names = [str(name) for name, _ in images]
        if len(set(names)) != len(names):
            raise ValueError("Image names must be unique")
        hashes = [hashlib.sha256(image.tobytes()).hexdigest() for _, image in images]
        phashes = [self.phash(image) for _, image in images]
        vectors = [self.embedding_features(image) for _, image in images]
        norms = [float(np.linalg.norm(vector)) for vector in vectors]
        parents = list(range(len(images)))
        findings = []

        def root(index):
            while parents[index] != index:
                parents[index] = parents[parents[index]]
                index = parents[index]
            return index

        for index in range(len(images)):
            for previous in range(index):
                distance = (phashes[index] ^ phashes[previous]).bit_count()
                if distance <= self.hamming_threshold:
                    findings.append(Finding(
                        asset_id=names[index], finding_type="perceptual_duplicate",
                        severity=0.5, confidence=0.9 - 0.2 * distance / 63,
                        evidence=[f"pHash Hamming distance to {names[previous]}: {distance}/63; "
                                  f"threshold={self.hamming_threshold}"],
                        modality=Modality.PIXEL,
                        provenance=self._create_provenance([hashes[previous], hashes[index]], config_hash),
                        recommended_action="review", quarantine_scope="sample",
                        access_assumptions="black_box",
                        counter_evidence=["pHash can collide on low-detail images; legitimate repeated "
                                          "views are not proof of duplicate flooding."],
                    ))
                if norms[index] == 0 or norms[previous] == 0:
                    similarity = float(norms[index] == norms[previous])
                else:
                    similarity = float(np.clip(
                        np.dot(vectors[index] / norms[index], vectors[previous] / norms[previous]), -1, 1
                    ))
                if similarity >= self.similarity_threshold:
                    parents[root(index)] = root(previous)

        clusters = {}
        for index in range(len(images)):
            clusters.setdefault(root(index), []).append(index)
        for members in clusters.values():
            if len(members) < 2:
                continue
            provenance = self._create_provenance([hashes[index] for index in members], config_hash)
            for index in members[1:]:
                findings.append(Finding(
                    asset_id=names[index], finding_type="semantic_near_duplicate",
                    severity=0.4, confidence=0.55,
                    evidence=[f"Offline mean-RGB cosine cluster: {[names[item] for item in members]}; "
                              f"single-link similarity threshold={self.similarity_threshold}"],
                    modality=Modality.EMBEDDING, provenance=provenance,
                    recommended_action="review", quarantine_scope="sample",
                    access_assumptions="black_box",
                    counter_evidence=["Average color is only an offline embedding proxy, not semantic "
                                      "proof. Real locally cached CLIP/ResNet embeddings can replace "
                                      "embedding_features later; unrelated images can share colors.",
                                      "Single-link clusters can chain; not every pair exceeds the threshold. "
                                      "Both passes share image content and are not calibrated."],
                ))
        return findings
