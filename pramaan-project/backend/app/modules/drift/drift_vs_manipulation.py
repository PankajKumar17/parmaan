import hashlib

import numpy as np

from app.core.evidence import EvidenceProvider, Finding, Modality
from app.manifests._common import digest
from app.modules.drift.cause_breakdown import classify_shift
from app.modules.drift.energy_ood import energy_score
from app.modules.drift.mmd import _matrix, kl_divergence_histogram, mmd_rbf


class DriftVsManipulationProvider(EvidenceProvider):
    def __init__(self, mmd_threshold=0.1, image_threshold=0.1, gamma=None):
        super().__init__("drift_vs_manipulation")
        if not np.isfinite(mmd_threshold) or mmd_threshold < 0:
            raise ValueError("mmd_threshold must be finite and nonnegative")
        if not np.isfinite(image_threshold) or image_threshold < 0:
            raise ValueError("image_threshold must be finite and nonnegative")
        if gamma is not None and (not np.isfinite(gamma) or gamma <= 0):
            raise ValueError("gamma must be finite and positive")
        self.mmd_threshold = mmd_threshold
        self.image_threshold = image_threshold
        self.gamma = gamma

    def analyze(self, asset):
        reference = _matrix(asset["reference_embeddings"], "reference_embeddings")
        current = _matrix(asset["current_embeddings"], "current_embeddings")
        reference_images = list(asset["reference_images"])
        current_images = list(asset["current_images"])
        if len(reference_images) != len(reference) or len(current_images) != len(current):
            raise ValueError("Each image batch must align row-for-row with its embeddings")
        for images in (reference_images, current_images):
            names = [str(name) for name, _ in images]
            if len(set(names)) != len(names):
                raise ValueError("Image names must be unique within each batch")
        gamma = self.gamma if self.gamma is not None else 1.0 / reference.shape[1]
        mmd = mmd_rbf(reference, current, gamma)
        attribution = classify_shift(reference_images, current_images)
        hashes = [hashlib.sha256(matrix.astype("<f8").tobytes()).hexdigest() for matrix in (reference, current)]
        hashes.extend(hashlib.sha256(image.tobytes()).hexdigest() for _, image in reference_images + current_images)
        hashes.append(digest({"reference_names": [str(name) for name, _ in reference_images],
                              "current_names": [str(name) for name, _ in current_images]}))
        kl_values = []
        for dimension in range(reference.shape[1]):
            bins = np.histogram_bin_edges(np.concatenate([reference[:, dimension], current[:, dimension]]), bins=16)
            kl_values.append(kl_divergence_histogram(np.histogram(reference[:, dimension], bins)[0],
                                                   np.histogram(current[:, dimension], bins)[0]))
        energy_evidence = "Energy OOD not assessed: class logits were not supplied; embeddings are not treated as logits."
        if "reference_logits" in asset or "current_logits" in asset:
            if "reference_logits" not in asset or "current_logits" not in asset:
                raise ValueError("Both reference_logits and current_logits are required for energy OOD")
            ref_logits = _matrix(asset["reference_logits"], "reference_logits")
            cur_logits = _matrix(asset["current_logits"], "current_logits")
            if len(ref_logits) != len(reference) or len(cur_logits) != len(current) or ref_logits.shape[1] != cur_logits.shape[1]:
                raise ValueError("Logits must align with image batches and have matching class dimensions")
            ref_energy, cur_energy = energy_score(ref_logits), energy_score(cur_logits)
            hashes.extend(hashlib.sha256(matrix.astype("<f8").tobytes()).hexdigest() for matrix in (ref_logits, cur_logits))
            energy_evidence = (f"Liu et al. (2020) mean energy: reference={ref_energy.mean():.6g}, "
                               f"current={cur_energy.mean():.6g}, delta={cur_energy.mean() - ref_energy.mean():.6g}. "
                               "Energy is descriptive and requires a model-specific clean baseline for OOD thresholds.")
        if mmd <= self.mmd_threshold and attribution["total_magnitude"] <= self.image_threshold:
            return []
        severity = float(np.clip(max(mmd / 2, attribution["total_magnitude"]), 0.2, 0.8))
        return [Finding(
            asset_id=str(asset.get("batch_id", digest({"current_names": [str(name) for name, _ in current_images], "hashes": hashes}))),
            finding_type="distribution_shift", severity=severity, confidence=0.6,
            evidence=[
                f"Distribution shift: unbiased RBF MMD squared={mmd:.6g}, threshold={self.mmd_threshold}, gamma={gamma:.6g}; "
                f"mean marginal histogram KL(reference || current)={np.mean(kl_values):.6g}.",
                "Embedding or image-statistic discrepancies can be consistent with inserted or altered content, "
                "but distribution shift alone is not evidence of malicious intent.",
                energy_evidence,
                *attribution["evidence"],
            ],
            modality=Modality.EMBEDDING,
            provenance=self._create_provenance(hashes, asset["config_hash"]),
            recommended_action="review", quarantine_scope="batch", access_assumptions="black_box",
            counter_evidence=[
                f"Cause-breakdown attribution: illumination share={attribution['illumination']:.1%}, consistent with ordinary time-of-day/lighting variation rather than injected content; "
                f"color share={attribution['color']:.1%} may reflect terrain/season; blur_noise share={attribution['blur_noise']:.1%} may reflect sensor changes; "
                f"structural share={attribution['structural']:.1%} may reflect terrain/viewpoint.",
                "Attribution is heuristic, not a causal determination. Sampling variation, model/preprocessing changes, and legitimate operational drift "
                "can explain discrepancies; confidence is uncalibrated and review does not presume manipulation.",
            ],
        )]
