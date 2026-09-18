import hashlib
import random

import numpy as np

from app.core.evidence import EvidenceProvider, Finding, Modality
from app.manifests._common import digest


def _image(image):
    values = np.asarray(image, dtype=np.float64)
    if values.ndim != 3 or min(values.shape) == 0 or not np.isfinite(values).all():
        raise ValueError("STRIP images must be finite nonempty HWC arrays")
    if (values < 0).any() or (values > 1).any():
        raise ValueError("STRIP images must be in [0, 1]")
    return values


class STRIPDetector(EvidenceProvider):
    def __init__(self, num_overlays=16, seed=7, entropy_threshold=0.2, overlay_alpha=0.5):
        super().__init__("strip")
        if not isinstance(num_overlays, int) or num_overlays < 1:
            raise ValueError("num_overlays must be a positive integer")
        if not np.isfinite(entropy_threshold) or entropy_threshold < 0:
            raise ValueError("entropy_threshold must be finite and nonnegative")
        if not 0 < overlay_alpha < 1:
            raise ValueError("overlay_alpha must be in (0, 1)")
        self.num_overlays = num_overlays
        self.seed = seed
        self.entropy_threshold = entropy_threshold
        self.overlay_alpha = overlay_alpha

    def analyze(self, asset):
        images = [(str(name), _image(image)) for name, image in asset["images"]]
        if len({name for name, _ in images}) != len(images):
            raise ValueError("Image names must be unique")
        if not images:
            return []
        backgrounds = [_image(image) for image in asset["backgrounds"]]
        if not backgrounds or any(image.shape != images[0][1].shape for image in backgrounds):
            raise ValueError("Backgrounds must be nonempty and match image shapes")
        if any(image.shape != images[0][1].shape for _, image in images):
            raise ValueError("Image shapes must match")
        threshold = asset.get("entropy_threshold", self.entropy_threshold)
        if not np.isfinite(threshold) or threshold < 0:
            raise ValueError("entropy_threshold must be finite and nonnegative")
        rng = random.Random(self.seed)
        background_hashes = [hashlib.sha256(image.astype("<f8").tobytes()).hexdigest() for image in backgrounds]
        findings = []
        for name, image in images:
            selected = [rng.randrange(len(backgrounds)) for _ in range(self.num_overlays)]
            batch = np.stack([(1 - self.overlay_alpha) * image + self.overlay_alpha * backgrounds[index]
                              for index in selected])
            probabilities = np.asarray(asset["predict_fn"](batch), dtype=np.float64)
            if probabilities.ndim != 2 or probabilities.shape[0] != self.num_overlays or probabilities.shape[1] < 2:
                raise ValueError("predict_fn must return N x C probabilities with C >= 2")
            if not np.isfinite(probabilities).all() or (probabilities < 0).any() or (probabilities > 1).any():
                raise ValueError("Predicted probabilities must be finite and in [0, 1]")
            if not np.allclose(probabilities.sum(axis=1), 1.0, atol=1e-5, rtol=0):
                raise ValueError("Predicted probability rows must sum to one")
            entropy = float(np.mean(-np.sum(probabilities * np.log(np.maximum(probabilities, 1e-300)), axis=1)))
            if entropy >= threshold:
                continue
            _, counts = np.unique(probabilities.argmax(axis=1), return_counts=True)
            consistency = float(counts.max() / self.num_overlays)
            hashes = [hashlib.sha256(image.astype("<f8").tobytes()).hexdigest(), *background_hashes,
                      digest({"seed": self.seed, "selected": selected, "alpha": self.overlay_alpha,
                              "threshold": float(threshold), "probabilities": probabilities.tolist()})]
            findings.append(Finding(
                asset_id=name, finding_type="strip_low_entropy", severity=0.7, confidence=0.6,
                evidence=[f"CANDIDATE backdoor signature: STRIP mean prediction entropy={entropy:.6g} nats < {threshold}; "
                          f"{self.num_overlays} deterministic background overlays, seed={self.seed}.",
                          f"Low entropy suggests stability under perturbation; dominant predicted class share={consistency:.6g}. "
                          "Low entropy alone does not establish that every overlay retained the same class."],
                modality=Modality.BEHAVIORAL,
                provenance=self._create_provenance(hashes, asset["config_hash"]),
                recommended_action="review", quarantine_scope="sample", access_assumptions="black_box",
                counter_evidence=["Legitimately low-entropy confident models and insufficiently disruptive backgrounds can give false positives. "
                                  "This is not proof of a backdoor; entropy thresholds require clean calibration and confidence is uncalibrated."],
            ))
        return findings
