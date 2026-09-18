import random

import numpy as np

from app.core.evidence import EvidenceProvider, Finding, Modality
from app.manifests._common import digest
from app.modules.model_integrity.counterfactual import _predict


class TriggerReconstructionProvider(EvidenceProvider):
    def __init__(self, seed=0, max_iterations=50, anomaly_threshold=3.5):
        super().__init__("trigger_reconstruction")
        if not isinstance(max_iterations, int) or not 1 <= max_iterations <= 50:
            raise ValueError("max_iterations must be an integer in [1, 50]")
        if not np.isfinite(anomaly_threshold) or anomaly_threshold < 0:
            raise ValueError("anomaly_threshold must be finite and nonnegative")
        self.seed = seed
        self.max_iterations = max_iterations
        self.anomaly_threshold = anomaly_threshold

    def reconstruct(self, model, samples):
        samples = np.asarray(samples, dtype=np.float64)
        if samples.ndim != 2 or samples.shape[1] != 64 or not len(samples):
            raise ValueError("samples must be a nonempty matrix of flattened 8x8 grayscale images")
        if not np.isfinite(samples).all() or np.any((samples < 0) | (samples > 1)):
            raise ValueError("grayscale features must be finite and in [0, 1]")
        outputs = [_predict(model, sample.copy()) for sample in samples]
        classes = len(outputs[0])
        if classes < 2 or any(len(output) != classes for output in outputs):
            raise ValueError("model must return a fixed number of at least two classes")
        labels = np.array([int(output.argmax()) for output in outputs])
        rng = random.Random(self.seed)
        results = []
        for target in range(classes):
            reference = samples[labels != target]
            patch = np.zeros(64)
            if not len(reference):
                results.append({"class_id": target, "success": False, "l1_norm": None,
                                "patch": patch.tolist(), "iterations": 0})
                continue

            def objective(candidate):
                failures, margin = 0, 0.0
                for sample in reference:
                    logits = _predict(model, np.clip(sample + candidate, 0, 1))
                    if len(logits) != classes:
                        raise ValueError("model output dimensions changed during reconstruction")
                    failures += int(int(logits.argmax()) != target)
                    competitor = float(np.max(np.delete(logits, target)))
                    margin += max(0.0, competitor - float(logits[target]) + 1e-8)
                return failures, margin / len(reference), float(np.abs(candidate).sum())

            score = objective(patch)
            step = 1.0
            iterations = 0
            for iterations in range(1, self.max_iterations + 1):
                previous = score
                coordinates = list(range(64))
                rng.shuffle(coordinates)
                for coordinate in coordinates:
                    current = patch[coordinate]
                    for value in (0.0, max(-1.0, current - step), min(1.0, current + step)):
                        candidate = patch.copy()
                        candidate[coordinate] = value
                        candidate_score = objective(candidate)
                        if candidate_score < score:
                            patch, score = candidate, candidate_score
                if score == previous:
                    step *= 0.5
                    if step < 1 / 1024:
                        break
            results.append({"class_id": target, "success": score[0] == 0,
                            "l1_norm": score[2] if score[0] == 0 else None,
                            "patch": patch.tolist(), "iterations": iterations})
        return results

    def analyze(self, asset):
        results = self.reconstruct(asset["model"], asset["samples"])
        successful = [result for result in results if result["success"]]
        if len(successful) < 3:
            return []
        norms = np.array([result["l1_norm"] for result in successful])
        median = float(np.median(norms))
        mad = float(np.median(np.abs(norms - median)))
        outlier = successful[int(norms.argmax())]
        anomaly_index = (outlier["l1_norm"] - median) / max(1.4826 * mad, 1e-6)
        if anomaly_index <= self.anomaly_threshold:
            return []
        severity = float(anomaly_index / (1 + anomaly_index))
        provenance = self._create_provenance(
            [digest(np.asarray(asset["samples"], dtype=float).tolist())],
            asset.get("config_hash", digest({"seed": self.seed, "max_iterations": self.max_iterations,
                                            "anomaly_threshold": self.anomaly_threshold})),
        )
        provenance.update({"target_class": outlier["class_id"], "anomaly_index": anomaly_index,
                           "median_l1": median, "mad_l1": mad, "reconstruction": results})
        return [Finding(
            asset_id=str(asset["asset_id"]), finding_type="candidate_backdoor_trigger",
            severity=severity, confidence=min(0.6, 0.4 + 0.2 * severity),
            evidence=["candidate evidence, not proof — known false positives on naturally small decision boundaries per class",
                      f"Target class={outlier['class_id']}; maximum reconstructed L1={outlier['l1_norm']:.6g}; "
                      f"MAD={mad:.6g}; anomaly index={anomaly_index:.6g}.",
                      "Bounded coordinate descent uses a high-norm outlier heuristic, not the usual low-norm "
                      "Neural Cleanse criterion; results are local candidates, not global minima.",
                      f"Successful reconstructions={len(successful)}/{len(results)}; failed classes are excluded. "
                      "At least three successful classes are needed for this MAD comparison."],
            modality=Modality.BEHAVIORAL, provenance=provenance,
            recommended_action="review", quarantine_scope="model", access_assumptions="white_box",
            counter_evidence=["Naturally small decision boundaries and differing class geometry can create norm outliers.",
                              "Optimization failures or reference-battery coverage can distort the class comparison."],
        )]
