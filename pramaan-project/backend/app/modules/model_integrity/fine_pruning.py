import numpy as np

from app.core.evidence import EvidenceProvider, Finding, Modality
from app.manifests._common import digest
from app.modules.model_integrity.counterfactual import mask_channels, test_counterfactual


class FinePruningProvider(EvidenceProvider):
    def __init__(self, prune_fraction=0.1):
        super().__init__("fine_pruning")
        if not np.isfinite(prune_fraction) or not 0 < prune_fraction <= 1:
            raise ValueError("prune_fraction must be in (0, 1]")
        self.prune_fraction = prune_fraction

    def analyze(self, asset):
        activations = np.asarray(asset["activations"], dtype=np.float64)
        battery = np.asarray(asset["reference_battery"], dtype=np.float64)
        if activations.ndim != 2 or not all(activations.shape) or not np.isfinite(activations).all():
            raise ValueError("activations must be a finite nonempty clean-sample by neuron matrix")
        if battery.ndim != 2 or not len(battery) or battery.shape[1] != activations.shape[1] or not np.isfinite(battery).all():
            raise ValueError("reference_battery must contain finite vectors at the same exposed neuron layer")
        suspicious = set(asset["suspicious_indices"])
        if not suspicious or any(not isinstance(index, (int, np.integer)) or not 0 <= index < len(battery)
                                 for index in suspicious):
            raise ValueError("suspicious_indices must identify flagged reference-battery rows")
        count = max(1, int(activations.shape[1] * self.prune_fraction))
        neurons = np.argsort(np.mean(np.abs(activations), axis=0), kind="stable")[:count].tolist()
        mask = mask_channels(neurons)
        predict_fn = asset["predict_fn"]
        model = asset["model"]
        results = [test_counterfactual(lambda vector: predict_fn(model, vector), sample, mask)
                   for sample in battery]
        changed = [index for index, result in enumerate(results) if not result["behavior_persists"]]
        suspicious_changes = sorted(suspicious.intersection(changed))
        other_changes = sorted(set(changed) - suspicious)
        fraction = len(suspicious_changes) / len(suspicious)
        provenance = self._create_provenance(
            [digest(activations.tolist()), digest(battery.tolist())],
            asset.get("config_hash", digest({"prune_fraction": self.prune_fraction})),
        )
        provenance.update({"pruned_neurons": neurons, "suspicious_changed_indices": suspicious_changes,
                           "other_changed_indices": other_changes, "counterfactual_results": results,
                           "behavior_changed": bool(suspicious_changes)})
        return [Finding(
            asset_id=str(asset["asset_id"]), finding_type="fine_pruning_verification",
            severity=fraction, confidence=0.6 * fraction,
            evidence=[f"Pruned low-activation neurons={neurons}; flagged prediction changes="
                      f"{len(suspicious_changes)}/{len(suspicious)}; other battery changes={len(other_changes)}.",
                      "A change is supporting evidence for the backdoor hypothesis, not confirmation — "
                      "pruned neurons can also be legitimate rare-feature detectors",
                      "predict_fn(model, neuron_vector) evaluates the downstream model at the exposed layer; "
                      "masking its selected neurons is the pruned variant, with no weight mutation or retraining. "
                      "Only top-class changes are counted; unchanged behavior does not rule out a backdoor."],
            modality=Modality.ACTIVATION, provenance=provenance,
            recommended_action="review", quarantine_scope="model", access_assumptions="white_box",
            counter_evidence=["Pruned neurons can be legitimate rare-feature detectors, so behavior changes are not causal proof.",
                              f"Non-flagged battery rows changed={len(other_changes)}; collateral damage weakens attribution."],
        )]
