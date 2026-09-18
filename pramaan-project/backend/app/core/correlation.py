from collections import defaultdict

from app.core.evidence import Finding
from app.manifests._common import digest


FAMILY = {
    "perceptual_duplicate": "duplicate",
    "semantic_near_duplicate": "duplicate",
    "exact_duplicate": "duplicate",
    "distribution_shift": "data_anomaly",
    "poisoning": "data_anomaly",
    "candidate_poisoning": "data_anomaly",
    "spectral_signature": "data_anomaly",
    "activation_clustering": "data_anomaly",
    "out_of_distribution": "data_anomaly",
    "spectral_signature_outlier": "data_anomaly",
    "activation_cluster_outlier": "data_anomaly",
    "candidate_backdoor_trigger": "backdoor",
    "fine_pruning_verification": "backdoor",
    "strip_low_entropy": "backdoor",
}

KNOWN_LIMITATION = (
    "this convergence logic does not yet correct for detector signal correlation — "
    "treated as a known, stated limitation, not silently ignored."
)


class CorrelationEngine:
    @staticmethod
    def known_limitations():
        return [KNOWN_LIMITATION,
                "Naive-correlation limitation: same-modality agreement receives no confidence boost; "
                "declared shared signals or reused detectors also suppress the boost. "
                "Cross-modality boosts are heuristic, not calibrated probabilities."]

    def converge(self, findings: list[Finding]) -> list[Finding]:
        grouped = defaultdict(lambda: defaultdict(list))
        for finding in findings:
            grouped[finding.asset_id][finding.modality].append(finding)
        result = []
        for asset_id, modalities in grouped.items():
            families = defaultdict(list)
            for group in modalities.values():
                for finding in group:
                    families[FAMILY.get(finding.finding_type, finding.finding_type)].append(finding)
            for family, group in families.items():
                eligible = [finding for finding in group if finding.severity > 0 and finding.confidence > 0
                            and finding.recommended_action != "accept"]
                diverse = {finding.modality for finding in eligible}
                if len(diverse) < 2:
                    result.extend(group)
                    continue
                result.extend(finding for finding in group if finding not in eligible)
                detector_ids, signal_ids, sources = set(), set(), []
                shared = False
                for finding in eligible:
                    provenance = finding.provenance
                    detectors = set(provenance.get("detector_ids", []))
                    detectors.add(provenance["detector_id"])
                    signals = set(provenance.get("signal_ids", []))
                    if provenance.get("signal_id"):
                        signals.add(provenance["signal_id"])
                    shared = shared or bool(detector_ids & detectors or signal_ids & signals)
                    detector_ids.update(detectors)
                    signal_ids.update(signals)
                    sources.append(f"{', '.join(sorted(detectors))} ({finding.modality.value})")
                best = max(eligible, key=lambda finding: finding.confidence)
                per_modality = [max(finding.confidence for finding in eligible if finding.modality == modality)
                                for modality in diverse]
                confidence = best.confidence
                if not shared:
                    confidence += (1 - confidence) * 0.2 * min(per_modality) * (len(diverse) - 1)
                confidence = min(0.95, confidence)
                evidence = list(dict.fromkeys(text for finding in eligible for text in finding.evidence))
                evidence.extend([
                    f"Complementary signals converged for {family}: {'; '.join(sources)}.",
                    "No confidence boost: declared shared signal or reused detector." if shared else
                    "Confidence boost uses modality-diverse agreement; extra same-modality findings add no boost.",
                    KNOWN_LIMITATION,
                ])
                provenance = {
                    "detector_id": "correlation_engine", "version": "1.0.0",
                    "detector_ids": sorted(detector_ids), "signal_ids": sorted(signal_ids),
                    "modalities": sorted(modality.value for modality in diverse),
                    "input_hashes": sorted({value for finding in eligible for value in finding.provenance.get("input_hashes", [])}),
                    "config_hash": digest(sorted({finding.provenance.get("config_hash", "") for finding in eligible})),
                    "source_provenance": [finding.provenance.copy() for finding in eligible],
                }
                access = max((finding.access_assumptions for finding in eligible),
                             key={"black_box": 0, "gray_box": 1, "white_box": 2}.__getitem__)
                scopes = {finding.quarantine_scope for finding in eligible}
                result.append(Finding(
                    asset_id=asset_id, finding_type=f"composite_{family}",
                    severity=max(finding.severity for finding in eligible), confidence=confidence,
                    evidence=evidence, modality=best.modality, provenance=provenance,
                    recommended_action="review", quarantine_scope=next(iter(scopes)) if len(scopes) == 1 else None,
                    access_assumptions=access,
                    counter_evidence=list(dict.fromkeys(text for finding in eligible for text in finding.counter_evidence)),
                ))
        return result
