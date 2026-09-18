import math

from app.core.evidence import EvidenceProvider, Finding, Modality
from app.manifests._common import digest


class UnclassifiedAnomalyProvider(EvidenceProvider):
    def __init__(self, threshold=0.7):
        super().__init__("unclassified_anomaly")
        if not math.isfinite(threshold) or not 0 <= threshold <= 1:
            raise ValueError("threshold must be in [0, 1]")
        self.threshold = threshold

    def analyze(self, asset):
        if isinstance(asset, dict):
            anomalies = asset["anomalies"]
            config_hash = asset["config_hash"]
            matched = set(asset.get("matched_asset_ids", []))
        else:
            anomalies = asset
            config_hash = digest({"threshold": self.threshold})
            matched = set()
        findings = []
        for name, raw_score in anomalies:
            score = float(raw_score)
            if not math.isfinite(score) or not 0 <= score <= 1:
                raise ValueError("Anomaly scores must be finite and in [0, 1]")
            if score <= self.threshold or name in matched:
                continue
            findings.append(Finding(
                asset_id=str(name), finding_type="unclassified_anomaly", severity=score, confidence=0.5,
                evidence=[f"Unmatched anomaly score={score:.6g} exceeds threshold={self.threshold}. "
                          "This feeds the Coverage Statement and is not force-fitted into an existing finding_type."],
                modality=Modality.BEHAVIORAL,
                provenance=self._create_provenance([digest({"name": str(name), "score": score})], config_hash),
                recommended_action="review", quarantine_scope="sample", access_assumptions="black_box",
                counter_evidence=["An unclassified anomaly may be legitimate unseen variation or a detector error; "
                                  "the input score is not calibrated confidence and establishes no attack mechanism."],
            ))
        return findings
