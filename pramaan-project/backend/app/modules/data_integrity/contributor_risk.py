from collections import defaultdict
from dataclasses import dataclass

import numpy as np

from app.core.correlation import FAMILY


@dataclass(frozen=True)
class TemporalDriftPoint:
    contributor_id: str
    change_point_batch: str
    before_rate: float
    after_rate: float


class ContributorRiskAggregator:
    """aggregate(findings, {samples: {id: metadata}, ordered_batches: [id]}) -> dict.

    Only positive review/quarantine sample findings count as anomalies. Denominators
    include clean manifest samples; duplicate findings never increase prevalence.
    Risk is a heuristic, not a probability: prevalence * (.5 severity + .2
    convergence/5 + .15 max batch share) + .15 positive temporal rate jump.
    Convergence counts modalities agreeing within a sample and finding family.
    Adjacent rolling windows locate the largest upward rate jump >= drift_threshold.
    Missing contributor/batch metadata is reported as a coverage gap, not clean data.
    """

    def __init__(self, window=2, drift_threshold=0.15):
        if not isinstance(window, int) or isinstance(window, bool) or window < 1:
            raise ValueError("window must be a positive integer")
        if not 0 < drift_threshold <= 1:
            raise ValueError("drift_threshold must be in (0, 1]")
        self.window = window
        self.drift_threshold = drift_threshold
        self.temporal_drift_points = []

    def aggregate(self, findings, batch_metadata, ordered_batches=None):
        metadata = batch_metadata.to_dict() if hasattr(batch_metadata, "to_dict") else batch_metadata
        samples = metadata["samples"]
        order = ordered_batches if ordered_batches is not None else metadata.get("ordered_batches")
        if order is None:
            raise ValueError("Explicit ordered_batches is required; batch ids are not timestamps")
        order = list(order)
        if len(set(order)) != len(order):
            raise ValueError("ordered_batches must contain unique batch ids")
        by_sample = defaultdict(list)
        unknown = set()
        for finding in findings:
            if not 0 <= finding.severity <= 1 or not 0 <= finding.confidence <= 1:
                raise ValueError("Finding severity/confidence must be in [0, 1]")
            if finding.asset_id not in samples:
                unknown.add(finding.asset_id)
            elif finding.severity > 0 and finding.confidence > 0 and finding.recommended_action.lower() != "accept":
                by_sample[finding.asset_id].append(finding)
        grouped = defaultdict(lambda: defaultdict(list))
        missing = []
        for sample_id, sample in samples.items():
            contributor, batch = sample.get("contributor_id"), sample.get("batch_id")
            if contributor is None or batch is None:
                missing.append(sample_id)
                continue
            if batch not in order:
                raise ValueError(f"Batch {batch!r} is absent from ordered_batches")
            grouped[contributor][batch].append(sample_id)
        contributors = {}
        points = []
        for contributor in sorted(grouped):
            batches = []
            severities, convergence_counts = [], []
            for batch in order:
                ids = grouped[contributor].get(batch, [])
                if not ids:
                    continue
                affected = [sample for sample in ids if by_sample[sample]]
                batch_severities, batch_convergence = [], []
                for sample in affected:
                    group = by_sample[sample]
                    batch_severities.append(max(finding.severity for finding in group))
                    families = defaultdict(set)
                    for finding in group:
                        family = FAMILY.get(finding.finding_type, finding.finding_type)
                        families[family].add(finding.modality.value)
                        families[family].update(finding.provenance.get("modalities", []))
                    batch_convergence.append(max(map(len, families.values())))
                severities.extend(batch_severities)
                convergence_counts.extend(batch_convergence)
                batches.append({"batch_id": batch, "sample_count": len(ids),
                                "affected": sorted(affected), "anomaly_count": len(affected),
                                "anomaly_rate": len(affected) / len(ids),
                                "severity": float(np.mean(batch_severities)) if affected else 0.0,
                                "convergence_count": max(batch_convergence, default=0)})
            rates = np.array([batch["anomaly_rate"] for batch in batches])
            candidates = []
            for index in range(self.window, len(rates) - self.window + 1):
                before = float(rates[index - self.window:index].mean())
                after = float(rates[index:index + self.window].mean())
                candidates.append((after - before, index, before, after))
            point = None
            if candidates:
                jump, index, before, after = max(candidates, key=lambda item: (item[0], -item[1]))
                if jump >= self.drift_threshold:
                    point = TemporalDriftPoint(contributor, batches[index]["batch_id"], before, after)
                    points.append(point)
            affected_count = sum(batch["anomaly_count"] for batch in batches)
            prevalence = affected_count / sum(batch["sample_count"] for batch in batches)
            severity = float(np.mean(severities)) if severities else 0.0
            convergence = float(np.mean(convergence_counts)) if convergence_counts else 0.0
            concentration = max(batch["anomaly_count"] for batch in batches) / affected_count if affected_count else 0.0
            temporal = point.after_rate - point.before_rate if point else 0.0
            score = prevalence * (0.5 * severity + 0.2 * min(convergence / 5, 1) + 0.15 * concentration) + 0.15 * temporal
            contributors[contributor] = {"risk_score": float(np.clip(score, 0, 1)), "severity": severity,
                                         "prevalence": prevalence, "convergence_count": convergence,
                                         "batch_concentration": concentration, "temporal_change": temporal,
                                         "batches": batches, "temporal_drift_point": point}
        self.temporal_drift_points = points
        return {"contributors": contributors, "temporal_drift_points": points,
                "metadata_coverage": (len(samples) - len(missing)) / len(samples) if samples else 0.0,
                "missing_metadata": sorted(missing), "unmatched_findings": sorted(unknown)}
