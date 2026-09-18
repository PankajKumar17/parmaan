import logging
from itertools import zip_longest

from app.core.lineage import IntegrityLineage


logger = logging.getLogger(__name__)


class RiskDecisionMatrix:
    """Severity rows and confidence columns: low <.3, medium [.3,.7), high >=.7.

    Matrix rows: ACCEPT/ACCEPT/ACCEPT; ACCEPT/REVIEW/REVIEW;
    ACCEPT/REVIEW/QUARANTINE. Scores must be finite and in [0,1].
    Trust rollup is display-only. Scope selects the highest reachable upstream
    scoped ancestor (dataset maps to batch); ties use node id for determinism.
    Missing lineage uses the declared scope, or sample, with an explicit note.
    """

    MATRIX = (("ACCEPT", "ACCEPT", "ACCEPT"),
              ("ACCEPT", "REVIEW", "REVIEW"),
              ("ACCEPT", "REVIEW", "QUARANTINE"))
    SCOPES = {"contributor": "contributor", "dataset": "batch", "batch": "batch",
              "sample": "sample", "model": "model", "inference": "inference_record",
              "inference_record": "inference_record"}

    def __init__(self, lineage=None):
        self.lineage = lineage if lineage is not None else IntegrityLineage()

    @staticmethod
    def _band(value):
        if not 0 <= value <= 1:
            raise ValueError("Severity and confidence must be finite and in [0, 1]")
        return int(value >= 0.3) + int(value >= 0.7)

    def _scope(self, finding):
        graph = self.lineage.graph
        candidates = {node for node, attrs in graph.nodes(data=True)
                      if attrs.get("node_type") in self.SCOPES
                      and (node == finding.asset_id or finding.asset_id in self.lineage.downstream_of(node))}
        roots = sorted(node for node in candidates if not any(
            node in self.lineage.downstream_of(other) for other in candidates if other != node))
        if roots:
            node = roots[0]
            return self.SCOPES[graph.nodes[node]["node_type"]], node, None
        scope = finding.quarantine_scope
        if scope not in self.SCOPES.values():
            scope = "sample"
        return scope, finding.asset_id, "No scoped lineage ancestor; using declared scope or sample fallback."

    def decide(self, findings):
        result = []
        for finding in findings:
            verdict = self.MATRIX[self._band(finding.severity)][self._band(finding.confidence)]
            scope, scope_asset_id, note = self._scope(finding)
            item = {"finding": finding, "verdict": verdict, "scope": scope,
                    "scope_asset_id": scope_asset_id, "evidence": list(finding.evidence),
                    "counter_evidence": list(finding.counter_evidence)}
            if note:
                item["scope_note"] = note
            if verdict == "QUARANTINE" and not item["counter_evidence"]:
                item["warning"] = "QUARANTINE has no counter-evidence; decision requires a second look."
                logger.warning("%s Asset: %s", item["warning"], finding.asset_id)
            result.append(item)
        return result

    @staticmethod
    def unified_trust_score(findings):
        """Return per-detector 1-max(severity*confidence), and mean rollup, for display."""
        components = {}
        for finding in findings:
            RiskDecisionMatrix._band(finding.severity)
            RiskDecisionMatrix._band(finding.confidence)
            detector = finding.provenance.get("detector_id", "unknown")
            components[detector] = min(components.get(detector, 1.0),
                                       1 - finding.severity * finding.confidence)
        return {"components": components,
                "rollup": sum(components.values()) / len(components) if components else None,
                "display_only": True}

    @staticmethod
    def explain(verdict):
        def escape(text):
            return str(text).replace("|", "\\|").replace("\n", "<br>")

        lines = [f"{verdict['verdict']} — {verdict['scope']} ({verdict['scope_asset_id']})",
                 "Evidence | Counter-evidence", "--- | ---"]
        for evidence, counter in zip_longest(verdict["evidence"] or ["Not provided"],
                                             verdict["counter_evidence"] or ["Not provided"], fillvalue=""):
            lines.append(f"{escape(evidence)} | {escape(counter)}")
        if "warning" in verdict:
            lines.append(verdict["warning"])
        return "\n".join(lines)


def unified_trust_score(findings):
    return RiskDecisionMatrix.unified_trust_score(findings)
