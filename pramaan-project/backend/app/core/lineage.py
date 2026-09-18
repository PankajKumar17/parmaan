from dataclasses import asdict

import networkx as nx

from app.manifests._common import digest, snapshot


class IntegrityLineage:
    """Upstream-to-downstream lineage. Optional training_dataset_ids on a model
    manifest declares training parents; absent metadata creates an orphan dataset.
    Inference datasets are not assumed to be training datasets.
    """

    def __init__(self):
        self.graph = nx.DiGraph()

    @staticmethod
    def _payload(value):
        if isinstance(value, dict):
            return snapshot(value)
        if hasattr(value, "to_dict"):
            return value.to_dict()
        return asdict(value)

    def _node(self, node_id, node_type, node_hash, reference):
        if node_id in self.graph:
            existing = self.graph.nodes[node_id]
            if existing["node_type"] not in (node_type, "asset"):
                raise ValueError("Node identifier already belongs to another asset type")
        self.graph.add_node(node_id, node_type=node_type, hash=node_hash,
                            ref=reference, orphan=False)
        return node_id

    def _parent(self, node_id, node_type):
        if node_id not in self.graph:
            self.graph.add_node(node_id, node_type=node_type, hash=None,
                                ref=node_id, orphan=True)

    def _edge(self, parent, child):
        if parent == child or nx.has_path(self.graph, child, parent):
            raise ValueError("Lineage relationships must be acyclic")
        self.graph.add_edge(parent, child)

    def add_contributor(self, id):
        return self._node(id, "contributor", digest({"contributor_id": id}), id)

    def add_dataset(self, manifest, contributor_id):
        payload = self._payload(manifest)
        node_hash = manifest.compute_hash() if hasattr(manifest, "compute_hash") else digest(payload)
        node_id = payload.get("dataset_id", node_hash)
        self._node(node_id, "dataset", node_hash, payload)
        self._parent(contributor_id, "contributor")
        self._edge(contributor_id, node_id)
        return node_id

    def add_model(self, manifest):
        payload = self._payload(manifest)
        node_id = payload["model_hash"]
        self._node(node_id, "model", node_id, payload)
        parents = payload.get("training_dataset_ids", getattr(manifest, "training_dataset_ids", None))
        if not parents:
            parents = [f"unknown-training-dataset:{node_id}"]
        if isinstance(parents, str):
            parents = [parents]
        for parent in parents:
            self._parent(parent, "dataset")
            self._edge(parent, node_id)
        return node_id

    def add_inference_record(self, record, model_id, dataset_id):
        payload = self._payload(record)
        node_hash = record.compute_hash() if hasattr(record, "compute_hash") else digest(payload)
        self._node(node_hash, "inference", node_hash, payload)
        for parent, node_type in ((model_id, "model"), (dataset_id, "dataset")):
            self._parent(parent, node_type)
            self._edge(parent, node_hash)
        return node_hash

    def add_finding(self, finding, asset_id):
        payload = asdict(finding)
        payload["modality"] = finding.modality.value
        node_hash = digest({"finding": payload, "attached_asset_id": asset_id})
        node_id = f"finding:{node_hash}"
        self._node(node_id, "finding", node_hash, payload)
        self._parent(asset_id, "asset")
        self._edge(asset_id, node_id)
        return node_id

    def downstream_of(self, asset_id):
        if asset_id not in self.graph:
            return []
        return sorted(nx.descendants(self.graph, asset_id))

    def blast_radius(self, compromised_asset_id):
        """Count downstream assets only; exclude the source and finding nodes."""
        result = {"models": [], "inference_records": [], "datasets": [], "consumers": {}}
        groups = {"model": "models", "dataset": "datasets", "inference": "inference_records",
                  "inference_record": "inference_records"}
        for node_id in self.downstream_of(compromised_asset_id):
            node = self.graph.nodes[node_id]
            group = groups.get(node.get("node_type"))
            if group is None:
                continue
            result[group].append(node_id)
            payload = node.get("ref", {})
            if group == "inference_records" and isinstance(payload, dict):
                consumer = payload.get("consumer_id")
                if consumer is not None:
                    result["consumers"].setdefault(consumer, []).append(node_id)
        result["total"] = sum(len(result[key]) for key in ("models", "inference_records", "datasets"))
        return result

    def propagate_confidence(self, finding_confidence, asset_id):
        return propagate_confidence(finding_confidence, self, asset_id)


def propagate_confidence(finding_confidence, lineage, asset_id):
    """Cap confidence by findings attached to every upstream ancestor, not siblings."""
    confidences = [float(finding_confidence)]
    graph = lineage.graph
    if asset_id in graph:
        for ancestor in nx.ancestors(graph, asset_id):
            for child in graph.successors(ancestor):
                node = graph.nodes[child]
                if node.get("node_type") == "finding":
                    confidences.append(float(node["ref"]["confidence"]))
    if any(not 0 <= confidence <= 1 for confidence in confidences):
        raise ValueError("Confidences must be finite and in [0, 1]")
    return min(confidences)
