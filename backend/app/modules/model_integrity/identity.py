from dataclasses import replace
from pathlib import Path

from app.core.evidence import EvidenceProvider
from app.manifests._common import read_json
from app.manifests.model_manifest import ModelReferenceManifest


class ModelIdentityDetector(EvidenceProvider):
    def __init__(self):
        super().__init__("model_identity")

    def analyze(self, asset):
        reference = asset.get("reference")
        if reference is None:
            reference = ModelReferenceManifest(**read_json(Path(asset["reference_manifest_path"])))
        if not isinstance(reference, ModelReferenceManifest):
            raise TypeError("reference must be a ModelReferenceManifest")
        finding = reference.identity_check(asset["supplied_model_path"])
        input_hashes = [reference.compute_hash(), *finding.provenance["input_hashes"]]
        return [replace(
            finding,
            provenance=self._create_provenance(input_hashes, asset["config_hash"]),
            access_assumptions="black_box",
        )]
