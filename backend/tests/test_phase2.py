import hashlib
import json
import random
import struct
import tempfile
import unittest
from pathlib import Path

import networkx as nx
from PIL import Image

from app.core.evidence import EvidenceProvider, Modality
from app.core.lineage import IntegrityLineage
from app.manifests._common import digest
from app.manifests.dataset_manifest import DatasetManifest
from app.manifests.model_manifest import ModelReferenceManifest
from app.modules.data_integrity.annotation_integrity import AnnotationIntegrityDetector, covered_fraction
from app.modules.data_integrity.duplicates import DuplicateDetector
from app.modules.data_integrity.mislabeling import MislabelingDetector, feature_vector
from app.modules.data_integrity.ood import OODDetector
from app.modules.model_integrity.identity import ModelIdentityDetector
from app.provenance.chain import InferenceRecord


class ContractTests(unittest.TestCase):
    def check_findings(self, provider, dataset, findings):
        self.assertIsInstance(provider, EvidenceProvider)
        self.assertEqual(findings, provider.analyze(dataset))
        for finding in findings:
            self.assertTrue(finding.asset_id)
            self.assertTrue(finding.finding_type)
            self.assertTrue(0 <= finding.severity <= 1)
            self.assertTrue(0 <= finding.confidence <= 1)
            self.assertTrue(finding.evidence)
            self.assertTrue(all(isinstance(item, str) for item in finding.evidence))
            self.assertTrue(finding.counter_evidence)
            self.assertTrue(all(isinstance(item, str) for item in finding.counter_evidence))
            self.assertIn(finding.recommended_action, {"accept", "review", "quarantine"})
            self.assertEqual(finding.access_assumptions, "black_box")
            provenance = finding.provenance
            self.assertEqual(provenance["detector_id"], provider.detector_id)
            self.assertEqual(provenance["version"], provider.version)
            self.assertEqual(provenance["config_hash"], dataset["config_hash"])
            self.assertTrue(provenance["input_hashes"])
            for value in provenance["input_hashes"]:
                self.assertRegex(value, r"^[0-9a-f]{64}$")


class DuplicateTests(ContractTests):
    def test_injected_duplicate_and_real_hashes(self):
        rng = random.Random(0)
        image = Image.frombytes("RGB", (32, 32), bytes(rng.randrange(256) for _ in range(3072)))
        dataset = {"images": [("original", image), ("copy", image.copy())], "config_hash": "config"}
        provider = DuplicateDetector()
        findings = provider.analyze(dataset)
        self.check_findings(provider, dataset, findings)
        self.assertEqual({finding.modality for finding in findings}, {Modality.PIXEL, Modality.EMBEDDING})
        self.assertTrue(all(finding.asset_id == "copy" for finding in findings))
        self.assertEqual(findings[0].provenance["input_hashes"],
                         [hashlib.sha256(image.tobytes()).hexdigest()] * 2)

    def test_embedding_proxy_catches_different_spatial_layouts(self):
        first = Image.new("RGB", (32, 32), "black")
        first.paste((240, 60, 20), (0, 0, 16, 32))
        second = first.transpose(Image.Transpose.ROTATE_90)
        provider = DuplicateDetector(hamming_threshold=0)
        self.assertNotEqual(provider.phash(first), provider.phash(second))
        dataset = {"images": [("vertical", first), ("horizontal", second)], "config_hash": "config"}
        findings = provider.analyze(dataset)
        self.assertEqual([finding.modality for finding in findings], [Modality.EMBEDDING])
        self.check_findings(provider, dataset, findings)

    def test_hamming_threshold_and_zero_vector(self):
        first = Image.new("RGB", (32, 32))
        second = first.copy()
        second.paste("white", (0, 0, 16, 32))
        distance = (DuplicateDetector.phash(first) ^ DuplicateDetector.phash(second)).bit_count()
        self.assertGreater(distance, 0)
        dataset = {"images": [("black", first), ("half", second)], "config_hash": "config"}
        self.assertFalse(DuplicateDetector(hamming_threshold=distance - 1).analyze(dataset))
        self.assertEqual(DuplicateDetector(hamming_threshold=distance).analyze(dataset)[0].modality, Modality.PIXEL)
        dataset["images"] = [("black", first), ("black-copy", first.copy())]
        self.check_findings(DuplicateDetector(), dataset, DuplicateDetector().analyze(dataset))


class FeatureTests(ContractTests):
    def test_flipped_label_mean_and_histogram_features(self):
        rng = random.Random(0)
        samples = []
        for label, color in enumerate(((220, 30, 30), (30, 220, 30))):
            for index in range(8):
                varied = tuple(channel + rng.randint(-5, 5) for channel in color)
                samples.append((f"{label}-{index}", feature_vector(Image.new("RGB", (8, 8), varied)), label))
        samples.append(("flipped", feature_vector(Image.new("RGB", (8, 8), (220, 30, 30))), 1))
        dataset = {"samples": samples, "num_classes": 2, "config_hash": "config"}
        provider = MislabelingDetector()
        findings = provider.analyze(dataset)
        self.assertEqual([finding.asset_id for finding in findings], ["flipped"])
        self.assertEqual(findings[0].modality, Modality.ANNOTATION)
        self.check_findings(provider, dataset, findings)
        feature_hash = hashlib.sha256(struct.pack("<27d", *samples[-1][1])).hexdigest()
        self.assertIn(feature_hash, findings[0].provenance["input_hashes"])
        dataset["samples"] = samples[:-1]
        self.assertEqual(provider.analyze(dataset), [])

    def test_loo_and_tied_votes(self):
        dataset = {"samples": [("a", [0.0], 0), ("b", [0.1], 1), ("c", [0.2], 1)],
                   "num_classes": 2, "config_hash": "config"}
        findings = MislabelingDetector(k=2).analyze(dataset)
        self.assertEqual([finding.asset_id for finding in findings], ["a"])

    def test_ood_far_sample_and_per_class_centroids(self):
        rng = random.Random(0)
        samples = [(f"{label}-{index}", [label * 100 + rng.uniform(-1, 1) for _ in range(2)], label)
                   for label in range(2) for index in range(30)]
        dataset = {"samples": samples, "num_classes": 2, "config_hash": "config"}
        provider = OODDetector()
        self.assertEqual(provider.analyze(dataset), [])
        samples.append(("far", [1000.0, 1000.0], 0))
        findings = provider.analyze(dataset)
        self.assertEqual([finding.asset_id for finding in findings], ["far"])
        self.assertEqual(findings[0].modality, Modality.EMBEDDING)
        self.check_findings(provider, dataset, findings)
        self.assertIn(hashlib.sha256(struct.pack("<2d", 1000, 1000)).hexdigest(),
                      findings[0].provenance["input_hashes"])

    def test_singular_covariance_and_small_class(self):
        dataset = {"samples": [(str(index), [0.0, 0.0], 0) for index in range(5)],
                   "num_classes": 1, "config_hash": "config"}
        self.assertEqual(OODDetector().analyze(dataset), [])
        dataset["samples"].append(("far", [10.0, 10.0], 0))
        self.assertEqual([finding.asset_id for finding in OODDetector().analyze(dataset)], ["far"])
        dataset["samples"] = [("one", [1.0], 0), ("two", [100.0], 0)]
        self.assertEqual(OODDetector().analyze(dataset), [])

    def test_invalid_features(self):
        for provider in (MislabelingDetector(), OODDetector()):
            for features in ([[1.0], [float("nan")]], [[1.0], [2.0, 3.0]], [[], []]):
                with self.subTest(provider=provider.detector_id, features=features):
                    with self.assertRaises(ValueError):
                        provider.analyze({"samples": [(str(index), vector, 0)
                                                      for index, vector in enumerate(features)],
                                          "num_classes": 1, "config_hash": "config"})


class AnnotationTests(ContractTests):
    @staticmethod
    def annotation(name, boxes):
        return {"image_id": name, "boxes": boxes, "width": 100, "height": 100}

    def test_invalid_boxes_and_annotation_hash(self):
        annotation = self.annotation("invalid", [{"x": 90, "y": 0, "w": 30, "h": 10},
                                                 {"x": 0, "y": 0, "w": 0, "h": 10},
                                                 {"x": 0, "y": 0, "w": -2, "h": 10}])
        dataset = {"annotations": [annotation], "config_hash": "config"}
        provider = AnnotationIntegrityDetector()
        findings = provider.analyze(dataset)
        self.assertEqual([finding.finding_type for finding in findings],
                         ["box_out_of_bounds", "invalid_box_area", "invalid_box_area"])
        self.assertTrue(all(finding.modality == Modality.ANNOTATION for finding in findings))
        self.assertEqual(findings[0].provenance["input_hashes"], [digest(annotation)])
        self.check_findings(provider, dataset, findings)

    def test_consistent_shift_against_majority_layout(self):
        boxes = [{"x": x, "y": 10, "w": 10, "h": 10} for x in (10, 30, 50)]
        annotations = [self.annotation(f"reference-{index}", boxes) for index in range(3)]
        annotations += [self.annotation("shifted", [dict(box, x=box["x"] + 10, y=box["y"] + 10)
                                                   for box in boxes])]
        dataset = {"annotations": annotations, "config_hash": "config"}
        provider = AnnotationIntegrityDetector()
        findings = provider.analyze(dataset)
        self.assertEqual([(item.asset_id, item.finding_type) for item in findings],
                         [("shifted", "systematic_box_shift")])
        self.check_findings(provider, dataset, findings)
        dataset["annotations"] = annotations[:3]
        self.assertEqual(provider.analyze(dataset), [])

    def test_deleted_labels_and_union_area(self):
        boxes = [{"x": 5, "y": 5, "w": 90, "h": 90}]
        dataset = {"annotations": [self.annotation("a", boxes), self.annotation("b", boxes),
                                    self.annotation("missing", [])], "config_hash": "config"}
        provider = AnnotationIntegrityDetector()
        findings = provider.analyze(dataset)
        self.assertEqual([(item.asset_id, item.finding_type) for item in findings],
                         [("missing", "large_unlabeled_region")])
        self.check_findings(provider, dataset, findings)
        self.assertAlmostEqual(covered_fraction([(0, 0, 50, 50)] * 2, 100, 100), 0.25)
        dataset["annotations"] = [self.annotation("empty", [])]
        self.assertEqual(provider.analyze(dataset), [])


class IdentityAndLineageTests(ContractTests):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.model_path = self.root / "model.onnx"
        self.model_path.write_bytes(b"trusted weights")
        self.reference = ModelReferenceManifest.build_from_file(
            self.model_path, architecture="tiny", expected_metrics={}, activation_statistics={},
            output_fingerprints={}, reference_battery_id="battery", calibration_set_id="calibration")

    def test_identity_substitution_matching_missing_and_manifest_path(self):
        provider = ModelIdentityDetector()
        dataset = {"reference": self.reference, "supplied_model_path": str(self.model_path),
                   "config_hash": "config"}
        self.assertEqual(provider.analyze(dataset)[0].recommended_action, "accept")
        self.model_path.write_bytes(b"substituted weights")
        findings = provider.analyze(dataset)
        self.check_findings(provider, dataset, findings)
        self.assertEqual(findings[0].finding_type, "model_identity_mismatch")
        self.assertEqual(findings[0].confidence, 1.0)
        self.assertEqual(findings[0].recommended_action, "quarantine")
        self.assertIn(hashlib.sha256(b"substituted weights").hexdigest(), findings[0].provenance["input_hashes"])
        path = self.root / "manifest.json"
        path.write_text(json.dumps(self.reference.to_dict()), encoding="utf-8")
        del dataset["reference"]
        dataset["reference_manifest_path"] = str(path)
        self.assertEqual(provider.analyze(dataset), findings)
        dataset["supplied_model_path"] = str(self.root / "missing.onnx")
        missing = provider.analyze(dataset)
        self.assertEqual(missing[0].finding_type, "model_identity_unverified")
        self.assertEqual(missing[0].confidence, 0.0)
        self.check_findings(provider, dataset, missing)

    def test_lineage_full_chain_and_finding_attachment(self):
        graph = IntegrityLineage()
        manifest = DatasetManifest("v1", "coco", {}, digest([]), {}, {}, "author", None, {}, [])
        dataset_id = graph.add_dataset(manifest, "author")
        self.assertTrue(graph.graph.nodes["author"]["orphan"])
        graph.add_contributor("author")
        self.assertFalse(graph.graph.nodes["author"]["orphan"])
        model_payload = dict(self.reference.to_dict(), training_dataset_ids=[dataset_id])
        model_id = graph.add_model(model_payload)
        record = InferenceRecord("input", model_id, "config", "output", 0, "nonce", 1.0)
        inference_id = graph.add_inference_record(record, model_id, dataset_id)
        finding = ModelIdentityDetector().analyze({"reference": self.reference,
            "supplied_model_path": str(self.model_path), "config_hash": "config"})[0]
        finding_id = graph.add_finding(finding, inference_id)
        self.assertEqual(graph.add_finding(finding, inference_id), finding_id)
        self.assertEqual(set(graph.downstream_of("author")), {dataset_id, model_id, inference_id, finding_id})
        self.assertTrue(graph.graph.has_edge(dataset_id, model_id))
        self.assertTrue(graph.graph.has_edge(dataset_id, inference_id))
        self.assertTrue(graph.graph.has_edge(inference_id, finding_id))
        self.assertTrue(nx.is_directed_acyclic_graph(graph.graph))
        for _, attributes in graph.graph.nodes(data=True):
            self.assertTrue({"node_type", "hash", "ref", "orphan"} <= attributes.keys())
        self.assertEqual(graph.downstream_of(finding_id), [])
        self.assertEqual(graph.downstream_of("unknown"), [])

    def test_orphans_and_no_invented_training_relationship(self):
        graph = IntegrityLineage()
        model_id = graph.add_model(self.reference)
        parent = next(graph.graph.predecessors(model_id))
        self.assertEqual(graph.graph.nodes[parent]["node_type"], "dataset")
        self.assertTrue(graph.graph.nodes[parent]["orphan"])
        record = InferenceRecord("input", model_id, "config", "output", 0, "nonce", 1.0)
        inference_id = graph.add_inference_record(record, model_id, "evaluation-data")
        self.assertNotIn(model_id, graph.downstream_of("evaluation-data"))
        self.assertIn(inference_id, graph.downstream_of("evaluation-data"))
        finding = ModelIdentityDetector().analyze({"reference": self.reference,
            "supplied_model_path": str(self.model_path), "config_hash": "config"})[0]
        finding_id = graph.add_finding(finding, "unknown-asset")
        self.assertTrue(graph.graph.nodes["unknown-asset"]["orphan"])
        self.assertEqual(graph.downstream_of("unknown-asset"), [finding_id])
        graph.add_contributor("unknown-asset")
        self.assertFalse(graph.graph.nodes["unknown-asset"]["orphan"])
        self.assertEqual(graph.downstream_of("unknown-asset"), [finding_id])


if __name__ == "__main__":
    unittest.main()
