import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from app.core.evidence import Finding, Modality
from app.ingestion.coco_yolo import load_coco, load_yolo
from app.manifests.dataset_manifest import DatasetManifest
from app.manifests.model_manifest import ModelReferenceManifest
from app.manifests.pipeline_manifest import PipelineEnvironmentManifest
from app.provenance.canonical import canonical_serialization


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return path

    def coco(self, source="annotations.json"):
        self.write("images/a.jpg", b"sample a")
        self.write("images/b.jpg", b"sample b")
        self.document = {
            "dataset_version": "v1", "contributor_id": "team", "batch_id": "batch-1",
            "images": [
                {"id": 1, "file_name": "a.jpg", "contributor_id": "alice"},
                {"id": 2, "file_name": "b.jpg", "batch_id": "batch-2"},
            ],
            "categories": [{"id": 1, "name": "cat"}, {"id": 2, "name": "dog"}],
            "annotations": [
                {"id": 1, "image_id": 1, "category_id": 1, "bbox": [0, 0, 2, 3]},
                {"id": 2, "image_id": 2, "category_id": 1, "bbox": [1, 1, 2, 3]},
            ],
        }
        self.source = self.write(source, json.dumps(self.document))
        return DatasetManifest.build_from_coco(self.root)

    def save_coco(self):
        self.source.write_text(json.dumps(self.document), encoding="utf-8")

    def yolo(self):
        self.write("classes.txt", "cat\ndog\n")
        self.write("images/train/a.jpg", b"sample a")
        self.write("images/val/b.png", b"sample b")
        self.write("labels/train/a.txt", "0 0.5 0.5 0.25 0.25\n1 0.2 0.2 0.1 0.1\n")
        self.write("labels/val/b.txt", "")
        self.write("metadata.json", json.dumps({
            "dataset_version": "v2", "contributor_id": "team", "batch_id": "batch-1",
            "samples": {"images/train/a.jpg": {"contributor_id": "alice", "batch_id": "batch-2"}},
        }))
        return DatasetManifest.build_from_yolo(self.root)

    def model(self, suffix=".onnx", **overrides):
        path = self.write("model" + suffix, b"synthetic weights, not executable")
        arguments = {
            "architecture": "tiny-v1", "expected_metrics": {"accuracy": 0.9},
            "activation_statistics": {"layer1": {"mean": [0.1, 0.2], "std": [0.3, 0.4]}},
            "output_fingerprints": {"sample-1": {"output_hash": "a" * 64}},
            "reference_battery_id": "reference-v1", "calibration_set_id": "calibration-v1",
        }
        arguments.update(overrides)
        return ModelReferenceManifest.build_from_file(path, **arguments), path

    def pipeline(self):
        return PipelineEnvironmentManifest(
            preprocessing_parameters={"normalize": {"mean": [0.5], "std": [0.25]}},
            confidence_thresholds={"default": 0.5}, nms_settings={"iou_threshold": 0.45},
            input_resolution=(640, 480), model_identifier="a" * 64,
            framework_version="torch:2.0", runtime_version="onnxruntime:1.0",
            pipeline_version="1.0",
        )

    def test_coco_manifest_hashes_counts_metadata(self):
        manifest = self.coco()
        self.assertEqual(manifest.dataset_version, "v1")
        self.assertEqual(manifest.sample_hashes["images/a.jpg"], hashlib.sha256(b"sample a").hexdigest())
        self.assertEqual(manifest.class_distribution, {"1": 2, "2": 0})
        self.assertEqual(manifest.samples["images/a.jpg"]["contributor_id"], "alice")
        self.assertEqual(manifest.samples["images/b.jpg"]["contributor_id"], "team")
        self.assertEqual(manifest.samples["images/b.jpg"]["batch_id"], "batch-2")
        self.assertTrue(manifest.verify(self.root))
        self.assertEqual(manifest.digest, hashlib.sha256(canonical_serialization(manifest.to_dict())).hexdigest())
        self.assertEqual(manifest.annotation_hash, hashlib.sha256(canonical_serialization(load_coco(self.root)["annotations"])).hexdigest())

    def test_coco_nested_and_explicit_json_layouts(self):
        manifest = self.coco("annotations/instances.json")
        self.assertTrue(manifest.verify(self.root))
        self.source.unlink()
        custom = self.write("custom.json", json.dumps(self.document))
        manifest = DatasetManifest.build_from_coco(custom)
        self.assertTrue(manifest.verify(custom))

    def test_coco_ignores_json_layout_and_record_order(self):
        manifest = self.coco()
        for key in ("images", "categories", "annotations"):
            self.document[key].reverse()
        self.source.write_text(json.dumps(self.document, indent=4, sort_keys=True), encoding="utf-8")
        self.assertTrue(manifest.verify(self.root))
        self.assertEqual(manifest.annotation_hash, DatasetManifest.build_from_coco(self.root).annotation_hash)

    def test_coco_sample_rehash_not_stat_cache(self):
        manifest = self.coco()
        self.write("images/a.jpg", b"sample z")
        self.assertFalse(manifest.verify(self.root))

    def test_coco_annotation_and_metadata_changes(self):
        manifest = self.coco()
        self.document["annotations"][0]["category_id"] = 2
        self.save_coco()
        self.assertFalse(manifest.verify(self.root))
        manifest = DatasetManifest.build_from_coco(self.root)
        self.document["images"][0]["batch_id"] = "changed"
        self.save_coco()
        self.assertFalse(manifest.verify(self.root))

    def test_coco_additions_deletions_and_auxiliary_files(self):
        manifest = self.coco()
        extra = self.write("images/unlisted.png", b"extra")
        self.assertFalse(manifest.verify(self.root))
        extra.unlink()
        self.assertTrue(manifest.verify(self.root))
        extra = self.write("extra.bin", b"extra")
        manifest = DatasetManifest.build_from_coco(self.root)
        extra.unlink()
        self.assertFalse(manifest.verify(self.root))
        manifest = DatasetManifest.build_from_coco(self.root)
        (self.root / "images/b.jpg").unlink()
        self.assertFalse(manifest.verify(self.root))

    def test_coco_rejects_unsafe_paths_portably(self):
        self.coco()
        for name in ("../outside.jpg", "/outside.jpg", "C:/outside.jpg", "C:outside.jpg", "images/../a.jpg", "..\\outside.jpg", "//host/share/a.jpg", "a.jpg:stream", "images//a.jpg", "images/./a.jpg", "NUL", "a.jpg."):
            with self.subTest(name=name):
                self.document["images"][0]["file_name"] = name
                self.save_coco()
                with self.assertRaisesRegex(ValueError, "Supported COCO layouts"):
                    DatasetManifest.build_from_coco(self.root)

    def test_coco_rejects_duplicates_and_dangling_references(self):
        self.coco()
        original = copy.deepcopy(self.document)
        for change in ("image", "category", "annotation", "reference", "bbox"):
            self.document = copy.deepcopy(original)
            if change == "reference":
                self.document["annotations"][0]["image_id"] = 999
            elif change == "bbox":
                self.document["annotations"][0]["bbox"][2] = -1
            else:
                key = {"image": "images", "category": "categories", "annotation": "annotations"}[change]
                self.document[key].append(copy.deepcopy(self.document[key][0]))
            self.save_coco()
            with self.subTest(change=change), self.assertRaises(ValueError):
                DatasetManifest.build_from_coco(self.root)

    def test_coco_rejects_ambiguous_layout_and_images(self):
        self.coco()
        extra = self.write("annotations/instances.json", json.dumps(self.document))
        with self.assertRaisesRegex(ValueError, "exactly one"):
            DatasetManifest.build_from_coco(self.root)
        extra.unlink()
        self.write("a.jpg", b"ambiguous")
        with self.assertRaisesRegex(ValueError, "ambiguous image"):
            DatasetManifest.build_from_coco(self.root)

    def test_invalid_json_and_deleted_root_fail_closed(self):
        manifest = self.coco()
        for payload in ('{"images": [], "images": []}', '{"x": NaN}', '{"x": 1e999}', "[]", "not json"):
            self.source.write_text(payload, encoding="utf-8")
            self.assertFalse(manifest.verify(self.root))
        self.assertFalse(manifest.verify(self.root / "missing"))

    def test_explicit_metadata_defaults_and_manifest_mutation(self):
        self.coco()
        self.document.pop("contributor_id")
        self.document.pop("batch_id")
        self.save_coco()
        manifest = DatasetManifest.build_from_coco(self.root, dataset_version="release", contributor_id="fallback", batch_id="fallback-batch")
        self.assertTrue(manifest.verify(self.root))
        self.assertEqual(manifest.dataset_version, "release")
        self.assertEqual(manifest.samples["images/b.jpg"]["contributor_id"], "fallback")
        self.assertEqual(manifest.samples["images/a.jpg"]["contributor_id"], "alice")
        manifest.class_distribution["1"] = 999
        self.assertFalse(manifest.verify(self.root))

    def test_yolo_manifest_and_canonical_labels(self):
        manifest = self.yolo()
        self.assertEqual(manifest.dataset_version, "v2")
        self.assertEqual(manifest.class_distribution, {"0": 1, "1": 1})
        self.assertEqual(manifest.samples["images/train/a.jpg"]["contributor_id"], "alice")
        self.assertEqual(manifest.samples["images/val/b.png"]["batch_id"], "batch-1")
        self.assertEqual(manifest.sample_hashes["images/train/a.jpg"], hashlib.sha256(b"sample a").hexdigest())
        self.assertTrue(manifest.verify(self.root))
        self.write("labels/train/a.txt", "1 0.2000 0.2 0.1 0.1\n\n0   0.500  0.5 0.25 0.25\n")
        self.assertTrue(manifest.verify(self.root))
        self.write("labels/train/a.txt", "0 0.4 0.5 0.25 0.25\n")
        self.assertFalse(manifest.verify(self.root))

    def test_yolo_additions_and_deletions(self):
        manifest = self.yolo()
        image = self.write("images/new.jpg", b"new")
        label = self.write("labels/new.txt", "")
        self.assertFalse(manifest.verify(self.root))
        image.unlink()
        label.unlink()
        self.assertTrue(manifest.verify(self.root))
        (self.root / "labels/val/b.txt").unlink()
        self.assertFalse(manifest.verify(self.root))

    def test_yolo_rejects_invalid_detection_rows(self):
        self.yolo()
        for row in ("0 0.5 0.5", "2 0.5 0.5 0.2 0.2", "0 nan 0.5 0.2 0.2", "0 inf 0.5 0.2 0.2", "0 1.1 0.5 0.2 0.2", "0 0.5 0.5 -0.2 0.2", "0 0.5 0.5 0 0.2", "0.0 0.5 0.5 0.2 0.2", "0 0.1 0.2 0.3 0.4 0.5 0.6"):
            self.write("labels/train/a.txt", row)
            with self.subTest(row=row), self.assertRaisesRegex(ValueError, "Supported YOLO layout"):
                DatasetManifest.build_from_yolo(self.root)

    def test_yolo_rejects_orphan_labels_and_colliding_stems(self):
        self.yolo()
        orphan = self.write("labels/orphan.txt", "")
        with self.assertRaisesRegex(ValueError, "Orphan"):
            load_yolo(self.root)
        orphan.unlink()
        self.write("images/train/a.png", b"collision")
        with self.assertRaisesRegex(ValueError, "Multiple images"):
            load_yolo(self.root)

    def test_yolo_metadata_and_class_changes(self):
        manifest = self.yolo()
        self.write("classes.txt", "dog\ncat\n")
        self.assertFalse(manifest.verify(self.root))
        self.write("classes.txt", "cat\ndog\n")
        self.write("metadata.json", '{"samples": {"../outside.jpg": {}}}')
        self.assertFalse(manifest.verify(self.root))
        self.write("metadata.json", '{"samples": {"images/unknown.jpg": {}}}')
        self.assertFalse(manifest.verify(self.root))
        self.write("metadata.json", "{}")
        self.assertFalse(manifest.verify(self.root))
        self.write("classes.txt", "cat\ncat\n")
        with self.assertRaises(ValueError):
            load_yolo(self.root)

    def test_unsupported_layout_errors_describe_support(self):
        self.write("data.yaml", "names: [cat]\n")
        with self.assertRaisesRegex(ValueError, "YAML configs"):
            load_yolo(self.root)
        with self.assertRaisesRegex(ValueError, "Supported COCO layouts"):
            load_coco(self.root)

    def test_dataset_rejects_symlinks(self):
        manifest = self.coco()
        target = self.write("target.bin", b"target")
        link = self.root / "linked.bin"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("Creating symlinks requires OS support/privileges")
        with self.assertRaisesRegex(ValueError, "links are not supported"):
            DatasetManifest.build_from_coco(self.root)
        self.assertFalse(manifest.verify(self.root))

    def test_model_identity_is_binary_and_not_behavioral(self):
        manifest, path = self.model()
        self.assertEqual(manifest.model_hash, hashlib.sha256(path.read_bytes()).hexdigest())
        finding = manifest.identity_check(path)
        self.assertIsInstance(finding, Finding)
        self.assertEqual(finding.finding_type, "model_identity_match")
        self.assertEqual((finding.severity, finding.confidence), (0.0, 1.0))
        self.assertEqual(finding.recommended_action, "accept")
        self.assertNotEqual(finding.modality, Modality.BEHAVIORAL)
        self.assertIn("no behavioral integrity", finding.counter_evidence[0])
        self.assertEqual(finding.provenance["config_hash"], manifest.digest)
        path.write_bytes(b"modified weights")
        finding = manifest.identity_check(path)
        self.assertEqual(finding.finding_type, "model_identity_mismatch")
        self.assertEqual((finding.severity, finding.confidence), (1.0, 1.0))
        self.assertEqual(finding.quarantine_scope, "model")
        self.assertFalse(manifest.verify(path))

    def test_missing_model_is_unverified_not_mismatch(self):
        manifest, path = self.model()
        path.unlink()
        finding = manifest.identity_check(path)
        self.assertEqual(finding.finding_type, "model_identity_unverified")
        self.assertEqual(finding.confidence, 0.0)
        self.assertEqual(finding.recommended_action, "review")
        self.assertFalse(manifest.verify(path))

    def test_model_formats_metrics_and_snapshot(self):
        for suffix in (".onnx", ".pt", ".ts", ".torchscript"):
            metrics = {"accuracy": 0.9}
            manifest, path = self.model(suffix, expected_metrics=metrics)
            self.assertTrue(manifest.verify(path))
            self.assertEqual(manifest.model_format, "onnx" if suffix == ".onnx" else "torchscript")
            original = manifest.digest
            metrics["accuracy"] = 0.1
            self.assertEqual(manifest.digest, original)
            manifest.expected_metrics["accuracy"] = 0.1
            self.assertNotEqual(manifest.digest, original)
            self.assertTrue(manifest.verify(path))
        with self.assertRaises(ValueError):
            self.model(".bin")
        manifest, path = self.model(".bin", model_format="onnx")
        self.assertTrue(manifest.verify(path))

    def test_model_rejects_invalid_baselines(self):
        for arguments in (
            {"expected_metrics": {"accuracy": float("nan")}},
            {"activation_statistics": {"x": {"mean": 0.1, "std": -0.1}}},
            {"activation_statistics": {"x": {"mean": [0.1], "std": [0.1, 0.2]}}},
            {"activation_statistics": {"x": {"mean": 0.1}}},
            {"architecture": ""}, {"reference_battery_id": ""},
        ):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                self.model(**arguments)

    def test_pipeline_full_binding_and_verification(self):
        manifest = self.pipeline()
        data = manifest.to_dict()
        self.assertEqual(manifest.digest, hashlib.sha256(canonical_serialization(data)).hexdigest())
        self.assertEqual(manifest.config_hash, manifest.digest)
        self.assertTrue(manifest.verify(data))
        self.assertTrue(manifest.verify(PipelineEnvironmentManifest(**dict(reversed(list(data.items()))))))
        replacements = {
            "preprocessing_parameters": {"normalize": False},
            "confidence_thresholds": {"default": 0.6}, "nms_settings": {"iou_threshold": 0.5},
            "input_resolution": [320, 240], "model_identifier": "b" * 64,
            "framework_version": "torch:3.0", "runtime_version": "onnxruntime:2.0",
            "pipeline_version": "2.0", "schema_version": "2",
        }
        for key, value in replacements.items():
            changed = copy.deepcopy(data)
            changed[key] = value
            with self.subTest(key=key):
                self.assertFalse(manifest.verify(changed))
                self.assertNotEqual(manifest.digest, PipelineEnvironmentManifest(**changed).digest)

    def test_pipeline_invalid_configuration_and_defensive_copy(self):
        manifest = self.pipeline()
        data = manifest.to_dict()
        cloned = PipelineEnvironmentManifest(**data)
        data["preprocessing_parameters"]["normalize"]["mean"][0] = 0.9
        self.assertTrue(manifest.verify(cloned))
        for change in (
            {"confidence_thresholds": {"default": 1.1}},
            {"confidence_thresholds": {"default": float("inf")}},
            {"input_resolution": [0, 480]}, {"input_resolution": [True, 480]},
            {"runtime_version": ""}, {"nms_settings": {"bad": float("nan")}},
        ):
            invalid = manifest.to_dict()
            invalid.update(change)
            with self.subTest(change=change):
                self.assertFalse(manifest.verify(invalid))
        self.assertFalse(manifest.verify({"unknown": 1}))


if __name__ == "__main__":
    unittest.main()
