import hashlib
import json
import math
import random
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import numpy as np
from PIL import Image

from app.core.evidence import EvidenceProvider, Finding, Modality
from app.core.tiered_computation import run_assessment
from app.manifests.model_manifest import ModelReferenceManifest
from app.modules.data_integrity.activation_based import ActivationClusteringProvider, SpectralSignatureProvider
from app.modules.data_integrity.strip import STRIPDetector
from app.modules.drift.cause_breakdown import classify_shift
from app.modules.drift.drift_vs_manipulation import DriftVsManipulationProvider
from app.modules.drift.energy_ood import energy_score
from app.modules.drift.mmd import kl_divergence_histogram, mmd_rbf
from app.modules.drift.unclassified import UnclassifiedAnomalyProvider
from app.modules.model_integrity.behavioral import ReferenceBatteryProvider, WeightStatsProvider
from app.modules.model_integrity.counterfactual import mask_channels, mask_region, test_counterfactual


class ContractTests(unittest.TestCase):
    def check_findings(self, provider, asset, findings, modality, access="black_box"):
        self.assertIsInstance(provider, EvidenceProvider)
        self.assertEqual(findings, provider.analyze(asset))
        self.assertTrue(findings)
        for finding in findings:
            self.assertIsInstance(finding, Finding)
            self.assertTrue(finding.asset_id)
            self.assertTrue(finding.finding_type)
            self.assertTrue(0 <= finding.severity <= 1)
            self.assertTrue(0 <= finding.confidence <= 1)
            self.assertEqual(finding.modality, modality)
            self.assertEqual(finding.access_assumptions, access)
            self.assertIn(finding.recommended_action, {"accept", "review", "quarantine"})
            for items in (finding.evidence, finding.counter_evidence):
                self.assertIsInstance(items, list)
                self.assertTrue(items)
                self.assertTrue(all(isinstance(item, str) for item in items))
            self.assertEqual(finding.provenance["detector_id"], provider.detector_id)
            self.assertEqual(finding.provenance["version"], provider.version)
            if isinstance(asset, dict):
                self.assertEqual(finding.provenance["config_hash"], asset["config_hash"])
            self.assertTrue(finding.provenance["input_hashes"])
            for value in finding.provenance["input_hashes"]:
                self.assertRegex(value, r"^[0-9a-f]{64}$")


class StubSession:
    def __init__(self, offset=0.0):
        self.offset = offset

    def get_inputs(self):
        return [SimpleNamespace(name="images", shape=[1, 3, 4, 4])]

    def run(self, outputs, inputs):
        batch = inputs["images"]
        return [np.array([[float(batch.mean()) + self.offset, -float(batch.mean())]])]


class BehavioralTests(ContractTests):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / "model.onnx"
        self.path.write_bytes(b"synthetic parser fixture; not executable ONNX")
        self.images = [("black", Image.new("RGB", (4, 4), "black")),
                       ("white", Image.new("RGB", (4, 4), "white"))]
        self.reference = ModelReferenceManifest.build_from_file(
            self.path, architecture="test", expected_metrics={}, activation_statistics={},
            output_fingerprints={"mean": [0.5, -0.5], "std": [0.5, 0.5]},
            reference_battery_id="fixed", calibration_set_id="black-white",
        )
        self.asset = {"supplied_model_path": str(self.path), "reference": self.reference,
                      "calibration_images": self.images, "session": StubSession(), "config_hash": "config"}

    def test_reference_battery_match_and_direct_mismatch(self):
        provider = ReferenceBatteryProvider()
        findings = provider.analyze(self.asset)
        self.check_findings(provider, self.asset, findings, Modality.BEHAVIORAL)
        self.assertEqual(findings[0].recommended_action, "accept")
        self.assertEqual(findings[0].severity, 0)
        self.asset["session"] = StubSession(3.0)
        findings = provider.analyze(self.asset)
        self.check_findings(provider, self.asset, findings, Modality.BEHAVIORAL)
        self.assertEqual(findings[0].finding_type, "model_behavioral_mismatch")
        self.assertEqual(findings[0].confidence, 0.8)
        self.assertIn("DIRECT comparison evidence", " ".join(findings[0].evidence))
        self.assertIn(hashlib.sha256(self.images[0][1].tobytes()).hexdigest(), findings[0].provenance["input_hashes"])

    def test_predict_fallback_named_outputs_and_manifest_path(self):
        path = self.root / "manifest.json"
        path.write_text(json.dumps(self.reference.to_dict()), encoding="utf-8")
        self.asset.pop("reference")
        self.asset["reference_manifest_path"] = str(path)
        self.asset.pop("session")
        self.asset["predict_fn"] = lambda batch: np.array([[batch.mean(), -batch.mean()]])
        self.asset["reference_outputs"] = {"black": [0.0, 0.0], "white": [1.0, -1.0]}
        provider = ReferenceBatteryProvider()
        self.assertEqual(provider.analyze(self.asset)[0].recommended_action, "accept")
        self.asset.pop("reference_outputs")
        self.assertEqual(provider.analyze(self.asset)[0].recommended_action, "accept")

    def test_reference_std_difference_is_detected(self):
        self.asset["reference_outputs"] = [[0.5, -0.5], [0.5, -0.5]]
        self.assertEqual(ReferenceBatteryProvider().analyze(self.asset)[0].finding_type, "model_behavioral_mismatch")

    def test_runtime_unavailable_degrades_without_crashing(self):
        self.asset.pop("session")
        with patch.dict("sys.modules", {"onnxruntime": None}):
            provider = ReferenceBatteryProvider()
            findings = provider.analyze(self.asset)
            self.check_findings(provider, self.asset, findings, Modality.BEHAVIORAL)
        self.assertEqual(findings[0].finding_type, "reference_battery_unverified")
        self.assertEqual(findings[0].recommended_action, "review")
        self.assertLess(findings[0].severity, 0.4)
        self.assertEqual(findings[0].confidence, 0)

    def test_invalid_runtime_and_reference_are_degraded(self):
        for output in (np.array([[math.nan, 0]]), np.array([[1.0]])):
            with self.subTest(output=output):
                self.asset["predict_fn"] = lambda batch: output
                finding = ReferenceBatteryProvider().analyze(self.asset)[0]
                self.assertEqual(finding.finding_type, "reference_battery_unverified")
        self.asset.pop("predict_fn")
        self.asset["calibration_images"] = []
        self.assertEqual(ReferenceBatteryProvider().analyze(self.asset)[0].confidence, 0)

    def test_weight_stats_parser_baseline_and_degraded_dependency(self):
        self.reference.output_fingerprints["weight_statistics"] = {"weights": {"mean": 1.0, "std": 0.0, "norm": 2.0}}
        tensor = SimpleNamespace(name="weights", data_location=0, values=np.full((2, 2), 3.0))
        model = SimpleNamespace(graph=SimpleNamespace(initializer=[tensor]))
        fake_onnx = SimpleNamespace(load=lambda path, load_external_data: model,
                                    TensorProto=SimpleNamespace(EXTERNAL=1),
                                    numpy_helper=SimpleNamespace(to_array=lambda item: item.values))
        provider = WeightStatsProvider()
        with patch.dict("sys.modules", {"onnx": fake_onnx}):
            findings = provider.analyze(self.asset)
            self.check_findings(provider, self.asset, findings, Modality.BEHAVIORAL, "white_box")
            self.assertEqual(findings[0].confidence, 0.5)
            self.assertIn("alone don't confirm tampering", " ".join(findings[0].evidence))
            tensor.values = np.ones((2, 2))
            self.assertEqual(provider.analyze(self.asset), [])
            tensor.data_location = 1
            self.assertEqual(provider.analyze(self.asset)[0].finding_type, "weight_stats_unverified")
        with patch.dict("sys.modules", {"onnx": None}):
            findings = provider.analyze(self.asset)
            self.check_findings(provider, self.asset, findings, Modality.BEHAVIORAL, "white_box")
            self.assertEqual(findings[0].finding_type, "weight_stats_unverified")
            self.assertLess(findings[0].severity, 0.4)

    def test_activation_only_baseline_cannot_be_weight_baseline(self):
        self.reference.activation_statistics = {"weights": {"mean": 1.0, "std": 0.0}}
        finding = WeightStatsProvider().analyze(self.asset)[0]
        self.assertEqual(finding.finding_type, "weight_stats_unverified")


class CounterfactualTests(unittest.TestCase):
    def test_region_removes_behavior_without_mutating_sample(self):
        sample = np.ones((4, 4, 3), dtype=np.float32)
        original = sample.copy()
        model = lambda image: np.array([image.sum(), 1.0])
        result = test_counterfactual(model, sample, mask_region((0, (0, 0, 4, 4))))
        self.assertIs(result["behavior_persists"], False)
        self.assertEqual(result["details"]["original_class"], 0)
        self.assertEqual(result["details"]["masked_class"], 1)
        np.testing.assert_array_equal(sample, original)
        self.assertTrue(test_counterfactual(model, sample, mask_region((0, 0, 1, 1)))["behavior_persists"])

    def test_channels_and_session_wrapper(self):
        sample = np.ones((3, 4, 4), dtype=np.float32)
        result = test_counterfactual(StubSession(), sample, mask_channels([0], axis=0))
        self.assertIs(result["behavior_persists"], True)
        self.assertGreater(result["details"]["logit_delta_norm"], 0)
        np.testing.assert_array_equal(mask_channels([1])(np.ones((2, 2, 3)))[..., 1], 0)
        with self.assertRaises(ValueError):
            mask_channels([9])(sample)
        with self.assertRaises(ValueError):
            test_counterfactual(lambda value: np.array([1, 0]), sample, lambda value: value[:1])


class ActivationTests(ContractTests):
    def setUp(self):
        rng = random.Random(7)
        self.activations = {f"clean-{index}": np.array([rng.uniform(-0.1, 0.1) for _ in range(4)]) for index in range(30)}
        self.activations["poisoned"] = np.full(4, 15.0)
        self.asset = {"activations": self.activations, "labels": dict.fromkeys(self.activations, 0), "config_hash": "config"}

    def test_obvious_poison_caught_with_candidate_evidence(self):
        for provider in (SpectralSignatureProvider(), ActivationClusteringProvider()):
            with self.subTest(provider=provider.detector_id):
                findings = provider.analyze(self.asset)
                self.check_findings(provider, self.asset, findings, Modality.ACTIVATION, "gray_box")
                self.assertEqual([finding.asset_id for finding in findings], ["poisoned"])
                self.assertIn("CANDIDATE evidence for poisoning, not proof", " ".join(findings[0].evidence))

    def test_constant_small_and_separate_classes_are_clean(self):
        for provider in (SpectralSignatureProvider(), ActivationClusteringProvider()):
            for count in (2, 10):
                self.asset["activations"] = {str(index): np.ones(3) for index in range(count)}
                self.asset["labels"] = dict.fromkeys(self.asset["activations"], 0)
                self.assertEqual(provider.analyze(self.asset), [])
            self.asset["activations"] = {str(index): np.full(3, 100 * (index // 10)) for index in range(20)}
            self.asset["labels"] = {str(index): index // 10 for index in range(20)}
            self.assertEqual(provider.analyze(self.asset), [])

    def test_zero_mad_and_invalid_vectors(self):
        for provider in (SpectralSignatureProvider(), ActivationClusteringProvider()):
            self.asset["activations"] = {str(index): np.zeros(2) for index in range(10)}
            self.asset["activations"]["poisoned"] = np.full(2, 50.0)
            self.asset["labels"] = dict.fromkeys(self.asset["activations"], 0)
            self.assertEqual([finding.asset_id for finding in provider.analyze(self.asset)], ["poisoned"])
            for value in (np.array([math.nan, 1]), np.array([1]), np.ones((1, 2))):
                self.asset["activations"]["poisoned"] = value
                with self.assertRaises(ValueError):
                    provider.analyze(self.asset)

    def test_balanced_separated_clusters_not_flagged(self):
        self.asset["activations"] = {str(index): np.full(2, index // 5) for index in range(10)}
        self.asset["labels"] = dict.fromkeys(self.asset["activations"], 0)
        self.assertEqual(ActivationClusteringProvider().analyze(self.asset), [])


class STRIPTests(ContractTests):
    def setUp(self):
        rng = random.Random(7)
        self.asset = {
            "images": [("stable", np.full((4, 4, 3), 0.5))],
            "backgrounds": [np.array([rng.random() for _ in range(48)]).reshape(4, 4, 3) for _ in range(5)],
            "predict_fn": lambda batch: np.tile([0.999, 0.001], (len(batch), 1)),
            "config_hash": "config", "entropy_threshold": 0.2,
        }

    def test_stable_predictions_flagged_deterministically(self):
        provider = STRIPDetector(seed=7)
        findings = provider.analyze(self.asset)
        self.check_findings(provider, self.asset, findings, Modality.BEHAVIORAL)
        self.assertEqual(findings[0].asset_id, "stable")
        self.assertIn("Legitimately low-entropy confident models", " ".join(findings[0].counter_evidence))
        batches = []

        def predict(batch):
            batches.append(batch.copy())
            return np.tile([0.999, 0.001], (len(batch), 1))

        self.asset["predict_fn"] = predict
        provider.analyze(self.asset)
        provider.analyze(self.asset)
        np.testing.assert_array_equal(batches[0], batches[1])
        np.testing.assert_array_equal(self.asset["images"][0][1], np.full((4, 4, 3), 0.5))

    def test_high_entropy_clean_and_invalid_probabilities(self):
        self.asset["predict_fn"] = lambda batch: np.tile([0.5, 0.5], (len(batch), 1))
        self.assertEqual(STRIPDetector().analyze(self.asset), [])
        for probabilities in ([2, -1], [0.1, 0.1], [math.nan, 1]):
            self.asset["predict_fn"] = lambda batch: np.tile(probabilities, (len(batch), 1))
            with self.assertRaises(ValueError):
                STRIPDetector().analyze(self.asset)
        self.asset["backgrounds"] = []
        with self.assertRaises(ValueError):
            STRIPDetector().analyze(self.asset)


class DriftTests(ContractTests):
    def setUp(self):
        rng = random.Random(7)
        reference = []
        for index in range(8):
            pixels = bytes(rng.randrange(30, 60) for _ in range(8 * 8 * 3))
            reference.append((f"reference-{index}", Image.frombytes("RGB", (8, 8), pixels)))
        current = [(name.replace("reference", "current"), Image.fromarray(np.asarray(image) + 120)) for name, image in reference]
        self.asset = {
            "reference_images": reference, "current_images": current,
            "reference_embeddings": np.array([np.asarray(image).mean(axis=(0, 1)) / 255 for _, image in reference]),
            "current_embeddings": np.array([np.asarray(image).mean(axis=(0, 1)) / 255 for _, image in current]),
            "config_hash": "config",
        }

    def test_illumination_shift_has_both_evidence_and_counter_evidence(self):
        provider = DriftVsManipulationProvider()
        findings = provider.analyze(self.asset)
        self.check_findings(provider, self.asset, findings, Modality.EMBEDDING)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_type, "distribution_shift")
        self.assertEqual(findings[0].recommended_action, "review")
        self.assertIn("illumination share=100.0%", " ".join(findings[0].counter_evidence))
        self.assertIn("embeddings are not treated as logits", " ".join(findings[0].evidence))

    def test_cause_attribution_shares_and_clean_batch(self):
        result = classify_shift(self.asset["reference_images"], self.asset["current_images"])
        categories = ("illumination", "color", "blur_noise", "structural")
        self.assertAlmostEqual(sum(result[key] for key in categories), 1)
        self.assertAlmostEqual(result["illumination"], 1)
        same = classify_shift(self.asset["reference_images"], self.asset["reference_images"])
        self.assertEqual(sum(same[key] for key in categories), 0)
        self.asset["current_images"] = self.asset["reference_images"]
        self.asset["current_embeddings"] = self.asset["reference_embeddings"].copy()
        self.assertEqual(DriftVsManipulationProvider().analyze(self.asset), [])

    def test_color_sensor_structure_attribution_is_finite(self):
        reference = [Image.new("RGB", (8, 8), (80, 80, 80))]
        current = [Image.new("RGB", (8, 8), (120, 40, 80))]
        color = classify_shift(reference, current)
        self.assertGreater(color["color"], 0.9)
        checker = np.indices((8, 8)).sum(axis=0) % 2 * 200
        current = [Image.fromarray(np.repeat(checker[..., None], 3, axis=2).astype(np.uint8))]
        sensor = classify_shift(reference, current)
        self.assertGreater(sensor["blur_noise"], 0)
        self.assertTrue(all(math.isfinite(value) for value in sensor["magnitudes"].values()))

    def test_optional_real_logits_enable_energy_evidence(self):
        self.asset["reference_logits"] = np.tile([2.0, 0], (8, 1))
        self.asset["current_logits"] = np.tile([0.0, 0], (8, 1))
        finding = DriftVsManipulationProvider().analyze(self.asset)[0]
        self.assertIn("mean energy", " ".join(finding.evidence))
        self.asset["current_logits"] = np.zeros((7, 2))
        with self.assertRaises(ValueError):
            DriftVsManipulationProvider().analyze(self.asset)

    def test_energy_scores_are_stable_and_shift_equivariant(self):
        logits = np.array([[0.0, 0.0], [1000.0, 1000.0], [-1000.0, -1000.0]])
        np.testing.assert_allclose(energy_score(logits), [-math.log(2), -1000 - math.log(2), 1000 - math.log(2)])
        np.testing.assert_allclose(energy_score(logits + 10), energy_score(logits) - 10)
        self.assertAlmostEqual(float(energy_score([0.0, 0.0])), -math.log(2))
        self.assertEqual(energy_score(np.empty((0, 2))).shape, (0,))
        for invalid in ([], [math.nan, 1], np.zeros((2, 0)), np.zeros((1, 2, 3))):
            with self.assertRaises(ValueError):
                energy_score(invalid)

    def test_mmd_matches_unbiased_manual_estimate_and_can_be_negative(self):
        reference, current = np.array([[0.0], [1.0]]), np.array([[2.0], [3.0], [4.0]])
        kernel = lambda x, y: math.exp(-0.5 * float(np.sum((x - y) ** 2)))
        expected = sum(kernel(x, y) for i, x in enumerate(reference) for j, y in enumerate(reference) if i != j) / 2
        expected += sum(kernel(x, y) for i, x in enumerate(current) for j, y in enumerate(current) if i != j) / 6
        expected -= 2 * sum(kernel(x, y) for x in reference for y in current) / 6
        self.assertAlmostEqual(mmd_rbf(reference, current, 0.5), expected)
        self.assertAlmostEqual(mmd_rbf(current, reference, 0.5), expected)
        self.assertLess(mmd_rbf(reference, reference, 0.5), 0)
        self.assertGreater(mmd_rbf(np.zeros((3, 2)), np.full((3, 2), 10), 1), 1.9)
        for first, second, gamma in (([[0]], [[0], [1]], 1), ([[0], [1]], [[0, 1], [1, 2]], 1), (reference, current, 0)):
            with self.assertRaises(ValueError):
                mmd_rbf(first, second, gamma)

    def test_kl_smoothing_and_validation(self):
        self.assertAlmostEqual(kl_divergence_histogram([1, 2], [1, 2]), 0)
        self.assertAlmostEqual(kl_divergence_histogram([0, 0], [0, 0]), 0)
        self.assertTrue(math.isfinite(kl_divergence_histogram([1, 0], [0, 1])))
        self.assertGreater(kl_divergence_histogram([1, 0], [0, 1]), 0)
        for first, second in (([], []), ([1], [1, 2]), ([-1, 1], [1, 1]), ([math.nan], [1])):
            with self.assertRaises(ValueError):
                kl_divergence_histogram(first, second)


class StubProvider(EvidenceProvider):
    def __init__(self, name, severity=None, calls=None):
        super().__init__(name)
        self.severity = severity
        self.calls = calls if calls is not None else []

    def analyze(self, asset):
        self.calls.append((self.detector_id, asset))
        if self.severity is None:
            return []
        return [Finding(asset_id="asset", finding_type="test", severity=self.severity, confidence=0.5,
                        evidence=["test evidence"], modality=Modality.BEHAVIORAL,
                        provenance=self._create_provenance(["0" * 64], "config"), recommended_action="review",
                        counter_evidence=["test counter-evidence"])]


class TieredTests(unittest.TestCase):
    def test_clean_and_boundary_skip_expensive(self):
        for severity in (None, 0.0, 0.4):
            cheap, expensive = StubProvider("cheap", severity), StubProvider("expensive", 0.9)
            ticks = iter([1.0, 1.25])
            result = run_assessment({"cheap": "payload"}, [cheap], [expensive], clock=lambda: next(ticks))
            self.assertEqual(cheap.calls, [("cheap", "payload")])
            self.assertEqual(expensive.calls, [])
            self.assertEqual(result["timings"], {"cheap": 0.25, "expensive": 0.0})
            self.assertEqual([log["ran"] for log in result["tier_logs"]], [True, False])
            self.assertTrue(all(log["reason"] for log in result["tier_logs"]))

    def test_trigger_runs_all_cheap_before_expensive_and_records_time(self):
        calls = []
        first, second, expensive = StubProvider("first", 0.7, calls), StubProvider("second", None, calls), StubProvider("expensive", 0.1, calls)
        ticks = iter([0, 0.1, 1, 1.2, 2, 2.3])
        result = run_assessment({"a": 1, "b": 2, "c": 3}, {"a": first, "b": second}, {"c": expensive}, clock=lambda: next(ticks))
        self.assertEqual(calls, [("first", 1), ("second", 2), ("expensive", 3)])
        self.assertEqual(len(result["findings"]), 2)
        self.assertEqual([log["tier"] for log in result["tier_logs"]], ["cheap", "cheap", "expensive"])
        self.assertTrue(all(log["ran"] for log in result["tier_logs"]))
        for key, expected in (("a", 0.1), ("b", 0.2), ("c", 0.3)):
            self.assertAlmostEqual(result["timings"][key], expected)

    def test_empty_tiers_and_duplicate_keys(self):
        self.assertEqual(run_assessment({}, [], []), {"findings": [], "timings": {}, "tier_logs": []})
        provider = StubProvider("same")
        with self.assertRaises(ValueError):
            run_assessment({}, [provider], [provider])
        with self.assertRaises(ValueError):
            run_assessment({}, [], [], risk_threshold=math.nan)


class UnclassifiedTests(ContractTests):
    def test_threshold_coverage_and_no_force_fitting(self):
        provider = UnclassifiedAnomalyProvider(threshold=0.7)
        asset = {"anomalies": [("boundary", 0.7), ("unmatched", 0.9), ("matched", 1.0)],
                 "matched_asset_ids": ["matched"], "config_hash": "config"}
        findings = provider.analyze(asset)
        self.check_findings(provider, asset, findings, Modality.BEHAVIORAL)
        self.assertEqual([finding.asset_id for finding in findings], ["unmatched"])
        self.assertEqual(findings[0].finding_type, "unclassified_anomaly")
        self.assertIn("Coverage Statement", " ".join(findings[0].evidence))
        self.assertIn("not force-fitted", " ".join(findings[0].evidence))
        self.check_findings(provider, [("raw", 0.8)], provider.analyze([("raw", 0.8)]), Modality.BEHAVIORAL)
        with self.assertRaises(ValueError):
            provider.analyze([("invalid", math.nan)])


if __name__ == "__main__":
    unittest.main()
