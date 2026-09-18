import hashlib
import random
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import numpy as np

from app.core.correlation import CorrelationEngine, KNOWN_LIMITATION
from app.core.evidence import EvidenceProvider, Finding, Modality
from app.modules.model_integrity import fine_pruning
from app.modules.model_integrity.counterfactual import test_counterfactual
from app.modules.model_integrity.fine_pruning import FinePruningProvider
from app.modules.model_integrity.trigger_reconstruction import TriggerReconstructionProvider
from app.provenance.canonical import canonical_serialization
from app.provenance.chain import InferenceRecord, Verifier
from app.provenance.merkle import build_merkle_tree, merkle_proof, verify_proof
from app.provenance.spot_reexecution import SpotReexecutor, activation_leaves, payload_bytes


def toy_logits(features):
    values = np.asarray(features)
    return np.array([4 * values[20], 4 * values[21], 8 * values[[0, 1, 8, 9]].sum() - 24])


def clean_samples():
    samples = np.zeros((2, 64))
    samples[0, 20] = 0.2
    samples[1, 21] = 0.2
    return samples


class ReconstructionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.provider = TriggerReconstructionProvider(seed=7)
        cls.asset = {"asset_id": "toy-model", "model": toy_logits, "samples": clean_samples(), "config_hash": "config"}
        cls.findings = cls.provider.analyze(cls.asset)

    def test_corner_trigger_class_and_hedged_contract(self):
        self.assertIsInstance(self.provider, EvidenceProvider)
        self.assertEqual(len(self.findings), 1)
        finding = self.findings[0]
        self.assertEqual(finding.finding_type, "candidate_backdoor_trigger")
        self.assertEqual(finding.provenance["target_class"], 2)
        self.assertEqual(finding.modality, Modality.BEHAVIORAL)
        self.assertEqual(finding.access_assumptions, "white_box")
        self.assertLessEqual(finding.confidence, 0.6)
        self.assertTrue(0 < finding.severity <= 1)
        self.assertIn("candidate evidence, not proof — known false positives on naturally small decision boundaries per class",
                      " ".join(finding.evidence))
        self.assertIn("small decision boundaries", " ".join(finding.counter_evidence))
        reconstructions = finding.provenance["reconstruction"]
        target = reconstructions[2]
        self.assertEqual(target["l1_norm"], max(result["l1_norm"] for result in reconstructions))
        trigger = np.asarray(target["patch"])
        self.assertTrue(any(trigger[index] > 0 for index in (0, 1, 8, 9)))
        for sample in self.asset["samples"]:
            self.assertNotEqual(int(toy_logits(sample).argmax()), 2)
            self.assertEqual(int(toy_logits(np.clip(sample + trigger, 0, 1)).argmax()), 2)
        self.assertTrue(all(result["iterations"] <= 50 for result in reconstructions))
        self.assertEqual(finding.provenance["config_hash"], "config")

    def test_seed_determinism_and_no_mutation(self):
        self.assertEqual(self.findings, self.provider.analyze(self.asset))
        np.testing.assert_array_equal(self.asset["samples"], clean_samples())

    def test_invalid_inputs_and_iteration_cap(self):
        for cap in (0, 51, 1.5):
            with self.assertRaises(ValueError):
                TriggerReconstructionProvider(max_iterations=cap)
        for samples in ([], np.zeros((2, 63)), np.full((2, 64), np.nan), np.full((2, 64), 2)):
            with self.assertRaises(ValueError):
                self.provider.reconstruct(toy_logits, samples)

    def test_unreachable_classes_do_not_emit_candidates(self):
        provider = TriggerReconstructionProvider(max_iterations=1)
        asset = dict(self.asset, model=lambda values: np.array([1, 0, 0]))
        self.assertEqual(provider.analyze(asset), [])


class PruningTests(unittest.TestCase):
    def setUp(self):
        clean = np.full((3, 64), 0.2)
        clean[:, [0, 1, 8, 9]] = 0
        triggered = clean_samples()[0]
        triggered[[0, 1, 8, 9]] = 1
        self.asset = {"asset_id": "toy-model", "activations": clean, "model": toy_logits,
                      "reference_battery": np.vstack([clean_samples(), triggered]),
                      "predict_fn": lambda model, values: model(values), "suspicious_indices": [2],
                      "config_hash": "config"}
        self.provider = FinePruningProvider(prune_fraction=1 / 64)

    def test_pruned_variant_changes_flagged_behavior_using_shared_utility(self):
        original = self.asset["reference_battery"].copy()
        with patch.object(fine_pruning, "test_counterfactual", wraps=test_counterfactual) as counterfactual:
            finding = self.provider.analyze(self.asset)[0]
            self.assertEqual(counterfactual.call_count, 3)
        self.assertEqual(finding.modality, Modality.ACTIVATION)
        self.assertEqual(finding.access_assumptions, "white_box")
        self.assertEqual(finding.provenance["pruned_neurons"], [0])
        self.assertEqual(finding.provenance["suspicious_changed_indices"], [2])
        self.assertEqual(finding.provenance["other_changed_indices"], [])
        self.assertIn("supporting evidence for the backdoor hypothesis, not confirmation — pruned neurons can also be legitimate rare-feature detectors",
                      " ".join(finding.evidence))
        np.testing.assert_array_equal(self.asset["reference_battery"], original)
        self.assertEqual(finding, self.provider.analyze(self.asset)[0])

    def test_unchanged_behavior_is_not_support(self):
        self.asset["predict_fn"] = lambda model, sample: np.array([1, 0, 0])
        finding = self.provider.analyze(self.asset)[0]
        self.assertFalse(finding.provenance["behavior_changed"])
        self.assertEqual(finding.confidence, 0)
        self.assertEqual(finding.severity, 0)

    def test_validation(self):
        with self.assertRaises(ValueError):
            FinePruningProvider(prune_fraction=0)
        for update in ({"suspicious_indices": []}, {"suspicious_indices": [99]},
                       {"activations": np.zeros((3, 2))}, {"activations": np.full((3, 64), np.nan)}):
            with self.subTest(update=update), self.assertRaises(ValueError):
                self.provider.analyze(dict(self.asset, **update))


class MerkleTests(unittest.TestCase):
    def test_proofs_odd_duplicate_and_tampering(self):
        leaves = [b"a", b"b", b"c"]
        tree = build_merkle_tree(leaves)
        hashes = [hashlib.sha256(leaf).digest() for leaf in leaves]
        left = hashlib.sha256(hashes[0] + hashes[1]).digest()
        right = hashlib.sha256(hashes[2] + hashes[2]).digest()
        self.assertEqual(tree["root"], hashlib.sha256(left + right).hexdigest())
        for index, leaf in enumerate(leaves):
            proof = tree.merkle_proof(index)
            self.assertEqual(proof, merkle_proof(tree, index))
            self.assertTrue(verify_proof(leaf, proof, tree["root"]))
            self.assertFalse(verify_proof(b"tampered", proof, tree["root"]))
            self.assertFalse(verify_proof(leaf, proof, "0" * 64))
        proof = tree.merkle_proof(0)
        proof[0]["position"] = "left"
        self.assertFalse(verify_proof(leaves[0], proof, tree["root"]))
        proof[0]["hash"] = "invalid"
        self.assertFalse(verify_proof(leaves[0], proof, tree["root"]))

    def test_dict_canonicalization_empty_singleton_and_bounds(self):
        first = {"z": 2, "a": 1.5}
        tree = build_merkle_tree([first])
        self.assertEqual(tree["root"], hashlib.sha256(canonical_serialization(first)).hexdigest())
        self.assertTrue(verify_proof({"a": 1.5, "z": 2}, tree.merkle_proof(0), tree["root"]))
        self.assertEqual(tree.merkle_proof(0), [])
        empty = build_merkle_tree([])
        self.assertEqual(empty["root"], hashlib.sha256(b"").hexdigest())
        self.assertEqual(empty["levels"], [])
        for target, index in ((empty, 0), (tree, -1), (tree, 1)):
            with self.assertRaises(ValueError):
                target.merkle_proof(index)


class SpotTests(unittest.TestCase):
    def setUp(self):
        self.predict = lambda values: np.array([sum(values), -sum(values)])
        self.activate = lambda values: {"hidden": np.asarray(values) * 2}
        self.store = {}
        for index in range(12):
            sample = np.array([float(index), 1.0])
            record = InferenceRecord(
                hashlib.sha256(payload_bytes(sample)).hexdigest(), "model", "config",
                hashlib.sha256(payload_bytes(self.predict(sample))).hexdigest(), index, f"nonce-{index}", 1.0,
                merkle_root=build_merkle_tree(activation_leaves(self.activate(sample)))["root"],
            )
            self.store[f"record-{index:02d}"] = {"record": record, "input": sample}
        self.executor = SpotReexecutor(self.store, self.predict, self.activate, sample_rate=1, seed=7)

    def test_matches_and_tampered_root_output_input(self):
        reports = self.executor.run()
        self.assertEqual(len(reports), 12)
        self.assertTrue(all(report["output_match"] and report["merkle_match"] and not report["mismatches"] for report in reports))
        entry = self.store["record-03"]
        entry["record"] = replace(entry["record"], merkle_root="0" * 64)
        report = self.executor.run(["record-03"])[0]
        self.assertTrue(report["output_match"])
        self.assertFalse(report["merkle_match"])
        self.assertEqual(report["mismatches"], ["merkle_root"])
        entry["record"] = replace(entry["record"], output_hash="0" * 64, input_hash="0" * 64)
        self.assertEqual(self.executor.run(["record-03"])[0]["mismatches"], ["input_hash", "output_hash", "merkle_root"])

    def test_sampling_is_seeded_and_endpoints_are_exact(self):
        executor = SpotReexecutor(self.store, self.predict, self.activate, sample_rate=0.5, seed=7)
        rng = random.Random(7)
        expected = [name for name in sorted(self.store) if rng.random() < 0.5]
        self.assertEqual([report["record_id"] for report in executor.run()], expected)
        self.assertEqual(executor.run(), executor.run())
        executor.sample_rate = 0
        self.assertEqual(executor.run(), [])
        with self.assertRaises(ValueError):
            SpotReexecutor(self.store, self.predict, self.activate, sample_rate=float("nan"))

    def test_activation_layout_binding_and_failure_reports(self):
        self.assertNotEqual(build_merkle_tree(activation_leaves(np.array([[1, 2]])))["root"],
                            build_merkle_tree(activation_leaves(np.array([1, 2])))["root"])
        self.executor.activation_fn = lambda values: np.array([np.nan])
        report = self.executor.run(["record-00"])[0]
        self.assertFalse(report["merkle_match"])
        self.assertIn("ValueError", report["mismatches"][0])
        self.assertTrue(report["output_match"])

    def test_verifier_partial_default_empty_and_mismatch(self):
        verifier = Verifier(public_key=object())
        self.assertEqual(verifier.verify_computation_consistency()["status"], "not yet implemented")
        record = self.store["record-00"]["record"]
        result = verifier.verify_computation_consistency([(record, None)], self.executor)
        self.assertEqual(result["status"], "partial assurance")
        self.assertEqual(result["checked_count"], 1)
        self.assertFalse(result["fully_assured"])
        self.assertIn("proves the log wasn't altered post-hoc and spot-checks match, not a full cryptographic guarantee of computation (zkML out of scope)", result["note"])
        self.assertEqual(verifier._seen, set())
        self.assertEqual(verifier.verify_computation_consistency([], self.executor)["status"], "not checked")
        tampered = replace(record, merkle_root="0" * 64)
        self.assertEqual(verifier.verify_computation_consistency([tampered], self.executor)["status"], "mismatch")


class CorrelationTests(unittest.TestCase):
    def finding(self, detector="pixel", kind="perceptual_duplicate", modality=Modality.PIXEL, **changes):
        finding = Finding("asset", kind, 0.7, 0.6, [f"{detector} evidence"], modality,
                          {"detector_id": detector, "version": "1.0.0", "input_hashes": ["a" * 64], "config_hash": "config"},
                          "review", counter_evidence=[f"{detector} counter"])
        return replace(finding, **changes)

    def test_cross_modality_boost_and_sources(self):
        first = self.finding()
        second = self.finding("semantic", "semantic_near_duplicate", Modality.EMBEDDING)
        engine = CorrelationEngine()
        result = engine.converge([first, second])
        self.assertEqual(len(result), 1)
        composite = result[0]
        self.assertEqual(composite.finding_type, "composite_duplicate")
        self.assertGreater(composite.confidence, 0.6)
        self.assertLessEqual(composite.confidence, 0.95)
        for source in ("pixel", "semantic", "PIXEL", "EMBEDDING"):
            self.assertIn(source, " ".join(composite.evidence))
        self.assertEqual(composite.provenance["detector_ids"], ["pixel", "semantic"])
        self.assertEqual(set(composite.counter_evidence), {"pixel counter", "semantic counter"})
        self.assertEqual(first.confidence, 0.6)
        self.assertIn(KNOWN_LIMITATION, engine.known_limitations())
        self.assertEqual(result, engine.converge([first, second]))

    def test_same_modality_other_assets_and_families_do_not_boost(self):
        first = self.finding()
        for second in (self.finding("other"), self.finding("other", modality=Modality.EMBEDDING, asset_id="other"),
                       self.finding("other", kind="unclassified_anomaly", modality=Modality.EMBEDDING)):
            result = CorrelationEngine().converge([first, second])
            self.assertEqual(len(result), 2)
            self.assertTrue(all(finding.confidence == 0.6 for finding in result))
        self.assertEqual(CorrelationEngine().converge([]), [])

    def test_shared_signal_and_reused_detector_suppress_boost(self):
        first = self.finding()
        second = self.finding(modality=Modality.EMBEDDING)
        self.assertEqual(CorrelationEngine().converge([first, second])[0].confidence, 0.6)
        first.provenance["signal_ids"] = ["shared"]
        second.provenance.update(detector_id="other", signal_ids=["shared"])
        self.assertEqual(CorrelationEngine().converge([first, second])[0].confidence, 0.6)

    def test_same_modality_extra_no_boost_and_cap(self):
        first = self.finding()
        second = self.finding("semantic", modality=Modality.EMBEDDING)
        engine = CorrelationEngine()
        base = engine.converge([first, second])[0]
        extra = engine.converge([first, second, self.finding("extra")])[0]
        self.assertEqual(base.confidence, extra.confidence)
        high = engine.converge([replace(first, confidence=0.94), replace(second, confidence=0.94)])[0]
        self.assertEqual(high.confidence, 0.95)

    def test_zero_support_and_accept_do_not_converge(self):
        first = self.finding(kind="candidate_backdoor_trigger", modality=Modality.BEHAVIORAL)
        second = self.finding("pruning", "fine_pruning_verification", Modality.ACTIVATION, severity=0, confidence=0)
        self.assertEqual(len(CorrelationEngine().converge([first, second])), 2)
        second = replace(second, severity=0.8, confidence=0.8, recommended_action="accept")
        self.assertEqual(len(CorrelationEngine().converge([first, second])), 2)

    def test_detector_language_guard(self):
        app = Path(__file__).resolve().parents[1] / "app"
        paths = list((app / "modules").rglob("*.py")) + [app / "core" / "correlation.py"]
        self.assertTrue(paths)
        for path in paths:
            with self.subTest(path=path):
                self.assertNotIn("independent", path.read_text(encoding="utf-8").lower())


if __name__ == "__main__":
    unittest.main()
