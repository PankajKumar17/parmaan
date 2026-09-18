import random
import unittest
from dataclasses import replace
from unittest.mock import patch

import numpy as np

from app.evaluation.ablation import run_ablation
from app.evaluation.adaptive_attacker import optimize_trigger_against
from app.evaluation.attack_toolkit import backdoor_model, poison_dataset, substitute_model, tamper_log
from app.evaluation.calibration import apply_calibration, brier_score, reliability_diagram
from app.evaluation.false_positive_cost import false_positive_rate
from app.evaluation.metrics import per_detector_metrics, pr_points, roc_points
from app.evaluation.reproducibility import assert_reproducible
from app.evaluation.runtime_cost import aggregate_runtime
from app.modules.data_integrity.contributor_risk import ContributorRiskAggregator, TemporalDriftPoint
from app.modules.model_integrity.access_matrix import CHECK_CAPABILITIES, coverage_confidence, evaluate_access
from app.provenance.chain import InferenceRecord

from app.core.decision import RiskDecisionMatrix
from app.core.evidence import Finding, Modality
from app.core.lineage import IntegrityLineage, propagate_confidence


def finding(asset="sample", detector="test", **changes):
    values = dict(asset_id=asset, finding_type="poisoning", severity=0.8, confidence=0.9,
                  evidence=["support"], modality=Modality.PIXEL,
                  provenance={"detector_id": detector, "version": "1.0.0"},
                  recommended_action="review", counter_evidence=["alternative explanation"])
    values.update(changes)
    return Finding(**values)


class LineageTests(unittest.TestCase):
    def setUp(self):
        self.lineage = IntegrityLineage()
        self.lineage.add_contributor("contributor")
        self.lineage.add_dataset({"dataset_id": "dataset"}, "contributor")
        self.lineage.add_model({"model_hash": "model", "training_dataset_ids": ["dataset"]})
        self.record = self.lineage.add_inference_record({"consumer_id": "consumer", "output": 1}, "model", "dataset")
        self.lineage.add_finding(finding("dataset", confidence=0.4), "dataset")
        self.lineage.add_finding(finding("contributor", confidence=0.6), "contributor")

    def test_blast_radius_downstream_counts_and_consumers(self):
        radius = self.lineage.blast_radius("contributor")
        self.assertEqual(radius, {"models": ["model"], "inference_records": [self.record],
                                  "datasets": ["dataset"], "consumers": {"consumer": [self.record]}, "total": 3})
        self.assertEqual(self.lineage.blast_radius("model")["total"], 1)
        self.assertEqual(self.lineage.blast_radius("missing")["total"], 0)

    def test_confidence_min_cap_does_not_follow_siblings(self):
        self.assertEqual(propagate_confidence(0.9, self.lineage, self.record), 0.4)
        self.assertEqual(self.lineage.propagate_confidence(0.2, "model"), 0.2)
        self.assertEqual(propagate_confidence(0.8, self.lineage, "missing"), 0.8)
        self.lineage.add_model({"model_hash": "sibling", "training_dataset_ids": ["dataset"]})
        self.lineage.add_finding(finding("sibling", confidence=0.1), "sibling")
        self.assertEqual(propagate_confidence(0.9, self.lineage, self.record), 0.4)
        with self.assertRaises(ValueError):
            propagate_confidence(float("nan"), self.lineage, "model")

    def test_decision_consumes_existing_lineage_for_highest_scope(self):
        verdict = RiskDecisionMatrix(self.lineage).decide([finding(self.record)])[0]
        self.assertEqual(verdict["verdict"], "QUARANTINE")
        self.assertEqual(verdict["scope"], "contributor")
        self.assertEqual(verdict["scope_asset_id"], "contributor")
        radius = self.lineage.blast_radius(verdict["scope_asset_id"])
        self.assertIn(self.record, radius["inference_records"])


class DecisionTests(unittest.TestCase):
    def test_matrix_boundaries_without_rollup(self):
        engine = RiskDecisionMatrix()
        with patch.object(engine, "unified_trust_score", side_effect=AssertionError("display only")):
            for severity in (0, 0.2999, 0.3, 0.6999, 0.7, 1):
                for confidence in (0, 0.2999, 0.3, 0.6999, 0.7, 1):
                    expected = "ACCEPT" if severity < 0.3 or confidence < 0.3 else (
                        "QUARANTINE" if severity >= 0.7 and confidence >= 0.7 else "REVIEW")
                    with self.subTest(severity=severity, confidence=confidence):
                        verdict = engine.decide([finding(severity=severity, confidence=confidence)])[0]
                        self.assertEqual(verdict["verdict"], expected)
                        self.assertEqual(verdict["scope"], "sample")
                        self.assertIn("scope_note", verdict)
        for value in (-1, 2, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                engine.decide([finding(confidence=value)])

    def test_counter_evidence_warning_and_explanation(self):
        engine = RiskDecisionMatrix()
        source = finding(counter_evidence=[])
        with self.assertLogs("app.core.decision", level="WARNING"):
            verdict = engine.decide([source])[0]
        self.assertIs(verdict["finding"], source)
        self.assertIn("warning", verdict)
        self.assertIn("support | Not provided", engine.explain(verdict))
        verdict = engine.decide([finding()])[0]
        self.assertIn("support | alternative explanation", engine.explain(verdict))
        self.assertNotIn("warning", verdict)
        self.assertIsNone(engine.unified_trust_score([])["rollup"])
        self.assertAlmostEqual(engine.unified_trust_score([finding()])["components"]["test"], 0.28)

    def test_scope_for_each_node_type(self):
        for node_type, scope in RiskDecisionMatrix.SCOPES.items():
            lineage = IntegrityLineage()
            lineage.graph.add_node("asset", node_type=node_type)
            self.assertEqual(RiskDecisionMatrix(lineage).decide([finding("asset")])[0]["scope"], scope)


class ContributorTests(unittest.TestCase):
    def fixture(self):
        samples, findings = {}, []
        order = [f"batch-{index}" for index in range(1, 7)]
        for contributor in ("changing", "clean"):
            for batch_index, batch in enumerate(order):
                for index in range(20):
                    asset = f"{contributor}-{batch}-{index}"
                    samples[asset] = {"contributor_id": contributor, "batch_id": batch}
                    if contributor == "changing" and index < (1 if batch_index < 2 else 8):
                        findings.append(finding(asset))
        return findings, {"samples": samples, "ordered_batches": order}

    def test_batch_three_change_point_and_clean_denominators(self):
        findings, metadata = self.fixture()
        aggregator = ContributorRiskAggregator()
        report = aggregator.aggregate(findings, metadata)
        point = report["temporal_drift_points"][0]
        self.assertEqual(point, TemporalDriftPoint("changing", "batch-3", 0.05, 0.4))
        changing = report["contributors"]["changing"]
        self.assertEqual([batch["anomaly_rate"] for batch in changing["batches"]], [0.05, 0.05, 0.4, 0.4, 0.4, 0.4])
        self.assertAlmostEqual(changing["prevalence"], 34 / 120)
        self.assertAlmostEqual(changing["batch_concentration"], 8 / 34)
        self.assertGreater(changing["risk_score"], report["contributors"]["clean"]["risk_score"])
        self.assertEqual(aggregator.aggregate(findings * 2, metadata), report)
        self.assertEqual(aggregator.aggregate([], metadata)["temporal_drift_points"], [])
        self.assertEqual(aggregator.temporal_drift_points, [])

    def test_modality_convergence_and_metadata_gaps(self):
        findings, metadata = self.fixture()
        aggregator = ContributorRiskAggregator()
        baseline = aggregator.aggregate(findings, metadata)["contributors"]["changing"]
        diverse = [replace(item, modality=Modality.EMBEDDING) for item in findings]
        report = aggregator.aggregate(findings + diverse, metadata)
        self.assertGreater(report["contributors"]["changing"]["convergence_count"], baseline["convergence_count"])
        self.assertGreater(report["contributors"]["changing"]["risk_score"], baseline["risk_score"])
        metadata["samples"]["missing"] = {"contributor_id": None, "batch_id": None}
        report = aggregator.aggregate(findings + [finding("unknown")], metadata)
        self.assertEqual(report["missing_metadata"], ["missing"])
        self.assertEqual(report["unmatched_findings"], ["unknown"])
        self.assertLess(report["metadata_coverage"], 1)
        with self.assertRaises(ValueError):
            aggregator.aggregate(findings, dict(metadata, ordered_batches=["batch-1"]))


class AccessTests(unittest.TestCase):
    def test_exact_capabilities_skip_reasons_and_debt(self):
        expected = [("yes", "yes", "yes"), ("yes", "partial", "no"),
                    ("yes", "partial", "no"), ("yes", "no", "no"),
                    ("yes", "yes", "yes (output-only)"), ("yes", "partial", "no")]
        self.assertEqual([tuple(row.values()) for row in CHECK_CAPABILITIES.values()], expected)
        report = evaluate_access("black_box", CHECK_CAPABILITIES)
        self.assertEqual(len(report["ran"]), 2)
        self.assertEqual(len(report["skipped"]), 4)
        self.assertAlmostEqual(report["coverage_confidence"], 1 / 3)
        self.assertTrue(all(item["reason"] for item in report["skipped"]))
        self.assertTrue(all(item["gap"] and item["recommendation"] for item in report["assurance_debt"]))
        gray = evaluate_access("gray_box", CHECK_CAPABILITIES)
        self.assertEqual(len(gray["degraded"]), 3)
        self.assertEqual(len(gray["assurance_debt"]), 4)
        self.assertEqual(len(evaluate_access("white_box", [])["skipped"]), 6)
        self.assertEqual(coverage_confidence(["a", "a", "extra"], ["a", "b"]), 0.5)
        self.assertEqual(coverage_confidence([], []), 0)
        self.assertFalse(report["execution_verified"])
        with self.assertRaises(ValueError):
            evaluate_access("invalid", [])


class AttackFixtureTests(unittest.TestCase):
    def test_dataset_truth_matches_changes_for_all_modes(self):
        images = np.arange(80).reshape(20, 2, 2)
        labels = np.arange(20) % 2
        for mode in ("label_flip", "duplicate_flood", "ood_insert"):
            with self.subTest(mode=mode):
                poisoned, truth = poison_dataset(images, labels, 0.4, 7, mode)
                changed = np.any(poisoned["images"] != images, axis=(1, 2)) | (poisoned["labels"] != labels)
                self.assertEqual(truth["affected"], np.flatnonzero(changed).tolist())
                self.assertEqual(truth["attack_type"], mode)
                again, repeated = poison_dataset(images, labels, 0.4, 7, mode)
                self.assertEqual(truth, repeated)
                np.testing.assert_array_equal(poisoned["images"], again["images"])
                self.assertEqual(poison_dataset(images, labels, 0, 7, mode)[1]["affected"], [])
        np.testing.assert_array_equal(images, np.arange(80).reshape(20, 2, 2))
        np.testing.assert_array_equal(labels, np.arange(20) % 2)
        with self.assertRaises(ValueError):
            poison_dataset(images, labels, float("nan"), 7)

    def test_synthetic_predictor_truth_and_repeatability(self):
        samples = np.array([[0, 0], [1, 0], [1, 1], [0, 1]])
        wrapped, truth = backdoor_model(lambda batch: np.zeros(len(batch), dtype=int),
                                        lambda row: bool(row[0] == 1), 1, 1, 7)
        result = wrapped(samples)
        np.testing.assert_array_equal(result, [0, 1, 1, 0])
        self.assertEqual(truth["affected"], [1, 2])
        np.testing.assert_array_equal(wrapped(samples), result)
        self.assertEqual(truth["calls"][0], truth["calls"][1])
        logits, truth = backdoor_model(lambda batch: np.tile([1.0, 0.0], (len(batch), 1)),
                                       lambda row: bool(row[0]), 1, 0, 7)
        logits(samples)
        self.assertEqual(truth["affected"], [])

    def test_weights_and_log_copies_truth(self):
        weights = np.zeros((2, 3))
        perturbed, truth = substitute_model(weights, 0.01, 7)
        self.assertEqual(truth["affected"], list(range(6)))
        self.assertLessEqual(float(np.abs(perturbed).max()), 0.01)
        np.testing.assert_array_equal(weights, np.zeros((2, 3)))
        np.testing.assert_array_equal(perturbed, substitute_model(weights, 0.01, 7)[0])
        self.assertEqual(substitute_model(weights, 0, 7)[1]["affected"], [])
        records = [{"output_hash": "a" * 64}, {"output_hash": "b" * 64}]
        corrupted, truth = tamper_log(records, 1, 7)
        self.assertEqual(truth["affected"], [1])
        self.assertEqual(corrupted[0], records[0])
        self.assertNotEqual(corrupted[1], records[1])
        self.assertEqual(records[1]["output_hash"], "b" * 64)
        self.assertEqual(corrupted, tamper_log(records, 1, 7)[0])
        record = InferenceRecord("input", "model", "config", "output", 0, "nonce", 1.0)
        self.assertNotEqual(tamper_log([record], 0, 7)[0][0].output_hash, record.output_hash)
        with self.assertRaises(ValueError):
            tamper_log(records, -1, 7)


class EvaluationTests(unittest.TestCase):
    def test_per_detector_metrics_deduplicate_assets(self):
        findings = [finding("0", "a"), finding("0", "a"), finding("2", "a"), finding("1", "b"),
                    finding("2", "b", recommended_action="accept")]
        report = per_detector_metrics({"affected": [0, 1], "attack_type": "label_flip"}, findings, ["silent"])
        self.assertEqual(report["a"], {"tp": 1, "fp": 1, "fn": 1, "precision": 0.5, "recall": 0.5, "f1": 0.5})
        self.assertEqual(report["b"]["precision"], 1)
        self.assertEqual(report["b"]["recall"], 0.5)
        self.assertEqual(report["silent"]["recall"], 0)

    def test_curves_ties_endpoints_and_invalid_input(self):
        roc = roc_points([0.9, 0.8, 0.8, 0.1], [1, 0, 1, 0])
        self.assertEqual([(point["fpr"], point["tpr"]) for point in roc], [(0, 0), (0, 0.5), (0.5, 1), (1, 1)])
        pr = pr_points([0.9, 0.8, 0.8, 0.1], [1, 0, 1, 0])
        self.assertAlmostEqual(pr[2]["precision"], 2 / 3)
        self.assertEqual(pr[-1]["recall"], 1)
        self.assertIsNone(roc_points([0.5], [0])[0]["tpr"])
        self.assertIsNone(pr_points([], [])[0]["recall"])
        for scores, truth in (([float("nan")], [1]), ([0.5], [2]), ([1], [])):
            with self.assertRaises(ValueError):
                roc_points(scores, truth)

    def test_reproducible_pipeline_and_real_mismatch(self):
        def pipeline(seed):
            images, truth = poison_dataset(np.arange(40).reshape(10, 2, 2), np.arange(10) % 2, 0.4, seed)
            return [finding(str(index), confidence=float(np.random.default_rng(seed + index).uniform(0.3, 0.9)))
                    for index in truth["affected"] if images["labels"][index] != index % 2]

        state = random.getstate()
        self.assertEqual(assert_reproducible(pipeline, 7), {"deterministic": True, "diff": []})
        self.assertEqual(random.getstate(), state)
        calls = []

        def changing(seed):
            calls.append(seed)
            return [finding(confidence=0.1 * len(calls))]

        report = assert_reproducible(changing, 7)
        self.assertFalse(report["deterministic"])
        self.assertTrue(report["diff"])

    def test_ablation_disables_one_module_with_signed_deltas(self):
        calls = []

        def pipeline(disabled_modules):
            calls.append(disabled_modules)
            return {"ground_truth": {"affected": [0, 1], "attack_type": "fixture"},
                    "findings": [finding(str(index), module) for index, module in enumerate(("a", "b"))
                                 if module not in disabled_modules]}

        report = run_ablation(pipeline, ["a", "b"])
        self.assertEqual(calls, [(), ("a",), ("b",)])
        self.assertEqual(report["a"]["recall_delta"], -0.5)
        self.assertEqual(report["a"]["precision_delta"], 0)

    def test_false_positive_boundary_and_empty_input(self):
        pipeline = lambda variant: [finding(severity=0.5)] if variant else []
        self.assertFalse(false_positive_rate(pipeline, [True] + [False] * 19)["flag"])
        report = false_positive_rate(pipeline, [True] + [False] * 9)
        self.assertEqual(report["rate"], 0.1)
        self.assertTrue(report["flag"])
        self.assertEqual(report["quarantine_rate"], 0)
        self.assertIsNone(false_positive_rate(pipeline, [])["rate"])

    def test_runtime_phase_three_contract_and_skip(self):
        report = aggregate_runtime([{"timings": {"a": 1, "skipped": 0},
                                     "tier_logs": [{"provider": "a", "ran": True}, {"provider": "skipped", "ran": False}]},
                                    {"a": 3}, {"detector_id": "a", "wall_clock": 2}])
        self.assertEqual(set(report), {"a"})
        self.assertEqual(report["a"]["mean"], 2)
        self.assertEqual(report["a"]["p50"], 2)
        self.assertAlmostEqual(report["a"]["p95"], 2.9)
        self.assertEqual(report["a"]["max"], 3)
        self.assertIn("not measured", report["a"]["memory_note"])

    def test_fixed_trigger_assessment_reports_no_optimization(self):
        trigger = np.array([0.1, 0.9])
        result, report = optimize_trigger_against(lambda value: [True, False, True], trigger,
                                                 lambda value: value.sum(), 10, 7)
        np.testing.assert_array_equal(result, trigger)
        self.assertFalse(report["optimized"])
        self.assertEqual(report["iterations_run"], 0)
        self.assertAlmostEqual(report["detection_rate"], 2 / 3)


class CalibrationTests(unittest.TestCase):
    def test_brier_known_values_and_bin_edges(self):
        self.assertAlmostEqual(brier_score([0, 0.5, 1], [0, 1, 1]), 1 / 12)
        self.assertEqual(brier_score([0, 1], [0, 1]), 0)
        self.assertEqual(brier_score([0, 1], [1, 0]), 1)
        bins = reliability_diagram([0, 0.5, 1], [0, 1, 1], bins=2)
        self.assertEqual([item["count"] for item in bins], [1, 2])
        self.assertEqual(bins[1]["mean_confidence"], 0.75)
        self.assertEqual(bins[1]["accuracy"], 1)
        self.assertIsNone(reliability_diagram([], [])[0]["accuracy"])
        self.assertIsNone(brier_score([], []))
        with self.assertRaises(ValueError):
            brier_score([1.1], [1])

    def test_calibration_copies_provenance_and_is_idempotent(self):
        source = finding(confidence=0.5)
        mapping = {0: 0.1, 1: 0.7}
        calibrated = apply_calibration([source], mapping)[0]
        self.assertAlmostEqual(calibrated.confidence, 0.4)
        self.assertEqual(source.confidence, 0.5)
        self.assertNotIn("calibration_applied", source.provenance)
        self.assertTrue(calibrated.provenance["calibration_applied"])
        self.assertEqual(apply_calibration([calibrated], mapping)[0], calibrated)
        for invalid in ({}, {0: 1, 1: 0}, {0: float("nan")}):
            with self.assertRaises(ValueError):
                apply_calibration([source], invalid)


if __name__ == "__main__":
    unittest.main()
