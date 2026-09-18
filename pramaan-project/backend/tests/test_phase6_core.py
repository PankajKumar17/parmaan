import json
import tempfile
import unittest
from dataclasses import fields, replace
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.correlation import CorrelationEngine
from app.core.coverage_statement import build_coverage_statement
from app.core.decision import RiskDecisionMatrix
from app.core.evidence import Finding, Modality
from app.core.lineage import IntegrityLineage
from app.core.passport import Passport, generate_passport
from app.core.security import hash_password
from app.core.self_integrity import IntegrityReport
from app.core.staleness import check_staleness
from app.db.models import User
from app.main import create_app
from app.manifests.dataset_manifest import DatasetManifest
from app.manifests.model_manifest import ModelReferenceManifest
from app.manifests.pipeline_manifest import PipelineEnvironmentManifest
from app.modules.model_integrity.access_matrix import evaluate_access
from app.provenance import keys
from app.provenance.canonical import canonical_serialization


def finding(asset="sample", **changes):
    values = dict(asset_id=asset, finding_type="candidate_poisoning", severity=0.8,
                  confidence=0.9, evidence=["Unusual sample distribution"], modality=Modality.PIXEL,
                  provenance={"detector_id": "test", "version": "1.0.0", "input_hashes": [], "config_hash": ""},
                  recommended_action="review", counter_evidence=["Natural variation remains possible"])
    values.update(changes)
    return Finding(**values)


class CoreFixture(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        key_dir = self.root / "keys"
        self.enterContext(patch.object(keys, "KEYS_DIR", key_dir))
        self.enterContext(patch.object(keys, "PRIVATE_KEY_FILE", key_dir / "private.pem"))
        self.enterContext(patch.object(keys, "PUBLIC_KEY_FILE", key_dir / "public.pem"))
        self.lineage = IntegrityLineage()

    def passport(self, findings=None):
        return generate_passport("sample", self.lineage, [finding()] if findings is None else findings,
                                 RiskDecisionMatrix(self.lineage))

    def dataset(self):
        root = self.root / "dataset"
        root.mkdir()
        (root / "images").mkdir()
        (root / "images" / "sample.jpg").write_bytes(b"sample image bytes")
        (root / "annotations.json").write_text(json.dumps({
            "dataset_version": "v1", "images": [{"id": 1, "file_name": "sample.jpg"}],
            "categories": [{"id": 1, "name": "cat"}],
            "annotations": [{"id": 1, "image_id": 1, "category_id": 1, "bbox": [0, 0, 2, 2]}],
        }), encoding="utf-8")
        return DatasetManifest.build_from_coco(root), root


class PassportTests(CoreFixture):
    def test_roundtrip_exact_fields_and_canonical_signature(self):
        passport = self.passport()
        expected = {"findings", "affected_asset", "disposition", "limitations", "coverage_statement",
                    "passport_version", "issued_at", "asset_id", "signature", "public_key_fingerprint"}
        self.assertEqual({item.name for item in fields(Passport)}, expected)
        payload = json.loads(json.dumps(passport.to_json()))
        self.assertEqual(set(payload), expected)
        restored = Passport(**payload)
        self.assertTrue(restored.verify_signature())
        body = restored.to_json()
        signature = body.pop("signature")
        self.assertTrue(keys.verify_signature(canonical_serialization(body), bytes.fromhex(signature), keys.load_public_key()))
        self.assertEqual(restored.disposition[0]["verdict"], "quarantine")
        for name in ("reason", "evidence", "confidence", "severity"):
            self.assertIn(name, restored.findings[0])

    def test_tamper_every_body_field_and_signature(self):
        passport = self.passport()
        replacements = {"findings": [], "affected_asset": {}, "disposition": [], "limitations": [],
                        "coverage_statement": "fake", "passport_version": "fake", "issued_at": "fake",
                        "asset_id": "fake", "public_key_fingerprint": "0" * 64, "signature": "00" * 64}
        for name, value in replacements.items():
            with self.subTest(field=name):
                self.assertFalse(replace(passport, **{name: value}).verify_signature())
        self.assertFalse(replace(passport, signature="not hex").verify_signature())
        keys.PUBLIC_KEY_FILE.unlink()
        self.assertFalse(passport.verify_signature())

    def test_markdown_required_content_and_snapshot(self):
        source = finding()
        passport = self.passport([source])
        source.evidence.append("later mutation")
        payload = passport.to_json()
        payload["findings"][0]["evidence"].clear()
        self.assertTrue(passport.verify_signature())
        markdown = passport.render_markdown()
        for text in ("Asset ID:", "sample", "Passport version:", "Issued at:", "Affected asset",
                     "Findings", "Reason:", "Unusual sample distribution", "Confidence: 0.9", "Severity: 0.8",
                     "Disposition", "quarantine", "scope", "Counter-evidence", "Natural variation remains possible",
                     "Limitations", "Coverage statement", "Signature", "Ed25519", "Public key fingerprint"):
            self.assertIn(text, markdown)
        self.assertNotIn("later mutation", markdown)

    def test_scope_and_debt_context_and_coverage_reference(self):
        self.lineage.graph.add_node("sample", node_type="model", hash="model-hash")
        debt = evaluate_access("black_box", [])['assurance_debt']
        self.lineage.graph.graph.update(assurance_debt=debt, coverage_statement="coverage-v1")
        passport = self.passport()
        self.assertEqual(passport.disposition[0]["scope"], "model")
        self.assertEqual(passport.coverage_statement, "coverage-v1")
        for item in debt:
            self.assertIn(item, passport.limitations)
        self.assertEqual(passport.affected_asset["hash"], "model-hash")

    def test_empty_findings_do_not_imply_acceptance(self):
        passport = self.passport([])
        self.assertEqual(passport.disposition, [])
        self.assertIn("No verdicts supplied; no acceptance is inferred.", passport.render_markdown())

    def test_all_matrix_verdicts_and_access_assumptions(self):
        passport = self.passport([finding(severity=0.1), finding(confidence=0.5),
                                  finding(access_assumptions="white_box")])
        self.assertEqual([item["verdict"] for item in passport.disposition], ["accept", "review", "quarantine"])
        self.assertEqual(passport.coverage_statement["access_assumptions"]["used"], ["black_box", "white_box"])


class CoverageTests(unittest.TestCase):
    def test_classes_taxonomies_limitations_and_honest_results(self):
        debt = evaluate_access("black_box", [])['assurance_debt']
        ablation = {"disabled": {"precision_delta": -0.2}}
        adaptive = {"detection_rate": 0.1, "optimized": False}
        coverage = build_coverage_statement(debt, ablation, adaptive)
        self.assertEqual(set(coverage["supported_attack_classes"]), {
            "label-flip", "near-duplicate flooding", "OOD insertion", "model substitution",
            "candidate backdoors", "inference tampering & replay"})
        for reference in coverage["supported_attack_classes"].values():
            self.assertIn("MITRE ATLAS:", reference)
        for limitation in CorrelationEngine.known_limitations() + debt:
            self.assertIn(limitation, coverage["limitations"])
        self.assertEqual(coverage["ablation_results"], ablation)
        self.assertEqual(coverage["adaptive_attacker_results"], adaptive)
        adaptive["detection_rate"] = 1
        self.assertEqual(coverage["adaptive_attacker_results"]["detection_rate"], 0.1)
        self.assertIn("output-only", coverage["black_box_fallback"])
        self.assertTrue(coverage["version"])
        self.assertTrue(coverage["generated_at"])
        self.assertIn("not evaluated", json.dumps(build_coverage_statement([], None, None)))


class StalenessTests(CoreFixture):
    def test_fail_closed_without_manifests(self):
        report = check_staleness(self.passport())
        self.assertTrue(report.stale)
        self.assertIn("no manifests supplied — cannot verify", report.reasons)
        self.assertTrue(report.checked_at)

    def test_dataset_fresh_modified_deleted_and_missing_manifest(self):
        manifest, path = self.dataset()
        self.lineage.graph.graph["manifest_bindings"] = {"dataset": (manifest, path)}
        passport = self.passport()
        self.assertFalse(check_staleness(passport, dataset_manifest=manifest).stale)
        self.assertFalse(check_staleness(passport, dataset_manifest=(manifest, path)).stale)
        sample = path / "images" / "sample.jpg"
        sample.write_bytes(b"modified image")
        self.assertTrue(check_staleness(passport, dataset_manifest=manifest).stale)
        replacement = DatasetManifest.build_from_coco(path)
        report = check_staleness(passport, dataset_manifest=(replacement, path))
        self.assertIn("dataset manifest differs from passport issuance", report.reasons)
        sample.unlink()
        self.assertTrue(check_staleness(passport, dataset_manifest=manifest).stale)
        self.assertIn("dataset manifest missing", check_staleness(passport).reasons)

    def test_model_rehash_and_pipeline_current_config(self):
        path = self.root / "model.onnx"
        path.write_bytes(b"original weights")
        model = ModelReferenceManifest.build_from_file(
            path, architecture="tiny", expected_metrics={}, activation_statistics={}, output_fingerprints={},
            reference_battery_id="battery-v1", calibration_set_id="calibration-v1")
        pipeline = PipelineEnvironmentManifest({}, {"default": 0.5}, {}, [32, 32], model.model_hash, "torch", "cpu", "1")
        self.lineage.graph.graph["manifest_bindings"] = {"model": (model, path), "pipeline": (pipeline, pipeline.to_dict())}
        passport = self.passport()
        self.assertFalse(check_staleness(passport, model_manifest=model, pipeline_manifest=pipeline).stale)
        current = pipeline.to_dict()
        current["pipeline_version"] = "2"
        self.assertTrue(check_staleness(passport, model_manifest=model, pipeline_manifest=(pipeline, current)).stale)
        pipeline.pipeline_version = "2"
        self.assertTrue(check_staleness(passport, model_manifest=model, pipeline_manifest=pipeline).stale)
        path.write_bytes(b"changed weights")
        report = check_staleness(passport, model_manifest=model)
        self.assertIn("model manifest mismatch or current input missing", report.reasons)
        self.assertIn("pipeline manifest missing", report.reasons)

    def test_missing_path_invalid_manifest_and_tampered_passport(self):
        manifest, path = self.dataset()
        passport = self.passport()
        self.assertTrue(check_staleness(passport, dataset_manifest=manifest).stale)
        self.assertTrue(check_staleness(passport, dataset_manifest=object()).stale)
        self.assertTrue(check_staleness(replace(passport, asset_id="tampered"), dataset_manifest=(manifest, path)).stale)


class PassportApiTests(CoreFixture):
    @classmethod
    def setUpClass(cls):
        cls.password = "test-only-password-123"
        cls.encoded = hash_password(cls.password)

    def setUp(self):
        super().setUp()
        self.app = create_app(Settings("sqlite:///:memory:", "test-only-secret-" * 4))
        self.enterContext(patch("app.main.self_integrity.check_self_integrity", return_value=IntegrityReport()))
        self.client = self.enterContext(TestClient(self.app))
        with self.app.state.session_factory.begin() as session:
            session.add(User(email="analyst@example.com", hashed_password=self.encoded))
        token = self.client.post("/api/auth/login", data={
            "username": "analyst@example.com", "password": self.password}).json()["access_token"]
        self.headers = {"Authorization": "Bearer " + token}
        self.app.state.findings_registry = {"sample": [finding()]}

    def test_auth_and_missing_assessment(self):
        for url in ("/api/passport/sample", "/api/passport/sample/export"):
            self.assertEqual(self.client.get(url).status_code, 401)
        self.assertEqual(self.client.get("/api/passport/missing", headers=self.headers).status_code, 404)

    def test_passport_with_staleness_and_signed_roundtrip(self):
        response = self.client.get("/api/passport/sample", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        report = payload.pop("staleness")
        self.assertTrue(report["stale"])
        self.assertIn("no manifests supplied — cannot verify", report["reasons"])
        self.assertTrue(Passport(**payload).verify_signature())
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_exports_and_repeated_reads_recheck_current_inputs(self):
        manifest, path = self.dataset()
        self.app.state.manifests_registry = {"sample": {"dataset": (manifest, path)}}
        before = self.client.get("/api/passport/sample", headers=self.headers).json()
        self.assertFalse(before["staleness"]["stale"])
        (path / "images" / "sample.jpg").write_bytes(b"changed")
        exported = self.client.get("/api/passport/sample/export?format=json", headers=self.headers)
        self.assertEqual(exported.status_code, 200)
        self.assertIn("attachment", exported.headers["content-disposition"])
        self.assertTrue(exported.json()["staleness"]["stale"])
        self.assertEqual(exported.json()["signature"], before["signature"])
        markdown = self.client.get("/api/passport/sample/export?format=markdown", headers=self.headers)
        self.assertEqual(markdown.status_code, 200)
        self.assertIn("text/markdown", markdown.headers["content-type"])
        self.assertIn("STALE/INVALIDATED", markdown.text)
        self.assertIn("Assurance Passport", markdown.text)
        self.assertEqual(self.client.get("/api/passport/sample/export?format=xml", headers=self.headers).status_code, 422)
        self.app.state.manifests_registry["sample"]["dataset"] = (DatasetManifest.build_from_coco(path), path)
        after = self.client.get("/api/passport/sample", headers=self.headers).json()
        self.assertTrue(after["staleness"]["stale"])
        self.assertEqual(after["signature"], before["signature"])

    def test_registries_are_isolated_per_application(self):
        other = create_app(Settings("sqlite:///:memory:", "other-test-secret-" * 4))
        self.assertFalse(hasattr(other.state, "findings_registry"))
        self.assertFalse(hasattr(other.state, "passport_registry"))


if __name__ == "__main__":
    unittest.main()
