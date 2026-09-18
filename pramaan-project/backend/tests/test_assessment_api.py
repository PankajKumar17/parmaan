import unittest
from unittest.mock import patch

import numpy as np
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.core.config import Settings
from app.core.lineage import IntegrityLineage
from app.core.security import hash_password
from app.core.self_integrity import IntegrityReport
from app.db.models import AssessmentRow, FindingRow, User
from app.main import create_app


class AssessmentApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password = "test-only-password-123"
        cls.encoded = hash_password(cls.password)

    def setUp(self):
        self.app = create_app(Settings("sqlite:///:memory:", "test-only-secret-" * 4))
        self.enterContext(patch("app.main.self_integrity.check_self_integrity", return_value=IntegrityReport()))
        self.client = self.enterContext(TestClient(self.app))
        with self.app.state.session_factory.begin() as session:
            session.add(User(email="analyst@example.com", hashed_password=self.encoded))
        login = self.client.post("/api/auth/login", data={
            "username": "analyst@example.com", "password": self.password,
        })
        self.headers = {"Authorization": "Bearer " + login.json()["access_token"]}
        for asset_id, asset_type in (("dataset-1", "DATASET"), ("model-1", "MODEL")):
            result = self.client.post("/api/assets", headers=self.headers, json={
                "id": asset_id, "asset_type": asset_type, "manifest_hash": "a" * 64,
            })
            self.assertEqual(result.status_code, 201)

    def payload(self):
        pixels = [[[120, 80, 40] for _ in range(8)] for _ in range(8)]
        return {
            "images": [["sample-0", pixels], ["sample-1", pixels]],
            "samples": [[f"sample-{index}", [0.0, 0.0], int(index == 5)] for index in range(6)],
            "num_classes": 2,
            "annotations": [{"image_id": "sample-1", "width": 8, "height": 8,
                             "boxes": [{"x": 0, "y": 0, "w": -1, "h": 2}]}],
            "batch_metadata": {
                "samples": {f"sample-{index}": {"contributor_id": "contributor-1", "batch_id": "batch-1"}
                            for index in range(6)},
                "ordered_batches": ["batch-1"],
            },
        }

    def assess(self, payload=None, asset_id="dataset-1"):
        return self.client.post("/api/assess", headers=self.headers,
                                json={"asset_id": asset_id, "payload": payload or {}})

    def test_auth_and_unknown_asset(self):
        self.assertEqual(self.client.post("/api/assess", json={"asset_id": "dataset-1"}).status_code, 401)
        for path in ("/api/assessments", "/api/lineage/dataset-1", "/api/dashboard/heatmap",
                     "/api/dashboard/radar/model-1", "/api/dashboard/matrix", "/api/dashboard/coverage"):
            self.assertEqual(self.client.get(path).status_code, 401)
        self.assertEqual(self.assess(self.payload(), "missing").status_code, 404)
        self.assertEqual(self.client.get("/api/lineage/missing", headers=self.headers).status_code, 404)
        self.assertEqual(self.client.get("/api/dashboard/radar/dataset-1", headers=self.headers).status_code, 404)

    def test_real_assessment_persistence_and_dashboards(self):
        response = self.assess(self.payload())
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertGreater(result["finding_count"], 0)
        self.assertEqual(result["finding_count"], len(result["findings"]))
        self.assertEqual(len(result["tier_logs"]), 9)
        self.assertEqual(len(result["timings"]), 9)
        self.assertTrue(all(item["reason"] for item in result["skipped"]))
        self.assertTrue(all(item["modality"] in {"PIXEL", "EMBEDDING", "ANNOTATION"} for item in result["findings"]))
        self.assertTrue(any(item["finding_type"] == "composite_duplicate" for item in result["findings"]))
        with self.app.state.session_factory() as session:
            self.assertEqual(session.scalar(select(func.count()).select_from(FindingRow)), result["finding_count"])
            row = session.get(AssessmentRow, result["assessment_id"])
            self.assertEqual(row.asset_id, "dataset-1")
            self.assertLessEqual(row.started_at, row.finished_at)
            self.assertEqual(row.skipped, result["skipped"])
            self.assertTrue(all(row.asset_id == "dataset-1" for row in session.scalars(select(FindingRow))))
        lineage = self.client.get("/api/lineage/dataset-1", headers=self.headers).json()
        self.assertTrue(any(node["id"] == "dataset-1" and not node["orphan"] for node in lineage["nodes"]))
        self.assertTrue(any(edge[0] == "dataset-1" for edge in lineage["edges"]))
        self.assertIn("total", lineage["blast_radius"])
        matrix = self.client.get("/api/dashboard/matrix", headers=self.headers).json()
        self.assertEqual(matrix["assessment_id"], result["assessment_id"])
        self.assertEqual(len(matrix["verdicts"]), result["finding_count"])
        self.assertTrue(all(item["verdict"] in {"ACCEPT", "REVIEW", "QUARANTINE"} for item in matrix["verdicts"]))
        self.assertTrue(all("quarantine_scope" in item for item in matrix["verdicts"]))
        coverage = self.client.get("/api/dashboard/coverage", headers=self.headers).json()
        self.assertAlmostEqual(coverage["coverage_confidence"], 4 / 9)
        self.assertTrue(coverage["execution_verified"])
        self.assertTrue(all({"check", "gap", "recommendation"} <= item.keys() for item in coverage["assurance_debt"]))
        assessments = self.client.get("/api/assessments", headers=self.headers).json()
        self.assertEqual(assessments[0]["assessment_id"], result["assessment_id"])
        heatmap = self.client.get("/api/dashboard/heatmap", headers=self.headers).json()
        self.assertEqual(heatmap["series"][0]["contributor_id"], "contributor-1")
        self.assertEqual(heatmap["series"][0]["batches"][0]["anomaly_count"], 2)
        self.assertEqual(heatmap["series"][0]["batches"][0]["sample_count"], 6)
        self.assertIn("change_points", heatmap)

    def test_latest_assessment_and_registry_merge(self):
        first = self.assess(self.payload()).json()
        self.app.state.passport_registry = {"dataset-1": object()}
        second = self.assess(self.payload()).json()
        self.assertEqual(len(self.app.state.findings_registry["dataset-1"]), first["finding_count"] + second["finding_count"])
        self.assertNotIn("dataset-1", self.app.state.passport_registry)
        self.app.state.findings_registry.clear()
        self.app.state.assurance_registry.clear()
        self.app.state.lineage = IntegrityLineage()
        matrix = self.client.get("/api/dashboard/matrix", headers=self.headers).json()
        self.assertEqual(matrix["assessment_id"], second["assessment_id"])
        self.assertEqual(len(matrix["verdicts"]), second["finding_count"])
        empty = self.assess().json()
        matrix = self.client.get("/api/dashboard/matrix", headers=self.headers).json()
        self.assertEqual(matrix["assessment_id"], empty["assessment_id"])
        self.assertEqual(matrix["verdicts"], [])
        self.assertEqual(len(empty["skipped"]), 9)

    def test_empty_dashboards_and_pagination(self):
        self.assertEqual(self.client.get("/api/assessments", headers=self.headers).json(), [])
        coverage = self.client.get("/api/dashboard/coverage", headers=self.headers).json()
        self.assertFalse(coverage["execution_verified"])
        self.assertTrue(coverage["assurance_debt"])
        self.assertEqual(self.client.get("/api/dashboard/heatmap", headers=self.headers).json()["series"], [])
        radar = self.client.get("/api/dashboard/radar/model-1", headers=self.headers).json()
        self.assertEqual(radar["identity"], [])
        self.assertEqual(radar["behavioral"], [])
        self.assess()
        self.assertEqual(self.client.get("/api/assessments?offset=1&limit=1", headers=self.headers).json(), [])
        for query in ("offset=-1", "limit=0", "limit=201"):
            self.assertEqual(self.client.get("/api/assessments?" + query, headers=self.headers).status_code, 422)

    def test_expensive_providers_registered_runtime_and_gate(self):
        self.app.state.payload_registry = {"model-1": {
            "access_level": "white_box",
            "trigger_reconstruction": {"model": lambda sample: np.array([1.0, 0.0]),
                                       "samples": [[0.0] * 64]},
            "fine_pruning": {"model": object(), "predict_fn": lambda model, vector: np.array([vector[0], 0.5]),
                             "activations": [[0.0, 1.0], [0.0, 1.0]],
                             "reference_battery": [[1.0, 1.0]], "suspicious_indices": [0]},
            "strip": {"images": [["sample-1", [[[0.0]]]]], "backgrounds": [[[[1.0]]]],
                      "predict_fn": lambda batch: np.tile([1.0, 0.0], (len(batch), 1))},
        }}
        clean = self.assess(asset_id="model-1").json()
        for log in clean["tier_logs"]:
            if log["tier"] == "expensive":
                self.assertFalse(log["ran"])
                self.assertIn("No cheap finding", log["reason"])
        response = self.assess({"annotations": self.payload()["annotations"]}, asset_id="model-1")
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertTrue(all(log["ran"] for log in result["tier_logs"] if log["tier"] == "expensive"))
        detectors = {finding["provenance"]["detector_id"] for finding in result["findings"]}
        self.assertIn("fine_pruning", detectors)
        self.assertIn("strip", detectors)
        radar = self.client.get("/api/dashboard/radar/model-1", headers=self.headers).json()
        self.assertTrue(any(vector["detector"] == "fine_pruning" for vector in radar["behavioral"]))

    def test_invalid_inputs_and_provider_failure_are_visible(self):
        for payload in ({"supplied_model_path": "secret"}, {"identity": {"reference_manifest_path": "secret"}},
                        {"batch_metadata": {"samples": {"a": {"contributor_id": "c", "batch_id": "b"}}}}):
            self.assertEqual(self.assess(payload).status_code, 422)
        result = self.assess({"samples": [["sample", [1, 2], 0], ["other", [1], 0]]}).json()
        skips = {item["provider"]: item["reason"] for item in result["skipped"]}
        self.assertIn("Provider failed", skips["mislabeling"])
        self.assertIn("Provider failed", skips["ood"])
        coverage = self.client.get("/api/dashboard/coverage", headers=self.headers).json()
        self.assertEqual(coverage["coverage_confidence"], 0)
        self.assertEqual(coverage["ran"], [])

    def test_registered_payload_without_inline_data(self):
        self.app.state.payload_registry = {"dataset-1": self.payload()}
        response = self.assess()
        self.assertEqual(response.status_code, 200)
        self.assertGreater(response.json()["finding_count"], 0)


if __name__ == "__main__":
    unittest.main()
