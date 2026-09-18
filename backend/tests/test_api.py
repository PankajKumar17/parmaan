import unittest
from unittest.mock import patch

import jwt
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import Settings
from app.core.security import hash_password, verify_password
from app.core.self_integrity import IntegrityReport, SelfIntegrityError
from app.db.models import User
from app.main import create_app


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password = "test-only-password-123"
        cls.encoded = hash_password(cls.password)

    def setUp(self):
        self.settings = Settings("sqlite:///:memory:", "test-only-secret-" * 4)
        self.app = create_app(self.settings)
        patcher = patch("app.main.self_integrity.check_self_integrity", return_value=IntegrityReport())
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client = self.enterContext(TestClient(self.app))
        with self.app.state.session_factory.begin() as session:
            user = User(email="analyst@example.com", hashed_password=self.encoded)
            session.add(user)
            session.flush()
            self.user_id = user.id

    def login(self):
        return self.client.post("/api/auth/login", data={
            "username": "analyst@example.com", "password": self.password,
        })

    def headers(self):
        return {"Authorization": "Bearer " + self.login().json()["access_token"]}

    def test_health_and_protected_endpoints(self):
        self.assertEqual(self.client.get("/api/health").status_code, 200)
        for path in ["/api/assets", "/api/auth/me", "/api/system/integrity"]:
            self.assertEqual(self.client.get(path).status_code, 401)
        result = self.login()
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.headers["cache-control"], "no-store")
        self.assertNotIn("hashed_password", self.client.get("/api/auth/me", headers=self.headers()).text)

    def test_wrong_password_unknown_and_disabled(self):
        for username in ["analyst@example.com", "missing@example.com"]:
            response = self.client.post("/api/auth/login", data={"username": username, "password": "wrong"})
            self.assertEqual(response.status_code, 401)
        headers = self.headers()
        with self.app.state.session_factory.begin() as session:
            session.get(User, self.user_id).is_active = False
        self.assertEqual(self.client.get("/api/assets", headers=headers).status_code, 401)
        self.assertEqual(self.login().status_code, 401)

    def test_expired_wrong_algorithm_and_tampered_token(self):
        token = self.login().json()["access_token"]
        claims = jwt.decode(token, options={"verify_signature": False})
        claims["exp"] = 1
        expired = jwt.encode(claims, self.settings.jwt_secret_key, algorithm="HS256")
        wrong = jwt.encode(claims, self.settings.jwt_secret_key, algorithm="HS384")
        for invalid in [expired, wrong, token + "corrupt", "nonsense"]:
            self.assertEqual(self.client.get("/api/assets", headers={"Authorization": f"Bearer {invalid}"}).status_code, 401)

    def test_asset_validation_conflict_and_persistence(self):
        headers = self.headers()
        payload = {"id": "dataset-1", "asset_type": "DATASET", "manifest_hash": "a" * 64}
        self.assertEqual(self.client.post("/api/assets", json=payload, headers=headers).status_code, 201)
        self.assertEqual(self.client.post("/api/assets", json=payload, headers=headers).status_code, 409)
        self.assertEqual(self.client.get("/api/assets", headers=headers).json()[0]["id"], "dataset-1")
        self.assertEqual(self.client.get("/api/assets/dataset-1", headers=headers).status_code, 200)
        self.assertEqual(self.client.get("/api/assets/missing", headers=headers).status_code, 404)
        self.assertEqual(self.client.get("/api/assets?limit=201", headers=headers).status_code, 422)
        payload["manifest_hash"] = "invalid"
        self.assertEqual(self.client.post("/api/assets", json=payload, headers=headers).status_code, 422)

    def test_login_throttling(self):
        for _ in range(10):
            self.app.state.login_limiter.check("testclient")
        self.assertEqual(self.login().status_code, 429)

    def test_degraded_status_is_visible(self):
        response = self.client.get("/api/system/integrity", headers=self.headers())
        self.assertFalse(response.json()["verified"])
        self.assertEqual(response.json()["status"], "DEGRADED/UNVERIFIED")

    def test_password_hash(self):
        self.assertTrue(verify_password(self.password, self.encoded))
        self.assertFalse(verify_password("wrong", self.encoded))
        self.assertFalse(verify_password(self.password, "invalid"))
        with self.assertRaises(ValueError):
            hash_password("short")


class StartupTests(unittest.TestCase):
    def test_integrity_failure_precedes_database_creation(self):
        app = create_app(Settings("sqlite:///:memory:", "test-only-secret-" * 4))
        with patch("app.main.self_integrity.check_self_integrity", side_effect=SelfIntegrityError(IntegrityReport())):
            with patch("app.db.session.create_database") as create_database:
                with self.assertRaises(SelfIntegrityError):
                    with TestClient(app):
                        pass
                create_database.assert_not_called()

    def test_missing_secret_fails(self):
        with self.assertRaises(ValueError):
            Settings("sqlite:///:memory:", "")


if __name__ == "__main__":
    unittest.main()
