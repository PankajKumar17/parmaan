import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

from fastapi import Request
from sqlalchemy import inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.pool import StaticPool

from app.db.models import Asset, Base, FindingRow, InferenceRecordRow, User
from app.db.session import create_database, get_session


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.engine, self.factory = create_database("sqlite:///:memory:")
        self.addCleanup(self.engine.dispose)
        self.assertIsInstance(self.engine.pool, StaticPool)
        self.assertEqual(inspect(self.engine).get_table_names(), [])
        Base.metadata.create_all(self.engine)
        with self.factory.begin() as session:
            session.add(Asset(id="asset", asset_type="DATASET", manifest_hash="manifest"))

    def finding(self, **overrides):
        values = {
            "asset_id": "asset",
            "finding_type": "integrity",
            "severity": 0.5,
            "confidence": 0.75,
            "evidence": ["evidence"],
            "modality": "PIXEL",
            "provenance": {"detector_id": "test", "input_hashes": ["hash"]},
            "recommended_action": "review",
        }
        values.update(overrides)
        return FindingRow(**values)

    def record(self, **overrides):
        values = {
            "input_hash": "input",
            "model_digest": "model",
            "config_hash": "config",
            "output_hash": "output",
            "sequence_number": 1,
            "nonce": "nonce",
            "previous_record_hash": "previous",
            "record_hash": "record",
            "signature": "signature",
        }
        values.update(overrides)
        return InferenceRecordRow(**values)

    def test_unique_email_and_user_defaults(self):
        with self.factory.begin() as session:
            user = User(email="user@example.com", hashed_password="hashed")
            session.add(user)
            session.flush()
            self.assertEqual(str(UUID(user.id)), user.id)
            self.assertTrue(user.is_active)
        with self.assertRaises(IntegrityError):
            with self.factory.begin() as session:
                session.add(User(email="user@example.com", hashed_password="other"))

    def test_unique_nonce_and_sequence_number(self):
        with self.factory.begin() as session:
            session.add(self.record())
        for overrides in ({"sequence_number": 2}, {"nonce": "other"}):
            with self.subTest(overrides=overrides):
                with self.assertRaises(IntegrityError):
                    with self.factory.begin() as session:
                        session.add(self.record(**overrides))
        with self.factory.begin() as session:
            session.add(self.record(sequence_number=2, nonce="other"))

    def test_primary_keys_are_unique(self):
        factories = (
            lambda: User(id="duplicate", email="duplicate@example.com", hashed_password="hash"),
            lambda: Asset(id="duplicate", asset_type="MODEL", manifest_hash="hash"),
            lambda: self.record(id="duplicate"),
            lambda: self.finding(id="duplicate"),
        )
        for factory in factories:
            with self.subTest(model=type(factory()).__name__):
                with self.factory.begin() as session:
                    session.add(factory())
                duplicate = factory()
                if isinstance(duplicate, User):
                    duplicate.email = "different@example.com"
                elif isinstance(duplicate, InferenceRecordRow):
                    duplicate.nonce = "different"
                    duplicate.sequence_number = 2
                with self.assertRaises(IntegrityError):
                    with self.factory.begin() as session:
                        session.add(duplicate)

    def test_foreign_key_rejects_missing_asset_and_referenced_deletion(self):
        with self.assertRaises(IntegrityError):
            with self.factory.begin() as session:
                session.add(self.finding(asset_id="missing"))
        with self.factory.begin() as session:
            session.add(self.finding())
        with self.assertRaises(IntegrityError):
            with self.factory.begin() as session:
                session.delete(session.get(Asset, "asset"))

    def test_asset_type_constraint(self):
        for asset_type in ("DATASET", "MODEL", "CONTRIBUTOR"):
            with self.factory.begin() as session:
                session.add(Asset(id=asset_type, asset_type=asset_type, manifest_hash="hash"))
        with self.assertRaises(IntegrityError):
            with self.factory.begin() as session:
                session.add(Asset(id="invalid", asset_type="invalid", manifest_hash="hash"))

    def test_finding_constraints_and_boundaries(self):
        for field in ("severity", "confidence"):
            for value in (-0.01, 1.01, None):
                with self.subTest(field=field, value=value):
                    with self.assertRaises(IntegrityError):
                        with self.factory.begin() as session:
                            session.add(self.finding(**{field: value}))
            for value in (0.0, 1.0):
                with self.factory.begin() as session:
                    session.add(self.finding(**{field: value}))
        for modality in ("PIXEL", "EMBEDDING", "ANNOTATION", "ACTIVATION", "BEHAVIORAL"):
            with self.factory.begin() as session:
                session.add(self.finding(modality=modality))
        with self.assertRaises(IntegrityError):
            with self.factory.begin() as session:
                session.add(self.finding(modality="invalid"))

    def test_failed_transaction_rolls_back_and_session_can_be_reused(self):
        with self.factory() as session:
            session.add(User(email="rollback@example.com", hashed_password="hash"))
            session.flush()
            session.add(self.finding(asset_id="missing"))
            with self.assertRaises(IntegrityError):
                session.flush()
            session.rollback()
            self.assertIsNone(session.scalar(select(User)))
            session.add(User(email="committed@example.com", hashed_password="hash"))
            session.commit()
        with self.factory() as session:
            self.assertEqual(session.scalar(select(User.email)), "committed@example.com")

    def test_dependency_does_not_commit_and_rolls_back_on_close_or_error(self):
        request = Request({
            "type": "http",
            "app": SimpleNamespace(state=SimpleNamespace(session_factory=self.factory)),
        })
        for fail in (False, True):
            with self.subTest(fail=fail):
                dependency = get_session(request)
                session = next(dependency)
                session.add(User(email="pending@example.com", hashed_password="hash"))
                session.flush()
                if fail:
                    with self.assertRaisesRegex(RuntimeError, "failure"):
                        dependency.throw(RuntimeError("failure"))
                else:
                    with self.assertRaises(StopIteration):
                        next(dependency)
                with self.factory() as check:
                    self.assertIsNone(check.scalar(select(User)))
        dependency = get_session(request)
        session = next(dependency)
        session.add(User(email="explicit@example.com", hashed_password="hash"))
        session.commit()
        dependency.close()
        with self.factory() as check:
            self.assertEqual(check.scalar(select(User.email)), "explicit@example.com")

    def test_file_persistence_across_engines(self):
        with tempfile.TemporaryDirectory() as temporary:
            url = f"sqlite:///{(Path(temporary) / 'database.sqlite3').as_posix()}"
            engine, factory = create_database(url)
            try:
                Base.metadata.create_all(engine)
                with factory.begin() as session:
                    session.add(Asset(id="asset", asset_type="DATASET", manifest_hash="manifest"))
                    session.add(User(email="persist@example.com", hashed_password="hash"))
                    session.flush()
                    session.add(self.finding(
                        quarantine_scope="batch",
                        access_assumptions="white_box",
                        counter_evidence=["counter"],
                    ))
                    session.add(self.record())
            finally:
                engine.dispose()
            engine, factory = create_database(url)
            try:
                with factory() as session:
                    self.assertEqual(session.scalar(select(User.email)), "persist@example.com")
                    self.assertEqual(session.get(Asset, "asset").manifest_hash, "manifest")
                    self.assertIsNotNone(session.get(Asset, "asset").created_at)
                    finding = session.scalar(select(FindingRow))
                    self.assertEqual(finding.evidence, ["evidence"])
                    self.assertEqual(finding.provenance, {"detector_id": "test", "input_hashes": ["hash"]})
                    self.assertEqual(finding.access_assumptions, "white_box")
                    self.assertEqual(finding.quarantine_scope, "batch")
                    self.assertEqual(finding.counter_evidence, ["counter"])
                    record = session.scalar(select(InferenceRecordRow))
                    self.assertEqual(record.record_hash, "record")
                    self.assertEqual(record.signature, "signature")
                    self.assertIsNotNone(record.timestamp)
                    self.assertIsNone(record.merkle_root)
                with self.assertRaises(IntegrityError):
                    with factory.begin() as session:
                        session.add(self.finding(asset_id="missing"))
            finally:
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
