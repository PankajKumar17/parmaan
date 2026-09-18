import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.provenance import keys
from app.provenance.canonical import canonical_serialization
from app.provenance.chain import InferenceRecord, ProvenanceChain, Verifier


class CanonicalTests(unittest.TestCase):
    def test_exact_bytes_and_order(self):
        payload = {"z": None, "a": [True, False, 1.25, {"b": "café\n", "a": -0.0}]}
        expected = '{"a":[true,false,1.250000,{"a":0.000000,"b":"café\\n"}],"z":null}'.encode()
        self.assertEqual(canonical_serialization(payload), expected)
        self.assertEqual(json.loads(expected), payload)
        self.assertEqual(canonical_serialization(dict(reversed(list(payload.items())))), expected)
        self.assertNotEqual(canonical_serialization([1, 2]), canonical_serialization([2, 1]))

    def test_invalid_values(self):
        for value in [float("nan"), float("inf"), float("-inf")]:
            with self.assertRaises(ValueError):
                canonical_serialization(value)
        for value in [{1: "a"}, {"a", "b"}, object()]:
            with self.assertRaises(TypeError):
                canonical_serialization(value)


class KeyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for name, value in {
            "KEYS_DIR": root,
            "PRIVATE_KEY_FILE": root / "private.pem",
            "PUBLIC_KEY_FILE": root / "public.pem",
        }.items():
            patcher = patch.object(keys, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_roundtrip_and_no_overwrite(self):
        private, public = keys.generate_keypair()
        signature = keys.sign_data(b"payload", private)
        self.assertTrue(keys.verify_signature(b"payload", signature, public))
        self.assertFalse(keys.verify_signature(b"changed", signature, public))
        self.assertFalse(keys.verify_signature(b"payload", signature, None))
        loaded, loaded_public = keys.get_or_generate_keypair()
        self.assertTrue(keys.verify_signature(b"payload", loaded.sign(b"payload"), loaded_public))
        with self.assertRaises(FileExistsError):
            keys.generate_keypair()

    def test_incomplete_pair_is_not_replaced(self):
        keys.generate_keypair()
        original = keys.PRIVATE_KEY_FILE.read_bytes()
        keys.PUBLIC_KEY_FILE.unlink()
        with self.assertRaises(ValueError):
            keys.get_or_generate_keypair()
        self.assertEqual(keys.PRIVATE_KEY_FILE.read_bytes(), original)

    def test_mismatch_and_corruption(self):
        keys.generate_keypair()
        other = Ed25519PrivateKey.generate().public_key()
        keys.PUBLIC_KEY_FILE.write_bytes(other.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        with self.assertRaises(ValueError):
            keys.get_or_generate_keypair()
        keys.PUBLIC_KEY_FILE.write_bytes(b"invalid")
        with self.assertRaises(ValueError):
            keys.load_public_key()

    def test_chain_append_and_tamper(self):
        chain = ProvenanceChain()
        chain.append("input", "model", "config", "output")
        chain.append("second", "model", "config", "result", "root", "consumer")
        self.assertTrue(chain.verify()["passed"])
        self.assertFalse(chain.verify()["fully_assured"])
        original, signature = chain.records[-1]
        for field in ["output_hash", "merkle_root", "consumer_id"]:
            with self.subTest(field=field):
                chain.records[-1] = (replace(original, **{field: "changed"}), signature)
                report = chain.verify()
                self.assertFalse(report["passed"])
                self.assertEqual(report["authenticity"][0]["index"], 1)
        chain.records[-1] = (replace(original, previous_record_hash="broken"), signature)
        self.assertEqual(chain.verify()["integrity"][0]["index"], 1)


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.private = Ed25519PrivateKey.generate()
        self.verifier = Verifier(self.private.public_key())
        self.record = InferenceRecord("input", "model", "config", "output", 0, "nonce", 1.0)

    def signed(self, record):
        return [(record, self.private.sign(bytes.fromhex(record.compute_hash())))]

    def test_replay_and_sequence_are_persistent(self):
        self.assertTrue(self.verifier.verify_chain(self.signed(self.record))["passed"])
        self.assertFalse(self.verifier.verify_chain(self.signed(self.record))["passed"])
        same_nonce = replace(self.record, sequence_number=1)
        self.assertTrue(self.verifier.check_freshness(self.signed(same_nonce)))
        same_sequence = replace(self.record, nonce="new")
        self.assertTrue(self.verifier.check_freshness(self.signed(same_sequence)))
        next_record = replace(self.record, sequence_number=1, nonce="new")
        self.assertFalse(self.verifier.check_freshness(self.signed(next_record)))

    def test_bad_signature_does_not_consume_replay_state(self):
        report = self.verifier.verify_chain([(self.record, b"invalid")])
        self.assertFalse(report["passed"])
        self.assertFalse(report["freshness_checked"])
        self.assertTrue(self.verifier.verify_chain(self.signed(self.record))["passed"])

    def test_bad_chain_does_not_consume_replay_state(self):
        broken = replace(self.record, previous_record_hash="broken")
        self.assertFalse(self.verifier.verify_chain(self.signed(broken))["passed"])
        self.assertTrue(self.verifier.verify_chain(self.signed(self.record))["passed"])


if __name__ == "__main__":
    unittest.main()
