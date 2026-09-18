"""
Provenance chain mechanism for PRAMAAN

Implements the FULL binding explicitly:
  input image hash -> model/weight digest -> preprocessing/config hash ->
  output hash -> Ed25519 signature -> sequence/nonce/timestamp replay state

Each InferenceRecord is canonically serialized, SHA-256 hashed, and signed
with Ed25519. Records are hash-chained (each record stores the hash of the
previous record) so the whole log is tamper-evident even without signatures.

The Verifier maintains STATE (seen sequence_number/nonce pairs) — replay
protection exists only because the verifier tracks what it has seen.

The FOUR SEPARATE, NAMED provenance properties:
  1. integrity           — record content not altered (hash re-computation)
  2. authenticity        — record signed by the expected key (Ed25519)
  3. freshness           — replay protection via verifier-seen state
  4. computation-correctness — partial (Merkle + spot re-execution; zkML out of scope)
"""

import hashlib
import time
import uuid
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Set, Tuple

from .canonical import canonical_serialization
from . import keys


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def record_hash(record: "InferenceRecord") -> str:
    """Canonically serialize a record and return its SHA-256 hash."""
    payload = {
        "input_hash": record.input_hash,
        "model_digest": record.model_digest,
        "config_hash": record.config_hash,
        "output_hash": record.output_hash,
        "sequence_number": record.sequence_number,
        "nonce": record.nonce,
        "timestamp": record.timestamp,
        "previous_record_hash": record.previous_record_hash,
        "merkle_root": record.merkle_root,
        "consumer_id": record.consumer_id,
    }
    return sha256_bytes(canonical_serialization(payload))


@dataclass
class InferenceRecord:
    """
    A single inference provenance record. Full binding:
    input -> model -> config -> output, chained + signed.
    """
    input_hash: str
    model_digest: str
    config_hash: str
    output_hash: str
    sequence_number: int
    nonce: str
    timestamp: float
    previous_record_hash: str = ""
    merkle_root: Optional[str] = None
    consumer_id: Optional[str] = None

    def compute_hash(self) -> str:
        return record_hash(self)


class ProvenanceSigner:
    """Signs InferenceRecords with Ed25519."""

    def __init__(self):
        self.private_key, self.public_key = keys.get_or_generate_keypair()

    def sign_record(self, record: InferenceRecord) -> bytes:
        return keys.sign_data(bytes.fromhex(record.compute_hash()), self.private_key)

    @staticmethod
    def verify_record_signature(record: InferenceRecord, signature: bytes,
                                public_key) -> bool:
        return keys.verify_signature(bytes.fromhex(record.compute_hash()),
                                     signature, public_key)


class Verifier:
    """
    Verifier with explicit STATE for replay protection.

    Re-walks a chain of records and reports exactly which record failed
    and which property failed (integrity / signature / replay state).
    """

    def __init__(self, public_key=None):
        self.public_key = public_key if public_key is not None else keys.load_public_key()
        # Replay state: set of seen (sequence_number, nonce) pairs
        self._seen: Set[Tuple[int, str]] = set()
        self._seen_nonces: Set[str] = set()
        self._last_sequence = -1

    # ---- Property 1: INTEGRITY ----
    def check_integrity(self, records: List[Tuple[InferenceRecord, Optional[bytes]]]) -> List[Dict[str, Any]]:
        """Re-compute each record's hash and compare chain links. Returns list of failures."""
        failures = []
        prev_hash = ""
        for i, (record, _sig) in enumerate(records):
            if record.previous_record_hash != prev_hash:
                failures.append({
                    "index": i,
                    "property": "integrity",
                    "reason": f"chain break: expected previous_record_hash {prev_hash!r}, got {record.previous_record_hash!r}",
                })
            recomputed = record.compute_hash()
            # The stored hash is implied by the record content itself; a tampered
            # record's content no longer matches what the signature covers (checked
            # in authenticity). Chain-link mismatch is caught above.
            prev_hash = recomputed
        return failures

    # ---- Property 2: AUTHENTICITY ----
    def check_authenticity(self, records: List[Tuple[InferenceRecord, Optional[bytes]]]) -> List[Dict[str, Any]]:
        """Verify each record's Ed25519 signature. Returns list of failures."""
        failures = []
        for i, (record, sig) in enumerate(records):
            if sig is None:
                failures.append({
                    "index": i,
                    "property": "authenticity",
                    "reason": "missing signature",
                })
                continue
            if not ProvenanceSigner.verify_record_signature(record, sig, self.public_key):
                failures.append({
                    "index": i,
                    "property": "authenticity",
                    "reason": "Ed25519 signature invalid (record content does not match signed hash)",
                })
        return failures

    # ---- Property 3: FRESHNESS (replay protection) ----
    def check_freshness(self, records: List[Tuple[InferenceRecord, Optional[bytes]]]) -> List[Dict[str, Any]]:
        """
        Check for replays against verifier STATE. A (sequence_number, nonce)
        pair already seen is rejected. Also enforces monotonic sequence numbers.
        """
        failures = []
        seen = self._seen.copy()
        nonces = self._seen_nonces.copy()
        last_seq = self._last_sequence
        for i, (record, _sig) in enumerate(records):
            key = (record.sequence_number, record.nonce)
            if record.nonce in nonces:
                failures.append({
                    "index": i, "property": "freshness", "reason": "Nonce replay detected",
                })
            elif record.sequence_number <= last_seq:
                failures.append({
                    "index": i, "property": "freshness", "reason": "Sequence number regression or replay",
                })
            elif not record.nonce:
                failures.append({
                    "index": i, "property": "freshness", "reason": "Missing nonce",
                })
            seen.add(key)
            nonces.add(record.nonce)
            last_seq = max(last_seq, record.sequence_number)
        if not failures:
            self._seen = seen
            self._seen_nonces = nonces
            self._last_sequence = last_seq
        return failures

    # ---- Property 4: COMPUTATION-CORRECTNESS ----
    def verify_computation_consistency(self, records=None, spot_reexecutor=None) -> Dict[str, Any]:
        if spot_reexecutor is None:
            return {
                "property": "computation-correctness",
                "status": "not yet implemented",
                "note": ("planned via Merkle tree over activations + spot re-execution "
                         "in a later phase, full guarantee would require zkML which is "
                         "out of scope"),
            }
        reports = spot_reexecutor.run(records)
        matches = bool(reports) and all(
            report["output_match"] and report["merkle_match"] and not report["mismatches"]
            for report in reports
        )
        return {
            "property": "computation-correctness",
            "status": "partial assurance" if matches else ("mismatch" if reports else "not checked"),
            "note": ("Honest, partial assurance: only together with successful chain integrity and signature "
                     "verification and matching sampled executions, this proves the log wasn't altered post-hoc "
                     "and spot-checks match, not a full cryptographic guarantee of computation (zkML out of scope). "
                     "This method does not verify the chain or signatures; unselected records remain unchecked. "
                     "Callers must bind callbacks to the recorded model and configuration. Numeric payloads use "
                     "canonical six-decimal serialization; matching hashes do not assert finer precision."),
            "reports": reports,
            "checked_count": len(reports),
            "fully_assured": False,
        }

    # ---- Full walk ----
    def verify_chain(self, records: List[Tuple[InferenceRecord, Optional[bytes]]]) -> Dict[str, Any]:
        """
        Re-walk the full chain and report exactly which record failed
        and which property failed.
        """
        integrity = self.check_integrity(records)
        authenticity = self.check_authenticity(records)
        freshness = self.check_freshness(records) if not (integrity or authenticity) else []
        return {
            "integrity": integrity,
            "authenticity": authenticity,
            "freshness": freshness,
            "freshness_checked": not (integrity or authenticity),
            "computation_correctness": self.verify_computation_consistency(),
            "passed": not (integrity or authenticity or freshness),
            "fully_assured": False,
        }


class ProvenanceChain:
    """
    Maintains an ordered, signed, hash-chained log of InferenceRecords.
    """

    def __init__(self):
        self.signer = ProvenanceSigner()
        self.records: List[Tuple[InferenceRecord, bytes]] = []
        self._last_hash: str = ""
        self._last_seq: int = -1

    def append(self, input_hash: str, model_digest: str, config_hash: str,
               output_hash: str, merkle_root: Optional[str] = None,
               consumer_id: Optional[str] = None) -> InferenceRecord:
        """Create, sign, and append a new record to the chain."""
        record = InferenceRecord(
            input_hash=input_hash,
            model_digest=model_digest,
            config_hash=config_hash,
            output_hash=output_hash,
            sequence_number=self._last_seq + 1,
            nonce=uuid.uuid4().hex,
            timestamp=time.time(),
            previous_record_hash=self._last_hash,
            merkle_root=merkle_root,
            consumer_id=consumer_id,
        )
        signature = self.signer.sign_record(record)
        self.records.append((record, signature))
        self._last_hash = record.compute_hash()
        self._last_seq = record.sequence_number
        return record

    def verify(self, verifier: Optional[Verifier] = None) -> Dict[str, Any]:
        v = verifier if verifier is not None else Verifier(self.signer.public_key)
        return v.verify_chain(self.records)