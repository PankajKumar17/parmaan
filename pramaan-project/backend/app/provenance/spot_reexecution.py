import copy
import hashlib
import math
import random
from collections.abc import Mapping

import numpy as np

from app.provenance.canonical import canonical_serialization
from app.provenance.chain import InferenceRecord
from app.provenance.merkle import build_merkle_tree


def payload_bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, (np.ndarray, np.generic)):
        value = value.tolist()
    return canonical_serialization(value)


def activation_leaves(activations):
    if isinstance(activations, Mapping):
        if any(not isinstance(name, str) for name in activations):
            raise ValueError("activation layer names must be strings")
        layers = sorted(activations.items())
    else:
        layers = [("activations", activations)]
    leaves = []
    for name, values in layers:
        values = np.asarray(values, dtype=np.float64)
        if not values.size or not np.isfinite(values).all():
            raise ValueError("activations must be nonempty and finite")
        for index, value in enumerate(values.flat):
            leaves.append(canonical_serialization({"layer": name, "shape": list(values.shape),
                                                   "index": index, "value": float(value)}))
    if not leaves:
        raise ValueError("at least one activation is required")
    return leaves


class SpotReexecutor:
    def __init__(self, record_store, predict_fn, activation_fn, sample_rate=0.1, seed=0):
        if not math.isfinite(sample_rate) or not 0 <= sample_rate <= 1:
            raise ValueError("sample_rate must be in [0, 1]")
        if not isinstance(record_store, Mapping):
            raise TypeError("record_store must map record_id to {record: InferenceRecord, input: stored_input}")
        if any(not isinstance(record_id, str) for record_id in record_store):
            raise TypeError("record ids must be strings")
        self.record_store = record_store
        self.predict_fn = predict_fn
        self.activation_fn = activation_fn
        self.sample_rate = sample_rate
        self.seed = seed

    def run(self, records=None):
        if records is None:
            selected = [(record_id, self.record_store[record_id]["record"])
                        for record_id in sorted(self.record_store)]
        else:
            by_nonce = {}
            for record_id, entry in self.record_store.items():
                nonce = entry["record"].nonce
                if nonce in by_nonce:
                    raise ValueError("record_store nonces must be unique when selecting records")
                by_nonce[nonce] = record_id
            selected = []
            for item in records:
                record = item[0] if isinstance(item, tuple) else item
                if isinstance(record, str):
                    selected.append((record, self.record_store[record]["record"]))
                elif isinstance(record, InferenceRecord):
                    selected.append((by_nonce.get(record.nonce, record.nonce), record))
                else:
                    raise TypeError("records must contain record ids, InferenceRecords, or signed record tuples")
        rng = random.Random(self.seed)
        reports = []
        for record_id, record in selected:
            if rng.random() >= self.sample_rate:
                continue
            report = {"record_id": record_id, "output_match": False, "merkle_match": False, "mismatches": []}
            try:
                entry = self.record_store[record_id]
                sample = copy.deepcopy(entry["input"])
                if hashlib.sha256(payload_bytes(sample)).hexdigest() != record.input_hash:
                    report["mismatches"].append("input_hash")
                output = self.predict_fn(copy.deepcopy(sample))
                report["output_match"] = hashlib.sha256(payload_bytes(output)).hexdigest() == record.output_hash
                if not report["output_match"]:
                    report["mismatches"].append("output_hash")
            except Exception as error:
                report["mismatches"].append(f"input/output re-execution error: {type(error).__name__}")
            try:
                sample = copy.deepcopy(self.record_store[record_id]["input"])
                activations = self.activation_fn(sample)
                root = build_merkle_tree(activation_leaves(activations))["root"]
                report["merkle_match"] = root == record.merkle_root
                if not report["merkle_match"]:
                    report["mismatches"].append("merkle_root" if record.merkle_root else "missing_merkle_root")
            except Exception as error:
                report["mismatches"].append(f"activation re-execution error: {type(error).__name__}")
            reports.append(report)
        return reports
