import hashlib
from pathlib import Path

import numpy as np

from app.core.evidence import EvidenceProvider, Finding, Modality
from app.manifests._common import digest, file_sha256, read_json
from app.manifests.model_manifest import ModelReferenceManifest


def _reference(asset):
    reference = asset.get("reference", asset.get("reference_manifest_path"))
    if isinstance(reference, (str, Path)):
        reference = ModelReferenceManifest(**read_json(Path(reference)))
    if reference is not None and not isinstance(reference, ModelReferenceManifest):
        raise TypeError("reference must be a ModelReferenceManifest or manifest path")
    return reference


def _degraded(provider, asset, reason, access):
    return [Finding(
        asset_id=str(asset.get("supplied_model_path", provider.detector_id)),
        finding_type=f"{provider.detector_id}_unverified", severity=0.1, confidence=0.0,
        evidence=[f"DEGRADED: {reason}. This check was not completed."],
        modality=Modality.BEHAVIORAL,
        provenance=provider._create_provenance(
            [digest({"model_path": str(asset.get("supplied_model_path", "unavailable"))})],
            asset.get("config_hash", ""),
        ),
        recommended_action="review", quarantine_scope="model", access_assumptions=access,
        counter_evidence=["An unavailable check is an assurance gap, not evidence of tampering."],
    )]


def _output_statistics(outputs, names):
    if isinstance(outputs, dict) and {"mean", "std"} <= outputs.keys():
        mean = np.asarray(outputs["mean"], dtype=np.float64)
        std = np.asarray(outputs["std"], dtype=np.float64)
    else:
        if isinstance(outputs, dict):
            outputs = [outputs[name] for name in names]
        values = np.asarray(outputs, dtype=np.float64)
        if values.ndim != 2 or values.shape[0] != len(names) or not values.shape[1]:
            raise ValueError("Reference logits must have one row per calibration image")
        if not np.isfinite(values).all():
            raise ValueError("Reference logits must be finite")
        mean, std = values.mean(axis=0), values.std(axis=0)
    if mean.ndim != 1 or not mean.size or mean.shape != std.shape:
        raise ValueError("Baseline mean/std must be matching class vectors")
    if not np.isfinite(mean).all() or not np.isfinite(std).all() or (std < 0).any():
        raise ValueError("Baseline statistics must be finite with nonnegative std")
    return mean, std


class ReferenceBatteryProvider(EvidenceProvider):
    def __init__(self, deviation_threshold=0.25):
        super().__init__("reference_battery")
        if not np.isfinite(deviation_threshold) or deviation_threshold <= 0:
            raise ValueError("deviation_threshold must be finite and positive")
        self.deviation_threshold = deviation_threshold

    def analyze(self, asset):
        try:
            return self._analyze(asset)
        except Exception as error:
            return _degraded(self, asset, f"Reference battery unavailable ({type(error).__name__}: {error})", "black_box")

    def _analyze(self, asset):
        reference = _reference(asset)
        images = list(asset["calibration_images"])
        names = [str(name) for name, _ in images]
        if not names or len(set(names)) != len(names):
            raise ValueError("Calibration image names must be nonempty and unique")
        baseline = asset.get("reference_outputs")
        if baseline is None and reference is not None:
            baseline = reference.output_fingerprints.get("reference_outputs", reference.output_fingerprints)
        if baseline is None:
            raise ValueError("Reference output baseline is required")
        mean, std = _output_statistics(baseline, names)
        predict_fn = asset.get("predict_fn")
        session = asset.get("session")
        if predict_fn is None and session is None:
            import onnxruntime

            session = onnxruntime.InferenceSession(
                str(asset["supplied_model_path"]), providers=["CPUExecutionProvider"]
            )
        hashes, outputs = [], []
        for _, image in images:
            hashes.append(hashlib.sha256(image.tobytes()).hexdigest())
            if callable(asset.get("preprocess_fn")):
                batch = np.asarray(asset["preprocess_fn"](image))
            else:
                pixels = np.asarray(image.convert("RGB"), dtype=np.float32) / 255.0
                layout = asset.get("input_layout", "NCHW")
                if layout not in {"NCHW", "NHWC"}:
                    raise ValueError("input_layout must be NCHW or NHWC")
                batch = (pixels.transpose(2, 0, 1) if layout == "NCHW" else pixels)[None, ...]
            if predict_fn is not None:
                output = predict_fn(batch)
            else:
                inputs = session.get_inputs()
                if len(inputs) != 1:
                    raise ValueError("Reference battery expects a single input; use predict_fn for other models")
                output = session.run(None, {inputs[0].name: batch})[0]
            logits = np.asarray(output, dtype=np.float64)
            if logits.ndim == 2 and logits.shape[0] == 1:
                logits = logits[0]
            if logits.shape != mean.shape or not np.isfinite(logits).all():
                raise ValueError("Model must return one finite class-logit vector per image matching the baseline")
            outputs.append(logits)
        current = np.stack(outputs)
        observed_mean, observed_std = current.mean(axis=0), current.std(axis=0)
        scale = np.maximum(std, 1.0)
        deviation = float(max(np.max(np.abs(observed_mean - mean) / scale),
                              np.max(np.abs(observed_std - std) / scale)))
        hashes.extend([digest({"mean": mean.tolist(), "std": std.tolist()}), digest(current.tolist())])
        if reference is not None:
            hashes.append(reference.compute_hash())
        if asset.get("supplied_model_path") is not None:
            hashes.append(file_sha256(asset["supplied_model_path"]))
        shifted = deviation > self.deviation_threshold
        return [Finding(
            asset_id=reference.model_hash if reference is not None else str(asset.get("supplied_model_path", "reference-battery")),
            finding_type="model_behavioral_mismatch" if shifted else "model_behavioral_match",
            severity=0.7 if shifted else 0.0, confidence=0.8,
            evidence=[
                f"DIRECT comparison evidence on fixed calibration set {names}: max standardized mean/std deviation={deviation:.6g}; threshold={self.deviation_threshold}.",
                f"Per-class reference mean={mean.tolist()}, std={std.tolist()}; supplied mean={observed_mean.tolist()}, std={observed_std.tolist()}.",
            ],
            modality=Modality.BEHAVIORAL,
            provenance=self._create_provenance(hashes, asset["config_hash"]),
            recommended_action="review" if shifted else "accept", quarantine_scope="model" if shifted else None,
            access_assumptions="black_box",
            counter_evidence=["Preprocessing, runtime precision, or legitimate model updates can change logits. "
                              "Matching aggregate distributions do not establish identity or rule out untested behavior; confidence is uncalibrated."],
        )]


class WeightStatsProvider(EvidenceProvider):
    def __init__(self, deviation_threshold=0.5):
        super().__init__("weight_stats")
        if not np.isfinite(deviation_threshold) or deviation_threshold <= 0:
            raise ValueError("deviation_threshold must be finite and positive")
        self.deviation_threshold = deviation_threshold

    def analyze(self, asset):
        try:
            return self._analyze(asset)
        except Exception as error:
            return _degraded(self, asset, f"Weight statistics unavailable ({type(error).__name__}: {error})", "white_box")

    def _analyze(self, asset):
        reference = _reference(asset)
        if reference is None or reference.model_format != "onnx":
            raise ValueError("An ONNX reference manifest is required; no Torch execution is performed")
        baseline = reference.output_fingerprints.get("weight_statistics")
        if baseline is None:
            baseline = {name: stats for name, stats in reference.activation_statistics.items() if "norm" in stats}
        if not baseline:
            raise ValueError("Manifest requires explicit per-tensor weight_statistics with scalar mean/std/norm; activation-only statistics cannot substitute")
        import onnx
        from onnx import numpy_helper

        path = asset["supplied_model_path"]
        model = onnx.load(str(path), load_external_data=False)
        tensors = {}
        for tensor in model.graph.initializer:
            if tensor.data_location == onnx.TensorProto.EXTERNAL:
                raise ValueError("External ONNX tensor data is not supported by this check")
            tensors[tensor.name] = np.asarray(numpy_helper.to_array(tensor), dtype=np.float64)
        provenance = self._create_provenance([reference.compute_hash(), file_sha256(path)], asset["config_hash"])
        findings = []
        for name, statistics in baseline.items():
            if name not in tensors:
                raise ValueError(f"Baseline tensor {name} is missing from supplied ONNX weights")
            values = tensors[name]
            if not values.size or not np.isfinite(values).all():
                raise ValueError(f"Tensor {name} must be nonempty and finite")
            observed = {"mean": float(values.mean()), "std": float(values.std()), "norm": float(np.linalg.norm(values.ravel()))}
            expected = {}
            for key in observed:
                value = np.asarray(statistics[key], dtype=np.float64)
                if value.ndim != 0 or not np.isfinite(value) or (key != "mean" and value < 0):
                    raise ValueError("Weight baseline statistics must be finite scalars with nonnegative std/norm")
                expected[key] = float(value)
            if not all(np.isfinite(value) for value in observed.values()):
                raise ValueError("Weight statistics overflowed")
            deviation = max(abs(observed[key] - expected[key]) / max(abs(expected[key]), 1e-6) for key in observed)
            if deviation <= self.deviation_threshold:
                continue
            findings.append(Finding(
                asset_id=reference.model_hash, finding_type="weight_statistics_outlier", severity=0.6, confidence=0.5,
                evidence=[f"CANDIDATE evidence: tensor {name} statistics={observed}; baseline={expected}; max relative deviation={deviation:.6g}.",
                          "Outlier statistics alone don't confirm tampering; this torch-free weight proxy does not measure activations."],
                modality=Modality.BEHAVIORAL, provenance=provenance,
                recommended_action="review", quarantine_scope="model", access_assumptions="white_box",
                counter_evidence=["Legitimate retraining, quantization, and tensor reparameterization can change weight statistics. Confidence is uncalibrated."],
            ))
        return findings
