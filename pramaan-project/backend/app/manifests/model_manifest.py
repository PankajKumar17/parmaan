import math
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from app.core.evidence import Finding, Modality
from app.manifests._common import digest, file_sha256, snapshot


def _finite_values(value, nonnegative=False):
    values = value if isinstance(value, list) else [value]
    if not values or any(
        isinstance(item, bool) or not isinstance(item, (int, float))
        or not math.isfinite(item) or (nonnegative and item < 0) for item in values
    ):
        raise ValueError("Statistics and metrics must contain finite numbers; std must be nonnegative")


@dataclass
class ModelReferenceManifest:
    model_hash: str
    architecture: str
    expected_metrics: dict[str, float]
    activation_statistics: dict[str, dict[str, Any]]
    output_fingerprints: dict[str, Any]
    model_format: str
    reference_battery_id: str
    calibration_set_id: str
    schema_version: str = "1"

    def __post_init__(self):
        if not isinstance(self.model_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", self.model_hash):
            raise ValueError("model_hash must be a lowercase SHA-256 hex digest")
        for name in ("architecture", "reference_battery_id", "calibration_set_id"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name).strip():
                raise ValueError(f"{name} must be a nonempty string")
        if self.model_format not in {"onnx", "torchscript"}:
            raise ValueError("Supported model formats: onnx and torchscript; weights are hashed, never executed")
        for name in ("expected_metrics", "activation_statistics", "output_fingerprints"):
            value = getattr(self, name)
            if not isinstance(value, dict):
                raise ValueError(f"{name} must be an object")
            setattr(self, name, snapshot(value))
        for value in self.expected_metrics.values():
            if isinstance(value, list):
                raise ValueError("Expected metrics must be scalar numbers")
            _finite_values(value)
        for layer, statistics in self.activation_statistics.items():
            if not isinstance(statistics, dict) or not {"mean", "std"} <= statistics.keys():
                raise ValueError(f"Layer {layer} requires mean and std")
            _finite_values(statistics["mean"])
            _finite_values(statistics["std"], nonnegative=True)
            mean, std = statistics["mean"], statistics["std"]
            if isinstance(mean, list) != isinstance(std, list) or (
                isinstance(mean, list) and len(mean) != len(std)
            ):
                raise ValueError(f"Layer {layer} mean/std shapes differ")

    @classmethod
    def build_from_file(
        cls, path: str | Path, *, architecture: str,
        expected_metrics: dict[str, float], activation_statistics: dict[str, dict[str, Any]],
        output_fingerprints: dict[str, Any], reference_battery_id: str,
        calibration_set_id: str, model_format: str | None = None,
    ) -> "ModelReferenceManifest":
        path = Path(path)
        if model_format is None:
            model_format = {
                ".onnx": "onnx", ".pt": "torchscript", ".ts": "torchscript",
                ".torchscript": "torchscript",
            }.get(path.suffix.lower())
        if model_format not in {"onnx", "torchscript"}:
            raise ValueError("Use .onnx, .pt, .ts, .torchscript, or explicit model_format='onnx'/'torchscript'")
        return cls(
            model_hash=file_sha256(path), architecture=architecture,
            expected_metrics=expected_metrics, activation_statistics=activation_statistics,
            output_fingerprints=output_fingerprints, model_format=model_format,
            reference_battery_id=reference_battery_id, calibration_set_id=calibration_set_id,
        )

    def to_dict(self) -> dict:
        return asdict(self)

    def compute_hash(self) -> str:
        return digest(self.to_dict())

    @property
    def digest(self) -> str:
        return self.compute_hash()

    def verify(self, current_path: str | Path) -> bool:
        try:
            return file_sha256(current_path) == self.model_hash
        except (OSError, ValueError):
            return False

    def identity_check(self, supplied_model_path: str | Path) -> Finding:
        try:
            supplied_hash = file_sha256(supplied_model_path)
        except (OSError, ValueError):
            supplied_hash = None
        matched = supplied_hash == self.model_hash
        unavailable = supplied_hash is None
        return Finding(
            asset_id=self.model_hash,
            finding_type="model_identity_unverified" if unavailable else (
                "model_identity_match" if matched else "model_identity_mismatch"
            ),
            severity=0.0 if matched or unavailable else 1.0,
            confidence=0.0 if unavailable else 1.0,
            evidence=["Supplied weight file could not be read"] if unavailable else [
                f"Reference weight SHA-256: {self.model_hash}",
                f"Supplied weight SHA-256: {supplied_hash}",
                "Byte identity matches" if matched else "Byte identity differs",
            ],
            modality=Modality.ANNOTATION,
            provenance={
                "detector_id": "model_identity", "version": "1.0.0",
                "input_hashes": [self.model_hash] + ([] if unavailable else [supplied_hash]),
                "config_hash": self.compute_hash(),
            },
            recommended_action="review" if unavailable else ("accept" if matched else "quarantine"),
            quarantine_scope="model" if not matched else None,
            access_assumptions="white_box",
            counter_evidence=[
                "Identity checks only weight-file bytes; no behavioral integrity, model safety, "
                "runtime correctness, or authenticity of the reference baseline is established."
            ],
        )
