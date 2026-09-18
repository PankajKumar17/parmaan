import math
from dataclasses import asdict, dataclass
from typing import Any

from app.manifests._common import digest, snapshot


@dataclass
class PipelineEnvironmentManifest:
    preprocessing_parameters: dict[str, Any]
    confidence_thresholds: dict[str, float]
    nms_settings: dict[str, Any]
    input_resolution: list[int] | tuple[int, int]
    model_identifier: str
    framework_version: str
    runtime_version: str
    pipeline_version: str
    schema_version: str = "1"

    def __post_init__(self):
        for name in ("model_identifier", "framework_version", "runtime_version", "pipeline_version"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a nonempty string")
        for name in ("preprocessing_parameters", "confidence_thresholds", "nms_settings"):
            value = getattr(self, name)
            if not isinstance(value, dict):
                raise ValueError(f"{name} must be an object")
            setattr(self, name, snapshot(value))
        for value in self.confidence_thresholds.values():
            if (
                isinstance(value, bool) or not isinstance(value, (int, float))
                or not math.isfinite(value) or not 0 <= value <= 1
            ):
                raise ValueError("Confidence thresholds must be finite numbers in [0,1]")
        if (
            not isinstance(self.input_resolution, (list, tuple)) or len(self.input_resolution) != 2
            or any(isinstance(size, bool) or not isinstance(size, int) or size <= 0
                   for size in self.input_resolution)
        ):
            raise ValueError("input_resolution must be [width, height] in positive integer pixels")
        self.input_resolution = list(self.input_resolution)

    def to_dict(self) -> dict:
        return asdict(self)

    def compute_hash(self) -> str:
        return digest(self.to_dict())

    @property
    def digest(self) -> str:
        return self.compute_hash()

    @property
    def config_hash(self) -> str:
        return self.compute_hash()

    def verify(self, current: "PipelineEnvironmentManifest | dict") -> bool:
        try:
            if isinstance(current, dict):
                current = type(self)(**current)
            return isinstance(current, type(self)) and self.compute_hash() == current.compute_hash()
        except (TypeError, ValueError):
            return False
