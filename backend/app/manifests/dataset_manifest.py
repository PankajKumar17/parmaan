from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from app.ingestion.coco_yolo import load_coco, load_yolo
from app.manifests._common import digest, snapshot


@dataclass
class DatasetManifest:
    dataset_version: str
    format: str
    samples: dict[str, dict[str, Any]]
    annotation_hash: str
    class_distribution: dict[str, int]
    class_names: dict[str, str]
    contributor_id: str | None
    batch_id: str | None
    files: dict[str, str]
    sources: list[str]
    schema_version: str = "1"
    _options: dict = field(default_factory=dict, repr=False, compare=False)
    _baseline_digest: str = field(default="", repr=False, compare=False)

    def __post_init__(self):
        if not isinstance(self.dataset_version, str) or not self.dataset_version:
            raise ValueError("dataset_version must be a nonempty string")
        if self.format not in {"coco", "yolo"}:
            raise ValueError("Dataset format must be coco or yolo")
        for name in ("samples", "class_distribution", "class_names", "files", "sources", "_options"):
            setattr(self, name, snapshot(getattr(self, name)))
        if not self._baseline_digest:
            self._baseline_digest = self.compute_hash()

    @classmethod
    def _build(cls, path, format, dataset_version, contributor_id, batch_id):
        data = (load_coco if format == "coco" else load_yolo)(path)
        annotation_hash = digest(data.pop("annotations"))
        options = {
            "dataset_version": dataset_version,
            "contributor_id": contributor_id,
            "batch_id": batch_id,
        }
        for name, value in options.items():
            if value is not None:
                if not isinstance(value, str) or not value:
                    raise ValueError(f"{name} must be a nonempty string")
                data[name] = value
        for sample in data["samples"].values():
            for name in ("contributor_id", "batch_id"):
                if sample[name] is None:
                    sample[name] = data[name]
        return cls(**data, annotation_hash=annotation_hash, _options=options)

    @classmethod
    def build_from_coco(
        cls, path: str | Path, *, dataset_version: str | None = None,
        contributor_id: str | None = None, batch_id: str | None = None,
    ) -> "DatasetManifest":
        return cls._build(path, "coco", dataset_version, contributor_id, batch_id)

    @classmethod
    def build_from_yolo(
        cls, path: str | Path, *, dataset_version: str | None = None,
        contributor_id: str | None = None, batch_id: str | None = None,
    ) -> "DatasetManifest":
        return cls._build(path, "yolo", dataset_version, contributor_id, batch_id)

    @property
    def sample_hashes(self) -> dict[str, str]:
        return {name: sample["sha256"] for name, sample in self.samples.items()}

    @property
    def digest(self) -> str:
        return self.compute_hash()

    def to_dict(self) -> dict:
        return {key: value for key, value in asdict(self).items() if not key.startswith("_")}

    def compute_hash(self) -> str:
        return digest(self.to_dict())

    def verify(self, current_path: str | Path) -> bool:
        try:
            if self.compute_hash() != self._baseline_digest:
                return False
            current = self._build(current_path, self.format, **self._options)
            return current.compute_hash() == self._baseline_digest
        except (OSError, ValueError, TypeError, KeyError):
            return False
