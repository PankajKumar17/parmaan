import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from app.provenance.canonical import canonical_serialization


def digest(data: Any) -> str:
    return hashlib.sha256(canonical_serialization(data)).hexdigest()


def snapshot(data: Any) -> Any:
    canonical_serialization(data)
    json.dumps(data, allow_nan=False)
    return copy.deepcopy(data)


def file_sha256(path: str | Path) -> str:
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def read_json(path: Path) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError(f"Non-finite JSON number: {value}")

    with path.open("r", encoding="utf-8-sig") as stream:
        data = json.load(stream, object_pairs_hook=pairs, parse_constant=invalid_constant)
    return snapshot(data)
