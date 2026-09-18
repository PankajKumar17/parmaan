import json
import math
from typing import Any


def canonical_serialization(data: Any) -> bytes:
    if data is None:
        return b"null"
    if isinstance(data, bool):
        return b"true" if data else b"false"
    if isinstance(data, str):
        return json.dumps(data, ensure_ascii=False).encode("utf-8")
    if isinstance(data, int):
        return str(data).encode("ascii")
    if isinstance(data, float):
        if not math.isfinite(data):
            raise ValueError("Non-finite numbers cannot be canonically serialized")
        value = f"{data:.6f}"
        return ("0.000000" if value == "-0.000000" else value).encode("ascii")
    if isinstance(data, list):
        return b"[" + b",".join(canonical_serialization(item) for item in data) + b"]"
    if isinstance(data, dict):
        if any(not isinstance(key, str) for key in data):
            raise TypeError("Canonical object keys must be strings")
        return b"{" + b",".join(
            canonical_serialization(key) + b":" + canonical_serialization(data[key])
            for key in sorted(data)
        ) + b"}"
    raise TypeError(f"Cannot canonically serialize type {type(data).__name__}")


def canonical_json(data: dict) -> bytes:
    return canonical_serialization(data)


if __name__ == "__main__":
    first = {"z": 1, "a": [3.1415926535, 2, {"nested": "value"}], "b": True}
    second = {"b": True, "a": [3.1415926535, 2, {"nested": "value"}], "z": 1}
    assert canonical_serialization(first) == canonical_serialization(second)
    assert json.loads(canonical_serialization(first))["b"] is True
    print("Canonical serialization test passed")
