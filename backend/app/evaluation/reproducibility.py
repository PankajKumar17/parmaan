import difflib
import json
import random
from dataclasses import asdict
from enum import Enum

import numpy as np


def _json_value(value):
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, np.generic):
        return value.item()
    raise TypeError(f"Unsupported finding value: {type(value).__name__}")


def assert_reproducible(run_pipeline_fn, seed):
    """Call pipeline(seed=seed) twice, snapshotting findings before the next run.

    Callback returns findings or {findings: [...]}; versions/provenance are included
    via dataclasses.asdict and sorted-key JSON. Finding list order is significant.
    Python/NumPy legacy RNGs are reseeded and restored; callbacks must seed any
    default_rng instances with the supplied seed. No torch or global environment
    changes. A mismatch is returned as a unified line diff, not suppressed.
    """
    random_state, numpy_state = random.getstate(), np.random.get_state()
    serialized = []
    try:
        for _ in range(2):
            random.seed(seed)
            np.random.seed(seed)
            result = run_pipeline_fn(seed=seed)
            findings = result["findings"] if isinstance(result, dict) else result
            serialized.append(json.dumps([asdict(finding) for finding in findings],
                                         sort_keys=True, indent=2, ensure_ascii=False,
                                         allow_nan=False, default=_json_value))
    finally:
        random.setstate(random_state)
        np.random.set_state(numpy_state)
    diff = list(difflib.unified_diff(serialized[0].splitlines(), serialized[1].splitlines(),
                                   fromfile="run_1", tofile="run_2", lineterm=""))
    return {"deterministic": serialized[0] == serialized[1], "diff": diff}
