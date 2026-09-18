from collections import defaultdict

import numpy as np


def aggregate_runtime(timings):
    """Accept timing rows {detector_id|provider, wall_clock|seconds, ran?}, or
    Phase-3 timing maps {provider: seconds}, or full run_assessment reports.
    Skip nonexecuted checks when tier_logs/ran is available. Units are seconds;
    no memory measurements are inferred from elapsed time.
    """
    grouped = defaultdict(list)
    for entry in timings:
        if "timings" in entry:
            skipped = {log["provider"] for log in entry.get("tier_logs", []) if not log["ran"]}
            rows = [(key, value) for key, value in entry["timings"].items() if key not in skipped]
        elif "detector_id" in entry or "provider" in entry:
            if not entry.get("ran", True):
                continue
            rows = [(entry.get("detector_id", entry.get("provider")),
                     entry.get("wall_clock", entry.get("seconds")))]
        else:
            rows = list(entry.items())
        for detector, duration in rows:
            if duration is None or not np.isfinite(duration) or duration < 0:
                raise ValueError("Wall-clock timings must be finite nonnegative seconds")
            grouped[detector].append(float(duration))
    return {detector: {"count": len(values), "mean": float(np.mean(values)),
                       "p50": float(np.percentile(values, 50)), "p95": float(np.percentile(values, 95)),
                       "max": max(values), "unit": "seconds",
                       "memory_note": "Memory not measured; wall-clock timings do not estimate peak memory."}
            for detector, values in sorted(grouped.items())}
