import math
import time
from collections.abc import Mapping

from app.core.evidence import EvidenceProvider


def run_assessment(assets, providers, expensive_providers, risk_threshold=0.4, clock=time.perf_counter):
    if not math.isfinite(risk_threshold) or not 0 <= risk_threshold <= 1:
        raise ValueError("risk_threshold must be in [0, 1]")

    def entries(group):
        result = list(group.items()) if isinstance(group, Mapping) else [
            (provider.detector_id, provider) for provider in group
        ]
        if any(not isinstance(provider, EvidenceProvider) for _, provider in result):
            raise TypeError("Providers must be EvidenceProvider instances")
        return result

    cheap, expensive = entries(providers), entries(expensive_providers)
    keys = [key for key, _ in cheap + expensive]
    if len(set(keys)) != len(keys):
        raise ValueError("Provider keys must be unique across tiers")
    findings, timings, logs = [], {}, []
    triggered = False
    for tier, group in (("cheap", cheap), ("expensive", expensive)):
        for key, provider in group:
            ran = tier == "cheap" or triggered
            reason = "Cheap tier always runs" if tier == "cheap" else (
                f"Cheap finding severity > {risk_threshold}" if triggered
                else f"No cheap finding severity > {risk_threshold}"
            )
            logs.append({"provider": key, "tier": tier, "ran": ran, "reason": reason})
            if not ran:
                timings[key] = 0.0
                continue
            start = clock()
            batch = list(provider.analyze(assets[key]))
            timings[key] = max(0.0, float(clock() - start))
            findings.extend(batch)
        if tier == "cheap":
            triggered = any(finding.severity > risk_threshold for finding in findings)
    return {"findings": findings, "timings": timings, "tier_logs": logs}
