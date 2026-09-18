"""Recheck issued assurance against current inputs without rerunning detectors.

Each manifest argument accepts (baseline_manifest, current_path_or_config).
A bare dataset/model manifest uses the path signed into affected_asset.manifests;
a bare pipeline manifest is checked against its signed issuance digest.
"""

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class StalenessReport:
    stale: bool
    reasons: list[str]
    checked_at: str


def check_staleness(passport, dataset_manifest=None, model_manifest=None,
                    pipeline_manifest=None) -> StalenessReport:
    reasons = []
    supplied = {"dataset": dataset_manifest, "model": model_manifest, "pipeline": pipeline_manifest}
    if all(value is None for value in supplied.values()):
        reasons.append("no manifests supplied — cannot verify")
    if not passport.verify_signature():
        reasons.append("passport signature invalid or trusted public key unavailable")
        return StalenessReport(True, reasons, datetime.now(timezone.utc).isoformat())
    expected = passport.affected_asset.get("manifests", {})
    for kind, value in supplied.items():
        binding = expected.get(kind, {})
        if value is None:
            if kind in expected:
                reasons.append(f"{kind} manifest missing")
            continue
        try:
            if isinstance(value, tuple) and len(value) == 2:
                manifest, current = value
            else:
                manifest = value
                current = manifest if kind == "pipeline" else binding.get("current_path")
            if binding and manifest.compute_hash() != binding["digest"]:
                reasons.append(f"{kind} manifest differs from passport issuance")
                continue
            if current is None:
                reasons.append(f"{kind} current path missing — cannot verify")
            elif kind == "pipeline" and not binding and current is manifest:
                reasons.append("pipeline issuance baseline missing — cannot verify")
            elif not manifest.verify(current):
                reasons.append(f"{kind} manifest mismatch or current input missing")
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            reasons.append(f"{kind} manifest unavailable or invalid — cannot verify")
    return StalenessReport(bool(reasons), reasons, datetime.now(timezone.utc).isoformat())
