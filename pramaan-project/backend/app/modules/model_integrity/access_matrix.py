CHECK_CAPABILITIES = {
    "Model Identity (hash check)": {"white_box": "yes", "gray_box": "yes", "black_box": "yes"},
    "Weight/activation statistics": {"white_box": "yes", "gray_box": "partial", "black_box": "no"},
    "Trigger reconstruction": {"white_box": "yes", "gray_box": "partial", "black_box": "no"},
    "Fine-Pruning": {"white_box": "yes", "gray_box": "no", "black_box": "no"},
    "Reference-battery comparison": {"white_box": "yes", "gray_box": "yes", "black_box": "yes (output-only)"},
    "Merkle activation commitment": {"white_box": "yes", "gray_box": "partial", "black_box": "no"},
}

RECOMMENDATIONS = {
    "Model Identity (hash check)": "obtain the supplied model file and trusted reference digest",
    "Weight/activation statistics": "obtain white-box weights and baseline activation statistics",
    "Trigger reconstruction": "obtain white-box/gradient access to enable",
    "Fine-Pruning": "obtain white-box neuron access and a reference battery",
    "Reference-battery comparison": "obtain model outputs and a trusted reference battery",
    "Merkle activation commitment": "obtain intermediate activations and committed reference roots",
}


def coverage_confidence(ran, requested):
    """Fraction of unique requested checks evaluated, including partial checks."""
    requested = set(requested)
    return len(set(ran) & requested) / len(requested) if requested else 0.0


def assurance_debt(skipped):
    """Accept skipped/degraded report entries; preserve every named gap."""
    result = []
    for entry in skipped:
        check = entry if isinstance(entry, str) else entry["check"]
        gap = "unavailable" if isinstance(entry, str) else entry.get("reason", "unavailable")
        recommendation = RECOMMENDATIONS.get(check, "register the check and document its access requirements")
        result.append({"check": check, "gap": gap, "recommendation": f"{check}: {gap} — {recommendation}"})
    return result


def evaluate_access(access_level, available_checks):
    """Report eligibility, not execution: caller supplies installed/available checks.

    All six matrix checks are requested. 'ran' denotes available checks permitted
    at this access level, not a claim that detector code was executed here.
    Partial checks count toward coverage but always accrue assurance debt.
    """
    if access_level not in {"white_box", "gray_box", "black_box"}:
        raise ValueError("Unknown access level")
    available = set(available_checks)
    requested = list(CHECK_CAPABILITIES) + sorted(available - CHECK_CAPABILITIES.keys())
    ran, skipped, degraded, details = [], [], [], []
    for check in requested:
        capability = CHECK_CAPABILITIES.get(check, {}).get(access_level, "no")
        if check not in CHECK_CAPABILITIES:
            reason = "Unknown check; no capability contract registered"
        elif check not in available:
            reason = "Check implementation or required inputs are unavailable"
        elif capability == "no":
            reason = f"{access_level} does not provide required access"
        else:
            ran.append(check)
            reason = "Partial access; only exposed internals can be evaluated" if capability == "partial" else capability
            if capability == "partial":
                degraded.append({"check": check, "reason": reason})
            details.append({"check": check, "capability": capability, "status": "partial" if capability == "partial" else "ran",
                            "reason": reason})
            continue
        skipped.append({"check": check, "reason": reason})
        details.append({"check": check, "capability": capability, "status": "skipped", "reason": reason})
    return {"access_level": access_level, "requested": requested, "ran": ran, "skipped": skipped,
            "degraded": degraded, "checks": details, "coverage_confidence": coverage_confidence(ran, requested),
            "assurance_debt": assurance_debt(skipped + degraded), "execution_verified": False}
