from copy import deepcopy
from datetime import datetime, timezone

from app.core.correlation import CorrelationEngine
from app.modules.model_integrity.access_matrix import CHECK_CAPABILITIES


VERSION = "1.0.0"
SUPPORTED_ATTACK_CLASSES = {
    "label-flip": "cf. MITRE ATLAS: Poison Training Data",
    "near-duplicate flooding": "cf. MITRE ATLAS: Poison Training Data",
    "OOD insertion": "cf. MITRE ATLAS: Evade ML Model",
    "model substitution": "cf. MITRE ATLAS: ML Supply Chain Compromise",
    "candidate backdoors": "cf. MITRE ATLAS: Backdoor ML Model",
    "inference tampering & replay": "cf. MITRE ATLAS: AI Model Inference API Access (related access surface; replay is not a direct taxonomy equivalence)",
}


def build_coverage_statement(assurance_debt: list, ablation_results: dict | None,
                             adaptive_attacker_results: dict | None) -> dict:
    limitations = CorrelationEngine.known_limitations() + [
        "Supported attack classes describe available checks, not guaranteed detection or proof of absence.",
        "Candidate backdoors remain hypotheses; unknown attacks and unobserved triggers are unsupported.",
        "Inference computation checks provide sampled, partial assurance, not a full cryptographic guarantee (zkML out of scope).",
        "Replay detection requires persistent verifier state; a passport signature alone does not establish freshness.",
    ]
    limitations.extend(deepcopy(assurance_debt))
    for name, results in (("ablation", ablation_results), ("adaptive_attacker", adaptive_attacker_results)):
        limitations.append({
            "evaluation": name,
            "status": "not evaluated" if results is None else "reported; limited to supplied evaluation",
            "results": deepcopy(results),
            "note": "No robustness guarantee is inferred; missing, negative, and unoptimized results remain visible.",
        })
    return {
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "supported_attack_classes": dict(SUPPORTED_ATTACK_CLASSES),
        "access_assumptions": {
            "used": "not supplied; capability eligibility does not establish execution",
            "capabilities": deepcopy(CHECK_CAPABILITIES),
        },
        "black_box_fallback": (
            "Use output-only reference-battery comparisons when outputs and a trusted reference are available. "
            "Hash identity requires a supplied model file and trusted digest even in black-box mode. "
            "Skip unavailable weights, activations, gradient-based reconstruction, fine-pruning, and Merkle "
            "activation commitments; disclose skipped/degraded checks as assurance debt. "
            "Fallback execution is not asserted without assessment evidence."
        ),
        "limitations": limitations,
        "assurance_debt": deepcopy(assurance_debt),
        "ablation_results": deepcopy(ablation_results),
        "adaptive_attacker_results": deepcopy(adaptive_attacker_results),
    }
