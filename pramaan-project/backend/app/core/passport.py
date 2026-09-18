"""The FINAL END-TO-END ARTIFACT of the whole PRAMAAN pipeline.

Optional issuance context lives in lineage.graph.graph: assurance_debt,
coverage_statement (dict or version), ablation_results, adaptive_attacker_results,
and manifest_bindings ({kind: (baseline_manifest, current_path_or_config)}).
Verification uses the locally trusted Ed25519 public key, never an embedded key.
"""

import hashlib
import json
from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html import escape

from cryptography.hazmat.primitives import serialization

from app.core.correlation import CorrelationEngine
from app.core.coverage_statement import build_coverage_statement
from app.core.decision import RiskDecisionMatrix
from app.provenance import keys
from app.provenance.canonical import canonical_serialization


def _fingerprint(public_key):
    return hashlib.sha256(public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()


def _text(value):
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)
    text = escape(text, quote=False)
    for character in "\\`*_{}[]()#+-.!|":
        text = text.replace(character, "\\" + character)
    return text.replace("\n", "<br>")


@dataclass
class Passport:
    findings: list[dict]
    affected_asset: dict
    disposition: list[dict]
    limitations: list
    coverage_statement: dict | str
    passport_version: str
    issued_at: str
    asset_id: str
    signature: str
    public_key_fingerprint: str

    def to_json(self) -> dict:
        return asdict(self)

    def _body(self):
        body = self.to_json()
        del body["signature"]
        return body

    def verify_signature(self) -> bool:
        try:
            public_key = keys.load_public_key()
            return bool(public_key is not None and _fingerprint(public_key) == self.public_key_fingerprint
                        and keys.verify_signature(canonical_serialization(self._body()),
                                                  bytes.fromhex(self.signature), public_key))
        except (OSError, ValueError, TypeError):
            return False

    def render_markdown(self) -> str:
        lines = ["# PRAMAAN Assurance Passport", f"Asset ID: {_text(self.asset_id)}",
                 f"Passport version: {_text(self.passport_version)}", f"Issued at: {_text(self.issued_at)}",
                 "", "## Affected asset", _text(self.affected_asset), "", "## Findings"]
        for finding in self.findings:
            lines.extend([f"### {_text(finding['finding_type'])}",
                          f"Affected asset: {_text(finding['asset_id'])}",
                          f"Reason: {_text(finding['reason'])}",
                          f"Confidence: {finding['confidence']}", f"Severity: {finding['severity']}",
                          "Evidence:"])
            lines.extend(f"- {_text(item)}" for item in finding["evidence"])
            lines.extend(["Counter-evidence:", *[f"- {_text(item)}" for item in finding["counter_evidence"]],
                          f"Modality: {_text(finding['modality'])}",
                          f"Access assumptions: {_text(finding['access_assumptions'])}",
                          f"Provenance: {_text(finding['provenance'])}"])
        if not self.findings:
            lines.append("No findings supplied; this is not evidence of safety.")
        lines.extend(["", "## Disposition"])
        lines.extend(f"- {_text(item)}" for item in self.disposition)
        if not self.disposition:
            lines.append("No verdicts supplied; no acceptance is inferred.")
        lines.extend(["", "## Limitations", *[f"- {_text(item)}" for item in self.limitations],
                      "", "## Coverage statement"])
        if isinstance(self.coverage_statement, dict):
            lines.extend(f"- {_text(name)}: {_text(value)}" for name, value in self.coverage_statement.items())
        else:
            lines.append(_text(self.coverage_statement))
        lines.extend(["", "## Signature", "Algorithm: Ed25519", f"Signature: {self.signature}",
                      f"Public key fingerprint (SHA-256): {self.public_key_fingerprint}"])
        return "\n\n".join(lines) + "\n"


def generate_passport(asset_id, lineage, findings, decision_matrix) -> Passport:
    if not isinstance(asset_id, str) or not asset_id:
        raise ValueError("asset_id must be a nonempty string")
    context = lineage.graph.graph if lineage is not None else {}
    debt = context.get("assurance_debt", [])
    findings = list(findings)
    matrix = decision_matrix if decision_matrix is not None else RiskDecisionMatrix(lineage)
    verdicts = matrix.decide(findings)
    coverage = deepcopy(context.get("coverage_statement"))
    if coverage is None:
        coverage = build_coverage_statement(debt, context.get("ablation_results"),
                                            context.get("adaptive_attacker_results"))
        coverage["access_assumptions"]["used"] = sorted({item.access_assumptions for item in findings})
    if not isinstance(coverage, (dict, str)):
        raise ValueError("coverage_statement must be an embedded dict or version string")
    limitations = CorrelationEngine.known_limitations() + deepcopy(debt)
    if not findings:
        limitations.append("No findings supplied; no acceptance or safety assurance is inferred.")
    limitations.append("Canonical serialization uses six-decimal numeric precision; finer differences are not authenticated.")
    affected_asset = {"asset_id": asset_id}
    if lineage is not None and asset_id in lineage.graph:
        node = lineage.graph.nodes[asset_id]
        affected_asset.update({"node_type": node.get("node_type"), "hash": node.get("hash")})
    bindings = context.get("manifest_bindings", {})
    if bindings:
        affected_asset["manifests"] = {}
        for kind, (manifest, current) in bindings.items():
            if kind not in {"dataset", "model", "pipeline"}:
                raise ValueError("Unknown manifest kind")
            affected_asset["manifests"][kind] = {"digest": manifest.compute_hash()}
            if kind != "pipeline":
                affected_asset["manifests"][kind]["current_path"] = str(current)
    serialized, disposition = [], []
    for index, verdict in enumerate(verdicts):
        finding = verdict["finding"]
        item = asdict(finding)
        item["modality"] = finding.modality.value
        item["reason"] = (f"{finding.finding_type.replace('_', ' ')}: "
                          + ("; ".join(finding.evidence) or "No supporting evidence supplied.")
                          + f" Severity {finding.severity} and confidence {finding.confidence} "
                          + f"yield {verdict['verdict'].lower()} under the decision matrix.")
        serialized.append(item)
        disposition.append({"finding_index": index, "asset_id": finding.asset_id,
                            **{key: deepcopy(value) for key, value in verdict.items()
                               if key not in {"finding", "evidence", "counter_evidence", "verdict"}},
                            "verdict": verdict["verdict"].lower()})
    private_key, public_key = keys.get_or_generate_keypair()
    passport = Passport(serialized, affected_asset, disposition, limitations, coverage, "1.0.0",
                        datetime.now(timezone.utc).isoformat(), asset_id, "", _fingerprint(public_key))
    passport.signature = keys.sign_data(canonical_serialization(passport._body()), private_key).hex()
    return passport
