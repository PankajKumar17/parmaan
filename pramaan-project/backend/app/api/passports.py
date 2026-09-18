"""Authenticated passport access over application-local registries.

Assessment callers populate app.state.findings_registry[asset_id] with Findings
and optionally manifests_registry[asset_id] with {kind: (baseline, current)}.
Optional lineage and assurance_registry[asset_id] provide issuance context.
Issued artifacts are cached in passport_registry; remove an entry after a new
assessment to issue a replacement. Current manifest targets are checked on every
read/export, without silently replacing the signed issuance baseline.
"""

from copy import copy
from dataclasses import asdict
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from app.core.decision import RiskDecisionMatrix
from app.core.lineage import IntegrityLineage
from app.core.passport import _text, generate_passport
from app.core.security import current_user
from app.core.staleness import check_staleness


router = APIRouter(prefix="/api", dependencies=[Depends(current_user)])


def _passport(request, asset_id):
    state = request.app.state
    findings_registry = getattr(state, "findings_registry", {})
    if asset_id not in findings_registry:
        raise HTTPException(404, "Assessment findings not found")
    manifests = getattr(state, "manifests_registry", {}).get(asset_id, {})
    if not hasattr(state, "passport_registry"):
        state.passport_registry = {}
    if asset_id not in state.passport_registry:
        lineage = copy(getattr(state, "lineage", None) or IntegrityLineage())
        lineage.graph = lineage.graph.copy()
        context = getattr(state, "assurance_registry", {}).get(asset_id, {})
        lineage.graph.graph.update(context)
        lineage.graph.graph["manifest_bindings"] = manifests
        state.passport_registry[asset_id] = generate_passport(
            asset_id, lineage, findings_registry[asset_id], RiskDecisionMatrix(lineage))
    passport = state.passport_registry[asset_id]
    report = check_staleness(passport, dataset_manifest=manifests.get("dataset"),
                             model_manifest=manifests.get("model"),
                             pipeline_manifest=manifests.get("pipeline"))
    return passport, report


@router.get("/passport/{asset_id}")
def get_passport(asset_id: str, request: Request):
    passport, report = _passport(request, asset_id)
    return JSONResponse({**passport.to_json(), "staleness": asdict(report)},
                        headers={"Cache-Control": "no-store"})


@router.get("/passport/{asset_id}/export")
def export_passport(asset_id: str, request: Request, format: Literal["markdown", "json"] = "json"):
    passport, report = _passport(request, asset_id)
    headers = {"Cache-Control": "no-store"}
    if format == "json":
        headers["Content-Disposition"] = 'attachment; filename="passport.json"'
        return JSONResponse({**passport.to_json(), "staleness": asdict(report)}, headers=headers)
    headers["Content-Disposition"] = 'attachment; filename="passport.md"'
    status = "STALE/INVALIDATED" if report.stale else "FRESH"
    block = "\n## Staleness\n\n" + status + f"\n\nChecked at: {report.checked_at}\n"
    block += "".join(f"\n- {_text(reason)}\n" for reason in report.reasons)
    return Response(passport.render_markdown() + block, media_type="text/markdown", headers=headers)
