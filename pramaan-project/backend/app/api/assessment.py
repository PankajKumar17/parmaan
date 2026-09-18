import json
from collections import defaultdict
from dataclasses import asdict, fields, replace
from datetime import datetime, timezone
from uuid import uuid4

import numpy as np
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from PIL import Image
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import tiered_computation
from app.core.correlation import CorrelationEngine
from app.core.decision import RiskDecisionMatrix
from app.core.evidence import EvidenceProvider, Finding, Modality
from app.core.lineage import IntegrityLineage
from app.core.security import current_user
from app.db.models import AssessmentRow, Asset, FindingRow, InferenceRecordRow
from app.db.session import get_session
from app.manifests._common import digest
from app.manifests.model_manifest import ModelReferenceManifest
from app.modules.data_integrity.annotation_integrity import AnnotationIntegrityDetector
from app.modules.data_integrity.contributor_risk import ContributorRiskAggregator
from app.modules.data_integrity.duplicates import DuplicateDetector
from app.modules.data_integrity.mislabeling import MislabelingDetector, feature_vector
from app.modules.data_integrity.ood import OODDetector
from app.modules.data_integrity.strip import STRIPDetector
from app.modules.drift.drift_vs_manipulation import DriftVsManipulationProvider
from app.modules.model_integrity import access_matrix
from app.modules.model_integrity.fine_pruning import FinePruningProvider
from app.modules.model_integrity.identity import ModelIdentityDetector
from app.modules.model_integrity.trigger_reconstruction import TriggerReconstructionProvider


router = APIRouter(prefix="/api", dependencies=[Depends(current_user)])
PROVIDERS = (
    ("duplicates", DuplicateDetector, "cheap", ("images",)),
    ("mislabeling", MislabelingDetector, "cheap", ("samples", "num_classes")),
    ("ood", OODDetector, "cheap", ("samples", "num_classes")),
    ("annotation_integrity", AnnotationIntegrityDetector, "cheap", ("annotations",)),
    ("identity", ModelIdentityDetector, "cheap", ("reference", "supplied_model_path")),
    ("drift", DriftVsManipulationProvider, "cheap",
     ("reference_embeddings", "current_embeddings", "reference_images", "current_images")),
    ("trigger_reconstruction", TriggerReconstructionProvider, "expensive", ("model", "samples")),
    ("fine_pruning", FinePruningProvider, "expensive",
     ("model", "predict_fn", "activations", "reference_battery", "suspicious_indices")),
    ("strip", STRIPDetector, "expensive", ("images", "backgrounds", "predict_fn")),
)
MODEL_CHECKS = {
    "identity": "Model Identity (hash check)",
    "trigger_reconstruction": "Trigger reconstruction",
    "fine_pruning": "Fine-Pruning",
}
TRUSTED_KEYS = {"model", "predict_fn", "reference", "reference_manifest_path", "supplied_model_path", "access_level"}


class AssessmentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: str = Field(min_length=1, max_length=128)
    payload: dict = Field(default_factory=dict)


def _serialize(finding):
    return {**asdict(finding), "modality": finding.modality.value}


def _finding(row):
    values = {field.name: getattr(row, field.name) for field in fields(Finding)}
    values["modality"] = Modality(values["modality"])
    return Finding(**values)


def _manifest(state, asset_id, kind):
    binding = getattr(state, "manifests_registry", {}).get(asset_id, {}).get(kind)
    if isinstance(binding, (tuple, list)) and len(binding) == 2:
        return binding
    return None, None


def _document(value):
    if value is None:
        return {}
    return value.to_dict() if hasattr(value, "to_dict") else dict(value)


def _images(values, normalized=False):
    if not 0 < len(values) <= 64:
        raise ValueError("Image batches must contain 1 to 64 images")
    result = []
    for entry in values:
        name, pixels = (entry["id"], entry["pixels"]) if isinstance(entry, dict) else entry
        if isinstance(pixels, Image.Image):
            array = np.asarray(pixels.convert("RGB"))
        else:
            array = np.asarray(pixels)
        if array.ndim not in (2, 3) or not all(array.shape) or max(array.shape[:2]) > 256:
            raise ValueError("Images must be nonempty and at most 256 by 256")
        if array.ndim == 3 and array.shape[2] not in (1, 3, 4):
            raise ValueError("Unsupported channel count")
        if not np.isfinite(array).all() or np.any(array < 0) or np.any(array > 255):
            raise ValueError("Pixels must be finite and in [0, 255]")
        if normalized:
            scale = 255 if array.max() > 1 or array.dtype.kind in "ui" else 1
            array = array.astype(float) / scale
            if array.ndim == 2:
                array = array[:, :, None]
            result.append((str(name), array))
        else:
            if array.dtype.kind == "f" and array.max() <= 1:
                array = array * 255
            if array.ndim == 3 and array.shape[2] == 1:
                array = array[:, :, 0]
            result.append((str(name), Image.fromarray(array.astype(np.uint8))))
    return result


def _payload(state, asset, inline):
    try:
        encoded = json.dumps(inline, allow_nan=False)
    except (ValueError, TypeError):
        raise HTTPException(422, "Payload must contain finite JSON values") from None
    if len(encoded) > 2_000_000:
        raise HTTPException(413, "Inline payload exceeds 2 MB")
    data = dict(getattr(state, "payload_registry", {}).get(asset.id, {}))
    for key, value in inline.items():
        if key in TRUSTED_KEYS:
            raise HTTPException(422, "Model paths, runtimes and access levels must be registered server-side")
        if key in {entry[0] for entry in PROVIDERS} and isinstance(value, dict):
            if TRUSTED_KEYS.intersection(value):
                raise HTTPException(422, "Model paths, runtimes and access levels must be registered server-side")
            data[key] = {**data.get(key, {}), **value}
        else:
            data[key] = value
    reference, current = _manifest(state, asset.id, "model")
    if isinstance(reference, ModelReferenceManifest):
        identity = dict(data.get("identity", {}))
        identity.setdefault("reference", reference)
        if isinstance(current, (str, bytes)) or hasattr(current, "__fspath__"):
            identity.setdefault("supplied_model_path", current)
        data["identity"] = identity
    data["asset_id"] = asset.id
    data.setdefault("batch_id", asset.id)
    data.setdefault("config_hash", digest({"asset_id": asset.id, "manifest_hash": asset.manifest_hash}))
    return data


def _prepare(key, data, required):
    payload = {**data, **data.get(key, {})}
    if key in ("duplicates", "strip") and "images" in payload:
        payload["images"] = _images(payload["images"], normalized=key == "strip")
    if key == "strip" and "backgrounds" in payload:
        payload["backgrounds"] = [image for _, image in _images(
            list(enumerate(payload["backgrounds"])), normalized=True)]
    if key in ("mislabeling", "ood"):
        if "samples" not in payload and "images" in payload and "labels" in payload:
            images = _images(payload["images"])
            labels = payload["labels"]
            payload["samples"] = [(name, feature_vector(image), labels[name] if isinstance(labels, dict) else labels[index])
                                  for index, (name, image) in enumerate(images)]
        if "samples" in payload:
            if not 1 <= len(payload["samples"]) <= 256:
                raise ValueError("Sample batches must contain 1 to 256 rows")
            if any(len(sample[1]) > 256 for sample in payload["samples"]):
                raise ValueError("Feature vectors must have at most 256 dimensions")
            payload.setdefault("num_classes", len({sample[2] for sample in payload["samples"]}))
    if key == "drift":
        for field in ("reference_images", "current_images"):
            if field in payload:
                payload[field] = _images(payload[field])
    if key == "annotation_integrity" and "annotations" in payload:
        if not 1 <= len(payload["annotations"]) <= 256:
            raise ValueError("Annotation batches must contain 1 to 256 images")
        if any(len(annotation["boxes"]) > 256 for annotation in payload["annotations"]):
            raise ValueError("Each image must have at most 256 boxes")
    if key == "trigger_reconstruction" and "samples" in payload:
        if not 1 <= len(payload["samples"]) <= 64:
            raise ValueError("Reconstruction requires 1 to 64 samples")
    missing = [field for field in required if field not in payload or payload[field] is None]
    if missing:
        return None, "Required inputs unavailable: " + ", ".join(missing)
    return payload, None


class _GuardedProvider(EvidenceProvider):
    def __init__(self, key, provider, failures):
        super().__init__(key, provider.version)
        self.provider = provider
        self.failures = failures

    def analyze(self, asset):
        try:
            return list(self.provider.analyze(asset))
        except Exception as error:
            self.failures[self.detector_id] = f"Provider failed ({type(error).__name__}); validate registered inputs"
            return []


def _metadata(state, asset_id, data):
    manifest, _ = _manifest(state, asset_id, "dataset")
    document = _document(manifest)
    metadata = data.get("batch_metadata", {})
    samples = metadata.get("samples", document.get("samples", {}))
    order = metadata.get("ordered_batches", document.get("ordered_batches", []))
    if not order and document.get("batch_id"):
        order = [document["batch_id"]]
    return {"samples": {str(name): {key: sample.get(key, document.get(key)) for key in ("contributor_id", "batch_id")}
                        for name, sample in samples.items()}, "ordered_batches": list(order)}


def _assessment_output(row):
    return {"assessment_id": row.id, "asset_id": row.asset_id, "started_at": row.started_at,
            "finished_at": row.finished_at, "tier_logs": row.tier_logs, "timings": row.timings,
            "skipped": row.skipped, "finding_count": row.finding_count}


def _context(row):
    return row.tier_logs[0].get("context", {}) if row and row.tier_logs else {}


def _latest(session):
    return session.scalar(select(AssessmentRow).order_by(AssessmentRow.finished_at.desc(), AssessmentRow.id.desc()).limit(1))


def _latest_findings(session, assessment):
    if assessment is None:
        return []
    return [_finding(row) for row in session.scalars(select(FindingRow).where(FindingRow.asset_id == assessment.asset_id))
            if row.provenance.get("assessment_id") == assessment.id]


def _coverage(row):
    if row is None:
        return {"assessment_id": None, "requested": [], "ran": [], "skipped": [], "degraded": [],
                "coverage_confidence": 0.0, "assurance_debt": access_matrix.assurance_debt([
                    {"check": "assessment", "reason": "No assessment has been executed"}]),
                "execution_verified": False, "access_matrix": access_matrix.evaluate_access("black_box", [])}
    requested = [log["provider"] for log in row.tier_logs]
    ran = [log["provider"] for log in row.tier_logs if log["ran"]]
    access = access_matrix.evaluate_access(_context(row).get("access_level", "black_box"),
                                          [MODEL_CHECKS[key] for key in ran if key in MODEL_CHECKS])
    gaps = [{"check": MODEL_CHECKS.get(item["provider"], item["provider"]), "reason": item["reason"]}
            for item in row.skipped]
    degraded = [item for item in access["degraded"] if item["check"] in {MODEL_CHECKS.get(key) for key in requested}]
    return {"assessment_id": row.id, "requested": requested, "ran": ran, "skipped": row.skipped,
            "degraded": degraded, "coverage_confidence": access_matrix.coverage_confidence(ran, requested),
            "assurance_debt": access_matrix.assurance_debt(gaps + degraded),
            "execution_verified": True, "access_matrix": access}


@router.post("/assess")
def assess(body: AssessmentInput, request: Request, session: Session = Depends(get_session)):
    asset = session.get(Asset, body.asset_id)
    if asset is None:
        raise HTTPException(404, "Asset not found")
    started = datetime.now(timezone.utc)
    assessment_id = str(uuid4())
    state = request.app.state
    data = _payload(state, asset, body.payload)
    try:
        metadata = _metadata(state, asset.id, data)
        ContributorRiskAggregator().aggregate([], metadata)
    except (ValueError, TypeError, KeyError, AttributeError):
        raise HTTPException(422, "Invalid batch metadata; supply samples and explicit ordered_batches") from None
    available, expensive, assets, failures = {}, {}, {}, {}
    for key, factory, tier, required in PROVIDERS:
        try:
            payload, reason = _prepare(key, data, required)
        except (ValueError, TypeError, KeyError, IndexError, AttributeError):
            payload, reason = None, "Invalid or oversized provider payload"
        if reason:
            failures[key] = reason
            continue
        assets[key] = payload
        (available if tier == "cheap" else expensive)[key] = _GuardedProvider(key, factory(), failures)
    result = tiered_computation.run_assessment(assets, available, expensive)
    logs = {log["provider"]: log for log in result["tier_logs"]}
    for key, _, tier, _ in PROVIDERS:
        if key in failures:
            logs[key] = {"provider": key, "tier": tier, "ran": False, "reason": failures[key]}
        result["timings"].setdefault(key, 0.0)
    tier_logs = [logs[key] for key, _, _, _ in PROVIDERS]
    access_level = data.get("access_level", "black_box")
    if access_level not in {"white_box", "gray_box", "black_box"}:
        raise HTTPException(422, "Invalid registered access level")
    tier_logs[0]["context"] = {"batch_metadata": metadata, "access_level": access_level}
    skipped = [{"provider": log["provider"], "tier": log["tier"], "reason": log["reason"]}
               for log in tier_logs if not log["ran"]]
    findings = []
    for finding in CorrelationEngine().converge(result["findings"]):
        provenance = {**finding.provenance, "assessment_id": assessment_id, "source_asset_id": finding.asset_id}
        findings.append(replace(finding, asset_id=asset.id, provenance=provenance))
    record = AssessmentRow(id=assessment_id, asset_id=asset.id, started_at=started,
                           finished_at=datetime.now(timezone.utc), tier_logs=tier_logs,
                           timings=result["timings"], skipped=skipped, finding_count=len(findings))
    session.add(record)
    session.add_all(FindingRow(**_serialize(finding)) for finding in findings)
    session.commit()
    state.findings_registry.setdefault(asset.id, []).extend(findings)
    state.assurance_registry[asset.id] = _coverage(record)
    getattr(state, "passport_registry", {}).pop(asset.id, None)
    _build_lineage(state, session)
    return {**_assessment_output(record), "findings": [_serialize(finding) for finding in findings]}


@router.get("/assessments")
def list_assessments(offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200),
                     session: Session = Depends(get_session)):
    rows = session.scalars(select(AssessmentRow).order_by(AssessmentRow.finished_at.desc(), AssessmentRow.id.desc())
                           .offset(offset).limit(limit))
    return [_assessment_output(row) for row in rows]


def _build_lineage(state, session):
    if not hasattr(state, "lineage"):
        state.lineage = IntegrityLineage()
    lineage = state.lineage
    graph = lineage.graph
    assets = session.scalars(select(Asset).order_by(Asset.id)).all()
    for asset in assets:
        graph.add_node(asset.id, node_type=asset.asset_type.lower(), hash=asset.manifest_hash,
                       orphan=False, ref=asset.id)
    for asset in assets:
        manifest, _ = _manifest(state, asset.id, asset.asset_type.lower())
        document = _document(manifest)
        if asset.asset_type == "DATASET" and document.get("contributor_id"):
            contributor = document["contributor_id"]
            lineage._parent(contributor, "contributor")
            if contributor != asset.id and contributor not in lineage.downstream_of(asset.id):
                lineage._edge(contributor, asset.id)
        if asset.asset_type == "MODEL":
            parents = document.get("training_dataset_ids", getattr(manifest, "training_dataset_ids", None))
            parents = [parents] if isinstance(parents, str) else parents
            for parent in parents or [f"unknown-training-dataset:{asset.id}"]:
                lineage._parent(parent, "dataset")
                if parent != asset.id and parent not in lineage.downstream_of(asset.id):
                    lineage._edge(parent, asset.id)
    models = {asset.manifest_hash: asset.id for asset in assets if asset.asset_type == "MODEL"}
    for row in session.scalars(select(InferenceRecordRow)):
        parent = models.get(row.model_digest, row.model_digest)
        lineage._parent(parent, "model")
        graph.add_node(row.id, node_type="inference", hash=row.record_hash, orphan=False,
                       ref={"input_hash": row.input_hash, "sequence_number": row.sequence_number})
        if row.id != parent and parent not in lineage.downstream_of(row.id):
            lineage._edge(parent, row.id)
    for row in session.scalars(select(FindingRow)):
        lineage.add_finding(_finding(row), row.asset_id)
    return lineage


@router.get("/lineage/{asset_id}")
def get_lineage(asset_id: str, request: Request, session: Session = Depends(get_session)):
    lineage = _build_lineage(request.app.state, session)
    if asset_id not in lineage.graph:
        raise HTTPException(404, "Asset not found")
    return {"nodes": [{"id": node_id, "type": attrs.get("node_type"), "hash": attrs.get("hash"),
                       "orphan": attrs.get("orphan", False)}
                      for node_id, attrs in sorted(lineage.graph.nodes(data=True))],
            "edges": [list(edge) for edge in sorted(lineage.graph.edges)],
            "blast_radius": lineage.blast_radius(asset_id)}


@router.get("/dashboard/matrix")
def dashboard_matrix(request: Request, session: Session = Depends(get_session)):
    assessment = _latest(session)
    matrix = RiskDecisionMatrix(_build_lineage(request.app.state, session))
    verdicts = matrix.decide(_latest_findings(session, assessment))
    return {"assessment_id": assessment.id if assessment else None,
            "verdicts": [{**item, "finding": _serialize(item["finding"]), "quarantine_scope": item["scope"]}
                         for item in verdicts]}


@router.get("/dashboard/coverage")
def dashboard_coverage(session: Session = Depends(get_session)):
    return _coverage(_latest(session))


@router.get("/dashboard/radar/{model_id}")
def dashboard_radar(model_id: str, session: Session = Depends(get_session)):
    asset = session.get(Asset, model_id)
    if asset is None or asset.asset_type != "MODEL":
        raise HTTPException(404, "Model asset not found")
    groups = defaultdict(list)
    for row in session.scalars(select(FindingRow).where(FindingRow.asset_id == model_id)):
        finding = _finding(row)
        detector = finding.provenance["detector_id"]
        if detector == "model_identity" or finding.modality in {Modality.BEHAVIORAL, Modality.ACTIVATION}:
            groups[detector].append(finding)
    vectors = {"identity": [], "behavioral": []}
    for detector, findings in sorted(groups.items()):
        group = "identity" if detector == "model_identity" else "behavioral"
        vectors[group].append({"detector": detector, "severity": max(item.severity for item in findings),
                               "confidence": max(item.confidence for item in findings),
                               "finding_count": len(findings),
                               "findings": [_serialize(item) for item in findings]})
    return {"model_id": model_id, **vectors, "display_only": True}


@router.get("/dashboard/heatmap")
def dashboard_heatmap(request: Request, session: Session = Depends(get_session)):
    state = request.app.state
    latest = {}
    for row in session.scalars(select(AssessmentRow).order_by(AssessmentRow.finished_at.desc(), AssessmentRow.id.desc())):
        latest.setdefault(row.asset_id, row)
    samples, order = {}, []
    for asset in session.scalars(select(Asset).order_by(Asset.id)):
        metadata = _context(latest.get(asset.id)).get("batch_metadata")
        if metadata is None:
            metadata = _metadata(state, asset.id, {})
        for name, sample in metadata["samples"].items():
            samples[digest([asset.id, name])] = sample
        for batch in metadata["ordered_batches"]:
            if batch not in order:
                order.append(batch)
    findings = []
    for row in session.scalars(select(FindingRow)):
        finding = _finding(row)
        source = finding.provenance.get("source_asset_id", finding.asset_id)
        findings.append(replace(finding, asset_id=digest([finding.asset_id, source])))
    try:
        report = ContributorRiskAggregator().aggregate(findings, {"samples": samples, "ordered_batches": order})
    except (ValueError, TypeError, KeyError):
        raise HTTPException(422, "Contributor metadata requires a valid explicit batch order") from None
    series = [{"contributor_id": contributor, "batches": data["batches"],
               "sparkline": [batch["anomaly_rate"] for batch in data["batches"]]}
              for contributor, data in report["contributors"].items()]
    return {**report, "series": series,
            "change_points": [asdict(point) for point in report["temporal_drift_points"]]}
