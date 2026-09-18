from dataclasses import asdict
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import current_user
from app.db.models import Asset
from app.db.session import get_session

router = APIRouter(prefix="/api", dependencies=[Depends(current_user)])


class AssetInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    asset_type: Literal["DATASET", "MODEL", "CONTRIBUTOR"]
    manifest_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class AssetOutput(AssetInput):
    model_config = ConfigDict(from_attributes=True)
    created_at: datetime


@router.get("/assets", response_model=list[AssetOutput])
def list_assets(
    offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200),
    session: Session = Depends(get_session),
):
    return session.scalars(select(Asset).order_by(Asset.id).offset(offset).limit(limit)).all()


@router.post("/assets", response_model=AssetOutput, status_code=201)
def register_asset(payload: AssetInput, session: Session = Depends(get_session)):
    asset = Asset(**payload.model_dump())
    session.add(asset)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(409, "Asset already exists") from None
    session.refresh(asset)
    return asset


@router.get("/assets/{asset_id}", response_model=AssetOutput)
def get_asset(asset_id: str, session: Session = Depends(get_session)):
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(404, "Asset not found")
    return asset


@router.get("/system/integrity")
def integrity(request: Request):
    report = request.app.state.integrity
    return {"status": report.status, **asdict(report)}
