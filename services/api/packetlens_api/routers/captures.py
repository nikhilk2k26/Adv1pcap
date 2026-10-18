"""Capture upload/status/list routers (Phase 1)."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response

from ..deps import AppState, get_state
from ..models.schemas import CaptureOut, CaptureStatusOut, UploadRequest, UploadSession, CompleteRequest
from ..security.auth import Principal, current_principal, require_role
from ..services.capture_service import (
    CaptureService, DuplicateCapture, NotFoundError, ValidationError,
)

router = APIRouter(prefix="/v1/captures", tags=["captures"])


def _svc(request: Request) -> CaptureService:
    return get_state(request).captures


@router.post("/uploads", response_model=UploadSession, status_code=201)
def create_upload(body: UploadRequest, request: Request,
                  p: Principal = Depends(require_role("analyst"))):
    try:
        session = _svc(request).create_upload(
            tenant_id=p.tenant_id, filename=body.filename, size_bytes=body.size_bytes,
            sha256=body.sha256, chunk_size=body.chunk_size, created_by=p.user_id)
        session["auto_analyze"] = body.auto_analyze
        session["profile"] = body.profile
        return UploadSession(**{k: session[k] for k in ("capture_id", "chunk_size", "uploaded_chunks")})
    except DuplicateCapture as d:
        raise HTTPException(409, detail={"existing_capture_id": d.existing["capture_id"],
                                         "message": str(d)})
    except ValidationError as e:
        raise HTTPException(422, str(e))


@router.put("/{capture_id}/chunks/{chunk_number}")
async def put_chunk(capture_id: str, chunk_number: int, request: Request,
                    p: Principal = Depends(require_role("analyst"))):
    # Read in bounded slices; never buffer more than max_chunk_size (validated after).
    chunks: list[bytes] = []
    total = 0
    async for part in request.stream():
        chunks.append(part)
        total += len(part)
        if total > _svc(request).settings.max_chunk_size:
            raise HTTPException(413, "chunk too large")
    data = b"".join(chunks)
    if not data:
        raise HTTPException(400, "empty chunk body")
    try:
        return _svc(request).put_chunk(p.tenant_id, capture_id, chunk_number, data)
    except NotFoundError:
        raise HTTPException(404, "capture not found")
    except ValidationError as e:
        raise HTTPException(422, str(e))


@router.post("/{capture_id}/complete", response_model=CaptureStatusOut, status_code=202)
def complete_upload(capture_id: str, request: Request,
                    body: Optional[CompleteRequest] = Body(None),
                    p: Principal = Depends(require_role("analyst"))):
    b = body or CompleteRequest()
    try:
        result = _svc(request).complete_upload(
            p.tenant_id, capture_id, client_sha256=b.sha256,
            auto_analyze=b.auto_analyze, profile=b.profile)
        st = _svc(request).get_status(p.tenant_id, capture_id)
        return CaptureStatusOut(**st)
    except DuplicateCapture as d:
        raise HTTPException(409, detail={"existing_capture_id": d.existing["capture_id"],
                                         "message": str(d)})
    except NotFoundError:
        raise HTTPException(404, "capture not found")
    except ValidationError as e:
        raise HTTPException(422, str(e))


@router.get("/{capture_id}", response_model=CaptureOut)
def get_capture(capture_id: str, request: Request,
                p: Principal = Depends(current_principal)):
    try:
        return CaptureOut(**_svc(request).get_capture(p.tenant_id, capture_id))
    except NotFoundError:
        raise HTTPException(404, "capture not found")


@router.get("/{capture_id}/status", response_model=CaptureStatusOut)
def get_status(capture_id: str, request: Request,
               p: Principal = Depends(current_principal)):
    try:
        return CaptureStatusOut(**_svc(request).get_status(p.tenant_id, capture_id))
    except NotFoundError:
        raise HTTPException(404, "capture not found")


@router.delete("/{capture_id}", status_code=204)
def delete_capture(capture_id: str, request: Request,
                   p: Principal = Depends(require_role("admin"))):
    try:
        _svc(request).delete_capture(p.tenant_id, capture_id, actor=p.user_id)
        return Response(status_code=204)
    except NotFoundError:
        raise HTTPException(404, "capture not found")


@router.get("", response_model=list[CaptureOut])
def list_captures(request: Request, limit: int = 100,
                  p: Principal = Depends(current_principal)):
    return [CaptureOut(**c) for c in _svc(request).list_captures(p.tenant_id, limit)]
