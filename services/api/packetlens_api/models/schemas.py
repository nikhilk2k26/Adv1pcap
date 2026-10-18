"""Pydantic request/response models (typed schemas everywhere)."""
from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field


class UploadRequest(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    size_bytes: int = Field(gt=0)
    sha256: Optional[str] = Field(None, pattern=r"^[0-9a-fA-F]{64}$")
    chunk_size: Optional[int] = Field(None, ge=65536, le=64 * 1024 * 1024)
    auto_analyze: bool = True
    profile: str = "datacenter"


class UploadSession(BaseModel):
    capture_id: str
    chunk_size: int
    uploaded_chunks: List[int] = []


class DuplicateCaptureResponse(BaseModel):
    existing_capture_id: str
    message: str


class CompleteRequest(BaseModel):
    sha256: Optional[str] = Field(None, pattern=r"^[0-9a-fA-F]{64}$")
    auto_analyze: bool = True
    profile: str = "datacenter"


class JobOut(BaseModel):
    job_id: str
    type: str
    status: str
    current_stage: Optional[str] = None
    attempts: int = 0
    error: Optional[str] = None


class CaptureOut(BaseModel):
    capture_id: str
    tenant_id: str
    filename: str
    sha256: Optional[str] = None
    size_bytes: int
    received_bytes: int = 0
    format: Optional[str] = None
    status: str
    created_at: Optional[str] = None
    packet_count: Optional[int] = None
    duration_seconds: Optional[float] = None
    drop_count: Optional[int] = None
    profile: str = "datacenter"


class CaptureStatusOut(BaseModel):
    capture_id: str
    status: str
    stage_progress: Optional[float] = None
    received_bytes: int
    size_bytes: int
    job: Optional[JobOut] = None
    recent_events: List[dict] = []


class FindingOut(BaseModel):
    finding_id: str
    severity: str
    confidence: str
    category: str
    title: str
    description: str
    affected_hosts: List[str] = []
    affected_streams: List[int] = []
    evidence: dict = {}
    recommendation: Optional[str] = None
    chart: Optional[str] = None
