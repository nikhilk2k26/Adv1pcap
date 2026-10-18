"""FastAPI dependency wiring: single app state, no hidden globals."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from fastapi import Request

from ..services.capture_service import CaptureService, Settings
from ..services.object_store import ObjectStore, build_object_store
from ..services.queue import QueueBackend, build_queue


@dataclass
class AppState:
    settings: Settings
    store: ObjectStore
    queue: QueueBackend
    captures: CaptureService


def create_state(settings: Optional[Settings] = None) -> AppState:
    s = settings or Settings(
        storage_backend=os.environ.get("PACKETLENS_STORAGE_BACKEND", "filesystem"),
        storage_root=os.environ.get("PACKETLENS_STORAGE_ROOT", "./data/storage"),
        queue_backend=os.environ.get("PACKETLENS_QUEUE_BACKEND", "memory"),
        redis_url=os.environ.get("PACKETLENS_REDIS_URL", "redis://localhost:6379/0"),
    )
    store = build_object_store(s)
    queue = build_queue(s)
    db_path = os.environ.get("PACKETLENS_DB_PATH", os.path.join(s.storage_root, "packetlens.db"))
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    svc = CaptureService(store, queue, db_path, s)
    return AppState(settings=s, store=store, queue=queue, captures=svc)


def get_state(request: Request) -> AppState:
    return request.app.state.pl
