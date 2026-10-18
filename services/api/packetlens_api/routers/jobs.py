"""Jobs + health routers (Phase 1)."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Request
from sse_starlette.sse import EventSourceResponse  # optional; fallback below if unavailable

from ..deps import get_state
from ..security.auth import Principal, current_principal

router = APIRouter(prefix="/v1/jobs", tags=["jobs"])
health_router = APIRouter(tags=["health"])


@router.get("/{job_id}")
def get_job(job_id: str, request: Request, p: Principal = Depends(current_principal)):
    st = get_state(request)
    with st.captures._conn() as c:
        row = c.execute("SELECT * FROM jobs WHERE job_id=? AND tenant_id=?",
                        (job_id, p.tenant_id)).fetchone()
    if not row:
        raise HTTPException(404, "job not found")
    return dict(row)


@router.get("/{job_id}/events")
async def job_events(job_id: str, request: Request,
                     p: Principal = Depends(current_principal)):
    """SSE progress stream. Polls job_events table (swap for queue pub/sub fan-out in prod)."""
    st = get_state(request)

    async def gen():
        import asyncio
        last_id = 0
        for _ in range(600):  # 10 min max stream
            with st.captures._conn() as c:
                job = c.execute("SELECT status FROM jobs WHERE job_id=? AND tenant_id=?",
                                (job_id, p.tenant_id)).fetchone()
                if not job:
                    yield {"event": "error", "data": "job not found"}
                    return
                rows = c.execute(
                    "SELECT event_id, stage, progress, message, metrics_json FROM job_events"
                    " WHERE job_id=? AND event_id>? ORDER BY event_id", (job_id, last_id)).fetchall()
            for r in rows:
                last_id = r["event_id"]
                yield {"event": "progress", "data": json.dumps(dict(r))}
            if job and job["status"] in ("succeeded", "failed", "cancelled"):
                yield {"event": "done", "data": json.dumps({"status": job["status"]})}
                return
            await asyncio.sleep(1)

    try:
        return EventSourceResponse(gen())
    except NameError:  # sse-starlette not installed → plain JSON polling fallback
        async def poll():
            return {"detail": "install sse-starlette for streaming; poll /v1/captures/{id}/status"}
        return poll()


@health_router.get("/health")
def health():
    return {"status": "ok"}


@health_router.get("/ready")
def ready(request: Request):
    st = get_state(request)
    try:
        with st.captures._conn() as c:
            c.execute("SELECT 1").fetchone()
        store_ok = True
        probe_key = f"tenants/_health/probe"
        st.store.put(probe_key, b"ok")
        st.store.delete(probe_key)
    except Exception as e:
        return {"status": "not-ready", "error": str(e)}
    return {"status": "ready", "db": True, "storage": store_ok}
