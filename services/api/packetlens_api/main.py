"""PacketLens api-service application factory."""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from .deps import AppState, create_state
from .routers import captures as captures_router
from .routers import jobs as jobs_router
from .security.auth import AuthSettings, current_principal


def create_app(state: Optional[AppState] = None) -> FastAPI:
    app = FastAPI(
        title="PacketLens API",
        version="1.0.0",
        description="Automated pcap/pcapng performance analysis",
    )
    app.state.pl = state or create_state()

    # make auth settings injectable without globals
    current_principal._settings = AuthSettings(
        allow_dev_tokens=__import__("os").environ.get("PACKETLENS_ALLOW_DEV_TOKENS", "1") == "1")

    app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"],
                       allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    app.include_router(captures_router.router)
    app.include_router(jobs_router.router)
    app.include_router(jobs_router.health_router)

    logging.getLogger("packetlens").setLevel(logging.INFO)
    return app


app = create_app()  # for `uvicorn packetlens_api.main:app`
