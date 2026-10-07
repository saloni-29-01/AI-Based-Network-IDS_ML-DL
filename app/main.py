"""FastAPI application entry point.

Run:  uvicorn app.main:app --host 127.0.0.1 --port 8000
or:   python run.py
"""
from __future__ import annotations

import contextlib
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.api.websocket import start_hub, stop_hub, ws_router
from app.config import APP_VERSION, settings
from app.core.engine import get_engine
from app.storage.database import init_db
from app.storage.repositories import system_event
from app.utils.logging_setup import get_logger, setup_logging

log = get_logger("main")
FRONTEND = Path(__file__).resolve().parent.parent / "frontend"


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    settings.ensure_dirs()
    init_db()
    system_event("INFO", "app", f"application start v{APP_VERSION}")
    e = get_engine()
    try:
        warm = e.warm_up()
        log.info(f"engines warmed: {warm}")
    except Exception as exc:
        log.warning(f"warm-up incomplete (train models first?): {exc}")
    e.start_worker()
    start_hub()
    yield
    await stop_hub()
    e.shutdown()
    system_event("INFO", "app", "application stop")


app = FastAPI(title="AI-Based Network IDS", version=APP_VERSION, lifespan=lifespan)
app.include_router(router)
app.include_router(ws_router)


@app.exception_handler(Exception)
async def unhandled(request, exc):
    log.exception(f"unhandled error on {request.url.path}: {exc}")
    return JSONResponse(status_code=500, content={"error": f"{type(exc).__name__}: {exc}"})


_FAVICON = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">'
            '<stop offset="0" stop-color="#4f8cff"/><stop offset="1" stop-color="#30d0b6"/></linearGradient></defs>'
            '<rect width="64" height="64" rx="14" fill="url(#g)"/><path d="M32 12l16 6v12c0 10-7 18-16 22-9-4-16-12-16-22V18z" '
            'fill="none" stroke="#04142e" stroke-width="5" stroke-linejoin="round"/></svg>')


@app.get("/favicon.svg", include_in_schema=False)
@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    from fastapi.responses import Response
    return Response(_FAVICON, media_type="image/svg+xml")


@app.get("/")
def index():
    return FileResponse(FRONTEND / "index.html")


if FRONTEND.is_dir():
    app.mount("/static", StaticFiles(directory=FRONTEND), name="static")
