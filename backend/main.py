"""
SentinelX IDS - Application Entry Point

Run from project root:
    uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

Or:
    python -m backend.main
"""

from __future__ import annotations

import asyncio
import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

# Ensure project root is on PYTHONPATH when running as a script
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from backend.config import settings
from backend.database import init_db
from backend.pipeline import process_event
from backend.routes import api_router
from backend.seed import seed_all
from collectors.demo_collector import run_demo_collector
from collectors.file_watcher import run_file_watcher
from detection_engine.engine import DetectionEngine
from websocket.manager import ConnectionManager
from threat_intel.feeds import sync_all_feeds

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinelx")

RULES_PATH = _ROOT / "rules"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: DB, seeds, detection engine, background collectors."""
    await init_db()
    await seed_all()

    engine = DetectionEngine()
    loaded = engine.load_rules(str(RULES_PATH))
    logger.info("Loaded %d detection rules from %s", loaded, RULES_PATH)

    ws_manager = ConnectionManager()
    stop_event = asyncio.Event()

    app.state.detection_engine = engine
    app.state.ws_manager = ws_manager
    app.state.stop_event = stop_event

    async def on_event(event: dict) -> None:
        await process_event(event, engine, ws_manager)

    async def on_file_line(line: str, path: Path) -> None:
        await on_event(
            {
                "raw_message": line,
                "source": "syslog",
                "hostname": path.stem,
            }
        )

    async def _background_feed_sync():
        """Run an initial threat intel feed sync shortly after startup."""
        await asyncio.sleep(10)  # Give server 10s to fully start
        try:
            from backend.database import async_session
            async with async_session() as session:
                logger.info("Starting initial threat intel feed sync…")
                results = await sync_all_feeds(session)
                await session.commit()
                total = sum(results.values())
                logger.info("Threat intel sync complete: %d new IOCs imported", total)
        except Exception as exc:
            logger.warning("Background feed sync failed (non-fatal): %s", exc)

    tasks = [
        asyncio.create_task(run_demo_collector(on_event, stop_event)),
        asyncio.create_task(run_file_watcher(on_file_line, stop_event)),
        asyncio.create_task(_background_feed_sync()),
    ]

    yield

    stop_event.set()
    for task in tasks:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AI-Powered Intrusion Detection System",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api")


@app.websocket("/ws/{channel}")
async def websocket_endpoint(websocket: WebSocket, channel: str) -> None:
    """Real-time events channel (logs, alerts)."""
    manager: ConnectionManager = app.state.ws_manager
    await manager.connect(websocket, channel)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(websocket, channel)


@app.get("/", tags=["Root"])
async def root() -> dict:
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "api": "/api",
        "websocket": "/ws/events",
    }


def run() -> None:
    """Poetry script entry point."""
    import uvicorn

    uvicorn.run(
        "backend.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
    )


if __name__ == "__main__":
    run()
