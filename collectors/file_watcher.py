"""Watch log files and emit new lines for ingestion."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, Awaitable, Callable

from backend.config import settings

logger = logging.getLogger("sentinelx.collector")


async def run_file_watcher(
    on_line: Callable[[str, Path], Awaitable[None]],
    stop_event: asyncio.Event,
) -> None:
    """Tail configured log files and invoke *on_line* for each new line."""
    paths = settings.watch_log_paths_list
    if not paths:
        return

    positions: dict[Path, int] = {}
    logger.info("File watcher monitoring %d path(s)", len(paths))

    while not stop_event.is_set():
        for path in paths:
            if not path.exists():
                continue
            try:
                size = path.stat().st_size
                offset = positions.get(path, 0)
                if size < offset:
                    offset = 0
                if size == offset:
                    continue
                with path.open("r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(offset)
                    for line in fh:
                        line = line.strip()
                        if line:
                            await on_line(line, path)
                    positions[path] = fh.tell()
            except Exception as exc:
                logger.warning("Error reading %s: %s", path, exc)

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            pass
