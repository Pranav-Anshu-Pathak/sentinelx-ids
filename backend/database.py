"""
SentinelX IDS - Async Database Layer

Provides the async SQLAlchemy engine, session factory, declarative base,
table initialisation helper, and FastAPI dependency for DB sessions.
"""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from backend.config import settings

# ── Engine ───────────────────────────────────────────────────────────────
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    future=True,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {},
)

# ── Session Factory ──────────────────────────────────────────────────────
async_session = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ── Declarative Base ─────────────────────────────────────────────────────
class Base(DeclarativeBase):
    """Base class for all ORM models."""
    pass


# ── Initialisation ───────────────────────────────────────────────────────
async def init_db() -> None:
    """Create all tables that do not yet exist in the database."""
    # Import models so they register with Base.metadata
    import backend.models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


# ── FastAPI Dependency ───────────────────────────────────────────────────
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async database session and ensure it is closed after use."""
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
