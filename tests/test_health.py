"""Basic API smoke tests."""

import pytest
from httpx import ASGITransport, AsyncClient

from backend.main import app


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_root(client: AsyncClient):
    resp = await client.get("/")
    assert resp.status_code == 200
    assert resp.json()["name"]


@pytest.mark.asyncio
async def test_health(client: AsyncClient):
    resp = await client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ("healthy", "degraded")
    assert "version" in data
