from __future__ import annotations

import sys
from pathlib import Path

import aiohttp
import pytest
import pytest_asyncio
from aiohttp.test_utils import TestServer

sys.path.insert(0, str(Path(__file__).parent))

from fake_modem import FakeModem  # noqa: E402

from tplink_m7200.client import TPLinkM7200  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated_xdg(tmp_path, monkeypatch):
    """Never touch the real ~/.config, ~/.local/state or ~/.local/share."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg-state"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    monkeypatch.delenv("M7200_PASSWORD", raising=False)
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def fake_modem() -> FakeModem:
    return FakeModem()


@pytest_asyncio.fixture
async def modem_server(fake_modem):
    server = TestServer(fake_modem.app(), host="127.0.0.1")
    await server.start_server()
    try:
        yield server
    finally:
        await server.close()


@pytest_asyncio.fixture
async def http_session():
    async with aiohttp.ClientSession() as session:
        yield session


@pytest_asyncio.fixture
async def client(modem_server, http_session, fake_modem) -> TPLinkM7200:
    c = TPLinkM7200(f"{modem_server.host}:{modem_server.port}", "admin", fake_modem.password, http_session)
    c.timeout = 5.0
    await c.login()
    return c
