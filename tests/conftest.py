from __future__ import annotations

import io
from pathlib import Path

import pytest
import pytest_asyncio

from jsrecon import __version__
from jsrecon.cache import DiskCache
from jsrecon.config import ApiKeys, Settings
from jsrecon.dns import StaticResolver
from jsrecon.http import HttpClient
from jsrecon.models import Mode, ReconResult
from jsrecon.modules.base import Context
from jsrecon.scope import Scope
from jsrecon.ui import UI

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


@pytest.fixture
def scope() -> Scope:
    return Scope.from_lines(["exemplo.com", "*.exemplo.com", "!legado.exemplo.com", "203.0.113.0/24"])


def make_settings(scope: Scope, mode: Mode = Mode.ACTIVE, tmp_path: Path | None = None, **kw) -> Settings:
    defaults = dict(
        target="exemplo.com",
        scope=scope,
        mode=mode,
        rate_limit=0,
        passive_rate_limit=0,
        retries=1,
        backoff=0,
        timeout=5,
        cache_dir=tmp_path / "cache" if tmp_path else None,
        keys=ApiKeys(),
    )
    defaults.update(kw)
    return Settings(**defaults)


@pytest_asyncio.fixture
async def make_ctx(scope, tmp_path):
    clients: list[HttpClient] = []

    def _make(mode: Mode = Mode.ACTIVE, records=None, **kw) -> Context:
        settings = make_settings(kw.pop("scope", scope), mode, tmp_path, **kw)
        http = HttpClient(settings)
        clients.append(http)
        ui = UI(stdout=io.StringIO(), stderr=io.StringIO(), no_color=True)
        result = ReconResult(settings.target, settings.mode, settings.scope.to_dict(), __version__)
        return Context(settings, http, StaticResolver(records or {}), DiskCache(settings.cache_dir), ui, result)

    yield _make
    for client in clients:
        await client.aclose()


@pytest_asyncio.fixture
async def http_active(scope, tmp_path):
    client = HttpClient(make_settings(scope, Mode.ACTIVE, tmp_path))
    yield client
    await client.aclose()


@pytest_asyncio.fixture
async def http_passive(scope, tmp_path):
    client = HttpClient(make_settings(scope, Mode.PASSIVE, tmp_path))
    yield client
    await client.aclose()
