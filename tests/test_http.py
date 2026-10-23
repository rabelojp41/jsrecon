import asyncio
import time

import httpx
import pytest
import respx

from jsrecon.http import OutOfScopeError, RateLimiter


@respx.mock
async def test_active_in_scope(http_active):
    respx.get("https://exemplo.com/").respond(200, text="ok")
    r = await http_active.get("https://exemplo.com/")
    assert r.text == "ok"
    assert http_active.stats.active_count == 1


async def test_active_out_of_scope_refused(http_active):
    with respx.mock(assert_all_called=False) as router:
        route = router.get("https://evil.com/")
        with pytest.raises(OutOfScopeError):
            await http_active.get("https://evil.com/")
        assert not route.called
    assert http_active.stats.blocked[0].reason.startswith("host fora do escopo")


async def test_passive_mode_blocks_target(http_passive):
    with pytest.raises(OutOfScopeError, match="modo passivo"):
        await http_passive.get("https://exemplo.com/")


@respx.mock
async def test_passive_sources_allowed_in_passive_mode(http_passive):
    respx.get("https://web.archive.org/cdx/search/cdx").respond(200, json=[])
    r = await http_passive.get("https://web.archive.org/cdx/search/cdx")
    assert r.status_code == 200
    assert http_passive.stats.passive_count == 1


async def test_host_header_must_be_in_scope(http_active):
    with pytest.raises(OutOfScopeError, match="Host fora"):
        await http_active.get("https://203.0.113.5/", host_header="evil.com")
    with pytest.raises(OutOfScopeError, match="fora do escopo"):
        await http_active.get("https://198.51.100.5/", host_header="exemplo.com")


async def test_passive_source_with_host_header_is_active(http_passive):
    # Host sobrescrito transforma a requisição em ativa -> bloqueada no modo passivo
    with pytest.raises(OutOfScopeError):
        await http_passive.get("https://web.archive.org/", host_header="exemplo.com")


@respx.mock
async def test_redirect_out_of_scope_not_followed(http_active):
    respx.get("https://exemplo.com/login").respond(302, headers={"Location": "https://sso.evil.com/"})
    evil = respx.get("https://sso.evil.com/")
    r = await http_active.get("https://exemplo.com/login")
    assert r.status_code == 302
    assert not evil.called
    assert "redirecionamento" in http_active.stats.blocked[0].reason


@respx.mock
async def test_redirect_in_scope_followed(http_active):
    respx.get("http://exemplo.com/").respond(301, headers={"Location": "https://www.exemplo.com/"})
    respx.get("https://www.exemplo.com/").respond(200, text="final")
    r = await http_active.get("http://exemplo.com/")
    assert r.text == "final"


@respx.mock
async def test_retries_on_503_then_success(http_active):
    route = respx.get("https://exemplo.com/x")
    route.side_effect = [httpx.Response(503), httpx.Response(200, text="ok")]
    r = await http_active.get("https://exemplo.com/x")
    assert r.status_code == 200 and route.call_count == 2


@respx.mock
async def test_retries_on_transport_error(http_active):
    route = respx.get("https://exemplo.com/x")
    route.side_effect = [httpx.ConnectError("boom"), httpx.Response(200)]
    assert (await http_active.get("https://exemplo.com/x")).status_code == 200


@respx.mock
async def test_retries_exhausted_raise(http_active):
    respx.get("https://exemplo.com/x").mock(side_effect=httpx.ReadTimeout("t"))
    with pytest.raises(httpx.ReadTimeout):
        await http_active.get("https://exemplo.com/x")


@respx.mock
async def test_user_agent_and_max_bytes(http_active):
    route = respx.get("https://exemplo.com/big").respond(200, content=b"a" * 1000)
    r = await http_active.get("https://exemplo.com/big", max_bytes=100)
    assert len(r.content) == 100 and r.extensions["truncated"]
    assert route.calls[0].request.headers["user-agent"].startswith("jsrecon/")


def test_redacts_api_keys(http_active):
    assert "SEGREDO" not in http_active.redact("https://api.shodan.io/x?key=SEGREDO&q=1")


async def test_rate_limiter_spacing():
    limiter = RateLimiter(20)  # 50ms
    start = time.monotonic()
    await asyncio.gather(*(limiter.acquire() for _ in range(4)))
    assert time.monotonic() - start >= 0.14
