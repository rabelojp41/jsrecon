import json

import httpx
import respx

from jsrecon.models import Mode, Origin
from jsrecon.modules import sourcemaps, wayback
from jsrecon.modules.js_collector import JSCollector, extract_from_html, find_js_references
from tests.conftest import fixture_text

CDX = "https://web.archive.org/cdx/search/cdx"


def test_extract_from_html():
    urls, inline = extract_from_html("https://exemplo.com/", fixture_text("index.html"))
    assert "https://exemplo.com/static/app.js" in urls
    assert "https://exemplo.com/static/vendor.js" in urls  # modulepreload
    assert "https://exemplo.com/static/utils.js" in urls  # importmap
    assert "https://cdn.terceiro.com/lib.js" in urls
    assert len(inline) == 1 and "apiBase" in inline[0]  # ld+json ignorado


def test_find_js_references():
    refs = find_js_references("https://exemplo.com/static/app.js", fixture_text("app.js"))
    assert refs == ["https://exemplo.com/static/chunk.js"]


def test_sourcemap_helpers():
    assert sourcemaps.find_sourcemap_url("https://e.com/a/app.js", "x\n//# sourceMappingURL=app.js.map") == "https://e.com/a/app.js.map"
    assert sourcemaps.find_sourcemap_url("https://e.com/app.js", "x", {"SourceMap": "/m/app.map"}) == "https://e.com/m/app.map"
    parsed = sourcemaps.parse_sourcemap(fixture_text("app.js.map"))
    assert [p for p, _ in parsed] == ["webpack://app/./src/api.ts"]  # node_modules ignorado
    data = sourcemaps.decode_data_uri("data:application/json;base64,eyJhIjoxfQ")
    assert json.loads(data) == {"a": 1}


def test_cdx_dedupe():
    recs = wayback.dedupe_by_digest(wayback.parse_cdx(json.loads(fixture_text("cdx_js.json"))))
    assert len(recs) == 4
    old = next(r for r in recs if r.digest == "DIGEST_A")
    assert old.timestamp == "20200101000000"
    assert old.raw_url == "https://web.archive.org/web/20200101000000id_/https://exemplo.com/static/old.js"


def _mock_site(router):
    router.get("https://exemplo.com/").respond(200, text=fixture_text("index.html"), headers={"content-type": "text/html"})
    router.get("https://exemplo.com/static/app.js").respond(200, text=fixture_text("app.js"))
    router.get("https://exemplo.com/static/app.js.map").respond(200, text=fixture_text("app.js.map"))
    router.get("https://exemplo.com/static/chunk.js").respond(200, text="export const helper = 1;")
    router.get("https://exemplo.com/static/chunk.js.map").respond(404)
    router.get("https://exemplo.com/static/vendor.js").respond(200, text="var v=1;")
    router.get("https://exemplo.com/static/vendor.js.map").respond(404)
    router.get("https://exemplo.com/static/utils.js").respond(404)


@respx.mock(assert_all_called=False)
async def test_active_collection(respx_mock, make_ctx):
    _mock_site(respx_mock)
    third_party = respx_mock.get("https://cdn.terceiro.com/lib.js")
    ctx = make_ctx(Mode.ACTIVE, wayback=False)
    result = await JSCollector().run(ctx)

    urls = {f.url for f in ctx.result.js_files}
    assert "https://exemplo.com/static/app.js" in urls
    assert "https://exemplo.com/static/chunk.js" in urls  # seguiu o import
    assert "https://exemplo.com/#inline-1" in urls
    assert "https://exemplo.com/static/app.js.map::webpack://app/./src/api.ts" in urls
    assert not third_party.called
    assert {"url": "https://cdn.terceiro.com/lib.js", "reason": "fora do escopo"} in ctx.result.js_skipped
    assert all(f.origin is Origin.ATUAL for f in ctx.result.js_files)
    assert result.status.value == "COM ACHADOS"


@respx.mock(assert_all_called=False)
async def test_passive_collection_never_touches_target(respx_mock, make_ctx):
    target = respx_mock.route(host="exemplo.com")
    respx_mock.get(CDX).respond(200, json=json.loads(fixture_text("cdx_js.json")))
    respx_mock.get(url__regex=r"https://web\.archive\.org/web/\d+id_/.*").mock(
        side_effect=lambda req: httpx.Response(200, text=f"// archived {req.url.path}\nfetch('/api/old');")
    )
    ctx = make_ctx(Mode.PASSIVE)
    result = await JSCollector().run(ctx)

    assert not target.called
    files = ctx.result.js_files
    assert len(files) == 3  # legado.exemplo.com está excluído do escopo
    assert all(f.origin is Origin.HISTORICO and f.timestamp for f in files)
    assert any("fora do escopo" in w for w in ctx.result.warnings)
    assert "0 atuais, 3 históricos" in result.note


@respx.mock(assert_all_called=False)
async def test_historical_identical_to_current_is_dropped(respx_mock, make_ctx):
    _mock_site(respx_mock)
    respx_mock.get(CDX).respond(200, json=[
        ["timestamp", "original", "digest", "statuscode", "mimetype"],
        ["20220101000000", "https://exemplo.com/static/app.js", "D", "200", "application/javascript"],
    ])
    respx_mock.get("https://web.archive.org/web/20220101000000id_/https://exemplo.com/static/app.js").respond(
        200, text=fixture_text("app.js")
    )
    ctx = make_ctx(Mode.ACTIVE)
    await JSCollector().run(ctx)
    assert not any(f.origin is Origin.HISTORICO for f in ctx.result.js_files)


@respx.mock(assert_all_called=False)
async def test_wayback_failure_is_partial(respx_mock, make_ctx):
    _mock_site(respx_mock)
    respx_mock.get(CDX).respond(500)
    ctx = make_ctx(Mode.ACTIVE)
    result = await JSCollector().run(ctx)
    assert result.status.value == "FALHA PARCIAL"
    assert "Wayback indisponível" in result.note
