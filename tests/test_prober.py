import respx

from jsrecon.models import Endpoint, Location, Mode, Origin
from jsrecon.modules.prober import EndpointProber


def _ep(value, origin=Origin.HISTORICO, file="https://exemplo.com/app.js@20190101000000"):
    return Endpoint(value, "?", "api", [Location(file, 1, origin)])


async def test_skipped_without_flag(make_ctx):
    reason = EndpointProber().skip_reason(make_ctx(Mode.ACTIVE))
    assert reason == "desabilitado (use --probe)"
    assert EndpointProber().skip_reason(make_ctx(Mode.PASSIVE, probe=True)) == "requer --active"


@respx.mock(assert_all_called=False)
async def test_probes_only_historical_in_scope(respx_mock, make_ctx):
    ctx = make_ctx(Mode.ACTIVE, probe=True)
    ctx.result.endpoints = [
        _ep("/api/old"),
        _ep("/api/gone"),
        _ep("/api/{id}"),
        _ep("https://evil.com/api/x"),
        _ep("/api/current", origin=Origin.ATUAL),
    ]
    head_old = respx_mock.head("https://exemplo.com/api/old").respond(405)
    get_old = respx_mock.get("https://exemplo.com/api/old").respond(200)
    respx_mock.head("https://exemplo.com/api/gone").respond(404)
    current = respx_mock.route(url="https://exemplo.com/api/current")
    evil = respx_mock.route(host="evil.com")

    res = await EndpointProber().run(ctx)
    eps = {e.value: e for e in ctx.result.endpoints}
    assert head_old.called and get_old.called
    assert eps["/api/old"].probe_status == 200
    assert eps["/api/gone"].probe_status == 404
    assert eps["/api/{id}"].probe_note == "não testável (template)"
    assert eps["https://evil.com/api/x"].probe_note == "fora do escopo"
    assert not current.called and not evil.called
    assert res.findings == 1 and "1 de 2" in res.note
    assert all(r.method in ("HEAD", "GET") for r in ctx.http.stats.records)
