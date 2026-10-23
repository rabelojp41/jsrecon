import ipaddress

import httpx
import pytest
import respx

from jsrecon.analysis import similarity
from jsrecon.analysis.favicon import _murmur3_32, favicon_hash, favicon_url
from jsrecon.config import ApiKeys
from jsrecon.models import CDNResult, Mode, ProviderEvidence
from jsrecon.modules.origin_finder import OriginFinder
from jsrecon.providers.cdn_ranges import CDNRanges
from jsrecon.providers.securitytrails import SecurityTrails
from jsrecon.providers.virustotal import VirusTotal
from jsrecon.scope import Scope

PAGE = "<html><head><title>Exemplo App</title><link rel='icon' href='/img/fav.png'></head><body><div>Olá</div></body></html>"
FAVICON = b"\x89PNG fake favicon bytes"


@pytest.fixture(autouse=True)
def fast_providers(monkeypatch):
    monkeypatch.setattr(SecurityTrails, "RATE", 0)
    monkeypatch.setattr(VirusTotal, "RATE", 0)


def test_favicon_hash_matches_mmh3():
    import base64
    import mmh3
    data = b"x" * 1000
    assert favicon_hash(data) == mmh3.hash(base64.encodebytes(data))
    assert _murmur3_32(base64.encodebytes(data)) == mmh3.hash(base64.encodebytes(data))
    assert _murmur3_32(b"abc") == mmh3.hash(b"abc")


def test_favicon_url():
    assert favicon_url("https://exemplo.com/", PAGE) == "https://exemplo.com/img/fav.png"
    assert favicon_url("https://exemplo.com/a/", None) == "https://exemplo.com/favicon.ico"


def test_similarity():
    ref = similarity.fingerprint(httpx.Response(200, text=PAGE))
    same = similarity.fingerprint(httpx.Response(200, text=PAGE.replace("Olá", "Oi")))
    other = similarity.fingerprint(httpx.Response(404, text="<html><title>Default nginx</title></html>"))
    s1, _ = similarity.compare(ref, same)
    s2, _ = similarity.compare(ref, other)
    assert s1 >= 0.75 and s2 < 0.45
    assert similarity.verdict(s1).startswith("provável origem")


def _ctx(make_ctx, mode=Mode.ACTIVE, scope_lines=("exemplo.com", "*.exemplo.com"), **kw):
    records = {
        ("exemplo.com", "A"): ["104.16.5.5"],
        ("exemplo.com", "MX"): ["mail.exemplo.com", "aspmx.l.google.com"],
        ("exemplo.com", "TXT"): ["v=spf1 ip4:198.51.100.20 ip4:192.0.2.0/30 ip4:10.0.0.0/8 include:_spf.google.com ~all"],
        ("mail.exemplo.com", "A"): ["198.51.100.10"],
        ("aspmx.l.google.com", "A"): ["142.250.0.27"],
        ("direct.exemplo.com", "A"): ["198.51.100.30"],
        ("www.exemplo.com", "A"): ["104.16.5.6"],  # também no CDN -> descartado
        ("dev.exemplo.com", "A"): ["10.0.0.5"],  # privado -> descartado
    }
    ctx = make_ctx(mode, records=records, scope=Scope.from_lines(list(scope_lines)), **kw)
    ctx.result.resolved_ips = ["104.16.5.5"]
    ctx.result.cdn = CDNResult(True, ["104.16.5.5"], [ProviderEvidence("Cloudflare", ["header cf-ray"], True)])
    ctx.shared["cdn_ranges"] = CDNRanges([(ipaddress.ip_network("104.16.0.0/13"), "Cloudflare", "oficial")])
    ctx.result.add_subdomain("www.exemplo.com", "shodan-ssl", True)
    return ctx


async def test_skipped_without_cdn(make_ctx):
    ctx = make_ctx(Mode.ACTIVE)
    ctx.result.cdn = CDNResult(False)
    res = await OriginFinder().run(ctx)
    assert res.status.value == "PULADO" and "não está atrás" in res.note


@respx.mock(assert_all_called=False)
async def test_passive_collects_candidates_without_validation(respx_mock, make_ctx):
    target = respx_mock.route(host="exemplo.com")
    ip_hits = respx_mock.route(host__regex=r"^\d+\.\d+\.\d+\.\d+$")
    respx_mock.get(url__startswith="https://web.archive.org/web/2id_/").respond(200, content=FAVICON, headers={"content-type": "image/png"})
    ctx = _ctx(make_ctx, Mode.PASSIVE)
    res = await OriginFinder().run(ctx)

    assert not target.called and not ip_hits.called
    origins = {o.ip: o for o in ctx.result.origins}
    assert set(origins) == {"198.51.100.10", "198.51.100.20", "198.51.100.30", "192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"}
    assert "MX mail.exemplo.com" in origins["198.51.100.10"].sources
    assert origins["198.51.100.30"].sources == ["subdomínio direct.exemplo.com"]
    assert all(not o.validated and o.verdict == "candidato" and o.score is None for o in origins.values())
    assert "1 IP(s) descartados por serem de CDN" in res.note
    assert "SECURITYTRAILS_API_KEY ausente" in res.note
    assert "10.0.0.0/8" in res.note  # faixa SPF grande não expandida
    assert ctx.result.favicon_hash == favicon_hash(FAVICON)
    assert "busca de favicon PULADA: sem SHODAN_API_KEY" in res.note


@respx.mock(assert_all_called=False)
async def test_active_validates_only_user_authorized_ips(respx_mock, make_ctx):
    respx_mock.get("https://exemplo.com/").respond(200, text=PAGE)
    respx_mock.get("https://exemplo.com/img/fav.png").respond(200, content=FAVICON, headers={"content-type": "image/png"})
    good = respx_mock.get("https://198.51.100.30/").respond(200, text=PAGE)
    unauth = respx_mock.get("https://198.51.100.10/")
    ctx = _ctx(make_ctx, Mode.ACTIVE, scope_lines=("exemplo.com", "*.exemplo.com", "198.51.100.30"))
    res = await OriginFinder().run(ctx)

    origins = {o.ip: o for o in ctx.result.origins}
    assert good.called and not unauth.called
    req = good.calls[0].request
    assert req.headers["host"] == "exemplo.com"
    assert req.extensions.get("sni_hostname") == "exemplo.com"
    best = ctx.result.origins[0]
    assert best.ip == "198.51.100.30" and best.validated and best.score > 0.9
    assert best.verdict == "provável origem (validado)"
    assert not origins["198.51.100.10"].validated
    assert "--origin-ip" in origins["198.51.100.10"].details["validação"]
    assert "1 validado(s), 1 provável(is)" in res.note


@respx.mock(assert_all_called=False)
async def test_user_ip_and_api_sources(respx_mock, make_ctx):
    respx_mock.get("https://api.securitytrails.com/v1/history/exemplo.com/dns/a").respond(200, json={
        "records": [{"values": [{"ip": "203.0.113.50"}, {"ip": "104.16.9.9"}], "first_seen": "2018-01-01", "last_seen": "2019-01-01"}]})
    respx_mock.get("https://api.securitytrails.com/v1/domain/exemplo.com/subdomains").respond(200, json={"subdomains": ["origin"]})
    respx_mock.get("https://www.virustotal.com/api/v3/domains/exemplo.com/resolutions").respond(200, json={
        "data": [{"attributes": {"ip_address": "203.0.113.50", "date": 1546300800}}]})
    respx_mock.get("https://www.virustotal.com/api/v3/domains/exemplo.com/subdomains").respond(200, json={"data": [{"id": "api.exemplo.com"}]})
    respx_mock.get(url__startswith="https://web.archive.org/").respond(404)
    respx_mock.get(url__startswith="https://exemplo.com/").respond(200, text=PAGE)
    respx_mock.get("https://203.0.113.99/").respond(500, text="erro")
    ctx = _ctx(make_ctx, Mode.ACTIVE, scope_lines=("exemplo.com", "*.exemplo.com", "203.0.113.99"),
               keys=ApiKeys(securitytrails="ST", virustotal="VT"), origin_ips=["203.0.113.99"])
    ctx.dns.records[("origin.exemplo.com", "A")] = ["203.0.113.60"]
    await OriginFinder().run(ctx)

    origins = {o.ip: o for o in ctx.result.origins}
    assert origins["203.0.113.50"].sources == ["histórico DNS (SecurityTrails)", "histórico DNS (VirusTotal)"]
    assert "104.16.9.9" not in origins
    assert origins["203.0.113.60"].sources == ["subdomínio origin.exemplo.com"]
    assert origins["203.0.113.99"].sources == ["fornecido pelo usuário"]
    assert origins["203.0.113.99"].validated and origins["203.0.113.99"].score < 0.45
    assert any(s.host == "origin.exemplo.com" for s in ctx.result.subdomains)


@respx.mock(assert_all_called=False)
async def test_favicon_search_with_capable_plan(respx_mock, make_ctx):
    respx_mock.get("https://api.shodan.io/api-info").respond(200, json={"plan": "dev", "query_credits": 100})
    search = respx_mock.get("https://api.shodan.io/shodan/host/search").respond(200, json={
        "matches": [{"ip_str": "198.51.100.77"}, {"ip_str": "104.16.1.1"}]})
    respx_mock.get(url__startswith="https://web.archive.org/web/2id_/").respond(200, content=FAVICON, headers={"content-type": "image/x-icon"})
    ctx = _ctx(make_ctx, Mode.PASSIVE, keys=ApiKeys(shodan="K"))
    await OriginFinder().run(ctx)
    assert search.calls[0].request.url.params["query"] == f"http.favicon.hash:{favicon_hash(FAVICON)}"
    origins = {o.ip: o for o in ctx.result.origins}
    assert origins["198.51.100.77"].sources == ["favicon hash (Shodan)"]
    assert "104.16.1.1" not in origins
