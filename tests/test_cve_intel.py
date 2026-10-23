import pytest
import respx

from jsrecon.models import HostIntel, Mode
from jsrecon.modules.cve_intel import CveEnricher
from jsrecon.providers.cvedb import CveDb, parse


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    monkeypatch.setattr(CveDb, "RATE", 0)


APACHE = {"cve_id": "CVE-2021-41773", "summary": "Path traversal  in\nApache 2.4.49", "cvss": 9.8, "cvss_version": 3.0,
          "cvss_v2": 4.3, "cvss_v3": 9.8, "epss": 0.9999, "kev": True, "published_time": "2021-10-05T09:15:07",
          "references": ["http://exploit.example/x"]}
OPENSSH_OLD = {"cve_id": "CVE-2007-2768", "summary": "OpenSSH OPIE", "cvss": 4.3, "cvss_version": 2.0,
               "cvss_v2": 4.3, "cvss_v3": None, "epss": 0.086, "kev": False, "published_time": "2007-05-21T20:30:00"}
HIGH = {"cve_id": "CVE-2025-26465", "summary": "OpenSSH MitM", "cvss": 6.8, "cvss_v3": 6.8, "cvss_version": 3.1,
        "epss": 0.4, "kev": False, "published_time": "2025-02-18T19:15:29"}


def test_parse():
    c = parse("CVE-2021-41773", APACHE)
    assert (c.cvss, c.severity, c.kev, c.published) == (9.8, "crítica", True, "2021-10-05")
    assert c.summary == "Path traversal in Apache 2.4.49"
    assert "references" not in c.to_dict()  # links de exploit não entram no relatório
    assert c.to_dict()["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
    old = parse("CVE-2007-2768", OPENSSH_OLD)
    assert old.severity == "média" and old.cvss_version == 2.0
    missing = parse("CVE-2099-0001", {"detail": "No information available"})
    assert not missing.found and missing.severity == "desconhecida"


def _ctx(make_ctx, **kw):
    ctx = make_ctx(Mode.PASSIVE, **kw)
    ctx.result.hosts = [
        HostIntel("69.49.241.25", "internetdb", cves=["CVE-2007-2768", "CVE-2025-26465", "CVE-2021-41773", "lixo"]),
        HostIntel("198.51.100.9", "internetdb", cves=["CVE-2021-41773", "CVE-2099-0001"]),
    ]
    return ctx


def _mock(router):
    router.get("https://cvedb.shodan.io/cve/CVE-2021-41773").respond(200, json=APACHE)
    router.get("https://cvedb.shodan.io/cve/CVE-2007-2768").respond(200, json=OPENSSH_OLD)
    router.get("https://cvedb.shodan.io/cve/CVE-2025-26465").respond(200, json=HIGH)
    router.get("https://cvedb.shodan.io/cve/CVE-2099-0001").respond(404, json={"detail": "No information available"})


@respx.mock(assert_all_called=False)
async def test_enrich_sorted_and_never_touches_target(respx_mock, make_ctx):
    _mock(respx_mock)
    ctx = _ctx(make_ctx)
    res = await CveEnricher().run(ctx)

    assert all(c.request.url.host == "cvedb.shodan.io" for c in respx_mock.calls)
    ids = [c.id for c in ctx.result.cve_intel]
    assert ids == ["CVE-2021-41773", "CVE-2025-26465", "CVE-2007-2768", "CVE-2099-0001"]  # KEV, CVSS, depois sem dados
    assert ctx.result.cve_intel[0].ips == ["69.49.241.25", "198.51.100.9"]
    assert res.status.value == "COM ACHADOS" and res.findings == 4
    assert "1 crítica(s)" in res.note and "1 no CISA KEV" in res.note and "não confirmadas" in res.note


@respx.mock(assert_all_called=False)
async def test_cache_and_limit(respx_mock, make_ctx):
    _mock(respx_mock)
    await CveEnricher().run(_ctx(make_ctx))
    n = len(respx_mock.calls)
    ctx = _ctx(make_ctx, max_cves=2)
    res = await CveEnricher().run(ctx)
    assert len(respx_mock.calls) == n  # tudo do cache
    assert [c.id for c in ctx.result.cve_intel] == ["CVE-2025-26465", "CVE-2099-0001"]  # 2 mais recentes
    assert "2 não enriquecida(s)" in res.note


@respx.mock(assert_all_called=False)
async def test_source_down_is_failure(respx_mock, make_ctx):
    respx_mock.get(url__startswith="https://cvedb.shodan.io/").respond(503)
    res = await CveEnricher().run(_ctx(make_ctx, retries=0))
    assert res.status.value == "FALHA"


async def test_skips(make_ctx):
    assert (await CveEnricher().run(make_ctx(Mode.PASSIVE))).status.value == "PULADO"
    assert CveEnricher().skip_reason(make_ctx(Mode.PASSIVE, cve_intel=False)) == "desabilitado (--no-cve-intel)"
