import datetime

import respx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from jsrecon.config import ApiKeys
from jsrecon.models import Mode
from jsrecon.modules.shodan_enrich import ShodanEnricher
from jsrecon.providers.cdn_ranges import CDNRanges
from jsrecon.providers.shodan import extract_sans, intel_from_host

import ipaddress


def _pem(*names):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


HOST = {
    "ip_str": "198.51.100.7", "org": "Exemplo Hosting", "asn": "AS64500", "ports": [443, 22],
    "vulns": ["CVE-2021-41773"],
    "data": [
        {"port": 443, "transport": "tcp", "product": "Apache httpd", "version": "2.4.49",
         "ssl": {"cert": {"subject": {"CN": "exemplo.com"}}, "chain": [_pem("exemplo.com", "*.exemplo.com", "dev.exemplo.com", "outro.net")]}},
        {"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "8.2p1",
         "vulns": {"CVE-2020-15778": {"verified": False}}},
    ],
}


def test_extract_sans_from_extension_text():
    ssl = {"cert": {"extensions": [{"name": "subjectAltName", "data": "0\x1a\x82\x0bapi.exemplo.com\x82\x0bexemplo.com"}]}}
    assert {"api.exemplo.com", "exemplo.com"} <= extract_sans(ssl)


def test_intel_from_host():
    intel = intel_from_host("198.51.100.7", HOST)
    assert intel.org == "Exemplo Hosting" and intel.asn == "AS64500"
    assert "443/tcp Apache httpd 2.4.49" in intel.services
    assert intel.cves == ["CVE-2020-15778", "CVE-2021-41773"]
    assert "dev.exemplo.com" in intel.sans and "outro.net" in intel.sans


@respx.mock(assert_all_called=False)
async def test_without_key_uses_internetdb(respx_mock, make_ctx):
    api = respx_mock.route(host="api.shodan.io")
    respx_mock.get("https://internetdb.shodan.io/104.16.5.5").respond(
        200, json={"ip": "104.16.5.5", "ports": [80, 443], "cpes": ["cpe:/a:cloudflare"], "vulns": [], "hostnames": ["exemplo.com"]})
    ctx = make_ctx(Mode.PASSIVE)
    ctx.result.resolved_ips = ["104.16.5.5"]
    ctx.shared["cdn_ranges"] = CDNRanges([(ipaddress.ip_network("104.16.0.0/13"), "Cloudflare", "oficial")])
    res = await ShodanEnricher().run(ctx)
    assert not api.called
    h = ctx.result.hosts[0]
    assert h.source == "internetdb" and h.ports == [80, 443] and h.is_cdn_edge == "Cloudflare"
    assert "sem SHODAN_API_KEY" in res.note
    assert "dados refletem o CDN" in res.note


@respx.mock(assert_all_called=False)
async def test_with_key_full_api_sans_and_plan(respx_mock, make_ctx):
    respx_mock.get("https://api.shodan.io/api-info").respond(200, json={"plan": "oss", "query_credits": 0, "scan_credits": 0})
    host = respx_mock.get("https://api.shodan.io/shodan/host/198.51.100.7").respond(200, json=HOST)
    ctx = make_ctx(Mode.PASSIVE, keys=ApiKeys(shodan="CHAVE123"))
    ctx.result.resolved_ips = ["198.51.100.7"]
    res = await ShodanEnricher().run(ctx)

    assert host.calls[0].request.url.params["key"] == "CHAVE123"
    assert all("CHAVE123" not in r.url for r in ctx.http.stats.records)  # chave redigida no log
    h = ctx.result.hosts[0]
    assert h.source == "shodan" and "CVE-2021-41773" in h.cves
    subs = {s.host: s for s in ctx.result.subdomains}
    assert subs["dev.exemplo.com"].source == "shodan-ssl" and subs["dev.exemplo.com"].in_scope
    assert subs["outro.net"].in_scope is False
    assert "busca PULADA" in res.note and "plano 'oss'" in res.note
    assert "CVE(s) potenciais" in res.note


@respx.mock(assert_all_called=False)
async def test_plan_forbids_host_lookup_falls_back(respx_mock, make_ctx):
    respx_mock.get("https://api.shodan.io/api-info").respond(200, json={"plan": "free", "query_credits": 0})
    respx_mock.get("https://api.shodan.io/shodan/host/198.51.100.7").respond(403, json={"error": "Access denied"})
    respx_mock.get("https://internetdb.shodan.io/198.51.100.7").respond(200, json={"ports": [22]})
    ctx = make_ctx(Mode.PASSIVE, keys=ApiKeys(shodan="K"))
    ctx.result.resolved_ips = ["198.51.100.7"]
    res = await ShodanEnricher().run(ctx)
    assert ctx.result.hosts[0].source == "internetdb"
    assert "host lookup PULADO" in res.note


@respx.mock(assert_all_called=False)
async def test_cache_24h(respx_mock, make_ctx):
    route = respx_mock.get("https://internetdb.shodan.io/198.51.100.7").respond(200, json={"ports": [22]})
    for _ in range(2):
        ctx = make_ctx(Mode.PASSIVE)
        ctx.result.resolved_ips = ["198.51.100.7"]
        await ShodanEnricher().run(ctx)
    assert route.call_count == 1


@respx.mock(assert_all_called=False)
async def test_candidates_phase(respx_mock, make_ctx):
    from jsrecon.models import OriginCandidate
    respx_mock.get(url__startswith="https://internetdb.shodan.io/").respond(200, json={"ports": [443]})
    ctx = make_ctx(Mode.PASSIVE)
    ctx.result.resolved_ips = ["104.16.5.5"]
    mod = ShodanEnricher()
    await mod.run(ctx)
    ctx.result.origins = [OriginCandidate("198.51.100.9", ["mx"])]
    await mod.enrich_candidates(ctx)
    assert [h.role for h in ctx.result.hosts] == ["resolvido", "candidato-origem"]
    assert mod.result.findings == 2


async def test_skipped_without_ips(make_ctx):
    res = await ShodanEnricher().run(make_ctx(Mode.PASSIVE))
    assert res.status.value == "PULADO"
