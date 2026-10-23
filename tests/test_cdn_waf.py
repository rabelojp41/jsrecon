import httpx
import respx

from jsrecon.models import Mode
from jsrecon.modules.cdn_waf import CdnWafDetector, analyze_cname, analyze_headers
from jsrecon.providers.cdn_ranges import CDNRanges

AWS = {"prefixes": [{"ip_prefix": "13.32.0.0/15", "service": "CLOUDFRONT"},
                    {"ip_prefix": "3.0.0.0/8", "service": "EC2"}],
       "ipv6_prefixes": [{"ipv6_prefix": "2600:9000::/28", "service": "CLOUDFRONT"}]}


def mock_ranges(router, fail_cloudflare=False):
    if fail_cloudflare:
        router.get("https://www.cloudflare.com/ips-v4").respond(500)
    else:
        router.get("https://www.cloudflare.com/ips-v4").respond(200, text="104.16.0.0/13\n172.64.0.0/13\n")
    router.get("https://www.cloudflare.com/ips-v6").respond(200, text="2606:4700::/32\n")
    router.get("https://api.fastly.com/public-ip-list").respond(200, json={"addresses": ["151.101.0.0/16"], "ipv6_addresses": []})
    router.get("https://ip-ranges.amazonaws.com/ip-ranges.json").respond(200, json=AWS)
    router.post("https://my.imperva.com/api/integration/v1/ips").respond(200, json={"ipRanges": ["45.60.0.0/16"], "ipv6Ranges": []})
    router.get(url__startswith="https://stat.ripe.net/data/announced-prefixes/data.json").respond(
        200, json={"data": {"prefixes": [{"prefix": "23.32.0.0/11"}, {"prefix": "104.16.0.0/12"}]}}
    )


@respx.mock(assert_all_called=False)
async def test_ranges_lookup_and_cache(respx_mock, make_ctx):
    mock_ranges(respx_mock)
    ctx = make_ctx(Mode.PASSIVE)
    ranges, errors = await CDNRanges.load(ctx.http, ctx.cache)
    assert not errors
    assert ranges.provider_of("104.16.1.1") == "Cloudflare"  # oficial ganha do prefixo ASN sobreposto
    assert ranges.lookup("23.40.0.1").kind == "asn"
    assert ranges.provider_of("13.33.0.1") == "AWS CloudFront"
    assert ranges.provider_of("3.1.1.1") is None  # EC2 não é CDN
    assert ranges.provider_of("2606:4700::1") == "Cloudflare"
    # segunda carga vem do cache: nenhuma requisição nova
    n = len(respx_mock.calls)
    await CDNRanges.load(ctx.http, ctx.cache)
    assert len(respx_mock.calls) == n


@respx.mock(assert_all_called=False)
async def test_ranges_failure_uses_stale_cache(respx_mock, make_ctx, monkeypatch):
    mock_ranges(respx_mock, fail_cloudflare=True)
    ctx = make_ctx(Mode.PASSIVE)
    ctx.cache.set("cdn_ranges", "https://www.cloudflare.com/ips-v4", ["104.16.0.0/13"])
    import jsrecon.providers.cdn_ranges as mod
    monkeypatch.setattr(mod, "RANGES_TTL", -1)  # força cache "expirado"
    ranges, errors = await CDNRanges.load(ctx.http, ctx.cache)
    assert ranges.provider_of("104.16.1.1") == "Cloudflare"
    assert "usando cache antigo" in errors[0]


def test_header_and_cookie_signatures():
    headers = httpx.Headers([
        ("server", "cloudflare"), ("cf-ray", "8a1b2c3d4e-GRU"),
        ("set-cookie", "__cf_bm=abc; path=/; HttpOnly"), ("set-cookie", "incap_ses_123=x; path=/"),
        ("x-sucuri-id", "1234"),
    ])
    found = analyze_headers(headers)
    assert "header cf-ray: 8a1b2c3d4e-GRU" in found["Cloudflare"]
    assert "cookie __cf_bm" in found["Cloudflare"]
    assert "cookie incap_ses_123" in found["Imperva"]
    assert "Sucuri" in found


def test_cname_signatures():
    found = analyze_cname(["www.exemplo.com.edgekey.net", "e1234.a.akamaiedge.net"])
    assert len(found["Akamai"]) == 2


@respx.mock(assert_all_called=False)
async def test_module_active_cloudflare(respx_mock, make_ctx):
    mock_ranges(respx_mock)
    respx_mock.get("https://exemplo.com/").respond(200, headers={"cf-ray": "abc-GRU", "server": "cloudflare"})
    ctx = make_ctx(Mode.ACTIVE, records={("exemplo.com", "A"): ["104.16.5.5"]})
    res = await CdnWafDetector().run(ctx)
    cdn = ctx.result.cdn
    assert cdn.behind_cdn and cdn.provider_names() == ["Cloudflare"]
    assert cdn.providers[0].strong
    assert "Cloudflare (range + cf-ray + server)" == res.note
    assert ctx.shared["cdn_ranges"].provider_of("104.16.5.5") == "Cloudflare"


@respx.mock(assert_all_called=False)
async def test_module_passive_no_target_request(respx_mock, make_ctx):
    mock_ranges(respx_mock)
    target = respx_mock.route(host="exemplo.com")
    ctx = make_ctx(Mode.PASSIVE, records={
        ("exemplo.com", "A"): ["198.51.100.7"],
        ("exemplo.com", "CNAME"): ["exemplo.com.cdn.cloudflare.net"],
    })
    res = await CdnWafDetector().run(ctx)
    assert not target.called
    assert ctx.result.cdn.provider_names() == ["Cloudflare"]
    assert not ctx.result.cdn.providers[0].strong  # só CNAME
    assert res.status.value == "COM ACHADOS"


@respx.mock(assert_all_called=False)
async def test_module_no_cdn(respx_mock, make_ctx):
    mock_ranges(respx_mock)
    respx_mock.get("https://exemplo.com/").respond(200, headers={"server": "nginx"})
    ctx = make_ctx(Mode.ACTIVE, records={("exemplo.com", "A"): ["198.51.100.7"]})
    res = await CdnWafDetector().run(ctx)
    assert not ctx.result.cdn.behind_cdn
    assert res.status.value == "SEM ACHADOS"
