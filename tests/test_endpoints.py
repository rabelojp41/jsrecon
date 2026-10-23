from jsrecon.models import JSFile, Mode, Origin
from jsrecon.modules.endpoints import EndpointExtractor, aggregate, extract_endpoints, is_valid
from jsrecon.scope import Scope
from tests.conftest import fixture_text


def _by_value(raws):
    return {r.value: r for r in raws}


def test_extracts_methods_and_lines():
    eps = _by_value(extract_endpoints(fixture_text("app.js")))
    assert eps["/api/v2/login"].method == "POST" and eps["/api/v2/login"].line == 3
    assert eps["/api/v2/users/"].method == "DELETE"
    assert eps["/api/v2/orders/${orderId}"].method == "GET"
    assert "/api/v2" in eps
    assert eps["/graphql"].line == 7
    assert eps["query GetUser"].method == "POST"
    assert "./chunk.js" not in eps and "app.js.map" not in eps


def test_fetch_with_options_and_url_prop():
    js = """fetch('/api/items', {method: 'PUT', body: x});
    $.ajax({ url: "/legacy/save", type: "POST" });
    axios({ method: 'patch', url: '/api/profile' });
    """
    eps = _by_value(extract_endpoints(js))
    assert eps["/api/items"].method == "PUT"
    assert eps["/legacy/save"].method == "POST"
    assert eps["/api/profile"].method == "PATCH"


def test_absolute_urls_and_noise():
    js = 'a="https://api.exemplo.com/v1/users"; b="http://www.w3.org/2000/svg"; c="https://cdn.x.com/logo.png";'
    values = {r.value for r in extract_endpoints(js)}
    assert values == {"https://api.exemplo.com/v1/users"}


def test_is_valid_filters():
    assert not is_valid("/")
    assert not is_valid("/static/app.css")
    assert not is_valid("text/html")
    assert not is_valid("/abc/g")
    assert is_valid("/api/users?id=1")


def test_aggregate_marks_historical_and_scope():
    scope = Scope.from_lines(["exemplo.com", "*.exemplo.com"])
    cur = JSFile("https://exemplo.com/a.js", 'fetch("/api/a"); x="https://evil.com/api/x"', Origin.ATUAL, "page")
    old = JSFile("https://exemplo.com/a.js", 'fetch("/api/a"); fetch("/api/old")', Origin.HISTORICO, "wayback", timestamp="20190101000000")
    eps = {e.value: e for e in aggregate([cur, old], scope)}
    assert not eps["/api/a"].only_historical and len(eps["/api/a"].locations) == 2
    assert eps["/api/old"].only_historical
    assert eps["/api/old"].locations[0].file == "https://exemplo.com/a.js@20190101000000"
    assert eps["https://evil.com/api/x"].in_scope is False
    assert eps["/api/a"].kind == "api"


async def test_module(make_ctx):
    ctx = make_ctx(Mode.PASSIVE)
    ctx.result.js_files = [JSFile("https://exemplo.com/app.js", fixture_text("app.js"), Origin.ATUAL, "page")]
    res = await EndpointExtractor().run(ctx)
    assert res.status.value == "COM ACHADOS" and res.findings == len(ctx.result.endpoints)


async def test_module_skipped_without_files(make_ctx):
    res = await EndpointExtractor().run(make_ctx(Mode.PASSIVE))
    assert res.status.value == "PULADO"
