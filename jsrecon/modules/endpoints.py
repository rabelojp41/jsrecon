"""Módulo 2a — extração de endpoints e rotas de API dos arquivos JS."""

from __future__ import annotations

import re
from dataclasses import dataclass

from jsrecon.analysis.entropy import LineIndex
from jsrecon.models import Endpoint, JSFile, Location, ModuleResult
from jsrecon.modules.base import Context, Module
from jsrecon.scope import Scope, host_of

Q = r"""["'`]"""
HTTP_METHODS = "GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS"

# (regex, grupo do método ou método fixo, grupo da URL)
METHOD_PATTERNS: list[tuple[re.Pattern[str], str | int | None, int]] = [
    # fetch("url", { method: "POST" })
    (re.compile(rf"""\bfetch\s*\(\s*({Q})(?P<url>[^"'`\n]+?)\1\s*(?:,\s*\{{(?P<opts>[^{{}}]{{0,400}})\}})?"""), "opts", 2),
    # axios.post("url") / this.http.get("/url") / $.getJSON("/url") / client.delete("/url")
    (re.compile(rf"""\.\s*(get|post|put|patch|delete|head|options|getJSON)\s*\(\s*({Q})(?P<url>(?:/|https?://)[^"'`\n]+?)\2""", re.I), 1, 3),
    # xhr.open("DELETE", "/url")
    (re.compile(rf"""\.open\s*\(\s*{Q}({HTTP_METHODS}){Q}\s*,\s*({Q})(?P<url>[^"'`\n]+?)\2""", re.I), 1, 3),
]
# axios({ url: "...", method: "post" }) / $.ajax({ url: "...", type: "POST" })
URL_PROP = re.compile(rf"""\burl\s*:\s*({Q})(?P<url>[^"'`\n]+?)\1""")
METHOD_PROP = re.compile(rf"""\b(?:method|type)\s*:\s*{Q}({HTTP_METHODS}){Q}""", re.I)

ABS_URL = re.compile(r"""\bhttps?://[A-Za-z0-9.\-]+(?::\d+)?(?:/[^\s"'`<>\\)\]}]*)?""")
QUOTED_PATH = re.compile(rf"""{Q}(/(?!/)[A-Za-z0-9_\-.~/%{{}}$:?=&+,;@!*]*[A-Za-z0-9_\-}}/])["'`]""")
QUOTED_REL_API = re.compile(
    rf"""{Q}((?:api|rest|graphql|internal|admin|auth|v\d+)/[A-Za-z0-9_\-./%{{}}$:?=&]*)["'`]""", re.I
)
GRAPHQL_OP = re.compile(r"""\b(query|mutation|subscription)\s+([A-Za-z_]\w*)\s*[({]""")

STATIC_EXT = re.compile(
    r"\.(png|jpe?g|gif|svg|ico|webp|bmp|avif|css|less|scss|woff2?|ttf|eot|otf|mp4|mp3|webm|wav|ogg|"
    r"map|md|txt|m?js|ts|tsx|jsx|vue|html?)(\?|#|$)",
    re.I,
)
API_HINT = re.compile(r"(^|/)(api|rest|v\d+|graphql|internal|admin|auth|oauth2?|private|backend)(/|$|\?)", re.I)
NOISE_HOSTS = re.compile(
    r"(^|\.)(w3\.org|schema\.org|reactjs\.org|react\.dev|fb\.me|github\.com|mozilla\.org|npmjs\.(com|org)|"
    r"jquery\.com|angular\.io|vuejs\.org|lodash\.com|opensource\.org|json-schema\.org|example\.(com|org|net)|"
    r"momentjs\.com|underscorejs\.org|feross\.org|apache\.org|tc39\.es|whatwg\.org|ecma-international\.org|"
    r"jsperf\.com|stackoverflow\.com|wikipedia\.org|goo\.gl|bit\.ly|xml\.org|ietf\.org)$",
    re.I,
)
TRAILING = ".,;:)]}'\"`"


@dataclass
class RawEndpoint:
    value: str
    method: str
    line: int


def _method_from_opts(opts: str | None) -> str:
    if opts:
        m = METHOD_PROP.search(opts)
        if m:
            return m.group(1).upper()
    return "GET"


def _clean(value: str) -> str:
    return value.strip().rstrip(TRAILING) if value.startswith("http") else value.strip()


def is_valid(value: str) -> bool:
    if not 2 <= len(value) <= 400 or any(c in value for c in " \n\t\\<>"):
        return False
    if value.startswith("http"):
        host = host_of(value)
        if not host or "." not in host or NOISE_HOSTS.search(host):
            return False
        path = value.split(host, 1)[-1]
        return not STATIC_EXT.search(path.split("?", 1)[0])
    if value in ("/", "//") or not re.search(r"[A-Za-z]", value):
        return False
    if STATIC_EXT.search(value.split("?", 1)[0]):
        return False
    if re.fullmatch(r"/[\w\-]*/[gimsuy]*", value):  # literal de regex /abc/g
        return False
    if re.match(r"^/?(text|application|image|audio|video|multipart|font)/", value):  # MIME type
        return False
    return True


def classify(value: str) -> str:
    low = value.lower()
    if "graphql" in low:
        return "graphql"
    path = low.split("://", 1)[-1]
    path = path[path.find("/"):] if "://" in low else path
    if API_HINT.search(path):
        return "api"
    return "absoluta" if low.startswith("http") else "relativa"


def extract_endpoints(text: str) -> list[RawEndpoint]:
    lines = LineIndex(text)
    found: dict[tuple[str, int], RawEndpoint] = {}

    def add(value: str, method: str, offset: int) -> None:
        value = _clean(value)
        if not is_valid(value):
            return
        line = lines.line(offset)
        key = (value, line)
        cur = found.get(key)
        if cur is None or (cur.method == "?" and method != "?"):
            found[key] = RawEndpoint(value, method, line)

    for regex, method_ref, _ in METHOD_PATTERNS:
        for m in regex.finditer(text):
            if method_ref == "opts":
                method = _method_from_opts(m.group("opts"))
            else:
                method = m.group(method_ref).upper()  # type: ignore[arg-type]
                method = "GET" if method == "GETJSON" else method
            add(m.group("url"), method, m.start("url"))

    for m in URL_PROP.finditer(text):
        # procura o método só dentro do mesmo objeto literal { ... }
        start = text.rfind("{", max(0, m.start() - 300), m.start())
        end = text.find("}", m.end(), m.end() + 300)
        window = text[start:end] if start != -1 and end != -1 else ""
        mm = METHOD_PROP.search(window)
        add(m.group("url"), mm.group(1).upper() if mm else "?", m.start("url"))

    for regex in (ABS_URL,):
        for m in regex.finditer(text):
            add(m.group(0), "?", m.start())
    for regex in (QUOTED_PATH, QUOTED_REL_API):
        for m in regex.finditer(text):
            add(m.group(1), "?", m.start(1))

    for m in GRAPHQL_OP.finditer(text):
        # só considera operações dentro de strings/template literals GraphQL plausíveis
        context = text[max(0, m.start() - 40): m.start()]
        if any(q in context for q in "`'\"") or "gql" in context:
            found[(f"{m.group(1)} {m.group(2)}", lines.line(m.start()))] = RawEndpoint(
                f"{m.group(1)} {m.group(2)}", "POST", lines.line(m.start())
            )
    return list(found.values())


def aggregate(files: list[JSFile], scope: Scope) -> list[Endpoint]:
    by_key: dict[tuple[str, str], Endpoint] = {}
    for f in files:
        for raw in extract_endpoints(f.content):
            kind = "graphql-op" if raw.value.split(" ", 1)[0] in ("query", "mutation", "subscription") else classify(raw.value)
            key = (raw.method, raw.value)
            ep = by_key.get(key)
            if ep is None:
                in_scope = scope.contains_url(raw.value) if raw.value.startswith("http") else None
                ep = by_key[key] = Endpoint(raw.value, raw.method, kind, in_scope=in_scope)
            loc = Location(f.label, raw.line, f.origin)
            if not any(l.file == loc.file and l.line == loc.line for l in ep.locations):
                ep.locations.append(loc)
    order = {"api": 0, "graphql": 0, "graphql-op": 1, "relativa": 2, "absoluta": 3}
    return sorted(by_key.values(), key=lambda e: (order.get(e.kind, 9), e.value, e.method))


class EndpointExtractor(Module):
    key = "endpoints"
    title = "Endpoints"

    async def run(self, ctx: Context) -> ModuleResult:
        files = ctx.result.js_files
        if not files:
            return self.skipped("nenhum arquivo JS coletado")
        ctx.result.endpoints = aggregate(files, ctx.settings.scope)
        eps = ctx.result.endpoints
        hist = sum(1 for e in eps if e.only_historical)
        api = sum(1 for e in eps if e.kind in ("api", "graphql", "graphql-op"))
        note = f"{api} de API/GraphQL"
        if hist:
            note += f", {hist} só em versões antigas"
        return self.done(len(eps), note)
