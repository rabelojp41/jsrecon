import base64
import json

from jsrecon.models import Confidence, JSFile, Mode, Origin, mask_secret
from jsrecon.modules.secrets import SecretScanner, scan
from tests.conftest import fixture_text


def _jwt():
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'HS256', 'typ': 'JWT'})}.{enc({'sub': '1234567890', 'name': 'x'})}.c2lnbmF0dXJlX2Jsb2I"


def _scan(text, origin=Origin.ATUAL):
    return {s.type: s for s in scan(JSFile("https://exemplo.com/a.js", text, origin, "page"))}


def test_known_patterns_high_confidence():
    text = "\n".join([
        'const k = "AKIAQ3EGRT5JXH7PLM2N";',
        'const g = "AIzaSyA1b2C3d4E5f6G7h8I9j0KlMnOpQrStUvW";',
        'const s = "xoxb-1234567890-abcdefghijklmnop";',
        f'const t = "{_jwt()}";',
        'const db = "postgres://app:S3cr3tP4ss@db.internal:5432/prod";',
        'const pk = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEAuZ8y\\n-----END RSA PRIVATE KEY-----";',
    ])
    found = _scan(text)
    for name in ("AWS Access Key ID", "Google API Key", "Slack Token", "JWT", "Connection string", "Chave privada"):
        assert found[name].confidence is Confidence.ALTA, name
    assert "Chave privada (cabeçalho)" not in found  # coberto pelo bloco completo
    assert found["AWS Access Key ID"].location.line == 1
    assert found["Connection string"].location.line == 5


def test_placeholders_and_weak_values():
    found = _scan('db = "mysql://user:password@localhost/db"; k="AKIAXXXXXXXXXXXXXXXX";')
    assert found["Connection string"].confidence is Confidence.BAIXA
    assert "AWS Access Key ID" not in found or found["AWS Access Key ID"].confidence is Confidence.BAIXA


def test_generic_assignment_confidence():
    found = _scan('config = { apiKey: "q8Zr2LmX0vT7nB4k", secret: "changeme", token: "authorization" }')
    generic = [s for t, s in found.items() if t.startswith("Atribuição")]
    assert len(generic) == 1 and generic[0].confidence is Confidence.MEDIA


def test_entropy_low_confidence_and_filters():
    text = (
        'a="Zx9qL2vB7nT4kR8mW1pY6sD3fG5hJ0cV";'  # aleatória -> baixa
        'b="d41d8cd98f00b204e9800998ecf8427e";'  # hash hex -> ignorado
        'c="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123";'  # alfabeto -> ignorado
        'd="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K";'  # SRI -> ignorado
    )
    found = scan(JSFile("https://exemplo.com/a.js", text, Origin.ATUAL, "page"))
    assert [s.value for s in found] == ["Zx9qL2vB7nT4kR8mW1pY6sD3fG5hJ0cV"]
    assert found[0].confidence is Confidence.BAIXA


def test_mask():
    assert mask_secret("AKIAQ3EGRT5JXH7PLM2N") == "AKIA************LM2N"
    assert mask_secret("short") == "sh****"
    s = _scan('k="AKIAQ3EGRT5JXH7PLM2N"')["AWS Access Key ID"]
    assert s.to_dict()["value"] == "AKIA************LM2N"
    assert s.to_dict(reveal=True)["value"] == "AKIAQ3EGRT5JXH7PLM2N"


async def test_module_sorted_and_sourcemap(make_ctx):
    ctx = make_ctx(Mode.PASSIVE)
    ctx.result.js_files = [
        JSFile("https://exemplo.com/app.js", fixture_text("app.js"), Origin.ATUAL, "page"),
        JSFile("https://exemplo.com/app.js.map::src/api.ts", "const slack = 'xoxb-1234567890-abcdefghijklmnop';",
               Origin.ATUAL, "sourcemap"),
    ]
    res = await SecretScanner().run(ctx)
    assert res.findings == 2
    assert all(s.confidence is Confidence.ALTA for s in ctx.result.secrets)
    assert ctx.result.secrets[1].location.file.endswith("::src/api.ts")
