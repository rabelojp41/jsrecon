"""Testes ponta a ponta da CLI — todo HTTP e DNS é simulado."""

import json

import pytest
import respx
from typer.testing import CliRunner

import jsrecon.orchestrator as orchestrator
from jsrecon.cli import app
from jsrecon.dns import StaticResolver
from jsrecon.providers.shodan import ShodanClient
from tests.conftest import fixture_text
from tests.test_cdn_waf import mock_ranges

runner = CliRunner()
RECORDS = {
    ("exemplo.com", "A"): ["104.16.5.5"],
    ("mail.exemplo.com", "A"): ["198.51.100.10"],
    ("exemplo.com", "MX"): ["mail.exemplo.com"],
}


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setattr(orchestrator, "DnsResolver", lambda **kw: StaticResolver(RECORDS))
    monkeypatch.setattr(ShodanClient, "RATE", 0)
    for var in ("SHODAN_API_KEY", "SECURITYTRAILS_API_KEY", "VIRUSTOTAL_API_KEY"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def scope_file(tmp_path):
    p = tmp_path / "scope.txt"
    p.write_text("exemplo.com\n*.exemplo.com\n", encoding="utf-8")
    return p


def mock_all(router):
    mock_ranges(router)
    router.get("https://exemplo.com/").respond(
        200, text=fixture_text("index.html"), headers={"content-type": "text/html", "cf-ray": "abc-GRU", "server": "cloudflare"})
    router.get("https://exemplo.com/static/app.js").respond(200, text=fixture_text("app.js"))
    router.get("https://exemplo.com/static/app.js.map").respond(200, text=fixture_text("app.js.map"))
    router.get(url__regex=r"^https://exemplo\.com/.*").respond(404)
    router.get("https://web.archive.org/cdx/search/cdx").respond(200, json=[
        ["timestamp", "original", "digest", "statuscode", "mimetype"],
        ["20190101000000", "https://exemplo.com/static/old.js", "OLD", "200", "application/javascript"],
    ])
    router.get(url__regex=r"https://web\.archive\.org/web/20190101000000id_/.*").respond(
        200, text='fetch("/api/v0/legacy-export"); const t="ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";')
    router.get(url__startswith="https://web.archive.org/web/2id_/").respond(404)
    router.get(url__startswith="https://internetdb.shodan.io/").respond(200, json={"ports": [443], "vulns": []})


def _args(scope_file, tmp_path, *extra):
    return ["exemplo.com", "--scope", str(scope_file), "--no-cache", "--retries", "0",
            "--output-dir", str(tmp_path / "out"), "--rate", "0", "--passive-rate", "0", *extra]


@respx.mock(assert_all_called=False)
def test_json_mode_stdout_is_pure_json(respx_mock, scope_file, tmp_path):
    mock_all(respx_mock)
    res = runner.invoke(app, _args(scope_file, tmp_path, "--active", "--json"))
    assert res.exit_code == 0, res.output
    data = json.loads(res.stdout)
    assert data["meta"]["mode"] == "ativo"
    modules = {m["module"]: m for m in data["summary"]}
    assert modules["js"]["status"] == "COM ACHADOS"
    assert modules["cdn"]["note"].startswith("Cloudflare")
    assert modules["origin"]["status"] == "COM ACHADOS"
    gh = next(s for s in data["secrets"] if s["type"] == "GitHub Token")
    assert gh["value"] == "ghp_****************6789" and gh["origin"] == "histórico"
    assert any(e["value"] == "/api/v0/legacy-export" and e["only_historical"] for e in data["endpoints"])
    origin = next(o for o in data["origin_candidates"] if o["ip"] == "198.51.100.10")
    assert origin["verdict"] == "candidato" and not origin["validated"]
    assert not respx_mock.calls or all(c.request.url.host != "198.51.100.10" for c in respx_mock.calls)
    assert (tmp_path / "out" / "result.json").exists() and (tmp_path / "out" / "report.md").exists()


@respx.mock(assert_all_called=False)
def test_passive_never_touches_target(respx_mock, scope_file, tmp_path):
    mock_all(respx_mock)
    res = runner.invoke(app, _args(scope_file, tmp_path, "--json"))
    assert res.exit_code == 0, res.output
    assert all(c.request.url.host != "exemplo.com" for c in respx_mock.calls)
    data = json.loads(res.stdout)
    assert data["requests"]["active"] == 0
    assert {m["module"]: m["status"] for m in data["summary"]}["probe"] == "PULADO"


def test_target_out_of_scope_refused(scope_file, tmp_path):
    with respx.mock(assert_all_called=False) as router:
        res = runner.invoke(app, ["evil.com", "--scope", str(scope_file), "--active", "--no-save"])
        assert not router.calls
    assert res.exit_code == 2
    assert "não está no escopo" in res.stderr


def test_bad_scope_file(tmp_path):
    p = tmp_path / "s.txt"
    p.write_text("semponto\n")
    res = runner.invoke(app, ["exemplo.com", "--scope", str(p)])
    assert res.exit_code == 2 and "escopo" in res.stderr


@respx.mock(assert_all_called=False)
def test_human_output_quiet_html_and_reveal(respx_mock, scope_file, tmp_path):
    mock_all(respx_mock)
    html = tmp_path / "report.html"
    res = runner.invoke(app, _args(scope_file, tmp_path, "--active", "--quiet", "--reveal", "--html", str(html)))
    assert res.exit_code == 0, res.output
    assert "Resumo" in res.stdout and "Arquivo:linha" not in res.stdout  # quiet: só o painel final
    assert res.stderr == ""
    page = html.read_text(encoding="utf-8")
    assert "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789" in page  # --reveal
    assert "<h2>Secrets" in page and "Cloudflare" in page
    md = (tmp_path / "out" / "report.md").read_text(encoding="utf-8")
    assert "## Endpoints" in md and "REVELADOS" in md


@respx.mock(assert_all_called=False)
def test_human_output_tables_on_stdout_logs_on_stderr(respx_mock, scope_file, tmp_path):
    mock_all(respx_mock)
    res = runner.invoke(app, _args(scope_file, tmp_path, "--active", "--no-color"))
    assert res.exit_code == 0, res.output
    assert "Endpoints" in res.stdout and "Secrets" in res.stdout and "Resumo" in res.stdout
    assert "\x1b[" not in res.stdout
    assert "jsrecon | alvo=exemplo.com modo=ativo" in res.stderr
    assert "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789" not in res.stdout + res.stderr  # mascarado


@respx.mock(assert_all_called=False)
def test_without_scope_file_uses_target_and_subdomains(respx_mock, tmp_path):
    mock_all(respx_mock)
    respx_mock.get("https://cdn.terceiro.com/lib.js")
    res = runner.invoke(app, ["https://exemplo.com/qualquer", "--active", "--json", "--no-cache", "--retries", "0",
                              "--rate", "0", "--passive-rate", "0", "--output-dir", str(tmp_path / "out")])
    assert res.exit_code == 0, res.output
    data = json.loads(res.stdout)
    assert data["meta"]["scope"]["domains"] == ["exemplo.com", "*.exemplo.com"]
    assert all(c.request.url.host != "cdn.terceiro.com" for c in respx_mock.calls)  # trava continua valendo
    assert "escopo automático" in res.stderr or res.stderr == ""
