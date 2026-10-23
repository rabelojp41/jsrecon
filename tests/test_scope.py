import pytest

from jsrecon.scope import Scope, ScopeError


def test_exact_and_wildcard(scope):
    assert scope.contains_host("exemplo.com")
    assert scope.contains_host("API.Exemplo.com.")
    assert scope.contains_host("a.b.exemplo.com")
    assert not scope.contains_host("exemplo.com.br")
    assert not scope.contains_host("naoexemplo.com")


def test_exclusion_wins(scope):
    assert not scope.contains_host("legado.exemplo.com")
    assert scope.contains_host("x.legado.exemplo.com")  # exclusão exata, não wildcard


def test_wildcard_does_not_include_apex():
    s = Scope.from_lines(["*.exemplo.com"])
    assert not s.contains_host("exemplo.com")
    assert s.contains_host("www.exemplo.com")


def test_ips_and_cidrs(scope):
    assert scope.contains_host("203.0.113.7")
    assert not scope.contains_host("198.51.100.1")


def test_excluded_network():
    s = Scope.from_lines(["10.0.0.0/8", "!10.1.0.0/16"])
    assert s.contains_host("10.2.3.4")
    assert not s.contains_host("10.1.2.3")


def test_urls_and_ports(scope):
    assert scope.contains_url("https://api.exemplo.com:8443/v1/x")
    assert not scope.contains_url("https://evil.com/?r=exemplo.com")


def test_comments_and_url_entries():
    s = Scope.from_lines(["# comentário", "", "https://app.exemplo.com/path  # inline"])
    assert s.contains_host("app.exemplo.com")


def test_invalid_entries():
    with pytest.raises(ScopeError, match="linha 2"):
        Scope.from_lines(["exemplo.com", "300.1.1.1/40"])
    with pytest.raises(ScopeError):
        Scope.from_lines(["semponto"])


def test_from_file_empty(tmp_path):
    p = tmp_path / "scope.txt"
    p.write_text("# nada\n")
    with pytest.raises(ScopeError, match="nenhuma entrada"):
        Scope.from_file(p)


def test_summary(scope):
    assert "2 domínios" in scope.summary()
    assert "1 IP/CIDR" in scope.summary()
