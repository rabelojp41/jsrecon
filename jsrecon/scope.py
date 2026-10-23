"""Escopo autorizado: domínios exatos, wildcards, IPs/CIDRs e exclusões."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class ScopeError(ValueError):
    """Arquivo de escopo inválido."""


def normalize_host(host: str) -> str:
    """Minúsculas, sem ponto final, sem porta, sem colchetes de IPv6."""
    host = host.strip().lower()
    if host.startswith("["):
        return host[1:].split("]", 1)[0]
    if host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host.rstrip(".")


def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(normalize_host(value))
    except ValueError:
        return None


def host_of(url: str) -> str:
    return normalize_host(urlsplit(url).hostname or "")


@dataclass
class Scope:
    exact: set[str] = field(default_factory=set)
    wildcards: set[str] = field(default_factory=set)  # sufixos, sem o "*."
    networks: list[IPNetwork] = field(default_factory=list)
    excluded: set[str] = field(default_factory=set)
    excluded_wildcards: set[str] = field(default_factory=set)
    excluded_networks: list[IPNetwork] = field(default_factory=list)

    @classmethod
    def from_file(cls, path: str | Path) -> "Scope":
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise ScopeError(f"não foi possível ler o arquivo de escopo: {exc}") from exc
        scope = cls.from_lines(text.splitlines())
        if scope.is_empty():
            raise ScopeError("o arquivo de escopo não tem nenhuma entrada válida")
        return scope

    @classmethod
    def from_lines(cls, lines: list[str]) -> "Scope":
        scope = cls()
        for lineno, raw in enumerate(lines, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                scope.add(line)
            except ScopeError as exc:
                raise ScopeError(f"linha {lineno}: {exc}") from exc
        return scope

    def add(self, entry: str) -> None:
        negate = entry.startswith("!")
        entry = entry.lstrip("!").strip()
        if "://" in entry:
            entry = urlsplit(entry).hostname or ""
        if not entry:
            raise ScopeError("entrada vazia")

        if "/" in entry or parse_ip(entry) is not None:
            try:
                net = ipaddress.ip_network(entry, strict=False)
            except ValueError as exc:
                raise ScopeError(f"IP/CIDR inválido: {entry!r}") from exc
            (self.excluded_networks if negate else self.networks).append(net)
            return

        host = normalize_host(entry)
        if host.startswith("*."):
            suffix = host[2:]
            _validate_hostname(suffix)
            (self.excluded_wildcards if negate else self.wildcards).add(suffix)
        else:
            _validate_hostname(host)
            (self.excluded if negate else self.exact).add(host)

    def is_empty(self) -> bool:
        return not (self.exact or self.wildcards or self.networks)

    def contains_host(self, host: str) -> bool:
        host = normalize_host(host)
        if not host:
            return False
        ip = parse_ip(host)
        if ip is not None:
            if any(ip in n for n in self.excluded_networks):
                return False
            return any(ip in n for n in self.networks)
        if host in self.excluded or _matches_wildcard(host, self.excluded_wildcards):
            return False
        return host in self.exact or _matches_wildcard(host, self.wildcards)

    def contains_url(self, url: str) -> bool:
        return self.contains_host(host_of(url))

    def summary(self) -> str:
        parts = []
        n_domains = len(self.exact) + len(self.wildcards)
        if n_domains:
            parts.append(f"{n_domains} domínio{'s' if n_domains != 1 else ''}")
        if self.networks:
            parts.append(f"{len(self.networks)} IP/CIDR")
        n_excl = len(self.excluded) + len(self.excluded_wildcards) + len(self.excluded_networks)
        if n_excl:
            parts.append(f"{n_excl} exclusão(ões)")
        return ", ".join(parts) or "vazio"

    def to_dict(self) -> dict:
        return {
            "domains": sorted(self.exact) + sorted(f"*.{w}" for w in self.wildcards),
            "networks": [str(n) for n in self.networks],
            "excluded": sorted(self.excluded)
            + sorted(f"*.{w}" for w in self.excluded_wildcards)
            + [str(n) for n in self.excluded_networks],
        }


def _matches_wildcard(host: str, suffixes: set[str]) -> bool:
    return any(host.endswith("." + s) for s in suffixes)


def _validate_hostname(host: str) -> None:
    if not host or " " in host or "*" in host or "." not in host and host != "localhost":
        raise ScopeError(f"domínio inválido: {host!r}")
