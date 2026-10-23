"""Ranges de IP publicados por CDNs/WAFs (baixados e cacheados por 24h).

Cloudflare, Fastly, AWS CloudFront e Imperva publicam listas oficiais.
A Akamai não publica: usamos os prefixos anunciados pelos ASNs dela (RIPEstat),
o que é uma evidência mais fraca (kind="asn").
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Callable

import httpx

from jsrecon.cache import DiskCache
from jsrecon.http import HttpClient, OutOfScopeError
from jsrecon.scope import IPNetwork

RANGES_TTL = 24 * 3600


def _text_lines(body: str) -> list[str]:
    return [l.strip() for l in body.splitlines() if l.strip() and not l.startswith("#")]


def _fastly(data: Any) -> list[str]:
    return list(data.get("addresses", [])) + list(data.get("ipv6_addresses", []))


def _cloudfront(data: Any) -> list[str]:
    v4 = [p["ip_prefix"] for p in data.get("prefixes", []) if p.get("service") == "CLOUDFRONT"]
    v6 = [p["ipv6_prefix"] for p in data.get("ipv6_prefixes", []) if p.get("service") == "CLOUDFRONT"]
    return v4 + v6


def _imperva(data: Any) -> list[str]:
    return list(data.get("ipRanges", [])) + list(data.get("ipv6Ranges", []))


def _ripestat(data: Any) -> list[str]:
    return [p["prefix"] for p in data.get("data", {}).get("prefixes", []) if "prefix" in p]


@dataclass(frozen=True)
class RangeSource:
    provider: str
    url: str
    parse: Callable[[Any], list[str]]
    kind: str = "oficial"  # oficial | asn
    json: bool = True
    method: str = "GET"
    form: tuple[tuple[str, str], ...] = ()


SOURCES: tuple[RangeSource, ...] = (
    RangeSource("Cloudflare", "https://www.cloudflare.com/ips-v4", _text_lines, json=False),
    RangeSource("Cloudflare", "https://www.cloudflare.com/ips-v6", _text_lines, json=False),
    RangeSource("Fastly", "https://api.fastly.com/public-ip-list", _fastly),
    RangeSource("AWS CloudFront", "https://ip-ranges.amazonaws.com/ip-ranges.json", _cloudfront),
    RangeSource("Imperva", "https://my.imperva.com/api/integration/v1/ips", _imperva,
                method="POST", form=(("resp_format", "json"),)),
    RangeSource("Akamai", "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS20940",
                _ripestat, kind="asn"),
    RangeSource("Akamai", "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS16625",
                _ripestat, kind="asn"),
)


@dataclass(frozen=True)
class RangeMatch:
    provider: str
    network: str
    kind: str


class CDNRanges:
    def __init__(self, entries: list[tuple[IPNetwork, str, str]] | None = None):
        self.entries = entries or []

    def lookup(self, ip: str) -> RangeMatch | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        best: tuple[IPNetwork, str, str] | None = None
        for net, provider, kind in self.entries:
            if addr.version == net.version and addr in net:
                # lista oficial ganha de ASN; prefixo mais específico ganha
                rank = (kind != "oficial", -net.prefixlen)
                if best is None or rank < (best[2] != "oficial", -best[0].prefixlen):
                    best = (net, provider, kind)
        return RangeMatch(best[1], str(best[0]), best[2]) if best else None

    def provider_of(self, ip: str) -> str | None:
        match = self.lookup(ip)
        return match.provider if match else None

    @classmethod
    async def load(cls, http: HttpClient, cache: DiskCache) -> tuple["CDNRanges", list[str]]:
        entries: list[tuple[IPNetwork, str, str]] = []
        errors: list[str] = []
        for src in SOURCES:
            prefixes = cache.get("cdn_ranges", src.url, RANGES_TTL)
            if prefixes is None:
                try:
                    if src.method == "POST":
                        resp = await http.request("POST", src.url, data=dict(src.form))
                    else:
                        resp = await http.get(src.url)
                    resp.raise_for_status()
                    prefixes = src.parse(resp.json() if src.json else resp.text)
                    cache.set("cdn_ranges", src.url, prefixes)
                except (httpx.HTTPError, OutOfScopeError, ValueError, KeyError, AttributeError) as exc:
                    prefixes = cache.get("cdn_ranges", src.url, RANGES_TTL, allow_stale=True)
                    suffix = " (usando cache antigo)" if prefixes else ""
                    errors.append(f"{src.provider}: falha ao baixar ranges ({type(exc).__name__}){suffix}")
                    prefixes = prefixes or []
            for prefix in prefixes:
                try:
                    entries.append((ipaddress.ip_network(prefix, strict=False), src.provider, src.kind))
                except ValueError:
                    continue
        return cls(entries), errors
