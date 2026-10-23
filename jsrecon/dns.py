"""Resolução DNS assíncrona (consultas vão a resolvers, não ao servidor do alvo)."""

from __future__ import annotations

import asyncio
from typing import Protocol

import dns.asyncresolver
import dns.exception
import dns.resolver

from jsrecon.scope import normalize_host


class Resolver(Protocol):
    async def resolve(self, name: str, rdtype: str) -> list[str]: ...


class DnsResolver:
    def __init__(self, timeout: float = 5.0, nameservers: list[str] | None = None):
        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.lifetime = timeout
        if nameservers:
            self._resolver.nameservers = nameservers
        self._cache: dict[tuple[str, str], list[str]] = {}

    async def resolve(self, name: str, rdtype: str) -> list[str]:
        key = (normalize_host(name), rdtype.upper())
        if key in self._cache:
            return self._cache[key]
        try:
            answer = await self._resolver.resolve(key[0], key[1])
            values = [_format(rdata, key[1]) for rdata in answer]
        except (dns.exception.DNSException, asyncio.TimeoutError, OSError):
            values = []
        self._cache[key] = values
        return values


def _format(rdata, rdtype: str) -> str:
    if rdtype == "MX":
        return str(rdata.exchange).rstrip(".").lower()
    if rdtype == "TXT":
        return b"".join(rdata.strings).decode("utf-8", "replace")
    if rdtype in ("CNAME", "NS"):
        return str(rdata.target).rstrip(".").lower()
    return rdata.to_text()


async def resolve_ips(resolver: Resolver, name: str) -> list[str]:
    a, aaaa = await asyncio.gather(resolver.resolve(name, "A"), resolver.resolve(name, "AAAA"))
    return list(dict.fromkeys(a + aaaa))


async def resolve_cname_chain(resolver: Resolver, name: str, max_depth: int = 8) -> list[str]:
    chain: list[str] = []
    current = name
    for _ in range(max_depth):
        targets = await resolver.resolve(current, "CNAME")
        if not targets or targets[0] in chain:
            break
        chain.append(targets[0])
        current = targets[0]
    return chain


class StaticResolver:
    """Resolver em memória — usado nos testes e para IPs passados pelo usuário."""

    def __init__(self, records: dict[tuple[str, str], list[str]] | None = None):
        self.records = {(normalize_host(n), t.upper()): v for (n, t), v in (records or {}).items()}

    async def resolve(self, name: str, rdtype: str) -> list[str]:
        return list(self.records.get((normalize_host(name), rdtype.upper()), []))
