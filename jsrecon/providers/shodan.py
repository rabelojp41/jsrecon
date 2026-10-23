"""Cliente Shodan: InternetDB (sem chave), API completa, /api-info e busca.

Respeita 1 req/s (rate limit por host no HttpClient) e cacheia respostas por 24h.
As chaves de cache nunca incluem a chave de API.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import httpx

from jsrecon.cache import DiskCache
from jsrecon.http import HttpClient
from jsrecon.models import HostIntel

API = "https://api.shodan.io"
INTERNETDB = "https://internetdb.shodan.io"
TTL = 24 * 3600
PLAN_TTL = 3600
HOSTNAME_RE = re.compile(r"(?:\*\.)?(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", re.I)


class ShodanError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


@dataclass
class ShodanPlan:
    plan: str | None
    query_credits: int = 0
    scan_credits: int = 0

    @property
    def can_search(self) -> bool:
        return self.query_credits > 0

    def search_skip_reason(self) -> str:
        return f"plano '{self.plan or 'desconhecido'}' sem query credits — busca (ex.: favicon) não permitida"


class ShodanClient:
    RATE = 1.0  # req/s (limite da API)

    def __init__(self, http: HttpClient, cache: DiskCache, key: str | None):
        self.http = http
        self.cache = cache
        self.key = key
        http.set_host_rate("api.shodan.io", self.RATE)
        http.set_host_rate("internetdb.shodan.io", self.RATE)

    async def _get_json(self, url: str, cache_key: str, ttl: float, params: dict | None = None) -> Any:
        cached = self.cache.get("shodan", cache_key, ttl)
        if cached is not None:
            return cached
        resp = await self.http.get(url, params=params)
        if resp.status_code == 404:
            data: Any = {}
        elif resp.status_code in (401, 403):
            raise ShodanError(_error_message(resp), resp.status_code)
        elif resp.status_code >= 400:
            raise ShodanError(f"HTTP {resp.status_code}: {_error_message(resp)}", resp.status_code)
        else:
            data = resp.json()
        self.cache.set("shodan", cache_key, data)
        return data

    async def api_info(self) -> ShodanPlan:
        if not self.key:
            raise ShodanError("sem chave")
        data = await self._get_json(f"{API}/api-info", "api-info", PLAN_TTL, {"key": self.key})
        return ShodanPlan(data.get("plan"), int(data.get("query_credits") or 0), int(data.get("scan_credits") or 0))

    async def internetdb(self, ip: str) -> dict:
        return await self._get_json(f"{INTERNETDB}/{ip}", f"internetdb|{ip}", TTL)

    async def host(self, ip: str) -> dict:
        if not self.key:
            raise ShodanError("sem chave")
        return await self._get_json(f"{API}/shodan/host/{ip}", f"host|{ip}", TTL, {"key": self.key})

    async def search_favicon(self, favicon_hash: int, max_results: int = 100) -> list[str]:
        if not self.key:
            raise ShodanError("sem chave")
        query = f"http.favicon.hash:{favicon_hash}"
        data = await self._get_json(
            f"{API}/shodan/host/search", f"search|{query}", TTL,
            {"key": self.key, "query": query, "minify": "true"},
        )
        ips = [m.get("ip_str") for m in data.get("matches", []) if m.get("ip_str")]
        return list(dict.fromkeys(ips))[:max_results]


def _error_message(resp: httpx.Response) -> str:
    try:
        return str(resp.json().get("error") or resp.reason_phrase)
    except ValueError:
        return resp.reason_phrase or f"HTTP {resp.status_code}"


# ------------------------------------------------------------------ parsing
def intel_from_internetdb(ip: str, data: dict) -> HostIntel:
    return HostIntel(
        ip=ip,
        source="internetdb",
        ports=sorted(data.get("ports") or []),
        services=list(data.get("cpes") or []),
        cves=sorted(data.get("vulns") or []),
        hostnames=list(data.get("hostnames") or []),
    )


def intel_from_host(ip: str, data: dict) -> HostIntel:
    services: list[str] = []
    cves: set[str] = set(_vulns(data.get("vulns")))
    sans: set[str] = set()
    for banner in data.get("data") or []:
        desc = " ".join(str(x) for x in (banner.get("product"), banner.get("version")) if x)
        port = f"{banner.get('port')}/{banner.get('transport', 'tcp')}"
        services.append(f"{port} {desc}".strip())
        cves |= set(_vulns(banner.get("vulns")))
        sans |= extract_sans(banner.get("ssl") or {})
    asn = data.get("asn")
    return HostIntel(
        ip=ip,
        source="shodan",
        org=data.get("org") or data.get("isp"),
        asn=str(asn) if asn else None,
        ports=sorted(data.get("ports") or []),
        services=list(dict.fromkeys(services)),
        cves=sorted(cves),
        hostnames=list(data.get("hostnames") or []),
        sans=sorted(sans),
    )


def _vulns(value: Any) -> list[str]:
    if isinstance(value, dict):
        return list(value.keys())
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


def extract_sans(ssl: dict) -> set[str]:
    names: set[str] = set()
    cert = ssl.get("cert") or {}
    cn = (cert.get("subject") or {}).get("CN")
    if isinstance(cn, str) and HOSTNAME_RE.fullmatch(cn):
        names.add(cn.lower())
    for ext in cert.get("extensions") or []:
        if ext.get("name") == "subjectAltName" and isinstance(ext.get("data"), str):
            names |= {m.lower() for m in HOSTNAME_RE.findall(ext["data"])}
    chain = ssl.get("chain") or []
    if chain:
        names |= _sans_from_pem(chain[0])
    return names


def _sans_from_pem(pem: str) -> set[str]:
    try:
        from cryptography import x509

        cert = x509.load_pem_x509_certificate(pem.encode())
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return {n.lower() for n in ext.value.get_values_for_type(x509.DNSName)}
    except Exception:  # certificado ausente/malformado/sem SAN
        return set()
