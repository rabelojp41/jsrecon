"""SecurityTrails: histórico de registros A e subdomínios."""

from __future__ import annotations

from jsrecon.cache import DiskCache
from jsrecon.http import HttpClient

API = "https://api.securitytrails.com/v1"
TTL = 24 * 3600


class SecurityTrailsError(Exception):
    pass


class SecurityTrails:
    RATE = 1.0  # req/s

    def __init__(self, http: HttpClient, cache: DiskCache, key: str):
        self.http = http
        self.cache = cache
        self.key = key
        http.set_host_rate("api.securitytrails.com", self.RATE)

    async def _get(self, path: str, params: dict | None = None) -> dict:
        cache_key = f"{path}|{sorted((params or {}).items())}"
        cached = self.cache.get("securitytrails", cache_key, TTL)
        if cached is not None:
            return cached
        resp = await self.http.get(f"{API}{path}", params=params, headers={"APIKEY": self.key, "Accept": "application/json"})
        if resp.status_code == 404:
            data: dict = {}
        elif resp.status_code >= 400:
            raise SecurityTrailsError(f"HTTP {resp.status_code}")
        else:
            data = resp.json()
        self.cache.set("securitytrails", cache_key, data)
        return data

    async def a_history(self, domain: str) -> list[tuple[str, str]]:
        """[(ip, período)] — período no formato 'first_seen..last_seen'."""
        data = await self._get(f"/history/{domain}/dns/a")
        out: list[tuple[str, str]] = []
        for record in data.get("records") or []:
            period = f"{record.get('first_seen', '?')}..{record.get('last_seen', '?')}"
            for value in record.get("values") or []:
                if value.get("ip"):
                    out.append((value["ip"], period))
        return out

    async def subdomains(self, domain: str) -> list[str]:
        data = await self._get(f"/domain/{domain}/subdomains", {"children_only": "false"})
        return [f"{s}.{domain}" for s in data.get("subdomains") or [] if s]
