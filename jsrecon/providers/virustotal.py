"""VirusTotal v3: resoluções DNS passivas e subdomínios."""

from __future__ import annotations

from datetime import datetime, timezone

from jsrecon.cache import DiskCache
from jsrecon.http import HttpClient

API = "https://www.virustotal.com/api/v3"
TTL = 24 * 3600


class VirusTotalError(Exception):
    pass


class VirusTotal:
    RATE = 4 / 60  # API pública: 4 req/min

    def __init__(self, http: HttpClient, cache: DiskCache, key: str):
        self.http = http
        self.cache = cache
        self.key = key
        http.set_host_rate("www.virustotal.com", self.RATE)

    async def _get(self, path: str, params: dict | None = None) -> dict:
        cache_key = f"{path}|{sorted((params or {}).items())}"
        cached = self.cache.get("virustotal", cache_key, TTL)
        if cached is not None:
            return cached
        resp = await self.http.get(f"{API}{path}", params=params, headers={"x-apikey": self.key})
        if resp.status_code == 404:
            data: dict = {}
        elif resp.status_code >= 400:
            raise VirusTotalError(f"HTTP {resp.status_code}")
        else:
            data = resp.json()
        self.cache.set("virustotal", cache_key, data)
        return data

    async def resolutions(self, domain: str) -> list[tuple[str, str]]:
        data = await self._get(f"/domains/{domain}/resolutions", {"limit": "40"})
        out = []
        for item in data.get("data") or []:
            attrs = item.get("attributes") or {}
            ip = attrs.get("ip_address")
            if ip:
                ts = attrs.get("date")
                when = datetime.fromtimestamp(ts, timezone.utc).date().isoformat() if isinstance(ts, int) else "?"
                out.append((ip, when))
        return out

    async def subdomains(self, domain: str) -> list[str]:
        data = await self._get(f"/domains/{domain}/subdomains", {"limit": "40"})
        return [item["id"] for item in data.get("data") or [] if item.get("id")]
