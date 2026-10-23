"""Shodan CVEDB (cvedb.shodan.io): CVSS, EPSS e KEV por CVE — gratuito, sem chave.

Só consulta metadados públicos da CVE; nunca envia nada ao alvo.
"""

from __future__ import annotations

from jsrecon.cache import DiskCache
from jsrecon.http import HttpClient
from jsrecon.models import CveInfo

API = "https://cvedb.shodan.io/cve"
TTL = 24 * 3600


class CveDbError(Exception):
    pass


class CveDb:
    RATE = 2.0  # req/s

    def __init__(self, http: HttpClient, cache: DiskCache):
        self.http = http
        self.cache = cache
        http.set_host_rate("cvedb.shodan.io", self.RATE)

    async def lookup(self, cve_id: str) -> CveInfo:
        data = self.cache.get("cvedb", cve_id, TTL)
        if data is None:
            resp = await self.http.get(f"{API}/{cve_id}")
            if resp.status_code == 404:
                data = {"_missing": True}
            elif resp.status_code >= 400:
                raise CveDbError(f"HTTP {resp.status_code}")
            else:
                data = resp.json()
            self.cache.set("cvedb", cve_id, data)
        return parse(cve_id, data)


def _float(value) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def parse(cve_id: str, data: dict) -> CveInfo:
    if not isinstance(data, dict) or data.get("_missing") or "cve_id" not in data:
        return CveInfo(cve_id, found=False)
    cvss = _float(data.get("cvss_v3")) or _float(data.get("cvss"))
    version = _float(data.get("cvss_version"))
    if data.get("cvss_v3") is not None:
        version = version if version and version >= 3 else 3.0
    summary = data.get("summary")
    return CveInfo(
        id=data.get("cve_id") or cve_id,
        summary=" ".join(summary.split()) if isinstance(summary, str) else None,
        cvss=cvss,
        cvss_version=version,
        epss=_float(data.get("epss")),
        kev=bool(data.get("kev")),
        published=(data.get("published_time") or "")[:10] or None,
    )
