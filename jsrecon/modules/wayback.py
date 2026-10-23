"""Cliente da CDX API do Wayback Machine (fonte passiva)."""

from __future__ import annotations

from dataclasses import dataclass

from jsrecon.cache import DiskCache
from jsrecon.http import HttpClient

CDX_URL = "https://web.archive.org/cdx/search/cdx"
CDX_TTL = 24 * 3600
JS_FILTER = r"original:.*\.m?js(\?.*)?$"


@dataclass(frozen=True)
class CdxRecord:
    timestamp: str
    original: str
    digest: str
    statuscode: str = ""
    mimetype: str = ""

    @property
    def raw_url(self) -> str:
        """URL do conteúdo original arquivado (sufixo id_ = sem a barra do Wayback)."""
        return f"https://web.archive.org/web/{self.timestamp}id_/{self.original}"


async def cdx_query(
    http: HttpClient,
    cache: DiskCache,
    domain: str,
    *,
    filters: list[str],
    match_type: str = "domain",
    limit: int = 5000,
) -> list[CdxRecord]:
    params = {
        "url": domain,
        "matchType": match_type,
        "output": "json",
        "fl": "timestamp,original,digest,statuscode,mimetype",
        "filter": filters,
        "collapse": "digest",
        "limit": str(limit),
    }
    cache_key = f"{domain}|{match_type}|{'|'.join(filters)}|{limit}"
    rows = cache.get("wayback", cache_key, CDX_TTL)
    if rows is None:
        resp = await http.get(CDX_URL, params=params)  # type: ignore[arg-type]
        resp.raise_for_status()
        rows = resp.json() if resp.content.strip() else []
        cache.set("wayback", cache_key, rows)
    return parse_cdx(rows)


def parse_cdx(rows: list[list[str]]) -> list[CdxRecord]:
    if not rows:
        return []
    header, *data = rows
    idx = {name: i for i, name in enumerate(header)}
    records = []
    for row in data:
        try:
            records.append(
                CdxRecord(
                    timestamp=row[idx["timestamp"]],
                    original=row[idx["original"]],
                    digest=row[idx["digest"]],
                    statuscode=row[idx["statuscode"]] if "statuscode" in idx else "",
                    mimetype=row[idx["mimetype"]] if "mimetype" in idx else "",
                )
            )
        except (IndexError, KeyError):
            continue
    return records


def dedupe_by_digest(records: list[CdxRecord]) -> list[CdxRecord]:
    """Uma entrada por digest, preferindo a captura mais recente."""
    best: dict[str, CdxRecord] = {}
    for rec in records:
        cur = best.get(rec.digest)
        if cur is None or rec.timestamp > cur.timestamp:
            best[rec.digest] = rec
    return sorted(best.values(), key=lambda r: r.timestamp, reverse=True)


async def js_records(http: HttpClient, cache: DiskCache, domain: str) -> list[CdxRecord]:
    records = await cdx_query(http, cache, domain, filters=["statuscode:200", JS_FILTER])
    return dedupe_by_digest(records)
