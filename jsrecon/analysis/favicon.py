"""Hash de favicon no formato usado pelo Shodan (http.favicon.hash)."""

from __future__ import annotations

import base64
from urllib.parse import urljoin

from bs4 import BeautifulSoup

try:
    import mmh3
except ImportError:  # pragma: no cover - fallback puro Python
    mmh3 = None


def _murmur3_32(data: bytes, seed: int = 0) -> int:
    c1, c2 = 0xCC9E2D51, 0x1B873593
    h = seed & 0xFFFFFFFF
    n = len(data) - len(data) % 4
    for i in range(0, n, 4):
        k = int.from_bytes(data[i:i + 4], "little")
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[n:]
    k = 0
    for i, b in enumerate(tail):
        k |= b << (8 * i)
    if tail:
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= len(data)
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h - 0x100000000 if h & 0x80000000 else h


def favicon_hash(content: bytes) -> int:
    """mmh3 (32 bits, com sinal) do base64 com quebras de linha a cada 76 chars."""
    encoded = base64.encodebytes(content)
    if mmh3 is not None:
        return mmh3.hash(encoded)
    return _murmur3_32(encoded)


def favicon_url(page_url: str, html: str | None) -> str:
    if html:
        soup = BeautifulSoup(html, "html.parser")
        for link in soup.find_all("link", href=True):
            rel = " ".join(link.get("rel") or []).lower()
            if "icon" in rel.split() or rel in ("shortcut icon", "icon"):
                return urljoin(page_url, link["href"])
    return urljoin(page_url, "/favicon.ico")
