"""Localização e parsing de source maps (.js.map)."""

from __future__ import annotations

import base64
import json
import re
from urllib.parse import unquote, urljoin

SOURCEMAP_COMMENT = re.compile(r"[#@]\s*sourceMappingURL\s*=\s*([^\s'\"*]+)")
SKIP_SOURCES = re.compile(r"(^|/)(node_modules|bower_components)/|webpack/(bootstrap|runtime)")


def find_sourcemap_url(js_url: str, js_text: str, headers: dict[str, str] | None = None) -> str | None:
    """Ordem: header SourceMap/X-SourceMap, depois o último comentário sourceMappingURL."""
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    ref = headers.get("sourcemap") or headers.get("x-sourcemap")
    if not ref:
        matches = SOURCEMAP_COMMENT.findall(js_text[-4096:]) or SOURCEMAP_COMMENT.findall(js_text)
        ref = matches[-1] if matches else None
    if not ref:
        return None
    if ref.startswith("data:"):
        return ref
    return urljoin(js_url, ref)


def decode_data_uri(uri: str) -> str | None:
    try:
        meta, payload = uri.split(",", 1)
    except ValueError:
        return None
    try:
        if ";base64" in meta:
            return base64.b64decode(payload + "=" * (-len(payload) % 4)).decode("utf-8", "replace")
        return unquote(payload)
    except ValueError:
        return None


def parse_sourcemap(text: str, include_vendor: bool = False) -> list[tuple[str, str]]:
    """Retorna [(caminho_original, conteúdo)] dos sourcesContent embutidos."""
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    sections = data.get("sections")
    if isinstance(sections, list):  # index map
        out: list[tuple[str, str]] = []
        for section in sections:
            if isinstance(section, dict) and isinstance(section.get("map"), dict):
                out += parse_sourcemap(json.dumps(section["map"]), include_vendor)
        return out
    sources = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    out = []
    for path, content in zip(sources, contents):
        if not isinstance(path, str) or not isinstance(content, str) or not content.strip():
            continue
        if not include_vendor and SKIP_SOURCES.search(path):
            continue
        out.append((path, content))
    return out
