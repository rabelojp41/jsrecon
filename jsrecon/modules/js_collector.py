"""Módulo 1 — coleta de JavaScript (atual via alvo, histórico via Wayback)."""

from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup

from jsrecon.http import OutOfScopeError
from jsrecon.models import JSFile, ModuleResult, Origin
from jsrecon.modules import sourcemaps, wayback
from jsrecon.modules.base import Context, Module
from jsrecon.scope import host_of

JS_TYPES = {"", "text/javascript", "application/javascript", "module", "application/ecmascript",
            "text/ecmascript", "text/jsx", "text/babel"}
# especificadores que parecem caminho de arquivo JS: ./x.js, ../x.mjs, /static/x.js, https://.../x.js
JS_PATH_RE = re.compile(r"""["'`]((?:\.{1,2}/|/(?!/)|https?://)[^"'`\s<>]+?\.m?js(?:\?[^"'`\s<>]*)?)["'`]""")
MAX_IMPORT_DEPTH = 3


def extract_from_html(page_url: str, html: str) -> tuple[list[str], list[str]]:
    """Retorna (urls de <script src>/preload/importmap, scripts inline)."""
    soup = BeautifulSoup(html, "html.parser")
    urls: list[str] = []
    inline: list[str] = []
    for tag in soup.find_all("script"):
        stype = (tag.get("type") or "").strip().lower()
        src = tag.get("src")
        if stype == "importmap" and tag.string:
            try:
                imports = json.loads(tag.string).get("imports", {})
                urls += [urljoin(page_url, v) for v in imports.values() if isinstance(v, str)]
            except (ValueError, AttributeError):
                pass
            continue
        if stype not in JS_TYPES:
            continue
        if src:
            urls.append(urljoin(page_url, src.strip()))
        elif tag.string and tag.string.strip():
            inline.append(tag.string)
    for link in soup.find_all("link"):
        rel = " ".join(link.get("rel") or []).lower()
        href = link.get("href")
        if href and ("modulepreload" in rel or ("preload" in rel and link.get("as") == "script")):
            urls.append(urljoin(page_url, href.strip()))
    return list(dict.fromkeys(u for u in urls if urlsplit(u).scheme in ("http", "https"))), inline


def find_js_references(js_url: str, text: str) -> list[str]:
    refs = []
    for spec in JS_PATH_RE.findall(text):
        url = urljoin(js_url, spec)
        if urlsplit(url).scheme in ("http", "https"):
            refs.append(url.split("#", 1)[0])
    return list(dict.fromkeys(refs))


def _looks_like_html(resp: httpx.Response) -> bool:
    ctype = resp.headers.get("content-type", "").lower()
    return "text/html" in ctype or resp.text.lstrip()[:15].lower().startswith(("<!doctype", "<html"))


class JSCollector(Module):
    key = "js"
    title = "Coleta JS"

    def __init__(self, guess_sourcemaps: bool = True):
        self.guess_sourcemaps = guess_sourcemaps
        self.errors: list[str] = []

    async def run(self, ctx: Context) -> ModuleResult:
        notes: list[str] = []
        if ctx.settings.active:
            await self._collect_active(ctx)
        else:
            notes.append("coleta ativa desabilitada (modo passivo)")

        if ctx.settings.wayback:
            try:
                await self._collect_wayback(ctx)
            except (httpx.HTTPError, ValueError) as exc:
                self.errors.append(f"Wayback CDX: {exc}")
                notes.append("Wayback indisponível")
        files = ctx.result.js_files
        current = sum(1 for f in files if f.origin is Origin.ATUAL)
        hist = len(files) - current
        note = f"{current} atuais, {hist} histórico{'s' if hist != 1 else ''}"
        n_maps = sum(1 for f in files if f.source == "sourcemap")
        if n_maps:
            note += f" ({n_maps} de source maps)"
        if notes:
            note += "; " + "; ".join(notes)
        if self.errors:
            note += f"; {len(self.errors)} erro(s)"
        if not ctx.settings.active and not ctx.settings.wayback:
            return self.skipped("modo passivo com --no-wayback: nada a coletar")
        if self.errors and not files:
            return self.failed(self.errors[0])
        return self.done(len(files), note, partial=bool(self.errors))

    # ------------------------------------------------------------- ativo
    async def _collect_active(self, ctx: Context) -> None:
        resp = await ctx.baseline()
        if resp is None:
            self.errors += [f"página inicial: {e}" for e in ctx.shared.get("baseline_errors", [])]
            return
        page_url, html = str(resp.url), resp.text
        src_urls, inline = extract_from_html(page_url, html)
        for i, code in enumerate(inline, 1):
            self._add(ctx, JSFile(f"{page_url}#inline-{i}", code, Origin.ATUAL, "inline", parent=page_url))
            for ref in find_js_references(page_url, code):
                src_urls.append(ref)

        seen: set[str] = set()
        queue = [(u, "page", page_url) for u in dict.fromkeys(src_urls)]
        with ctx.ui.progress("Coletando JS", total=len(queue)) as bar:
            depth = 0
            while queue and depth <= MAX_IMPORT_DEPTH:
                batch = []
                for url, source, parent in queue:
                    if url in seen or len(seen) >= ctx.settings.max_js:
                        continue
                    seen.add(url)
                    if not ctx.http.allowed(url):
                        ctx.result.js_skipped.append({"url": url, "reason": "fora do escopo"})
                        bar.advance()
                        continue
                    batch.append((url, source, parent))
                results = await asyncio.gather(*(self._fetch_js(ctx, *item) for item in batch))
                bar.advance(len(batch))
                queue = []
                for refs, url in results:
                    queue += [(r, "import", url) for r in refs if r not in seen]
                bar.set_total(len(seen) + len({u for u, _, _ in queue}))
                depth += 1

    async def _fetch_js(self, ctx: Context, url: str, source: str, parent: str) -> tuple[list[str], str]:
        try:
            resp = await ctx.http.get(url, max_bytes=ctx.settings.max_js_bytes)
        except (httpx.HTTPError, OutOfScopeError) as exc:
            self.errors.append(f"{url}: {type(exc).__name__}")
            return [], url
        if resp.status_code != 200 or _looks_like_html(resp):
            ctx.result.js_skipped.append({"url": url, "reason": f"HTTP {resp.status_code}" if resp.status_code != 200 else "resposta HTML"})
            return [], url
        text = resp.text
        self._add(ctx, JSFile(url, text, Origin.ATUAL, source, parent=parent))
        await self._collect_sourcemap(ctx, url, text, dict(resp.headers))
        return find_js_references(url, text), url

    async def _collect_sourcemap(self, ctx: Context, js_url: str, text: str, headers: dict[str, str]) -> None:
        map_url = sourcemaps.find_sourcemap_url(js_url, text, headers)
        map_text: str | None = None
        if map_url and map_url.startswith("data:"):
            map_text = sourcemaps.decode_data_uri(map_url)
            map_url = f"{js_url}#inline-map"
        else:
            candidates = [map_url] if map_url else []
            if self.guess_sourcemaps and not map_url:
                candidates.append(js_url.split("?", 1)[0] + ".map")
            for cand in candidates:
                if not ctx.http.allowed(cand):
                    ctx.result.js_skipped.append({"url": cand, "reason": "source map fora do escopo"})
                    continue
                try:
                    resp = await ctx.http.get(cand, max_bytes=ctx.settings.max_js_bytes * 3)
                except (httpx.HTTPError, OutOfScopeError):
                    continue
                if resp.status_code == 200 and resp.text.lstrip().startswith("{"):
                    map_text, map_url = resp.text, cand
                    break
        if not map_text:
            return
        for path, content in sourcemaps.parse_sourcemap(map_text):
            self._add(ctx, JSFile(f"{map_url}::{path}", content, Origin.ATUAL, "sourcemap", parent=js_url))

    # ---------------------------------------------------------- histórico
    async def _collect_wayback(self, ctx: Context) -> None:
        with ctx.ui.progress("Wayback CDX", total=None, suffix="consultando…") as bar:
            records = await wayback.js_records(ctx.http, ctx.cache, ctx.settings.target)
            in_scope = [r for r in records if ctx.settings.scope.contains_host(host_of(r.original))]
            out_scope = len(records) - len(in_scope)
            if out_scope:
                ctx.result.warnings.append(f"Wayback: {out_scope} arquivo(s) de hosts fora do escopo ignorados")
            selected = in_scope[: ctx.settings.max_historical]
            if len(in_scope) > len(selected):
                ctx.result.warnings.append(
                    f"Wayback: {len(in_scope)} versões encontradas, limitado a {len(selected)} (--max-historical)"
                )
            bar.set_total(len(selected))
            bar.set_suffix("arquivos históricos")
            current_hashes = {f.sha256 for f in ctx.result.js_files}

            async def fetch(rec: wayback.CdxRecord) -> None:
                try:
                    resp = await ctx.http.get(rec.raw_url, max_bytes=ctx.settings.max_js_bytes)
                except (httpx.HTTPError, OutOfScopeError) as exc:
                    self.errors.append(f"wayback {rec.original}: {type(exc).__name__}")
                    return
                finally:
                    bar.advance()
                if resp.status_code != 200 or _looks_like_html(resp):
                    return
                f = JSFile(rec.original, resp.text, Origin.HISTORICO, "wayback",
                           timestamp=rec.timestamp, digest=rec.digest)
                if f.sha256 in current_hashes:
                    return  # idêntico a um arquivo atual — já analisado
                self._add(ctx, f)

            await asyncio.gather(*(fetch(r) for r in selected))

    @staticmethod
    def _add(ctx: Context, f: JSFile) -> None:
        known = {(x.sha256, x.origin) for x in ctx.result.js_files}
        if (f.sha256, f.origin) not in known:
            ctx.result.js_files.append(f)
