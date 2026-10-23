"""Módulo 2c — verifica se endpoints vistos só em versões antigas ainda respondem.

Somente HEAD/GET, sem seguir redirecionamentos, e sempre dentro do escopo.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlsplit

import httpx

from jsrecon.http import OutOfScopeError
from jsrecon.models import Endpoint, ModuleResult
from jsrecon.modules.base import Context, Module
from jsrecon.scope import host_of

TEMPLATED = re.compile(r"\$\{|\{[^}]*\}|/:[A-Za-z_]")
GONE = {404, 410}


def _base_url(location_file: str) -> str:
    """Arquivo histórico 'https://x/app.js@2019...' -> 'https://x/app.js'."""
    url = location_file.split("::", 1)[0].split("#inline-", 1)[0]
    return re.sub(r"@\d{14}$", "", url)


def probe_url(ep: Endpoint, ctx: Context) -> str | None:
    if ep.kind == "graphql-op" or TEMPLATED.search(ep.value):
        return None
    if ep.value.startswith("http"):
        return ep.value
    for loc in ep.locations:
        base = _base_url(loc.file)
        if urlsplit(base).scheme not in ("http", "https"):
            continue
        url = urljoin(base, ep.value)
        if ctx.settings.scope.contains_host(host_of(url)):
            return url
    # sem base no escopo: usa o próprio alvo
    return urljoin(f"https://{ctx.settings.target}/", ep.value)


class EndpointProber(Module):
    key = "probe"
    title = "Probe endpoints"
    requires_active = True

    def skip_reason(self, ctx: Context) -> str | None:
        return super().skip_reason(ctx) or (None if ctx.settings.probe else "desabilitado (use --probe)")

    async def run(self, ctx: Context) -> ModuleResult:
        targets: dict[str, list[Endpoint]] = {}
        for ep in ctx.result.endpoints:
            if not ep.only_historical:
                continue
            url = probe_url(ep, ctx)
            if url is None:
                ep.probe_note = "não testável (template)"
                continue
            if not ctx.http.allowed(url):
                ep.probe_note = "fora do escopo"
                continue
            targets.setdefault(url, []).append(ep)

        if not targets:
            return self.done(0, "nenhum endpoint histórico testável no escopo")
        urls = list(targets)[: ctx.settings.probe_limit]
        statuses: dict[str, int | None] = {}

        with ctx.ui.progress("Probe endpoints", total=len(urls)) as bar:

            async def probe(url: str) -> None:
                try:
                    resp = await ctx.http.head(url, follow_redirects=False)
                    if resp.status_code in (405, 501):
                        resp = await ctx.http.get(url, follow_redirects=False, max_bytes=65536)
                    statuses[url] = resp.status_code
                except (httpx.HTTPError, OutOfScopeError):
                    statuses[url] = None
                finally:
                    bar.advance()

            await asyncio.gather(*(probe(u) for u in urls))

        alive = 0
        for url, status in statuses.items():
            for ep in targets[url]:
                ep.probe_status = status
                ep.probe_note = None if status is not None else "erro de conexão"
            if status is not None and status not in GONE:
                alive += 1
        note = f"{alive} de {len(urls)} endpoints históricos ainda respondem"
        if len(targets) > len(urls):
            note += f" (limitado a {len(urls)} — --probe-limit)"
        return self.done(alive, note)
