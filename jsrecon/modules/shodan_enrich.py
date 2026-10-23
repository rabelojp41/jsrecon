"""Módulo 5 — enriquecimento passivo de IPs via Shodan.

Fase 1: IPs resolvidos do alvo. Fase 2 (após o origin finder): IPs candidatos.
Sem SHODAN_API_KEY usa o InternetDB; com chave usa a API completa conforme o plano.
"""

from __future__ import annotations

import httpx

from jsrecon.http import OutOfScopeError
from jsrecon.models import HostIntel, ModuleResult
from jsrecon.modules.base import Context, Module
from jsrecon.providers.shodan import (
    ShodanClient, ShodanError, ShodanPlan, intel_from_host, intel_from_internetdb,
)


async def get_shodan(ctx: Context) -> tuple[ShodanClient, ShodanPlan | None, list[str]]:
    """Cliente e plano compartilhados entre módulos (detecta o plano uma vez só)."""
    if "shodan" not in ctx.shared:
        client = ShodanClient(ctx.http, ctx.cache, ctx.settings.keys.shodan)
        plan, notes = None, []
        if client.key:
            try:
                plan = await client.api_info()
            except ShodanError as exc:
                notes.append(f"chave Shodan rejeitada ({exc}); usando InternetDB")
                client.key = None
            except (httpx.HTTPError, ValueError) as exc:
                notes.append(f"/api-info indisponível ({type(exc).__name__}); usando InternetDB")
                client.key = None
        ctx.shared["shodan"] = (client, plan, notes)
    return ctx.shared["shodan"]


class ShodanEnricher(Module):
    key = "shodan"
    title = "Shodan"

    def __init__(self) -> None:
        self.result: ModuleResult | None = None
        self.notes: list[str] = []
        self.errors = 0

    async def run(self, ctx: Context) -> ModuleResult:
        client, plan, notes = await get_shodan(ctx)
        self.notes += notes
        if plan is not None:
            self.notes.append(f"plano {plan.plan or '?'}")
            if not plan.can_search:
                self.notes.append(f"busca PULADA: {plan.search_skip_reason()}")
        elif not ctx.settings.keys.shodan:
            self.notes.append("sem SHODAN_API_KEY: só InternetDB")
        await self.enrich(ctx, ctx.result.resolved_ips, "resolvido")
        self.result = self._build(ctx)
        return self.result

    async def enrich_candidates(self, ctx: Context) -> None:
        """Fase 2: chamada pelo orquestrador depois do origin finder."""
        if self.result is None or not ctx.result.origins:
            return
        ips = [o.ip for o in ctx.result.origins]
        await self.enrich(ctx, ips, "candidato-origem")
        updated = self._build(ctx)
        self.result.status, self.result.findings, self.result.note = updated.status, updated.findings, updated.note

    async def enrich(self, ctx: Context, ips: list[str], role: str) -> None:
        known = {h.ip for h in ctx.result.hosts}
        ips = [ip for ip in dict.fromkeys(ips) if ip not in known]
        if not ips:
            return
        client, _, _ = await get_shodan(ctx)
        ranges = ctx.shared.get("cdn_ranges")
        with ctx.ui.progress("Shodan", total=len(ips)) as bar:
            for ip in ips:  # sequencial: rate limit de 1 req/s
                intel = await self._lookup(ctx, client, ip)
                bar.advance()
                if intel is None:
                    continue
                intel.role = role
                if ranges is not None:
                    intel.is_cdn_edge = ranges.provider_of(ip)
                ctx.result.hosts.append(intel)
                for name in intel.sans:
                    host = name.removeprefix("*.")
                    ctx.result.add_subdomain(host, "shodan-ssl", ctx.settings.scope.contains_host(host))
                for name in intel.hostnames:
                    ctx.result.add_subdomain(name, "shodan-hostname", ctx.settings.scope.contains_host(name))

    async def _lookup(self, ctx: Context, client: ShodanClient, ip: str) -> HostIntel | None:
        try:
            if client.key:
                try:
                    data = await client.host(ip)
                    return intel_from_host(ip, data) if data else None
                except ShodanError as exc:
                    if exc.status in (401, 403):
                        msg = f"host lookup PULADO: plano não permite ({exc}); usando InternetDB"
                        if msg not in self.notes:
                            self.notes.append(msg)
                        client.key = None
                    else:
                        raise
            data = await client.internetdb(ip)
            return intel_from_internetdb(ip, data) if data else None
        except (ShodanError, httpx.HTTPError, OutOfScopeError, ValueError) as exc:
            self.errors += 1
            ctx.ui.warn(f"Shodan {ip}: {exc}")
            return None

    def _build(self, ctx: Context) -> ModuleResult:
        hosts = ctx.result.hosts
        if not hosts and not ctx.result.resolved_ips and not ctx.result.origins:
            return self.skipped("nenhum IP para consultar")
        notes = list(self.notes)
        edges = sorted({h.is_cdn_edge for h in hosts if h.is_cdn_edge})
        if edges:
            notes.append(f"IPs de borda ({', '.join(edges)}): dados refletem o CDN, não o servidor do cliente")
        n_cves = len({c for h in hosts for c in h.cves})
        if n_cves:
            notes.append(f"{n_cves} CVE(s) potenciais (por versão de banner, não confirmados)")
        n_sans = sum(1 for s in ctx.result.subdomains if s.source == "shodan-ssl")
        if n_sans:
            notes.append(f"{n_sans} subdomínio(s) via SAN")
        if self.errors:
            notes.append(f"{self.errors} erro(s)")
        if self.errors and not hosts:
            return self.failed("; ".join(notes))
        return self.done(len(hosts), "; ".join(notes), partial=bool(self.errors))
