"""Pipeline: executa os módulos em ordem, passando dados entre eles."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

import httpx

from jsrecon import __version__
from jsrecon.cache import DiskCache
from jsrecon.config import Settings
from jsrecon.dns import DnsResolver, Resolver, resolve_ips
from jsrecon.http import HttpClient
from jsrecon.models import ReconResult
from jsrecon.modules.base import Context, Module
from jsrecon.modules.cdn_waf import CdnWafDetector
from jsrecon.modules.cve_intel import CveEnricher
from jsrecon.modules.endpoints import EndpointExtractor
from jsrecon.modules.js_collector import JSCollector
from jsrecon.modules.origin_finder import OriginFinder
from jsrecon.modules.prober import EndpointProber
from jsrecon.modules.secrets import SecretScanner
from jsrecon.modules.shodan_enrich import ShodanEnricher
from jsrecon.ui import UI


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


async def resolve_user_origins(settings: Settings, dns: Resolver, ui: UI) -> None:
    """--origin-ip aceita IPs ou hosts. Cada IP resultante entra no escopo (autorização explícita)."""
    ips: list[str] = []
    for value in settings.origin_ips:
        try:
            ips.append(str(ipaddress.ip_address(value)))
            continue
        except ValueError:
            pass
        resolved = await resolve_ips(dns, value)
        if not resolved:
            ui.warn(f"--origin-ip {value}: não resolveu, ignorado")
        ips += resolved
    for ip in dict.fromkeys(ips):
        if not settings.scope.contains_host(ip):
            settings.scope.add(ip)
    settings.origin_ips = list(dict.fromkeys(ips))


async def run_module(ctx: Context, module: Module) -> None:
    reason = module.skip_reason(ctx)
    if reason:
        result = module.skipped(reason)
    else:
        try:
            result = await module.run(ctx)
        except Exception as exc:  # um módulo nunca derruba o pipeline
            result = module.failed(f"{type(exc).__name__}: {exc}")
            ctx.result.warnings.append(f"{module.title}: erro inesperado — {type(exc).__name__}: {exc}")
    ctx.result.modules.append(result)
    ctx.ui.module_status(result)


async def run_scan(
    settings: Settings,
    ui: UI,
    *,
    dns: Resolver | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> ReconResult:
    dns = dns or DnsResolver(timeout=min(settings.timeout, 10))
    await resolve_user_origins(settings, dns, ui)
    result = ReconResult(settings.target, settings.mode, settings.scope.to_dict(), __version__, started_at=_now())
    ui.banner(settings.target, settings.mode.value, settings.scope.summary())

    async with HttpClient(settings, transport=transport) as http:
        ctx = Context(settings, http, dns, DiskCache(settings.cache_dir), ui, result)
        shodan = ShodanEnricher()
        pipeline: list[Module] = [
            JSCollector(),
            EndpointExtractor(),
            SecretScanner(),
            EndpointProber(),
            CdnWafDetector(),
            shodan,  # fase 1: IPs resolvidos (SANs viram subdomínios para o origin finder)
            OriginFinder(),
        ]
        for module in pipeline:
            await run_module(ctx, module)
        try:
            await shodan.enrich_candidates(ctx)  # fase 2: IPs candidatos de origem
        except Exception as exc:
            result.warnings.append(f"Shodan (candidatos): {type(exc).__name__}: {exc}")
        await run_module(ctx, CveEnricher())  # depois das duas fases do Shodan: todas as CVEs já coletadas

        stats = http.stats
        result.requests = {
            "active": stats.active_count,
            "passive": stats.passive_count,
            "blocked": [{"url": b.url, "reason": b.reason, "host_header": b.host_header} for b in stats.blocked],
            "active_log": [
                {"method": r.method, "url": r.url, "status": r.status, "host_header": r.host_header, "error": r.error}
                for r in stats.records if r.kind == "ativo"
            ],
        }
    result.finished_at = _now()
    return result
