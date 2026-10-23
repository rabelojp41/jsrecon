"""Módulo 4 — busca do IP de origem atrás de CDN/WAF.

Coleta candidatos de fontes passivas e só valida (requisição direta ao IP com o
header Host do alvo) quando:
  * o modo é --active, e
  * o IP foi fornecido por vocês (scope.txt ou --origin-ip).
Sem validação, o IP é sempre reportado como "candidato".
"""

from __future__ import annotations

import asyncio
import ipaddress
import re

import httpx

from jsrecon.analysis import similarity
from jsrecon.analysis.favicon import favicon_hash, favicon_url
from jsrecon.dns import resolve_ips
from jsrecon.http import OutOfScopeError
from jsrecon.models import ModuleResult, OriginCandidate
from jsrecon.modules.base import Context, Module
from jsrecon.modules.shodan_enrich import get_shodan
from jsrecon.providers.cdn_ranges import CDNRanges
from jsrecon.providers.securitytrails import SecurityTrails, SecurityTrailsError
from jsrecon.providers.shodan import ShodanError
from jsrecon.providers.virustotal import VirusTotal, VirusTotalError
from jsrecon.scope import host_of

COMMON_PREFIXES = (
    "origin", "origin-www", "direct", "direct-connect", "www-origin", "backend", "server", "host",
    "mail", "webmail", "smtp", "ftp", "cpanel", "whm", "dev", "staging", "stage", "test", "old", "legacy",
    "admin", "api", "beta", "vpn", "remote",
)
THIRD_PARTY_MAIL = re.compile(
    r"(google\.com|googlemail\.com|outlook\.com|office365\.com|pphosted\.com|mimecast\.com|messagelabs\.com|"
    r"zoho\.(com|eu|in)|mailgun\.org|sendgrid\.net|amazonaws\.com|amazonses\.com|secureserver\.net|"
    r"protonmail\.ch|yandex\.(net|ru)|icloud\.com|barracudanetworks\.com|mailcontrol\.com|emailsrvr\.com|"
    r"messagingengine\.com|titan\.email|improvmx\.com|forwardemail\.net)$",
    re.I,
)
MAX_FAVICON_BYTES = 512 * 1024
NON_ROUTABLE = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.168.0.0/16", "224.0.0.0/3", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
)]


class OriginFinder(Module):
    key = "origin"
    title = "Origin finder"

    def __init__(self) -> None:
        self.candidates: dict[str, OriginCandidate] = {}
        self.notes: list[str] = []
        self.errors: list[str] = []
        self.discarded_cdn = 0

    async def run(self, ctx: Context) -> ModuleResult:
        cdn = ctx.result.cdn
        if not (cdn and cdn.behind_cdn):
            return self.skipped("alvo não está atrás de CDN/WAF")
        self.ranges: CDNRanges = ctx.shared.get("cdn_ranges") or CDNRanges()
        self.exclude = set(ctx.result.resolved_ips)
        target = ctx.settings.target

        for ip in ctx.settings.origin_ips:
            self._add(ip, "fornecido pelo usuário")

        subdomain_hosts: set[str] = set()
        await self._securitytrails(ctx, target, subdomain_hosts)
        await self._virustotal(ctx, target, subdomain_hosts)
        await self._subdomains(ctx, target, subdomain_hosts)
        await self._mail_records(ctx, target)
        await self._favicon(ctx, target)

        if self.discarded_cdn:
            self.notes.append(f"{self.discarded_cdn} IP(s) descartados por serem de CDN")
        await self._validate(ctx)

        origins = sorted(
            self.candidates.values(),
            key=lambda o: (-(o.score or -1), -len(o.sources), o.ip),
        )
        ctx.result.origins = origins
        validated = [o for o in origins if o.validated]
        likely = [o for o in validated if o.score is not None and o.score >= 0.75]
        note = f"{len(origins)} candidato(s)"
        if validated:
            note += f", {len(validated)} validado(s), {len(likely)} provável(is) origem"
        elif origins:
            note += ", nenhum validado"
        if self.notes:
            note += "; " + "; ".join(self.notes)
        return self.done(len(origins), note, partial=bool(self.errors))

    # ----------------------------------------------------------- candidatos
    def _add(self, ip: str, source: str) -> None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return
        if any(addr in net for net in NON_ROUTABLE if addr.version == net.version) or ip in self.exclude:
            return
        if self.ranges.provider_of(ip):
            self.discarded_cdn += 1
            return
        cand = self.candidates.setdefault(ip, OriginCandidate(ip))
        if source not in cand.sources:
            cand.sources.append(source)

    async def _securitytrails(self, ctx: Context, target: str, subs: set[str]) -> None:
        key = ctx.settings.keys.securitytrails
        if not key:
            self.notes.append("SecurityTrails PULADO: SECURITYTRAILS_API_KEY ausente")
            return
        st = SecurityTrails(ctx.http, ctx.cache, key)
        try:
            for ip, period in await st.a_history(target):
                self._add(ip, "histórico DNS (SecurityTrails)")
            subs.update(await st.subdomains(target))
        except (SecurityTrailsError, httpx.HTTPError, OutOfScopeError, ValueError) as exc:
            self.errors.append(f"SecurityTrails: {exc}")
            self.notes.append(f"SecurityTrails falhou ({exc})")

    async def _virustotal(self, ctx: Context, target: str, subs: set[str]) -> None:
        key = ctx.settings.keys.virustotal
        if not key:
            self.notes.append("VirusTotal PULADO: VIRUSTOTAL_API_KEY ausente")
            return
        vt = VirusTotal(ctx.http, ctx.cache, key)
        try:
            for ip, _when in await vt.resolutions(target):
                self._add(ip, "histórico DNS (VirusTotal)")
            subs.update(await vt.subdomains(target))
        except (VirusTotalError, httpx.HTTPError, OutOfScopeError, ValueError) as exc:
            self.errors.append(f"VirusTotal: {exc}")
            self.notes.append(f"VirusTotal falhou ({exc})")

    async def _subdomains(self, ctx: Context, target: str, extra: set[str]) -> None:
        scope = ctx.settings.scope
        for host in sorted(extra):
            ctx.result.add_subdomain(host, "securitytrails/virustotal", scope.contains_host(host))
        hosts = set(extra)
        hosts |= {s.host for s in ctx.result.subdomains}
        hosts |= {host_of(e.value) for e in ctx.result.endpoints if e.value.startswith("http")}
        hosts |= {host_of(f.host_url) for f in ctx.result.js_files if f.host_url.startswith("http")}
        hosts |= {f"{p}.{target}" for p in COMMON_PREFIXES}
        # resolve só nomes dentro do escopo; fora do escopo nada é consultado
        hosts = {h for h in hosts if h and h != target and scope.contains_host(h)}

        async def check(host: str) -> None:
            for ip in await resolve_ips(ctx.dns, host):
                self._add(ip, f"subdomínio {host}")

        with ctx.ui.progress("Subdomínios", total=len(hosts)) as bar:
            async def run(host: str) -> None:
                await check(host)
                bar.advance()

            await asyncio.gather(*(run(h) for h in sorted(hosts)))

    async def _mail_records(self, ctx: Context, target: str) -> None:
        for mx in await ctx.dns.resolve(target, "MX"):
            if THIRD_PARTY_MAIL.search(mx):
                continue
            for ip in await resolve_ips(ctx.dns, mx):
                self._add(ip, f"MX {mx}")
        for txt in await ctx.dns.resolve(target, "TXT"):
            if not txt.lower().startswith("v=spf1"):
                continue
            for mech in txt.split()[1:]:
                mech = mech.lstrip("+?~-")
                name, _, value = mech.partition(":")
                name = name.lower()
                if name in ("ip4", "ip6") and value:
                    try:
                        net = ipaddress.ip_network(value, strict=False)
                    except ValueError:
                        continue
                    if net.num_addresses == 1:
                        self._add(str(net.network_address), "SPF")
                    elif net.num_addresses <= 16:
                        for ip in net:
                            self._add(str(ip), f"SPF {net}")
                    else:
                        self.notes.append(f"SPF contém a faixa {net} (não expandida)")
                elif name in ("a", "mx"):
                    host = value.split("/", 1)[0] if value else target
                    if THIRD_PARTY_MAIL.search(host):
                        continue
                    if name == "mx":
                        names = [m for m in await ctx.dns.resolve(host, "MX") if not THIRD_PARTY_MAIL.search(m)]
                    else:
                        names = [host]
                    for n in names:
                        for ip in await resolve_ips(ctx.dns, n):
                            self._add(ip, f"SPF {name}:{n}")

    async def _favicon(self, ctx: Context, target: str) -> None:
        content = await self._fetch_favicon(ctx, target)
        if content is None:
            self.notes.append("favicon não obtido")
            return
        fav_hash = favicon_hash(content)
        ctx.result.favicon_hash = fav_hash
        client, plan, _ = await get_shodan(ctx)
        if not client.key:
            self.notes.append(f"busca de favicon PULADA: sem SHODAN_API_KEY (hash {fav_hash})")
            return
        if plan is None or not plan.can_search:
            reason = plan.search_skip_reason() if plan else "plano desconhecido"
            self.notes.append(f"busca de favicon PULADA: {reason} (hash {fav_hash})")
            return
        try:
            for ip in await client.search_favicon(fav_hash):
                self._add(ip, "favicon hash (Shodan)")
        except (ShodanError, httpx.HTTPError, OutOfScopeError, ValueError) as exc:
            self.errors.append(f"Shodan favicon: {exc}")
            self.notes.append(f"busca de favicon falhou ({exc})")

    async def _fetch_favicon(self, ctx: Context, target: str) -> bytes | None:
        urls: list[str] = []
        baseline = await ctx.baseline()
        page_url = str(baseline.url) if baseline is not None else f"https://{target}/"
        icon = favicon_url(page_url, baseline.text if baseline is not None else None)
        if ctx.settings.active and ctx.http.allowed(icon):
            urls.append(icon)
        # passivo: cópia arquivada mais recente no Wayback
        urls.append(f"https://web.archive.org/web/2id_/{icon}")
        for url in urls:
            try:
                resp = await ctx.http.get(url, max_bytes=MAX_FAVICON_BYTES)
            except (httpx.HTTPError, OutOfScopeError):
                continue
            ctype = resp.headers.get("content-type", "")
            if resp.status_code == 200 and resp.content and "text/html" not in ctype:
                return resp.content
        return None

    # ------------------------------------------------------------ validação
    async def _validate(self, ctx: Context) -> None:
        authorized = [c for c in self.candidates.values() if ctx.settings.scope.contains_host(c.ip)]
        for cand in self.candidates.values():
            if cand not in authorized:
                cand.details["validação"] = "não autorizada: passe o IP com --origin-ip (ou no scope.txt) para validar"
            elif not ctx.settings.active:
                cand.details["validação"] = "requer --active"
        if not ctx.settings.active or not authorized:
            return

        baseline = await ctx.baseline()
        if baseline is None:
            self.errors.append("baseline indisponível")
            self.notes.append("validação impossível: alvo não respondeu via CDN")
            return
        reference = similarity.fingerprint(baseline)

        with ctx.ui.progress("Validando origem", total=len(authorized)) as bar:
            for cand in authorized:
                await self._validate_one(ctx, cand, reference)
                bar.advance()

    async def _validate_one(self, ctx: Context, cand: OriginCandidate, reference: similarity.Fingerprint) -> None:
        target = ctx.settings.target
        host = f"[{cand.ip}]" if ":" in cand.ip else cand.ip
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            try:
                resp = await ctx.http.get(
                    url, host_header=target, sni_hostname=target if scheme == "https" else None,
                    verify=False, follow_redirects=False, max_bytes=1024 * 1024,
                )
            except OutOfScopeError as exc:
                cand.details["validação"] = f"bloqueada pelo escopo: {exc.reason}"
                return
            except httpx.HTTPError as exc:
                cand.details.setdefault("erros", []).append(f"{scheme}: {type(exc).__name__}")
                continue
            fp = similarity.fingerprint(resp)
            score, parts = similarity.compare(reference, fp)
            cand.validated = True
            cand.score = score
            cand.verdict = similarity.verdict(score)
            cand.details.update({
                "validação": f"GET {scheme}://{cand.ip}/ com Host: {target}",
                "referencia": reference.summary(),
                "candidato": fp.summary(),
                "componentes": parts,
            })
            return
        cand.details["validação"] = "sem resposta HTTP/HTTPS"
