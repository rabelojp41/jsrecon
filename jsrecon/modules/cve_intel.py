"""Enriquecimento defensivo das CVEs potenciais vindas do Shodan.

Para cada CVE: CVSS, severidade, EPSS e se consta no catálogo CISA KEV — para
priorizar o relatório. As CVEs continuam sendo *potenciais* (inferidas da versão
do banner); nada é testado contra o alvo.
"""

from __future__ import annotations

import re

import httpx

from jsrecon.http import OutOfScopeError
from jsrecon.models import CveInfo, ModuleResult
from jsrecon.modules.base import Context, Module
from jsrecon.providers.cvedb import CveDb, CveDbError

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


def _year_seq(cve_id: str) -> tuple[int, int]:
    _, year, seq = cve_id.split("-", 2)
    return int(year), int(seq)


class CveEnricher(Module):
    key = "cve"
    title = "CVEs"

    def skip_reason(self, ctx: Context) -> str | None:
        return None if ctx.settings.cve_intel else "desabilitado (--no-cve-intel)"

    async def run(self, ctx: Context) -> ModuleResult:
        if not ctx.result.hosts:
            return self.skipped("sem dados do Shodan")
        ips_by_cve: dict[str, list[str]] = {}
        for host in ctx.result.hosts:
            for cve in host.cves:
                cve = cve.upper()
                if CVE_RE.match(cve):
                    ips_by_cve.setdefault(cve, [])
                    if host.ip not in ips_by_cve[cve]:
                        ips_by_cve[cve].append(host.ip)
        if not ips_by_cve:
            return self.done(0, "nenhuma CVE potencial nos banners")

        # sem dados ainda para priorizar: limita pelas mais recentes
        ids = sorted(ips_by_cve, key=_year_seq, reverse=True)
        selected, dropped = ids[: ctx.settings.max_cves], len(ids) - ctx.settings.max_cves

        db = CveDb(ctx.http, ctx.cache)
        infos: list[CveInfo] = []
        errors = 0
        with ctx.ui.progress("CVEs (CVSS/EPSS)", total=len(selected)) as bar:
            for cve in selected:
                try:
                    info = await db.lookup(cve)
                except (CveDbError, httpx.HTTPError, OutOfScopeError, ValueError):
                    errors += 1
                    info = CveInfo(cve, found=False)
                info.ips = ips_by_cve[cve]
                infos.append(info)
                bar.advance()

        infos.sort(key=CveInfo.sort_key)
        ctx.result.cve_intel = infos
        count = lambda sev: sum(1 for i in infos if i.severity == sev)  # noqa: E731
        kev = sum(1 for i in infos if i.kev)
        parts = [f"{count('crítica')} crítica(s)", f"{count('alta')} alta(s)", f"{count('média')} média(s)"]
        note = ", ".join(parts)
        if kev:
            note += f"; {kev} no CISA KEV"
        note += " — potenciais (versão de banner, não confirmadas)"
        if dropped > 0:
            note += f"; {dropped} não enriquecida(s) (--max-cves)"
        if errors:
            note += f"; {errors} erro(s) na consulta"
        if errors == len(selected):
            return self.failed(f"cvedb.shodan.io indisponível ({errors} erro(s))")
        return self.done(len(infos), note, partial=bool(errors))
