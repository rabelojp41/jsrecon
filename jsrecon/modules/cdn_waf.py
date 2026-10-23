"""Módulo 3 — detecção de CDN/WAF por ranges de IP, CNAME, headers e cookies."""

from __future__ import annotations

import re
from http.cookies import SimpleCookie

import httpx

from jsrecon.dns import resolve_cname_chain, resolve_ips
from jsrecon.models import CDNResult, ModuleResult, ProviderEvidence
from jsrecon.modules.base import Context, Module
from jsrecon.providers.cdn_ranges import CDNRanges

CNAME_SIGS: list[tuple[str, str]] = [
    (r"\.cdn\.cloudflare\.net$", "Cloudflare"),
    (r"\.cloudfront\.net$", "AWS CloudFront"),
    (r"\.(fastly\.net|fastlylb\.net)$", "Fastly"),
    (r"\.(akamaiedge\.net|akamai\.net|edgekey\.net|edgesuite\.net|akamaized\.net|akamaihd\.net)$", "Akamai"),
    (r"\.(incapdns\.net|impervadns\.net)$", "Imperva"),
    (r"(\.sucuri\.net$|sucuridns)", "Sucuri"),
    (r"\.(azureedge\.net|azurefd\.net|trafficmanager\.net)$", "Azure Front Door/CDN"),
    (r"\.(stackpathdns\.com|stackpathcdn\.com)$", "StackPath"),
    (r"\.b-cdn\.net$", "Bunny CDN"),
    (r"\.cdn77\.(org|net)$", "CDN77"),
    (r"\.(edgecastcdn\.net|systemcdn\.net|edgio\.net)$", "Edgio"),
    (r"\.vercel-dns\.com$", "Vercel"),
    (r"\.netlify\.(app|com)$", "Netlify"),
]

# (provedor, header, regex do valor | None = basta existir)
HEADER_SIGS: list[tuple[str, str, str | None]] = [
    ("Cloudflare", "cf-ray", None),
    ("Cloudflare", "cf-cache-status", None),
    ("Cloudflare", "server", r"^cloudflare"),
    ("AWS CloudFront", "x-amz-cf-id", None),
    ("AWS CloudFront", "x-amz-cf-pop", None),
    ("AWS CloudFront", "via", r"cloudfront"),
    ("AWS CloudFront", "x-cache", r"cloudfront"),
    ("Fastly", "x-fastly-request-id", None),
    ("Fastly", "fastly-debug-digest", None),
    ("Fastly", "x-served-by", r"^cache-"),
    ("Akamai", "x-akamai-transformed", None),
    ("Akamai", "akamai-grn", None),
    ("Akamai", "akamai-cache-status", None),
    ("Akamai", "server", r"akamai(ghost|netstorage)"),
    ("Sucuri", "x-sucuri-id", None),
    ("Sucuri", "x-sucuri-cache", None),
    ("Sucuri", "server", r"sucuri|cloudproxy"),
    ("Imperva", "x-iinfo", None),
    ("Imperva", "x-cdn", r"incapsula|imperva"),
    ("Azure Front Door/CDN", "x-azure-ref", None),
    ("Azure Front Door/CDN", "x-msedge-ref", None),
    ("Google Cloud", "via", r"1\.1 google"),
    ("Vercel", "x-vercel-id", None),
    ("Netlify", "x-nf-request-id", None),
    ("StackPath", "x-sp-url", None),
    ("Bunny CDN", "server", r"^bunnycdn"),
    ("F5 BIG-IP", "server", r"big-?ip"),
    ("Barracuda WAF", "server", r"barracuda"),
    ("AWS WAF", "x-amzn-waf-action", None),
]

# (provedor, prefixo do nome do cookie)
COOKIE_SIGS: list[tuple[str, str]] = [
    ("Cloudflare", "__cf_bm"), ("Cloudflare", "cf_clearance"), ("Cloudflare", "__cfduid"), ("Cloudflare", "__cflb"),
    ("Akamai", "ak_bmsc"), ("Akamai", "bm_sv"), ("Akamai", "_abck"), ("Akamai", "bm_sz"),
    ("Imperva", "incap_ses_"), ("Imperva", "visid_incap_"), ("Imperva", "nlbi_"),
    ("Sucuri", "sucuri_cloudproxy_"),
    ("F5 BIG-IP", "BIGipServer"), ("F5 BIG-IP", "TS01"),
    ("AWS WAF", "aws-waf-token"),
    ("Barracuda WAF", "barra_counter_session"),
]


def analyze_headers(headers: httpx.Headers) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for provider, name, pattern in HEADER_SIGS:
        for value in headers.get_list(name):
            if pattern is None or re.search(pattern, value, re.I):
                shown = value if len(value) <= 40 else value[:37] + "..."
                found.setdefault(provider, []).append(f"header {name}: {shown}")
                break
    for raw in headers.get_list("set-cookie"):
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
            names = list(cookie.keys()) or [raw.split("=", 1)[0].strip()]
        except Exception:  # cookies malformados são comuns
            names = [raw.split("=", 1)[0].strip()]
        for name in names:
            for provider, prefix in COOKIE_SIGS:
                if name.startswith(prefix):
                    found.setdefault(provider, []).append(f"cookie {name}")
    return found


def analyze_cname(chain: list[str]) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for name in chain:
        for pattern, provider in CNAME_SIGS:
            if re.search(pattern, name, re.I):
                found.setdefault(provider, []).append(f"CNAME → {name}")
    return found


class CdnWafDetector(Module):
    key = "cdn"
    title = "CDN/WAF"

    async def run(self, ctx: Context) -> ModuleResult:
        target = ctx.settings.target
        ips = await resolve_ips(ctx.dns, target)
        ctx.result.resolved_ips = ips
        chain = await resolve_cname_chain(ctx.dns, target)

        with ctx.ui.progress("Ranges CDN", total=None, suffix="baixando listas…"):
            ranges, errors = await CDNRanges.load(ctx.http, ctx.cache)
        ctx.shared["cdn_ranges"] = ranges

        evidence: dict[str, ProviderEvidence] = {}

        def add(provider: str, items: list[str], strong: bool) -> None:
            ev = evidence.setdefault(provider, ProviderEvidence(provider))
            ev.evidence += [i for i in items if i not in ev.evidence]
            ev.strong = ev.strong or strong

        for ip in ips:
            match = ranges.lookup(ip)
            if match:
                label = "range oficial" if match.kind == "oficial" else "prefixo do ASN (RIPEstat)"
                add(match.provider, [f"{label} {match.network} contém {ip}"], match.kind == "oficial")
        for provider, items in analyze_cname(chain).items():
            add(provider, items, False)

        if ctx.settings.active:
            resp = await ctx.baseline()
            if resp is None:
                errors.append("requisição ao alvo falhou (" + ", ".join(ctx.shared.get("baseline_errors", [])) + ")")
            else:
                for provider, items in analyze_headers(resp.headers).items():
                    add(provider, items, True)

        providers = sorted(evidence.values(), key=lambda p: (not p.strong, p.provider))
        ctx.result.cdn = CDNResult(behind_cdn=bool(providers), ips=ips, providers=providers)
        ctx.result.warnings += [f"CDN/WAF: {e}" for e in errors]

        if not ips and not providers:
            return self.done(0, "domínio não resolveu", partial=bool(errors))
        if not providers:
            note = "nenhum CDN/WAF identificado"
            if not ctx.settings.active:
                note += " (sem headers: modo passivo)"
            return self.done(0, note, partial=bool(errors))
        note = "; ".join(f"{p.provider} ({_tags(p.evidence)})" for p in providers)
        return self.done(len(providers), note, partial=bool(errors) and len(errors) >= 3)


def _tags(evidence: list[str]) -> str:
    tags = []
    for e in evidence:
        if e.startswith("header "):
            tags.append(e.split(":", 1)[0].removeprefix("header "))
        elif e.startswith("cookie "):
            tags.append("cookie")
        elif e.startswith("range"):
            tags.append("range")
        elif e.startswith("prefixo"):
            tags.append("ASN")
        elif e.startswith("CNAME"):
            tags.append("CNAME")
    return " + ".join(dict.fromkeys(tags))
