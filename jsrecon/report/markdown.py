"""Relatório Markdown — gerado a partir do mesmo dicionário do JSON."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from jsrecon.models import ReconResult


def _cell(value: Any) -> str:
    if value is None or value == "":
        return "–"
    if isinstance(value, (list, tuple)):
        value = ", ".join(str(v) for v in value) or "–"
    return str(value).replace("|", "\\|").replace("\n", "<br>")


def _table(headers: list[str], rows: Iterable[Iterable[Any]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(_cell(c) for c in row) + " |" for row in rows]
    return "\n".join(lines)


def render_markdown(result: ReconResult, reveal: bool = False) -> str:
    d = result.to_dict(reveal)
    meta = d["meta"]
    req = d["requests"] or {}
    out: list[str] = [
        f"# jsrecon — {meta['target']}",
        "",
        f"- **Modo:** {meta['mode']}",
        f"- **Escopo:** {', '.join(meta['scope']['domains'] + meta['scope']['networks'])}"
        + (f" (exclusões: {', '.join(meta['scope']['excluded'])})" if meta["scope"]["excluded"] else ""),
        f"- **Início/fim:** {meta['started_at']} → {meta['finished_at']}",
        f"- **Requisições:** {req.get('active', 0)} ativas, {req.get('passive', 0)} passivas, "
        f"{len(req.get('blocked', []))} bloqueadas pelo escopo",
        f"- **Secrets:** {'REVELADOS (--reveal)' if reveal else 'mascarados (4 primeiros + 4 últimos caracteres)'}",
        "",
        "## Resumo",
        "",
        _table(["Módulo", "Status", "Achados", "Observação"],
               ([m["title"], m["status"], m["findings"], m["note"]] for m in d["summary"])),
    ]

    if d["secrets"]:
        out += ["", "## Secrets", "",
                _table(["Tipo", "Valor", "Confiança", "Arquivo:linha", "Origem", "Nota"],
                       ([s["type"], f"`{s['value']}`", s["confidence"].upper() if s["confidence"] == "alta" else s["confidence"],
                         f"{s['file']}:{s['line']}", s["origin"], s["note"]] for s in d["secrets"]))]

    if d["endpoints"]:
        out += ["", "## Endpoints", "",
                _table(["Método", "Rota", "Tipo", "Arquivo:linha", "Origem", "Probe"],
                       ([e["method"], f"`{e['value']}`", e["kind"],
                         f"{e['locations'][0]['file']}:{e['locations'][0]['line']}"
                         + (f" (+{len(e['locations']) - 1})" if len(e["locations"]) > 1 else ""),
                         e["origin"], e["probe_status"] or e["probe_note"]] for e in d["endpoints"]))]

    cdn = d["cdn_waf"]
    if cdn:
        out += ["", "## CDN/WAF", "",
                f"IPs resolvidos: {', '.join(cdn['ips']) or '–'} — "
                f"**{'atrás de CDN/WAF' if cdn['behind_cdn'] else 'nenhum CDN/WAF identificado'}**"]
        if cdn["providers"]:
            out += ["", _table(["Provedor", "Evidência", "Forte"],
                               ([p["provider"], p["evidence"], "sim" if p["strong"] else "não"] for p in cdn["providers"]))]

    if d["origin_candidates"]:
        out += ["", "## IPs de origem", "",
                "> Sem validação, um IP é apenas **candidato** — nunca \"IP real encontrado\".", "",
                _table(["IP", "Fonte", "Score", "Validado", "Veredito", "Observação"],
                       ([o["ip"], o["sources"], "–" if o["score"] is None else f"{o['score']:.0%}",
                         "sim" if o["validated"] else "não", o["verdict"], o["details"].get("validação")]
                        for o in d["origin_candidates"]))]
    if d["favicon_mmh3"] is not None:
        out += ["", f"Favicon mmh3: `{d['favicon_mmh3']}` (Shodan: `http.favicon.hash:{d['favicon_mmh3']}`)"]

    if d["shodan"]:
        out += ["", "## Shodan", "",
                "> CVEs são **potenciais**: inferidos da versão do banner, não confirmados.", "",
                _table(["IP", "Papel", "Org/ASN", "Portas", "Serviços/versões", "CVEs (potenciais)", "Fonte", "Borda CDN"],
                       ([h["ip"], h["role"], " / ".join(x for x in (h["org"], h["asn"]) if x), h["ports"],
                         h["services"], h["cves"], h["source"], h["is_cdn_edge"]] for h in d["shodan"]))]

    if d["cve_intel"]:
        out += ["", "## CVEs potenciais", "",
                "> Inferidas da versão do banner (Shodan), **não confirmadas**. Ordenadas por KEV, CVSS e EPSS "
                "para priorizar a verificação. EPSS = probabilidade de exploração em 30 dias; "
                "KEV = consta no catálogo CISA de vulnerabilidades exploradas.", "",
                _table(["CVE", "Severidade", "CVSS", "EPSS", "KEV", "IPs", "Publicada", "Resumo"],
                       ([f"[{c['id']}]({c['url']})", c["severity"] if c["found"] else "sem dados", c["cvss"],
                         None if c["epss"] is None else f"{c['epss']:.1%}", "**SIM**" if c["kev"] else "não",
                         c["ips"], c["published"], c["summary"]] for c in d["cve_intel"]))]

    if d["subdomains"]:
        out += ["", "## Subdomínios descobertos", "",
                _table(["Host", "Fonte", "No escopo"],
                       ([s["host"], s["source"], "sim" if s["in_scope"] else "**fora do escopo**"] for s in d["subdomains"]))]

    if d["js_files"]:
        out += ["", f"## Arquivos JS ({len(d['js_files'])})", "",
                _table(["Arquivo", "Origem", "Fonte", "Tamanho"],
                       ([f["label"], f["origin"], f["source"], f["size"]] for f in d["js_files"]))]

    blocked = req.get("blocked", [])
    if blocked or d["js_skipped"]:
        out += ["", "## Bloqueado / ignorado pelo escopo", ""]
        out += [_table(["URL", "Motivo"], ([b["url"], b["reason"]] for b in blocked + d["js_skipped"]))]

    if d["warnings"]:
        out += ["", "## Avisos", ""] + [f"- {w}" for w in d["warnings"]]
    return "\n".join(out) + "\n"


def write_markdown(result: ReconResult, path: Path, reveal: bool = False) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown(result, reveal), encoding="utf-8")
    return path
