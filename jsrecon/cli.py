"""Interface de linha de comando (Typer)."""

from __future__ import annotations

import asyncio
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

import typer

from jsrecon import __version__
from jsrecon.config import DEFAULT_CACHE_DIR, DEFAULT_USER_AGENT, ApiKeys, Settings
from jsrecon.models import Mode, ReconResult
from jsrecon.orchestrator import run_scan
from jsrecon.report.html import write_html
from jsrecon.report.json_report import write_json
from jsrecon.report.markdown import write_markdown
from jsrecon.scope import Scope, ScopeError, normalize_host, parse_ip
from jsrecon.ui import UI

app = typer.Typer(
    add_completion=False,
    rich_markup_mode=None,
    help="Recon de aplicações web (JS, endpoints, secrets, CDN/WAF, origem, Shodan) — "
    "somente para pentests autorizados e bug bounty dentro do escopo.",
)


def normalize_target(value: str) -> str:
    value = value.strip()
    host = urlsplit(value).hostname if "://" in value else value.split("/", 1)[0]
    return normalize_host(host or "")


def default_scope(host: str) -> Scope:
    """Escopo implícito: o alvo e todos os seus subdomínios (ou só o IP, se o alvo for um IP)."""
    if not host:
        raise ScopeError("alvo inválido")
    if parse_ip(host) is not None:
        return Scope.from_lines([host])
    return Scope.from_lines([host, f"*.{host}"])


def save_js_files(result: ReconResult, directory: Path) -> int:
    directory.mkdir(parents=True, exist_ok=True)
    for i, f in enumerate(result.js_files, 1):
        name = re.sub(r"[^A-Za-z0-9._-]+", "_", f.label.split("://", 1)[-1])[-150:]
        (directory / f"{i:04d}_{f.origin.name.lower()}_{name}").write_text(f.content, encoding="utf-8")
    return len(result.js_files)


@app.command()
def scan(
    target: str = typer.Argument(..., help="Domínio-alvo (ex.: exemplo.com). Precisa estar no escopo."),
    scope_file: Optional[Path] = typer.Option(
        None, "--scope", "-s",
        help="Arquivo de escopo (domínios, *.wildcards, IPs/CIDRs, !exclusões). "
        "Sem ele, o escopo é o próprio alvo + *.alvo.",
    ),
    active: bool = typer.Option(False, "--active/--passive", help="Modo ativo faz requisições ao alvo; passivo (padrão) usa só fontes públicas."),
    rate: float = typer.Option(5.0, "--rate", help="Máx. requisições/s contra o alvo."),
    passive_rate: float = typer.Option(2.0, "--passive-rate", help="Máx. requisições/s por fonte pública (Wayback etc.)."),
    concurrency: int = typer.Option(10, "--concurrency", help="Requisições simultâneas."),
    user_agent: str = typer.Option(DEFAULT_USER_AGENT, "--user-agent", "-A", help="User-Agent."),
    timeout: float = typer.Option(15.0, "--timeout", help="Timeout por requisição (s)."),
    retries: int = typer.Option(2, "--retries", help="Tentativas extras em erro de rede/429/5xx."),
    probe: bool = typer.Option(False, "--probe", help="(ativo) Testa com HEAD/GET se endpoints históricos ainda respondem."),
    probe_limit: int = typer.Option(200, "--probe-limit", help="Máx. de endpoints testados pelo --probe."),
    origin_ip: list[str] = typer.Option([], "--origin-ip", help="IP ou host de origem autorizado para validação (repetível)."),
    wayback: bool = typer.Option(True, "--wayback/--no-wayback", help="Consulta o Wayback Machine."),
    max_historical: int = typer.Option(300, "--max-historical", help="Máx. de arquivos JS históricos baixados."),
    max_js: int = typer.Option(300, "--max-js", help="Máx. de arquivos JS atuais baixados."),
    reveal: bool = typer.Option(False, "--reveal", help="Mostra secrets completos (por padrão são mascarados)."),
    no_color: bool = typer.Option(False, "--no-color", help="Sem cores."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Só o resumo final."),
    json_out: bool = typer.Option(False, "--json", help="Só JSON no stdout (nada mais)."),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir", "-o", help="Diretório dos relatórios (padrão: jsrecon-out/<alvo>_<data>)."),
    no_save: bool = typer.Option(False, "--no-save", help="Não grava result.json/report.md em disco."),
    html: Optional[Path] = typer.Option(None, "--html", help="Gera também um relatório HTML neste caminho."),
    save_js: bool = typer.Option(False, "--save-js", help="Salva os arquivos JS coletados no diretório de saída."),
    cache_dir: Path = typer.Option(DEFAULT_CACHE_DIR, "--cache-dir", help="Diretório de cache."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Desliga o cache em disco."),
    max_rows: int = typer.Option(50, "--max-rows", help="Máx. de linhas por tabela no terminal."),
    cve_intel: bool = typer.Option(True, "--cve-intel/--no-cve-intel", help="Enriquece CVEs potenciais com CVSS, EPSS e KEV (cvedb.shodan.io)."),
    max_cves: int = typer.Option(100, "--max-cves", help="Máx. de CVEs enriquecidas."),
) -> None:
    ui = UI(no_color=no_color, quiet=quiet, json_mode=json_out, max_rows=max_rows)
    host = normalize_target(target)
    try:
        if scope_file is not None:
            scope = Scope.from_file(scope_file)
        else:
            scope = default_scope(host)
            ui.info(f"sem --scope: escopo automático = {', '.join(scope.to_dict()['domains'] + scope.to_dict()['networks'])}")
    except ScopeError as exc:
        ui.error(f"escopo: {exc}")
        raise typer.Exit(2)

    if not host or not scope.contains_host(host):
        ui.error(f"o alvo {host or target!r} não está no escopo — nada será feito")
        raise typer.Exit(2)

    settings = Settings(
        target=host,
        scope=scope,
        mode=Mode.ACTIVE if active else Mode.PASSIVE,
        rate_limit=rate,
        passive_rate_limit=passive_rate,
        concurrency=concurrency,
        user_agent=user_agent,
        timeout=timeout,
        retries=retries,
        cache_dir=None if no_cache else cache_dir,
        keys=ApiKeys.from_env(),
        reveal=reveal,
        probe=probe,
        probe_limit=probe_limit,
        wayback=wayback,
        max_historical=max_historical,
        max_js=max_js,
        origin_ips=list(origin_ip),
        cve_intel=cve_intel,
        max_cves=max_cves,
    )
    if probe and not active:
        ui.warn("--probe só tem efeito com --active")
    if origin_ip and not active:
        ui.warn("--origin-ip só é validado com --active; no modo passivo os IPs entram como candidatos")

    try:
        result = asyncio.run(run_scan(settings, ui))
    except KeyboardInterrupt:
        ui.error("interrompido")
        raise typer.Exit(130)

    saved: list[Path] = []
    if not no_save:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        out = output_dir or Path("jsrecon-out") / f"{host}_{stamp}"
        saved.append(write_json(result, out / "result.json", reveal))
        saved.append(write_markdown(result, out / "report.md", reveal))
        if save_js and result.js_files:
            n = save_js_files(result, out / "js")
            ui.info(f"{n} arquivo(s) JS salvos em {out / 'js'}")
    if html:
        saved.append(write_html(result, html, reveal))

    if json_out:
        ui.print_json(result.to_dict(reveal))
    else:
        ui.render(result, reveal)
    for path in saved:
        ui.info(f"relatório: {path}")


def main() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    if "--version" in sys.argv[1:]:
        print(f"jsrecon {__version__}")
        return
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
