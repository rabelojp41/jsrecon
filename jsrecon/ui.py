"""Saída no terminal com Rich.

Regras para não quebrar automação:
  * banner, barras de progresso e logs  -> stderr
  * tabelas de achados e painel final   -> stdout
  * visual (cores, barras, banner em painel) só quando há TTY
  * --quiet: só o painel final; --json: só JSON no stdout
"""

from __future__ import annotations

import json
import sys
from contextlib import contextmanager
from typing import IO, Iterator

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn
from rich.table import Table
from rich.text import Text

from jsrecon.models import Confidence, ModuleResult, ReconResult, Status

STATUS_STYLE = {
    Status.COM_ACHADOS: ("✔", "green"),
    Status.SEM_ACHADOS: ("✔", "green"),
    Status.PULADO: ("⚠", "yellow"),
    Status.FALHA_PARCIAL: ("⚠", "yellow"),
    Status.FALHA: ("✖", "red"),
}
CONFIDENCE_STYLE = {Confidence.ALTA: "bold red", Confidence.MEDIA: "yellow", Confidence.BAIXA: "dim"}
SEVERITY_STYLE = {"crítica": "bold red", "alta": "red", "média": "yellow", "baixa": "dim", "nenhuma": "dim",
                  "desconhecida": "dim"}


class Tracker:
    """Handle de uma barra de progresso (no-op quando não há TTY)."""

    def __init__(self, progress: Progress | None = None, task_id=None):
        self._progress = progress
        self._task = task_id
        self.count = 0

    def advance(self, n: int = 1) -> None:
        self.count += n
        if self._progress is not None:
            self._progress.advance(self._task, n)

    def set_total(self, total: int | None) -> None:
        if self._progress is not None:
            self._progress.update(self._task, total=total)

    def set_suffix(self, suffix: str) -> None:
        if self._progress is not None:
            self._progress.update(self._task, suffix=suffix)


class UI:
    def __init__(
        self,
        *,
        no_color: bool = False,
        quiet: bool = False,
        json_mode: bool = False,
        max_rows: int = 50,
        stdout: IO[str] | None = None,
        stderr: IO[str] | None = None,
        force_terminal: bool | None = None,
    ):
        self.quiet = quiet
        self.json_mode = json_mode
        self.max_rows = max_rows
        out_file = stdout or sys.stdout
        err_file = stderr or sys.stderr
        self.err = Console(file=err_file, no_color=no_color, highlight=False, force_terminal=force_terminal)
        self.out = Console(file=out_file, no_color=no_color, highlight=False, force_terminal=force_terminal)
        if not self.out.is_terminal:
            self.out.width = 160
        if not self.err.is_terminal:
            self.err.width = 160
        self.interactive = self.err.is_terminal
        self._box = box.HEAVY_HEAD if self.out.is_terminal else box.ASCII

    # ------------------------------------------------------------------ logs
    @property
    def _chatty(self) -> bool:
        return not (self.quiet or self.json_mode)

    def banner(self, target: str, mode: str, scope_summary: str) -> None:
        if not self._chatty:
            return
        if self.interactive:
            body = Text.assemble(
                ("Alvo: ", "bold"), target, "   ", ("Modo: ", "bold"),
                (mode, "bold magenta" if mode == "ativo" else "bold cyan"),
                "\n", ("Escopo: ", "bold"), f"{scope_summary} carregado(s)",
            )
            self.err.print(Panel(body, title="[bold]jsrecon[/]", expand=False, border_style="blue"))
        else:
            self.err.print(f"jsrecon | alvo={target} modo={mode} escopo={scope_summary}", markup=False)

    # mensagens podem conter dados do alvo: sempre como Text (nunca interpretadas como markup)
    def _log(self, tty_prefix: str, plain_prefix: str, msg: str, style: str | None) -> None:
        if self.interactive:
            self.err.print(Text.assemble((tty_prefix, style or "dim"), (msg, style or "")))
        else:
            self.err.print(Text(f"{plain_prefix} {msg}"))

    def info(self, msg: str) -> None:
        if self._chatty:
            self._log("· ", "[i]", msg, None)

    def warn(self, msg: str) -> None:
        if not self.quiet:
            self._log("⚠ ", "[!]", msg, "yellow")

    def error(self, msg: str) -> None:
        self._log("✖ ", "[x]", msg, "red")

    @contextmanager
    def progress(self, description: str, total: int | None = None, suffix: str = "") -> Iterator[Tracker]:
        if not (self.interactive and self._chatty):
            yield Tracker()
            return
        progress = Progress(
            TextColumn(f"{description:<18}"),
            BarColumn(bar_width=10),
            MofNCompleteColumn(),
            TextColumn("{task.fields[suffix]}"),
            console=self.err,
        )
        with progress:
            task = progress.add_task(description, total=total, suffix=suffix)
            yield Tracker(progress, task)

    def module_status(self, result: ModuleResult) -> None:
        if not self._chatty:
            return
        icon, color = STATUS_STYLE[result.status]
        count = f" ({result.findings})" if result.findings is not None else ""
        note = f" — {result.note}" if result.note else ""
        head = f"{icon} {result.title}: {result.status.value}{count}"
        self.err.print(Text.assemble((head, color if self.interactive else ""), note))

    # ------------------------------------------------------------ resultados
    def print_json(self, data: dict) -> None:
        self.out.file.write(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
        self.out.file.flush()

    def render(self, result: ReconResult, reveal: bool) -> None:
        if self.json_mode:
            return
        if not self.quiet:
            for table in findings_tables(result, reveal, self.max_rows, self._box):
                self.out.print(table)
                self.out.print()
        self.out.print(summary_panel(result, self._box))


def _t(value) -> Text:
    """Células sempre como Text: dados do alvo (ex.: '/api/[id]') não viram markup."""
    return value if isinstance(value, Text) else Text(str(value))


def _row(table: Table, *cells, style: str | None = None) -> None:
    table.add_row(*(_t(c) for c in cells), style=style)


def new_table(title: str, columns, box_style) -> Table:
    table = Table(title=title, box=box_style, title_justify="left", title_style="bold")
    for col in columns:
        table.add_column(col, overflow="fold")
    return table


def _truncated(table: Table, total: int, limit: int) -> Table:
    if total > limit:
        table.caption = f"… mais {total - limit} linha(s) no relatório JSON/Markdown"
    return table


def findings_tables(result: ReconResult, reveal: bool, limit: int, box_style) -> list[Table]:
    tables: list[Table] = []

    if result.endpoints:
        t = new_table("Endpoints", ("Método", "Rota", "Arquivo:linha", "Origem", "Probe"), box_style)
        for ep in result.endpoints[:limit]:
            loc = ep.locations[0] if ep.locations else None
            extra = f" (+{len(ep.locations) - 1})" if len(ep.locations) > 1 else ""
            probe = "" if ep.probe_status is None else str(ep.probe_status)
            if ep.probe_note and ep.probe_status is None:
                probe = ep.probe_note
            _row(t, ep.method, ep.value, f"{loc}{extra}" if loc else "", ep.origin.value, probe)
        tables.append(_truncated(t, len(result.endpoints), limit))

    if result.secrets:
        t = new_table("Secrets", ("Tipo", "Valor", "Confiança", "Arquivo:linha"), box_style)
        for s in result.secrets[:limit]:
            style = CONFIDENCE_STYLE[s.confidence]
            _row(
                t, s.type, s.display(reveal), Text(s.confidence.value, style=style), s.location,
                style="red" if s.confidence is Confidence.ALTA else None,
            )
        tables.append(_truncated(t, len(result.secrets), limit))

    if result.cdn and result.cdn.providers:
        t = new_table("CDN/WAF", ("Provedor", "Evidência"), box_style)
        for p in result.cdn.providers:
            _row(t, p.provider, "\n".join(p.evidence))
        tables.append(t)

    if result.origins:
        t = new_table("IPs de origem", ("IP", "Fonte", "Score", "Validado", "Veredito"), box_style)
        for o in result.origins[:limit]:
            score = "–" if o.score is None else f"{o.score:.0%}"
            _row(t, o.ip, ", ".join(o.sources), score, "sim" if o.validated else "não", o.verdict)
        tables.append(_truncated(t, len(result.origins), limit))

    if result.hosts:
        t = new_table("Shodan", ("IP", "Org/ASN", "Portas", "Serviços/versões", "CVEs (potenciais)", "Fonte"), box_style)
        for h in result.hosts[:limit]:
            org = " / ".join(x for x in (h.org, h.asn) if x) or "–"
            if h.is_cdn_edge:
                org += f"\n(borda {h.is_cdn_edge})"
            cves = ", ".join(h.cves[:8]) + (f" +{len(h.cves) - 8}" if len(h.cves) > 8 else "")
            _row(
                t, h.ip, org, ", ".join(map(str, h.ports)) or "–",
                "\n".join(h.services[:6]) or "–", cves or "–", h.source,
            )
        tables.append(_truncated(t, len(result.hosts), limit))

    if result.cve_intel:
        t = new_table("CVEs potenciais (por versão de banner — não confirmadas)",
                      ("CVE", "Severidade (CVSS)", "EPSS", "KEV", "IPs", "Resumo"), box_style)
        for c in result.cve_intel[:limit]:
            if not c.found:
                _row(t, c.id, "sem dados", "–", "–", ", ".join(c.ips), "–")
                continue
            sev = f"{c.severity} ({c.cvss:.1f})" if c.cvss is not None else c.severity
            epss = "–" if c.epss is None else f"{c.epss:.1%}"
            summary = (c.summary or "–")
            summary = summary if len(summary) <= 90 else summary[:87] + "..."
            _row(
                t, c.id, Text(sev, style=SEVERITY_STYLE.get(c.severity, "")), epss,
                Text("SIM", style="bold red") if c.kev else "não", ", ".join(c.ips), summary,
            )
        tables.append(_truncated(t, len(result.cve_intel), limit))

    return tables


def summary_panel(result: ReconResult, box_style) -> Panel:
    t = Table(box=box_style, expand=False)
    for col in ("Módulo", "Status", "Achados", "Observação"):
        t.add_column(col)
    for m in result.modules:
        icon, color = STATUS_STYLE[m.status]
        _row(t, m.title, Text(f"{icon} {m.status.value}", style=color),
             "–" if m.findings is None else m.findings, m.note)
    req = result.requests
    subtitle = None
    if req:
        subtitle = (
            f"{req.get('active', 0)} req. ativas · {req.get('passive', 0)} passivas · "
            f"{len(req.get('blocked', []))} bloqueadas pelo escopo"
        )
    panel_box = box.ASCII if box_style is box.ASCII else box.ROUNDED
    return Panel(t, title="[bold]Resumo[/]", subtitle=subtitle, expand=False, box=panel_box)
