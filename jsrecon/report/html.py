"""Relatório HTML autocontido (--html), com as mesmas tabelas do terminal."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from jsrecon.models import ReconResult

TEMPLATES = Path(__file__).parent / "templates"


def render_html(result: ReconResult, reveal: bool = False) -> str:
    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html", "j2"]))
    return env.get_template("report.html.j2").render(d=result.to_dict(reveal), reveal=reveal)


def write_html(result: ReconResult, path: Path, reveal: bool = False) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(result, reveal), encoding="utf-8")
    return path
