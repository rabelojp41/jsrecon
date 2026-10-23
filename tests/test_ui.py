import io
import json

from jsrecon.models import Mode, ModuleResult, ReconResult, Status
from jsrecon.ui import UI


def _result():
    r = ReconResult("exemplo.com", Mode.ACTIVE, {}, "0")
    r.modules = [
        ModuleResult("js", "Coleta JS", Status.COM_ACHADOS, 3, "3 atuais"),
        ModuleResult("origin", "Origin finder", Status.PULADO, None, "SECURITYTRAILS_API_KEY ausente"),
    ]
    return r


def _ui(**kw):
    out, err = io.StringIO(), io.StringIO()
    return UI(stdout=out, stderr=err, **kw), out, err


def test_non_tty_plain_text():
    ui, out, err = _ui()
    ui.banner("exemplo.com", "ativo", "2 domínios")
    ui.render(_result(), reveal=False)
    assert "\x1b[" not in out.getvalue() + err.getvalue()  # sem ANSI
    assert "jsrecon | alvo=exemplo.com" in err.getvalue()
    assert "Coleta JS" in out.getvalue() and "PULADO" in out.getvalue()
    assert "Coleta JS" not in err.getvalue()


def test_json_mode_only_json_on_stdout():
    ui, out, err = _ui(json_mode=True)
    ui.banner("exemplo.com", "ativo", "x")
    ui.info("progresso")
    ui.render(_result(), reveal=False)
    ui.print_json({"ok": True})
    assert json.loads(out.getvalue()) == {"ok": True}
    assert err.getvalue() == ""


def test_quiet_only_summary():
    ui, out, err = _ui(quiet=True)
    ui.banner("exemplo.com", "ativo", "x")
    ui.warn("aviso")
    ui.render(_result(), reveal=False)
    assert err.getvalue() == ""
    assert "Resumo" in out.getvalue()


def test_tty_colors_and_no_color():
    ui, out, _ = _ui(force_terminal=True)
    ui.render(_result(), reveal=False)
    assert "\x1b[" in out.getvalue()
    ui, out, _ = _ui(force_terminal=True, no_color=True)
    ui.render(_result(), reveal=False)
    assert "\x1b[3" not in out.getvalue()  # sem cores de primeiro plano


def test_target_data_is_never_rich_markup():
    from jsrecon.models import Endpoint, Location, Origin

    r = _result()
    r.endpoints = [Endpoint("/api/[bold]x[/bold]/[id]", "GET", "api", [Location("https://e.com/a.js", 1, Origin.ATUAL)])]
    ui, out, err = _ui()
    ui.render(r, reveal=False)
    ui.info("visto em /x/[red]y")
    assert "/api/[bold]x[/bold]/[id]" in out.getvalue()
    assert "[i] visto em /x/[red]y" in err.getvalue()
