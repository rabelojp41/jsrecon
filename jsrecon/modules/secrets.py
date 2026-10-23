"""Módulo 2b — detecção de secrets (regex + entropia), com nível de confiança."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Callable

from jsrecon.analysis.entropy import LineIndex, has_sequential_run, shannon
from jsrecon.models import Confidence, JSFile, Location, ModuleResult, Secret
from jsrecon.modules.base import Context, Module

ALTA, MEDIA, BAIXA = Confidence.ALTA, Confidence.MEDIA, Confidence.BAIXA

PLACEHOLDER = re.compile(
    r"example|xxxx|your[_\-]?|changeme|change_me|placeholder|dummy|sample|insert|redacted|foobar|"
    r"<[^>]*>|\{\{|\$\{|\*\*\*|test[_\-]?key|fake|^(?:password|secret|token|null|undefined|true|false)$",
    re.I,
)

Validator = Callable[[str], Confidence | None]


@dataclass(frozen=True)
class Rule:
    name: str
    regex: re.Pattern[str]
    confidence: Confidence
    group: int = 0
    validator: Validator | None = None
    note: str | None = None


def _is_placeholder(value: str) -> bool:
    return bool(PLACEHOLDER.search(value)) or len(set(value)) <= 3


def _jwt(value: str) -> Confidence | None:
    try:
        header = value.split(".", 1)[0]
        data = json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))
    except (ValueError, UnicodeDecodeError):
        return MEDIA
    return ALTA if isinstance(data, dict) and "alg" in data else MEDIA


def _conn_string(value: str) -> Confidence | None:
    m = re.match(r"^[\w+]+://([^:@/]*):([^@]*)@", value)
    if not m:
        return None
    password = m.group(2)
    if not password or _is_placeholder(password) or password.lower() in ("pass", "pwd", "root", "admin"):
        return BAIXA
    return ALTA


def _by_entropy(threshold: float) -> Validator:
    def check(value: str) -> Confidence | None:
        return ALTA if shannon(value) >= threshold else MEDIA

    return check


RULES: list[Rule] = [
    Rule("AWS Access Key ID", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"), ALTA),
    Rule(
        "AWS Secret Access Key",
        re.compile(r"(?i)aws.{0,20}?(?:secret|private).{0,20}?[\"'`]([A-Za-z0-9/+=]{40})[\"'`]"),
        MEDIA, group=1, validator=_by_entropy(4.0),
    ),
    Rule(
        "Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), ALTA,
        note="chaves Google no frontend podem ser públicas por design — verifique restrições de API/referer",
    ),
    Rule("Google OAuth Client Secret", re.compile(r"\bGOCSPX-[0-9A-Za-z\-_]{28}\b"), ALTA),
    Rule("Slack Token", re.compile(r"\bxox[abposr]-[0-9A-Za-z\-]{10,72}\b"), ALTA),
    Rule("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,}"), ALTA),
    Rule("GitHub Token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{80,})\b"), ALTA),
    Rule("Stripe Secret Key", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{20,99}\b"), ALTA),
    Rule("SendGrid API Key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), ALTA),
    Rule("Twilio API Key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), MEDIA),
    Rule("Mailgun API Key", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"), MEDIA),
    Rule("Shopify Token", re.compile(r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b"), ALTA),
    Rule("NPM Token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), ALTA),
    Rule(
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
        MEDIA, validator=_jwt,
    ),
    Rule(
        "Chave privada",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
                   r"[\s\S]{16,8000}?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
        ALTA,
    ),
    Rule(
        "Chave privada (cabeçalho)",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
        MEDIA,
    ),
    Rule(
        "Connection string",
        re.compile(r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|rediss?|amqps?|mssql|sqlserver)://"
                   r"[^\s:'\"`<>/@]+:[^\s'\"`<>@]+@[^\s'\"`<>]+"),
        ALTA, validator=_conn_string,
    ),
]

GENERIC = re.compile(
    r"(?i)\b([\w\-]*(?:api[_\-]?key|apikey|secret|token|passw(?:or)?d|client[_\-]?secret|access[_\-]?key|"
    r"auth[_\-]?key|private[_\-]?key|bearer)[\w\-]*)[\"'`]?\s*[:=]\s*[\"'`]([^\"'`\s]{8,200})[\"'`]"
)
HIGH_ENTROPY_CANDIDATE = re.compile(r"[\"'`]([A-Za-z0-9+/=_\-]{24,200})[\"'`]")
NOT_SECRET_PREFIX = ("sha256-", "sha384-", "sha512-", "iVBOR", "R0lGOD", "/9j/", "PHN2Zy", "data:")
MAX_ENTROPY_HITS_PER_FILE = 20


def _generic_confidence(value: str) -> Confidence | None:
    if _is_placeholder(value) or re.fullmatch(r"[A-Za-z_.\-]+", value):  # identificador, não segredo
        return None
    if value.startswith(("http://", "https://", "/", "./")):
        return None
    has_mix = re.search(r"[A-Za-z]", value) and re.search(r"\d", value)
    return MEDIA if shannon(value) >= 3.5 and has_mix else BAIXA


def _entropy_candidate(value: str) -> bool:
    if value.startswith(NOT_SECRET_PREFIX) or value.count("/") >= 2 or has_sequential_run(value):
        return False
    if re.fullmatch(r"[0-9a-fA-F\-]+", value):  # hashes de build, UUIDs
        return False
    if not (re.search(r"[a-z]", value) and re.search(r"[A-Z]", value) and re.search(r"\d", value)):
        return False
    if re.fullmatch(r"[A-Za-z]+(?:[_\-][A-Za-z]+)*", value):
        return False
    return shannon(value) >= 4.3 and not _is_placeholder(value)


def scan(f: JSFile) -> list[Secret]:
    text = f.content
    lines = LineIndex(text)
    found: dict[str, Secret] = {}  # valor -> melhor achado neste arquivo

    def add(type_: str, value: str, conf: Confidence, offset: int, note: str | None = None) -> None:
        cur = found.get(value)
        if cur is not None and cur.confidence.rank >= conf.rank:
            return
        found[value] = Secret(type_, value, conf, Location(f.label, lines.line(offset), f.origin), shannon(value), note)

    covered: list[tuple[int, int]] = []
    for rule in RULES:
        for m in rule.regex.finditer(text):
            value = m.group(rule.group)
            start, end = m.span(rule.group)
            if any(s <= start and end <= e for s, e in covered):
                continue  # ex.: cabeçalho de chave privada já coberto pelo bloco completo
            conf = rule.validator(value) if rule.validator else rule.confidence
            if rule.validator is None and _is_placeholder(value):
                conf = BAIXA
            if conf is None:
                continue
            covered.append((start, end))
            add(rule.name, value, conf, start, rule.note)

    for m in GENERIC.finditer(text):
        value = m.group(2)
        if value in found:
            continue
        conf = _generic_confidence(value)
        if conf is not None:
            add(f"Atribuição suspeita ({m.group(1)[:40]})", value, conf, m.start(2))

    hits = 0
    for m in HIGH_ENTROPY_CANDIDATE.finditer(text):
        value = m.group(1)
        if value in found or any(value in v for v in found):
            continue
        if _entropy_candidate(value):
            add("Alta entropia", value, BAIXA, m.start(1))
            hits += 1
            if hits >= MAX_ENTROPY_HITS_PER_FILE:
                break
    return list(found.values())


class SecretScanner(Module):
    key = "secrets"
    title = "Secrets"

    async def run(self, ctx: Context) -> ModuleResult:
        files = ctx.result.js_files
        if not files:
            return self.skipped("nenhum arquivo JS coletado")
        secrets: list[Secret] = []
        with ctx.ui.progress("Buscando secrets", total=len(files)) as bar:
            for f in files:
                secrets += scan(f)
                bar.advance()
        secrets.sort(key=lambda s: (-s.confidence.rank, s.type, s.location.file, s.location.line))
        ctx.result.secrets = secrets
        high = sum(1 for s in secrets if s.confidence is ALTA)
        note = f"{len(files)} arquivos analisados"
        if secrets:
            note = f"{high} de confiança alta; " + note
        return self.done(len(secrets), note)
