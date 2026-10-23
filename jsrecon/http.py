"""Cliente HTTP assíncrono com trava de escopo, rate limit e retries.

Toda requisição da ferramenta passa por aqui. O ScopeGuard decide se ela é:
  * passiva — destino é uma fonte pública conhecida (Wayback, Shodan, ...),
    permitida em qualquer modo;
  * ativa  — qualquer outro destino; exige --active E host dentro do escopo
    (e, se houver header Host sobrescrito, ele também precisa estar no escopo).
Redirecionamentos são seguidos manualmente para que cada salto seja verificado.
"""

from __future__ import annotations

import asyncio
import random
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

from jsrecon.config import Settings
from jsrecon.models import Mode
from jsrecon.scope import Scope, host_of

PASSIVE_SOURCES = frozenset(
    {
        "web.archive.org",
        "archive.org",
        "internetdb.shodan.io",
        "api.shodan.io",
        "api.securitytrails.com",
        "www.virustotal.com",
        "www.cloudflare.com",
        "api.fastly.com",
        "ip-ranges.amazonaws.com",
        "stat.ripe.net",
        "my.imperva.com",
        "cvedb.shodan.io",
    }
)

RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})
_SENSITIVE_PARAMS = re.compile(r"([?&](?:key|apikey|api_key|token|access_token)=)[^&#]*", re.I)


class OutOfScopeError(Exception):
    def __init__(self, url: str, reason: str):
        super().__init__(f"{reason}: {url}")
        self.url = url
        self.reason = reason


@dataclass
class RequestRecord:
    method: str
    url: str
    kind: str  # ativo | passivo
    status: int | None = None
    host_header: str | None = None
    error: str | None = None


@dataclass
class BlockedRequest:
    url: str
    reason: str
    host_header: str | None = None


class RateLimiter:
    """Espaçamento mínimo entre requisições (rate em req/s; <=0 desliga)."""

    def __init__(self, rate: float):
        self.interval = 1.0 / rate if rate > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def acquire(self) -> None:
        if not self.interval:
            return
        async with self._lock:
            now = time.monotonic()
            wait = self._next - now
            if wait > 0:
                await asyncio.sleep(wait)
                now = time.monotonic()
            self._next = max(now, self._next) + self.interval


class ScopeGuard:
    def __init__(self, scope: Scope, mode: Mode):
        self.scope = scope
        self.mode = mode

    def classify(self, url: str, host_header: str | None = None) -> str:
        host = host_of(url)
        if not host:
            raise OutOfScopeError(url, "URL sem host")
        if host in PASSIVE_SOURCES and host_header is None:
            return "passivo"
        if self.mode is not Mode.ACTIVE:
            raise OutOfScopeError(url, "modo passivo: requisições ao alvo estão desabilitadas")
        if not self.scope.contains_host(host):
            raise OutOfScopeError(url, f"host fora do escopo ({host})")
        if host_header is not None and not self.scope.contains_host(host_header):
            raise OutOfScopeError(url, f"header Host fora do escopo ({host_header})")
        return "ativo"


@dataclass
class HttpStats:
    records: list[RequestRecord] = field(default_factory=list)
    blocked: list[BlockedRequest] = field(default_factory=list)

    @property
    def active_count(self) -> int:
        return sum(1 for r in self.records if r.kind == "ativo")

    @property
    def passive_count(self) -> int:
        return sum(1 for r in self.records if r.kind == "passivo")


class HttpClient:
    def __init__(self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None):
        self.settings = settings
        self.guard = ScopeGuard(settings.scope, settings.mode)
        self.stats = HttpStats()
        self._secrets = settings.keys.secret_values()
        self._sem = asyncio.Semaphore(max(1, settings.concurrency))
        self._active_limiter = RateLimiter(settings.rate_limit)
        self._host_rates: dict[str, float] = {}
        self._host_limiters: dict[str, RateLimiter] = {}
        self._transport = transport
        self._clients: dict[bool, httpx.AsyncClient] = {}

    # ------------------------------------------------------------------ setup
    def set_host_rate(self, host: str, rate: float) -> None:
        """Rate limit específico para uma fonte passiva (ex.: Shodan 1 req/s)."""
        self._host_rates[host] = rate
        self._host_limiters.pop(host, None)

    def _client(self, verify: bool) -> httpx.AsyncClient:
        if verify not in self._clients:
            self._clients[verify] = httpx.AsyncClient(
                timeout=self.settings.timeout,
                headers={"User-Agent": self.settings.user_agent},
                follow_redirects=False,
                verify=verify,
                transport=self._transport,
            )
        return self._clients[verify]

    def _limiter(self, kind: str, host: str) -> RateLimiter:
        if kind == "ativo":
            return self._active_limiter
        if host not in self._host_limiters:
            rate = self._host_rates.get(host, self.settings.passive_rate_limit)
            self._host_limiters[host] = RateLimiter(rate)
        return self._host_limiters[host]

    async def aclose(self) -> None:
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()

    async def __aenter__(self) -> "HttpClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    # --------------------------------------------------------------- helpers
    def redact(self, url: str) -> str:
        url = _SENSITIVE_PARAMS.sub(r"\1REDACTED", url)
        for secret in self._secrets:
            url = url.replace(secret, "REDACTED")
        return url

    def check(self, url: str, host_header: str | None = None) -> str:
        """Valida contra o escopo e registra bloqueios. Levanta OutOfScopeError."""
        try:
            return self.guard.classify(url, host_header)
        except OutOfScopeError as exc:
            self.stats.blocked.append(BlockedRequest(self.redact(url), exc.reason, host_header))
            raise

    def allowed(self, url: str, host_header: str | None = None) -> bool:
        """Consulta sem registrar bloqueio (para filtrar listas antes de requisitar)."""
        try:
            self.guard.classify(url, host_header)
            return True
        except OutOfScopeError:
            return False

    # ------------------------------------------------------------- requests
    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, str | list[str]] | None = None,
        data: dict[str, str] | None = None,
        host_header: str | None = None,
        sni_hostname: str | None = None,
        verify: bool = True,
        follow_redirects: bool = True,
        max_redirects: int = 5,
        max_bytes: int | None = None,
    ) -> httpx.Response:
        if params:
            url = str(httpx.URL(url, params=params))
        headers = dict(headers or {})
        if host_header:
            headers["Host"] = host_header

        response: httpx.Response | None = None
        for _ in range(max_redirects + 1):
            kind = self.check(url, host_header)
            response = await self._send(
                method, url, kind, headers, data, host_header, sni_hostname, verify, max_bytes
            )
            if not follow_redirects or response.status_code not in REDIRECT_STATUS:
                return response
            location = response.headers.get("location")
            if not location:
                return response
            next_url = urljoin(url, location)
            if not self.allowed(next_url, host_header):
                self.stats.blocked.append(
                    BlockedRequest(self.redact(next_url), "redirecionamento para fora do escopo", host_header)
                )
                return response
            url = next_url
            if response.status_code == 303:
                method, data = "GET", None
        assert response is not None
        return response

    async def get(self, url: str, **kw) -> httpx.Response:
        return await self.request("GET", url, **kw)

    async def head(self, url: str, **kw) -> httpx.Response:
        return await self.request("HEAD", url, **kw)

    async def _send(
        self,
        method: str,
        url: str,
        kind: str,
        headers: dict[str, str],
        data: dict[str, str] | None,
        host_header: str | None,
        sni_hostname: str | None,
        verify: bool,
        max_bytes: int | None,
    ) -> httpx.Response:
        record = RequestRecord(method, self.redact(url), kind, host_header=host_header)
        self.stats.records.append(record)
        client = self._client(verify)
        extensions = {"sni_hostname": sni_hostname} if sni_hostname else None
        last_exc: Exception | None = None

        for attempt in range(self.settings.retries + 1):
            await self._limiter(kind, host_of(url)).acquire()
            try:
                async with self._sem:
                    req = client.build_request(method, url, headers=headers, data=data, extensions=extensions)
                    resp = await client.send(req, stream=True)
                    try:
                        resp = await _read_limited(resp, max_bytes)
                    finally:
                        await resp.aclose()
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_exc = exc
                record.error = type(exc).__name__
                if attempt < self.settings.retries:
                    await asyncio.sleep(self._backoff(attempt))
                    continue
                raise
            record.status, record.error = resp.status_code, None
            if resp.status_code in RETRY_STATUS and attempt < self.settings.retries:
                await asyncio.sleep(self._backoff(attempt, resp.headers.get("retry-after")))
                continue
            return resp
        raise last_exc or RuntimeError("retries esgotados")  # pragma: no cover

    def _backoff(self, attempt: int, retry_after: str | None = None) -> float:
        if retry_after:
            try:
                return min(float(retry_after), 60.0)
            except ValueError:
                pass
        base = self.settings.backoff * (2**attempt)
        return base + random.uniform(0, base / 4) if base else 0.0


async def _read_limited(resp: httpx.Response, max_bytes: int | None) -> httpx.Response:
    """Lê o corpo respeitando um limite; devolve uma Response já materializada."""
    chunks: list[bytes] = []
    total = 0
    truncated = False
    async for chunk in resp.aiter_bytes():
        chunks.append(chunk)
        total += len(chunk)
        if max_bytes is not None and total > max_bytes:
            truncated = True
            break
    body = b"".join(chunks)
    if truncated and max_bytes is not None:
        body = body[:max_bytes]
    headers = [(k, v) for k, v in resp.headers.multi_items() if k.lower() not in ("content-encoding", "content-length")]
    out = httpx.Response(resp.status_code, headers=headers, content=body, request=resp.request)
    out.extensions["truncated"] = truncated
    return out
