# jsrecon

Ferramenta de recon para aplicações web, focada em JavaScript, CDN/WAF e origem. Ela:

- coleta JS atual e histórico (Wayback Machine), incluindo source maps;
- extrai endpoints e secrets, indicando arquivo e linha de cada achado;
- detecta CDN/WAF;
- procura candidatos a IP de origem atrás do CDN;
- enriquece IPs com dados do Shodan.

> **Uso autorizado apenas.** Use somente em pentests com autorização por escrito ou em programas de bug bounty, e sempre dentro do escopo publicado. A ferramenta recusa requisições ativas fora do `scope.txt`, mas a responsabilidade pelo uso é sua.

## Instalação

Requer Python 3.11 ou superior.

```bash
python -m venv .venv
.venv/Scripts/activate        # Windows  (Linux/macOS: source .venv/bin/activate)
pip install -r requirements.txt
pip install -e .              # instala o comando `jsrecon`
```

## Escopo

Sem `--scope`, o escopo é automaticamente o próprio alvo e todos os subdomínios dele (`exemplo.com` e `*.exemplo.com`). A ferramenta nunca faz requisição ativa fora disso.

```bash
jsrecon exemplo.com --active
```

Para exclusões, IPs/CIDRs ou vários domínios, use um arquivo com `--scope scope.txt`, uma entrada por linha. Comentários começam com `#`.

```text
exemplo.com              # domínio exato
*.exemplo.com            # qualquer subdomínio (não inclui o domínio raiz)
203.0.113.10             # IP único
203.0.113.0/24           # faixa CIDR
!pagamentos.exemplo.com  # exclusão (tem prioridade sobre as inclusões)
```

O alvo precisa estar no escopo, ou a ferramenta encerra sem fazer nada.

## Uso

```bash
# Passivo (padrão): só fontes públicas, nenhuma requisição ao alvo
jsrecon exemplo.com

# Ativo: baixa página e JS, analisa headers e valida o que for autorizado
jsrecon exemplo.com --active

# Ativo + teste de endpoints que só aparecem em versões antigas (HEAD/GET)
jsrecon exemplo.com --active --probe --probe-limit 100

# Validar IPs de origem que VOCÊ informa (IP ou host, repetível)
jsrecon exemplo.com --active --origin-ip 203.0.113.50 --origin-ip origem.exemplo.com

# Mais devagar e com User-Agent próprio
jsrecon exemplo.com --active --rate 1 --user-agent "Pentest-ACME/1.0 (contato@acme.com)"

# Relatório HTML para anexar na entrega + JS salvos em disco
jsrecon exemplo.com --active --html entrega.html --save-js -o resultados/exemplo

# Automação: só JSON no stdout
jsrecon exemplo.com --json | jq '.secrets[] | select(.confidence == "alta")'

# CI/scripts: só o painel de resumo, sem cores
jsrecon exemplo.com --quiet --no-color
```

Rode `jsrecon --help` para ver todas as opções.

### Opções principais

| Opção | Descrição |
|---|---|
| `--active` / `--passive` | Modo ativo faz requisições ao alvo. O passivo (padrão) não faz. |
| `--rate`, `--passive-rate` | Máximo de requisições/s ao alvo (padrão 5) e a cada fonte pública (padrão 2). |
| `--concurrency`, `--timeout`, `--retries` | Paralelismo, timeout em segundos e novas tentativas em erro de rede, 429 ou 5xx (com backoff). |
| `--user-agent` / `-A` | User-Agent de todas as requisições. |
| `--probe` | No modo ativo, testa se endpoints históricos ainda respondem. |
| `--origin-ip` | IP ou host autorizado para validação de origem. |
| `--reveal` | Mostra os secrets completos. Por padrão aparecem só os 4 primeiros e os 4 últimos caracteres. |
| `--json`, `--quiet`, `--no-color` | Modos de saída para automação. |
| `--html ARQ` | Gera também o relatório HTML. |
| `-o DIR`, `--no-save`, `--save-js` | Onde gravar `result.json` e `report.md`; desliga a gravação; salva os JS coletados. |
| `--no-wayback`, `--max-historical`, `--max-js` | Controlam a coleta de JS. |
| `--cve-intel` / `--no-cve-intel`, `--max-cves` | Liga/desliga o enriquecimento de CVEs (padrão: ligado, até 100). |
| `--cache-dir`, `--no-cache` | Cache em disco. O padrão é `~/.cache/jsrecon`, com validade de 24h. |

### Chaves de API (opcionais)

```bash
export SHODAN_API_KEY=...          # PowerShell: $env:SHODAN_API_KEY="..."
export SECURITYTRAILS_API_KEY=...
export VIRUSTOTAL_API_KEY=...
```

Quando falta uma chave, o módulo ou a fonte que depende dela aparece como **⚠ PULADO**, com o motivo. As chaves nunca são gravadas em relatórios, logs ou chaves de cache, e são removidas das URLs registradas.

## Módulos

| Módulo | Passivo | Ativo (adiciona) |
|---|---|---|
| **1. Coleta JS** | Wayback CDX (domínio e subdomínios no escopo), deduplicado por digest. Os arquivos são baixados do archive.org. | Página inicial, `<script src>`, scripts inline, `modulepreload`, `importmap`, imports encadeados e source maps (`sourceMappingURL`, header `SourceMap` ou `<arquivo>.map`). |
| **2. Endpoints** | URLs absolutas e relativas, `/api/`, `/vN/`, `fetch`, `axios`, `XMLHttpRequest`, `$.ajax`, rotas e operações GraphQL, com arquivo:linha e marca atual/histórico. | `--probe`: faz HEAD/GET, sem seguir redirecionamentos, em endpoints que só aparecem em versões antigas. |
| **2. Secrets** | Regex para AWS, Google, Slack, GitHub, Stripe, SendGrid, JWT, chaves privadas, connection strings e outros, mais atribuições suspeitas e entropia de Shannon. Cada achado recebe confiança alta, média ou baixa. | — |
| **3. CDN/WAF** | IPs resolvidos comparados com os ranges oficiais (Cloudflare, Fastly, CloudFront, Imperva) e com os prefixos de ASN da Akamai, além da cadeia de CNAME. | Headers (`cf-ray`, `x-amz-cf-id`, `x-sucuri-id`, `akamai-grn`…) e cookies (`__cf_bm`, `incap_ses_`, `ak_bmsc`…). |
| **4. Origin finder** (só se houver CDN/WAF) | Histórico DNS (SecurityTrails e VirusTotal), subdomínios fora do CDN, MX, SPF e hash mmh3 do favicon buscado no Shodan. IPs de CDN são descartados. | Validação: `GET /` direto no IP com `Host` e SNI do alvo. Compara status, `<title>`, tamanho e similaridade do HTML e gera um score. |
| **5. Shodan** | InternetDB sem chave. Com chave, usa a API completa (banners, versões, org/ASN, certificados) conforme o plano, detectado via `/api-info`. Os SANs viram subdomínios com fonte `shodan-ssl`. | — |
| **CVEs** | Para cada CVE potencial vinda do Shodan, consulta o `cvedb.shodan.io` (grátis, sem chave): CVSS, severidade, EPSS e se consta no CISA KEV. Ordena por KEV, CVSS e EPSS para priorizar. Links só para o NVD. | — |

### Regras de segurança

- **A trava de escopo fica no cliente HTTP.** Toda requisição, inclusive cada salto de redirecionamento, passa pelo `ScopeGuard`.
  - **Fontes públicas** (archive.org, Shodan, SecurityTrails, VirusTotal e as listas de CDN) estão numa allowlist separada e são as únicas permitidas no modo passivo.
  - **Requisições ativas** exigem `--active` e host dentro do escopo. Se o header `Host` for sobrescrito, ele também precisa estar no escopo.
  - **Bloqueios** são registrados no relatório, na seção *Bloqueado / ignorado pelo escopo*.
- **Achados de terceiros nunca recebem requisição fora do escopo.** Isso vale para hosts vindos de SANs, do Wayback ou encontrados em JS. Os que estão fora aparecem marcados como `fora do escopo`.
- **Validação de origem só acessa IPs que vocês forneceram**, via `scope.txt` ou `--origin-ip`, e só no modo ativo. Os demais aparecem como **candidato**. O relatório nunca afirma "IP real encontrado" sem validação.
- **O DNS é usado nos dois modos.** As consultas vão para resolvers públicos, não para o servidor do alvo.
- **O relatório traz todas as requisições ativas feitas** (`requests.active_log` no JSON), útil para a seção de evidências da entrega.

## Saída

- **stdout:** tabelas de achados e painel final de resumo, ou só JSON com `--json`.
- **stderr:** banner, barras de progresso, status de cada módulo e avisos.
- **Sem TTY** (pipe ou arquivo): texto simples, sem cores, barras ou ANSI.
- **Arquivos:** `jsrecon-out/<alvo>_<data>/result.json` e `report.md`, mais `--html` opcional.

Os status de cada módulo são:

- **✔ COM ACHADOS / SEM ACHADOS** (verde)
- **⚠ PULADO / FALHA PARCIAL** (amarelo)
- **✖ FALHA** (vermelho)

## Limitações conhecidas

- **Akamai** não publica lista oficial de IPs. Os prefixos dos ASNs AS20940 e AS16625 (via RIPEstat) contam como evidência mais fraca.
- **CVEs do Shodan** são *potenciais*, inferidos da versão do banner e não confirmados.
- **Se o IP é de borda de CDN**, os dados do Shodan descrevem o CDN, não o servidor do cliente. O relatório avisa quando isso acontece.
- **Chaves Google (`AIza…`)** no frontend muitas vezes são públicas por design. Verifique as restrições de API e referer antes de reportar.
- **A busca por favicon no Shodan** exige plano com query credits. Sem isso, o hash é reportado para busca manual (`http.favicon.hash:<hash>`).
- **O VirusTotal (API pública)** é limitado a 4 req/min, e a ferramenta respeita esse limite.

## Testes

Todos os testes usam respostas simuladas (respx) e um resolver DNS em memória. Nenhum teste acessa alvos reais.

```bash
pip install -r requirements-dev.txt
pytest
```

## Estrutura

```text
jsrecon/
  cli.py            CLI (Typer)
  config.py         Settings + chaves via ambiente
  scope.py          parser de escopo
  http.py           cliente async: ScopeGuard, rate limit, retries
  cache.py, dns.py  cache em disco com TTL, resolução DNS
  orchestrator.py   pipeline entre módulos
  ui.py             saída Rich (TTY-aware)
  modules/          js_collector, wayback, sourcemaps, endpoints, secrets,
                    prober, cdn_waf, origin_finder, shodan_enrich
  providers/        cdn_ranges, shodan, securitytrails, virustotal
  analysis/         entropy, similarity, favicon
  report/           json, markdown, html (+ template)
tests/              pytest + fixtures
```
