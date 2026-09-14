# 🛡️ STRIIS — Agente de Cibersegurança

STRIIS é a **casca** (frontend + orquestrador) de um agente de segurança que
roda no **servidor**. O usuário fala em **linguagem natural** (ex.: *"faça uma
varredura no meu sistema e encontre falhas"*), o STRIIS interpreta a intenção e
dispara a varredura certa, mostrando tudo num **dashboard web** em tempo real.

Por baixo, ele funciona em **dois modos**:

```
Usuário → "faça um pentest no site X"
   │
   ▼
STRIIS (front + orquestrador Node/Express)
   │
   ├── ⚡ Modo rápido (built-in)  → scanners próprios, instantâneos, sem custo
   │
   └── 🧠 Modo profundo (Strix)   → dispara o STRIX (pentest autônomo com IA)
                                     https://github.com/usestrix/strix
```

## Os dois engines

### ⚡ Modo rápido (built-in) — sempre disponível

Scanners próprios, leves, sem dependências externas nem custo:

| Tipo | O que verifica |
|------|----------------|
| 🌐 **URL / site** | Headers de segurança (HSTS, CSP, X-Frame-Options…), HTTPS, cookies inseguros, validade do certificado TLS e exposição de tecnologia. |
| 🖥️ **Servidor** | Portas sensíveis abertas (SSH, FTP, bancos de dados, Redis…), SO, execução como root e uptime elevado. |
| 📦 **Dependências** | CVEs conhecidas nas dependências de um projeto Node (via base pública [OSV.dev](https://osv.dev)). |

### 🧠 Modo profundo (Strix AI) — quando configurado no servidor

Dispara o [**Strix**](https://github.com/usestrix/strix), um pentester
autônomo com IA que executa o alvo dinamicamente, encontra vulnerabilidades e
**valida com prova de conceito (PoC)**. O STRIIS lê o resultado
(`vulnerabilities.json`) e mostra tudo no mesmo dashboard, com CVE, CWE, CVSS e
PoC. Alvos aceitos: URL, repositório Git, diretório de código, spec de API ou IP.

> O STRIIS detecta sozinho se o Strix está pronto (badge no topo). Se não
> estiver, ele cai no modo rápido e explica como ativar.

Cada scan (dos dois modos) gera **achados** classificados por severidade
(Crítica, Alta, Média, Baixa, Info), um **score de risco** e recomendações.

## Como rodar

```bash
npm install
npm start
```

Depois abra: **http://localhost:3000**

O dashboard já nasce com **dados de exemplo** para você ver o visual. Para
começar vazio (sem dados simulados):

```bash
STRIIS_NO_SEED=1 npm start
```

Porta configurável via variável `PORT`.

## 🧠 Ativando o modo profundo (Strix) no servidor

O modo rápido já funciona sozinho. Para ligar o **pentest com IA**, instale o
Strix no mesmo servidor onde o STRIIS roda:

1. **Docker** instalado e com o daemon rodando.
2. **CLI do Strix**:
   ```bash
   pip install strix-agent
   # ou: curl -sSL https://strix.ai/install | bash
   ```
3. **Chave de LLM** (OpenAI, Anthropic, Google, OpenRouter…):
   ```bash
   export STRIX_LLM="openai/gpt-4.1"     # provedor/modelo
   export LLM_API_KEY="sua-chave-aqui"
   ```
4. Reinicie o STRIIS. O badge no topo vira **🧠 Strix conectado**.

### Variáveis de ambiente do STRIIS ↔ Strix

| Variável | Default | Descrição |
|----------|---------|-----------|
| `STRIX_LLM` | — | Provedor/modelo do LLM (obrigatório p/ o Strix). |
| `LLM_API_KEY` | — | Chave da API do LLM (obrigatória). |
| `STRIX_BIN` | `strix` | Caminho do binário do Strix. |
| `STRIX_WORKDIR` | cwd | Onde ficará a pasta `strix_runs/`. |
| `STRIX_SCAN_MODE` | `standard` | `quick`, `standard` ou `deep`. |
| `STRIX_MAX_BUDGET` | — | Teto de custo (USD) por scan. |

> ⚠️ O Strix consome créditos do seu LLM e roda pentest de verdade. Use apenas
> em **alvos autorizados**.

## API

| Método | Rota | Descrição |
|--------|------|-----------|
| `GET`  | `/api/health` | Status do serviço. |
| `GET`  | `/api/summary` | Estatísticas agregadas para o painel. |
| `GET`  | `/api/scans` | Lista de scans (sem os achados). |
| `GET`  | `/api/scans/:id` | Detalhe de um scan com todos os achados. |
| `POST` | `/api/scans/url` | Escaneia uma URL. Body: `{ "target": "exemplo.com" }` |
| `POST` | `/api/scans/server` | Analisa o servidor local. |
| `POST` | `/api/scans/deps` | Verifica dependências. Body opcional: `{ "path": "/caminho/projeto" }` |
| `GET`  | `/api/engine` | Status do engine Strix (instalado? docker? LLM?). |
| `POST` | `/api/scans/strix` | Inicia um pentest com Strix (assíncrono). Body: `{ "target": "https://…", "mode": "deep" }`. Retorna um `jobId`. |
| `GET`  | `/api/jobs/:id` | Acompanha um job assíncrono. `?since=N` traz só o log novo. |
| `POST` | `/api/command` | Comando em linguagem natural. Body: `{ "text": "faça um pentest no site X", "engine": "strix" }` |

O comando em linguagem natural (`/api/command`) escolhe o engine sozinho: se o
texto pedir pentest/exploração profunda (ou `engine: "strix"`) e o Strix estiver
pronto, roda o modo profundo; senão, usa o modo rápido.

### Exemplo

```bash
curl -X POST http://localhost:3000/api/scans/url \
  -H 'content-type: application/json' \
  -d '{"target":"github.com"}'
```

## Estrutura

```
striis/
├── server/
│   ├── index.js            # Servidor Express (API + dashboard)
│   ├── routes/api.js       # Rotas da API
│   ├── scanners/           # Engine rápido (built-in)
│   │   ├── urlScanner.js    # Scan de URL/headers/TLS
│   │   ├── serverScanner.js # Scan do servidor local
│   │   └── depScanner.js    # Scan de dependências (OSV)
│   └── lib/
│       ├── findings.js      # Modelo de achado + severidade + score
│       ├── store.js         # Armazenamento em memória + dados de exemplo
│       ├── intent.js        # Interpretador de linguagem natural → scan
│       ├── strix.js         # Adaptador do engine Strix (pentest com IA)
│       └── jobs.js          # Jobs assíncronos (scans demorados)
└── public/                  # Dashboard (HTML/CSS/JS puro)
    ├── index.html
    ├── styles.css
    └── app.js
```

## Roadmap (próximos passos)

- [x] Interface conversacional (linguagem natural → scan)
- [x] Integração com o Strix (pentest autônomo com IA)
- [ ] Persistência em banco (SQLite/Postgres) no lugar do armazenamento em memória
- [ ] Scans agendados/contínuos (cron) com alertas
- [ ] Autenticação no dashboard
- [ ] Ver o `penetration_test_report.md` do Strix direto no dashboard
- [ ] Exportação de relatórios (PDF/JSON/SARIF)

## Aviso

Use o STRIIS apenas em **alvos que você tem autorização** para testar.
Escanear sistemas de terceiros sem permissão pode ser ilegal.

## Licença

MIT
