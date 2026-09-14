# 🛡️ STRIIS — Agente de Cibersegurança

STRIIS é um agente de segurança que roda no **servidor** e verifica falhas de
segurança de forma contínua, com um **dashboard web** para acompanhar tudo em
tempo real.

O "cérebro" (engine de scans) fica no backend; o front é apenas a interface que
mostra os resultados e dispara novos scans.

## O que ele escaneia

| Tipo | O que verifica |
|------|----------------|
| 🌐 **URL / site** | Headers de segurança (HSTS, CSP, X-Frame-Options…), HTTPS, cookies inseguros, validade do certificado TLS e exposição de tecnologia. |
| 🖥️ **Servidor** | Portas sensíveis abertas (SSH, FTP, bancos de dados, Redis…), SO, execução como root e uptime elevado. |
| 📦 **Dependências** | CVEs conhecidas nas dependências de um projeto Node (via base pública [OSV.dev](https://osv.dev)). |

Cada scan gera **achados** classificados por severidade (Crítica, Alta, Média,
Baixa, Info), um **score de risco** e recomendações de correção.

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
│   ├── scanners/
│   │   ├── urlScanner.js    # Scan de URL/headers/TLS
│   │   ├── serverScanner.js # Scan do servidor local
│   │   └── depScanner.js    # Scan de dependências (OSV)
│   └── lib/
│       ├── findings.js      # Modelo de achado + severidade + score
│       └── store.js         # Armazenamento em memória + dados de exemplo
└── public/                  # Dashboard (HTML/CSS/JS puro)
    ├── index.html
    ├── styles.css
    └── app.js
```

## Roadmap (próximos passos)

- [ ] Persistência em banco (SQLite/Postgres) no lugar do armazenamento em memória
- [ ] Scans agendados/contínuos (cron) com alertas
- [ ] Autenticação no dashboard
- [ ] Mais scanners (SQL injection, XSS ativo, scan de segredos no código)
- [ ] Exportação de relatórios (PDF/JSON)

## Aviso

Use o STRIIS apenas em **alvos que você tem autorização** para testar.
Escanear sistemas de terceiros sem permissão pode ser ilegal.

## Licença

MIT
