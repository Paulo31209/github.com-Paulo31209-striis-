# 🚀 Deploy do STRIIS em `scan.girabot.com.br` (Cloudflare Tunnel)

Este guia publica o dashboard do STRIIS num subdomínio usando **Cloudflare
Tunnel** — sem abrir porta no firewall e sem expor IP.

```
Internet → Cloudflare → Túnel (cloudflared) → localhost:3000 (STRIIS) → Strix
```

> 🔐 **O token do túnel é secreto.** Ele fica **só no servidor** (no `.env` ou no
> systemd). Nunca comite o token no Git nem cole em chats.

---

## Pré-requisitos no servidor

- STRIIS clonado e `npm install` feito (ver README).
- Strix instalado + Docker rodando (ver README) — para o modo profundo.
- `cloudflared` instalado.
- Um **Cloudflare Tunnel token** (do painel Zero Trust).

---

## Passo 1 — Rodar o STRIIS como serviço (systemd)

Assim ele sobe sozinho no boot e reinicia se cair.

1. Ajuste os caminhos/usuário em `scripts/striis.service` se necessário
   (o padrão assume usuário `saulo` e o projeto em `/home/saulo/striis`).

2. Instale o serviço:

   ```bash
   sudo cp scripts/striis.service /etc/systemd/system/striis.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now striis
   sudo systemctl status striis        # deve estar "active (running)"
   ```

O STRIIS lê o `.env` do projeto automaticamente (STRIX_LLM, LLM_API_KEY, etc.).

---

## Passo 2 — Mapear o hostname no túnel (painel Cloudflare)

Um túnel com **token** é gerenciado pelo painel (as regras de ingress ficam lá,
não em arquivo local).

1. Acesse **Cloudflare Zero Trust → Networks → Tunnels**.
2. Abra o seu túnel (o mesmo do token) → aba **Public Hostname** →
   **Add a public hostname**:
   - **Subdomain:** `scan`
   - **Domain:** `girabot.com.br`
   - **Type:** `HTTP`
   - **URL:** `localhost:3000`
3. Salve. O DNS de `scan.girabot.com.br` é criado automaticamente.

---

## Passo 3 — Rodar o cloudflared com o token

Se o `cloudflared` que já está rodando é o desse túnel, o Passo 2 já basta.
Caso precise (re)subir, use uma das opções:

**Opção A — como serviço (recomendado):**

```bash
sudo cloudflared service install <SEU_TOKEN_DO_TUNEL>
sudo systemctl status cloudflared
```

**Opção B — na mão (teste rápido):**

```bash
cloudflared tunnel run --token <SEU_TOKEN_DO_TUNEL>
```

> Dica: para não deixar o token no histórico do shell, guarde-o num arquivo e
> use `--token "$(cat ~/.cf_tunnel_token)"`.

---

## Passo 4 — Testar

Abra **https://scan.girabot.com.br** no navegador. O badge no topo deve mostrar
**🧠 Strix conectado** (se o Strix estiver configurado) ou **⚡ Modo rápido**.

---

## Segurança — leia antes de expor publicamente

O dashboard **não tem login** ainda. Ao publicá-lo, qualquer pessoa com o link
pode disparar scans. Escolha uma proteção:

- **Cloudflare Access** (recomendado, grátis): no mesmo painel Zero Trust, crie
  uma policy exigindo login (e-mail autorizado) para `scan.girabot.com.br`.
  Fecha o acesso sem mexer no código.
- Ou aguarde o login nativo do STRIIS (está no roadmap).

> ⚖️ Só escaneie alvos que você tem **autorização** para testar. O Strix roda
> pentest de verdade e consome créditos do seu LLM — use `STRIX_MAX_BUDGET`.
