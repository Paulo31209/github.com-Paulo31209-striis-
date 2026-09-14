// Interpretador de intenção (linguagem natural → scan).
// Lê o que o usuário digitou em português e decide qual scanner rodar.
// Abordagem baseada em palavras-chave/padrões — não depende de API externa.
// (Pode ser trocado por um LLM depois, mantendo o mesmo formato de retorno.)

// Regex que captura um domínio/URL dentro do texto (ex.: "escaneia github.com").
const URL_REGEX =
  /\b((?:https?:\/\/)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})(?:\/[^\s]*)?/i;

// Extensões/domínios que NÃO devem ser tratados como alvo de scan de URL
// (evita confundir "package.json" ou "node.js" com um site).
const NOT_A_DOMAIN = /\.(json|js|ts|md|txt|lock|yml|yaml|env)$/i;

const KW = {
  deps: /(depend[êe]ncia|pacote|bibliotec|\bcve\b|\bnpm\b|lockfile|package[- ]?lock|vulnerab\w*\s+(de\s+)?(pacote|lib|depend))/i,
  server: /(sistema|servidor|m[áa]quina|host\b|porta|infra|localhost|meu\s+pc|meu\s+computador|kernel|firewall)/i,
  url: /(site|url|link|dom[íi]nio|p[áa]gina|website|endere[çc]o\s+web|\bweb\b)/i,
  all: /(tudo|completa?|completo|geral|full|todas?\s+as?\s+(falhas|verifica)|varredura\s+geral)/i,
  scanVerb:
    /(varredur|escane|escanei|escanea|verific|analis|checar|checa|procur|encontr|busca|aud[íi]t|pentest|teste?\s+de\s+seguran|falhas?|vulnerab|invas)/i,
};

/**
 * Interpreta o texto e retorna a intenção.
 * @returns {{ type: 'url'|'server'|'deps'|'all'|'unknown', target?: string, matched: string }}
 */
export function parseIntent(text) {
  const raw = String(text || '').trim();
  const t = raw.toLowerCase();

  if (!raw) return { type: 'unknown', matched: 'vazio' };

  // 1) Domínio/URL explícito tem prioridade (alvo concreto).
  const urlMatch = raw.match(URL_REGEX);
  if (urlMatch && !NOT_A_DOMAIN.test(urlMatch[1])) {
    // Só trata como scan de URL se houver verbo de scan OU palavra de site,
    // para não disparar à toa quando o domínio aparece por acaso.
    if (KW.scanVerb.test(t) || KW.url.test(t)) {
      return { type: 'url', target: urlMatch[1], matched: `domínio detectado: ${urlMatch[1]}` };
    }
  }

  // 2) Varredura completa/geral → roda todos.
  if (KW.all.test(t) && KW.scanVerb.test(t)) {
    return { type: 'all', matched: 'varredura completa' };
  }

  // 3) Dependências.
  if (KW.deps.test(t)) {
    return { type: 'deps', matched: 'palavras-chave de dependências' };
  }

  // 4) Sistema/servidor.
  if (KW.server.test(t)) {
    return { type: 'server', matched: 'palavras-chave de sistema/servidor' };
  }

  // 5) Menção a site sem domínio → pede o endereço.
  if (KW.url.test(t)) {
    return { type: 'need_url', matched: 'quis escanear um site, mas sem endereço' };
  }

  // 6) Verbo de scan genérico sem alvo → assume o próprio servidor
  //    ("faça uma varredura e encontre falhas" = analisar o sistema atual).
  if (KW.scanVerb.test(t)) {
    return { type: 'server', matched: 'varredura genérica → servidor' };
  }

  // 7) Não entendeu.
  return { type: 'unknown', matched: 'nenhuma intenção reconhecida' };
}

const TYPE_NOME = {
  url: 'varredura de URL/site',
  server: 'análise do servidor',
  deps: 'verificação de dependências',
};

const SEV_NOME = {
  critical: 'crítica',
  high: 'alta',
  medium: 'média',
  low: 'baixa',
  info: 'informativa',
};

/**
 * Monta uma resposta conversacional a partir de um scan concluído.
 * @param {object} scan  Registro salvo (com findings, counts, riskScore).
 */
export function replyForScan(scan) {
  const c = scan.counts;
  const problemas = c.critical + c.high + c.medium + c.low;
  const nome = TYPE_NOME[scan.type] || 'varredura';

  if (problemas === 0) {
    return `✅ Rodei a ${nome} em **${scan.target}** e não encontrei falhas relevantes. Score de risco: ${scan.riskScore}/100. Continue monitorando de tempos em tempos!`;
  }

  // Descreve a contagem por severidade (só as que existem).
  const partes = [];
  for (const sev of ['critical', 'high', 'medium', 'low']) {
    if (c[sev] > 0) partes.push(`${c[sev]} ${SEV_NOME[sev]}${c[sev] > 1 ? 's' : ''}`);
  }

  // Pega o achado mais grave para destacar.
  const ordem = ['critical', 'high', 'medium', 'low', 'info'];
  const pior = [...scan.findings].sort(
    (a, b) => ordem.indexOf(a.severity) - ordem.indexOf(b.severity),
  )[0];

  let msg = `🔍 Fiz a ${nome} em **${scan.target}** e encontrei **${problemas} falha(s)** (${partes.join(', ')}). Score de risco: **${scan.riskScore}/100**.`;
  if (pior) {
    msg += `\n\n⚠️ A mais grave: *${pior.title}* — ${pior.detail}`;
    if (pior.recommendation) msg += `\n💡 ${pior.recommendation}`;
  }
  msg += `\n\nAbri os detalhes completos aqui embaixo. 👇`;
  return msg;
}

/** Resposta quando não há alvo/intenção clara. */
export function replyForIntent(intent) {
  if (intent.type === 'need_url') {
    return '🌐 Beleza, quer escanear um site! Qual é o endereço? (ex.: "escaneia o site exemplo.com")';
  }
  return (
    '🤔 Não entendi bem o que você quer escanear. Posso:\n' +
    '• **Analisar o servidor** — ex.: "faça uma varredura no meu sistema"\n' +
    '• **Escanear um site** — ex.: "verifique o site exemplo.com"\n' +
    '• **Checar dependências** — ex.: "procure CVEs nas dependências"\n' +
    '• **Varredura completa** — ex.: "faça uma varredura completa"'
  );
}
