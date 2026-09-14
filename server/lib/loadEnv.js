// Carregador de .env sem dependências.
// Lê um arquivo .env na raiz do projeto (se existir) e popula process.env.
// Variáveis já definidas no ambiente têm prioridade (não são sobrescritas).
// Importe este módulo ANTES de qualquer outro que leia process.env.

import fs from 'node:fs';
import path from 'node:path';

const envPath = path.join(process.cwd(), '.env');

try {
  const content = fs.readFileSync(envPath, 'utf8');
  let carregadas = 0;

  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;

    const key = trimmed.slice(0, eq).trim();
    let val = trimmed.slice(eq + 1).trim();

    // Valor entre aspas: mantém como está (sem tirar comentário interno).
    if (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    ) {
      val = val.slice(1, -1);
    } else {
      // Remove comentário inline do tipo "  # ..." em valores sem aspas.
      const hash = val.indexOf(' #');
      if (hash !== -1) val = val.slice(0, hash).trim();
    }

    // Ambiente real vence o .env.
    if (!(key in process.env)) {
      process.env[key] = val;
      carregadas += 1;
    }
  }

  if (carregadas > 0) {
    console.log(`  ⚙️  .env carregado (${carregadas} variável(is)).`);
  }
} catch {
  // Sem .env — tudo bem, segue com o ambiente atual.
}
