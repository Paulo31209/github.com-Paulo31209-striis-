// STRIIS — servidor principal.
// Serve a API de scans e o dashboard web estático.

import './lib/loadEnv.js'; // carrega .env antes de tudo
import express from 'express';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { api } from './routes/api.js';
import { seedMockData } from './lib/store.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(__dirname, '..', 'public');
const PORT = process.env.PORT || 3000;

const app = express();
app.use(express.json());

// ---------- Trava de acesso por PIN (opcional) ----------
// Ative definindo STRIIS_PIN no .env. Sem STRIIS_PIN, o acesso fica aberto.
const PIN = (process.env.STRIIS_PIN || '').trim();
if (PIN) {
  // Token do cookie derivado do PIN (não guarda o PIN em si; não dá pra forjar sem o PIN).
  const TOKEN = crypto.createHmac('sha256', PIN).update('striis-auth-v1').digest('hex');
  const loginPage = path.join(PUBLIC, 'login.html');

  const parseCookies = (header) => {
    const out = {};
    (header || '').split(';').forEach((c) => {
      const i = c.indexOf('=');
      if (i > -1) out[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim());
    });
    return out;
  };

  // Login: valida o PIN e seta o cookie de sessão.
  app.post('/api/login', (req, res) => {
    const pin = (req.body?.pin || '').toString().trim();
    // Comparação em tempo constante.
    const a = Buffer.from(pin);
    const b = Buffer.from(PIN);
    const ok = a.length === b.length && crypto.timingSafeEqual(a, b);
    if (!ok) return res.status(401).json({ error: 'PIN incorreto.' });
    res.setHeader(
      'Set-Cookie',
      `striis_auth=${TOKEN}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800`, // 7 dias
    );
    res.json({ ok: true });
  });

  // Página de login sempre acessível.
  app.get('/login', (req, res) => res.sendFile(loginPage));

  // Trava tudo o que vier depois, exceto quem já tem o cookie válido.
  app.use((req, res, next) => {
    const cookies = parseCookies(req.headers.cookie);
    if (cookies.striis_auth === TOKEN) return next();
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Não autenticado. Informe o PIN em /login.' });
    }
    return res.sendFile(loginPage);
  });
}

// API.
app.use('/api', api);

// Dashboard estático.
app.use(express.static(PUBLIC));

// Popula dados de exemplo para o dashboard já nascer preenchido.
// Defina STRIIS_NO_SEED=1 para começar vazio.
if (!process.env.STRIIS_NO_SEED) {
  seedMockData();
}

app.listen(PORT, () => {
  console.log(`\n  🛡️  STRIIS rodando em http://localhost:${PORT}`);
  console.log(`     Dashboard: http://localhost:${PORT}`);
  console.log(`     PIN de acesso: ${PIN ? 'ATIVADO' : 'desativado (defina STRIIS_PIN no .env)'}\n`);
});
