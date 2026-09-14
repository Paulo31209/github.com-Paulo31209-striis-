// Rotas da API do STRIIS.
import express from 'express';
import { scanUrl } from '../scanners/urlScanner.js';
import { scanServer } from '../scanners/serverScanner.js';
import { scanDeps } from '../scanners/depScanner.js';
import { saveScan, getScan, listScans, summary } from '../lib/store.js';
import { parseIntent, replyForScan, replyForIntent } from '../lib/intent.js';

export const api = express.Router();

// Health check.
api.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'striis', time: new Date().toISOString() });
});

// Resumo agregado para o dashboard.
api.get('/summary', (req, res) => {
  res.json(summary());
});

// Lista todos os scans (sem os findings completos, para leveza).
api.get('/scans', (req, res) => {
  const scans = listScans().map(({ findings, ...rest }) => rest);
  res.json(scans);
});

// Detalhe de um scan.
api.get('/scans/:id', (req, res) => {
  const scan = getScan(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan não encontrado.' });
  res.json(scan);
});

// Helper para executar um scanner e salvar o resultado.
async function runAndSave(res, { type, target, runner }) {
  const startedAt = new Date().toISOString();
  try {
    const findings = await runner();
    const finishedAt = new Date().toISOString();
    const record = saveScan({ type, target, findings, startedAt, finishedAt });
    res.json(record);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

// Scan de URL.
api.post('/scans/url', async (req, res) => {
  const target = (req.body?.target || '').trim();
  if (!target) return res.status(400).json({ error: 'Informe o campo "target" (URL).' });
  await runAndSave(res, { type: 'url', target, runner: () => scanUrl(target) });
});

// Scan do servidor local.
api.post('/scans/server', async (req, res) => {
  await runAndSave(res, {
    type: 'server',
    target: 'servidor STRIIS (localhost)',
    runner: () => scanServer(),
  });
});

// Scan de dependências.
api.post('/scans/deps', async (req, res) => {
  const projectPath = (req.body?.path || process.cwd()).trim();
  await runAndSave(res, {
    type: 'deps',
    target: projectPath,
    runner: () => scanDeps(projectPath),
  });
});

// Executa um scanner por tipo e salva. Retorna o registro.
async function executeScan(type) {
  const startedAt = new Date().toISOString();
  const runners = {
    url: null, // tratado à parte (precisa de alvo)
    server: { target: 'servidor STRIIS (localhost)', run: () => scanServer() },
    deps: { target: process.cwd(), run: () => scanDeps(process.cwd()) },
  };
  const cfg = runners[type];
  const findings = await cfg.run();
  const finishedAt = new Date().toISOString();
  return saveScan({ type, target: cfg.target, findings, startedAt, finishedAt });
}

// Comando em linguagem natural: interpreta a intenção e roda o(s) scan(s).
// Body: { text: "faça uma varredura no meu sistema e encontre falhas" }
api.post('/command', async (req, res) => {
  const text = (req.body?.text || '').trim();
  if (!text) return res.status(400).json({ error: 'Informe o campo "text".' });

  const intent = parseIntent(text);

  // Casos sem alvo/intenção clara: responde pedindo mais informação.
  if (intent.type === 'unknown' || intent.type === 'need_url') {
    return res.json({ intent, reply: replyForIntent(intent), scans: [] });
  }

  try {
    // Scan de URL precisa do alvo extraído do texto.
    if (intent.type === 'url') {
      const startedAt = new Date().toISOString();
      const findings = await scanUrl(intent.target);
      const finishedAt = new Date().toISOString();
      const scan = saveScan({
        type: 'url',
        target: intent.target,
        findings,
        startedAt,
        finishedAt,
      });
      return res.json({ intent, reply: replyForScan(scan), scans: [scan] });
    }

    // Varredura completa: roda servidor + dependências (URL exige alvo).
    if (intent.type === 'all') {
      const server = await executeScan('server');
      const deps = await executeScan('deps');
      const totalFalhas =
        server.counts.critical + server.counts.high + server.counts.medium + server.counts.low +
        deps.counts.critical + deps.counts.high + deps.counts.medium + deps.counts.low;
      const reply =
        `🛡️ Varredura completa concluída! Analisei o **servidor** e as **dependências**.\n\n` +
        `${replyForScan(server)}\n\n${replyForScan(deps)}\n\n` +
        `📊 Total: ${totalFalhas} falha(s) encontradas nas duas frentes.`;
      return res.json({ intent, reply, scans: [server, deps] });
    }

    // server ou deps.
    const scan = await executeScan(intent.type);
    return res.json({ intent, reply: replyForScan(scan), scans: [scan] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
