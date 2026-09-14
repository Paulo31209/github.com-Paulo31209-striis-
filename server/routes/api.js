// Rotas da API do STRIIS.
import express from 'express';
import { scanUrl } from '../scanners/urlScanner.js';
import { scanServer } from '../scanners/serverScanner.js';
import { scanDeps } from '../scanners/depScanner.js';
import { saveScan, getScan, listScans, summary } from '../lib/store.js';
import { parseIntent, replyForScan, replyForIntent } from '../lib/intent.js';
import { getEngineStatus, runStrixScan } from '../lib/strix.js';
import { createJob, jobView, appendLog, finishJob, failJob } from '../lib/jobs.js';

export const api = express.Router();

// Health check.
api.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'striis', time: new Date().toISOString() });
});

// Resumo agregado para o dashboard.
api.get('/summary', (req, res) => {
  res.json(summary());
});

// Status do engine Strix (instalado? docker? LLM configurado?).
api.get('/engine', (req, res) => {
  res.json(getEngineStatus());
});

// Inicia um scan do Strix (assíncrono). Retorna um jobId para polling.
// Body: { target, mode?, instruction? }
api.post('/scans/strix', (req, res) => {
  const target = (req.body?.target || '').trim();
  if (!target) return res.status(400).json({ error: 'Informe o campo "target".' });

  const engine = getEngineStatus();
  if (!engine.available) {
    return res.status(503).json({ error: `Strix indisponível. ${engine.reason}`, engine });
  }

  const mode = (req.body?.mode || '').trim() || undefined;
  const instruction = (req.body?.instruction || '').trim() || undefined;
  const job = startStrixJob({ target, mode, instruction });
  res.status(202).json(jobView(job.id));
});

// Polling de um job. ?since=N devolve só as linhas de log a partir de N.
api.get('/jobs/:id', (req, res) => {
  const since = parseInt(req.query.since, 10) || 0;
  const view = jobView(req.params.id, since);
  if (!view) return res.status(404).json({ error: 'Job não encontrado.' });
  res.json(view);
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

// Inicia um job de scan Strix em background e devolve o registro do job.
function startStrixJob({ target, mode, instruction }) {
  const job = createJob({ type: 'strix', target });
  const startedAt = new Date().toISOString();

  // Executa em background; o front acompanha via /api/jobs/:id.
  (async () => {
    try {
      const result = await runStrixScan({
        target,
        scanMode: mode,
        instruction,
        onLog: (line) => appendLog(job.id, line),
      });
      const finishedAt = new Date().toISOString();
      const scan = saveScan({
        type: 'strix',
        target,
        findings: result.findings,
        startedAt,
        finishedAt,
      });
      scan.runName = result.runName;
      scan.reportPath = result.reportPath;
      appendLog(job.id, `✅ Scan concluído: ${result.findings.length} achado(s).`);
      finishJob(job.id, { scanId: scan.id, runName: result.runName });
    } catch (err) {
      appendLog(job.id, `❌ Erro: ${err.message}`);
      failJob(job.id, err);
    }
  })();

  return job;
}

// Comando em linguagem natural: interpreta a intenção e roda o(s) scan(s).
// Body: { text: "faça uma varredura no meu sistema e encontre falhas", engine?: "strix"|"builtin" }
api.post('/command', async (req, res) => {
  const text = (req.body?.text || '').trim();
  if (!text) return res.status(400).json({ error: 'Informe o campo "text".' });

  const intent = parseIntent(text);

  // Modo profundo (Strix): usuário pediu explicitamente OU o front está em modo Strix.
  const wantsStrix =
    req.body?.engine === 'strix' || intent.deep === true;

  if (wantsStrix) {
    const engine = getEngineStatus();
    // Strix precisa de um alvo concreto (URL, repo, diretório, IP).
    if (!intent.target) {
      return res.json({
        intent,
        reply:
          '🧠 Modo Strix (pentest com IA) precisa de um alvo específico. ' +
          'Diga o que escanear, ex.: *"pentest no site exemplo.com"* ou ' +
          '*"analise o repo https://github.com/user/repo"*.',
        scans: [],
      });
    }
    if (!engine.available) {
      return res.json({
        intent,
        reply:
          `⚠️ O engine **Strix** ainda não está pronto no servidor. ${engine.reason}\n\n` +
          'Enquanto isso, posso rodar a varredura rápida (built-in). ' +
          'Veja o guia de instalação no README para ativar o Strix.',
        engine,
        scans: [],
      });
    }
    const job = startStrixJob({ target: intent.target, instruction: text });
    return res.json({
      intent,
      reply: `🧠 Iniciei um **pentest com IA (Strix)** em **${intent.target}**. Isso pode levar alguns minutos — vou te mostrando o progresso aqui. 👇`,
      job: jobView(job.id),
      scans: [],
    });
  }

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
