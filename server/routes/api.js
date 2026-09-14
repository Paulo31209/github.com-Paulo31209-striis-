// Rotas da API do STRIIS.
import express from 'express';
import { scanUrl } from '../scanners/urlScanner.js';
import { scanServer } from '../scanners/serverScanner.js';
import { scanDeps } from '../scanners/depScanner.js';
import { saveScan, getScan, listScans, summary } from '../lib/store.js';

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
