// Armazenamento em memória dos scans executados.
// Simples e sem banco de dados — suficiente para o MVP.
// (Para produção, trocar por SQLite/Postgres mantendo a mesma interface.)

import { randomUUID } from 'node:crypto';
import { countBySeverity, riskScore } from './findings.js';

const scans = new Map();

/** Salva um novo scan e retorna o registro completo. */
export function saveScan({ type, target, findings, startedAt, finishedAt }) {
  const id = randomUUID();
  const record = {
    id,
    type, // 'url' | 'server' | 'deps'
    target,
    findings,
    counts: countBySeverity(findings),
    riskScore: riskScore(findings),
    startedAt,
    finishedAt,
    durationMs: new Date(finishedAt) - new Date(startedAt),
  };
  scans.set(id, record);
  return record;
}

export function getScan(id) {
  return scans.get(id) || null;
}

/** Lista scans mais recentes primeiro. */
export function listScans() {
  return [...scans.values()].sort(
    (a, b) => new Date(b.finishedAt) - new Date(a.finishedAt),
  );
}

/** Estatísticas agregadas para o painel principal. */
export function summary() {
  const all = listScans();
  const totals = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const s of all) {
    for (const k of Object.keys(totals)) totals[k] += s.counts[k] || 0;
  }
  const avgRisk = all.length
    ? Math.round(all.reduce((sum, s) => sum + s.riskScore, 0) / all.length)
    : 0;
  return {
    totalScans: all.length,
    totals,
    avgRisk,
    lastScanAt: all[0]?.finishedAt || null,
  };
}

/** Popula dados de exemplo para o dashboard já nascer preenchido. */
export function seedMockData() {
  if (scans.size > 0) return;
  const now = Date.now();
  const mocks = [
    {
      type: 'url',
      target: 'https://exemplo-loja.com',
      offsetMin: 5,
      findings: [
        {
          severity: 'high',
          title: 'Header HSTS ausente',
          detail: 'O site não envia Strict-Transport-Security, permitindo downgrade para HTTP.',
          recommendation: 'Adicione: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload',
          evidence: 'Strict-Transport-Security: (não presente)',
        },
        {
          severity: 'medium',
          title: 'Content-Security-Policy ausente',
          detail: 'Sem CSP, o site fica mais exposto a XSS e injeção de conteúdo.',
          recommendation: "Defina uma CSP restritiva, ex.: default-src 'self'",
          evidence: 'Content-Security-Policy: (não presente)',
        },
        {
          severity: 'low',
          title: 'Cookie sem flag Secure',
          detail: 'Um cookie de sessão pode trafegar em conexões não criptografadas.',
          recommendation: 'Marque cookies sensíveis com Secure; HttpOnly; SameSite=Strict',
          evidence: 'Set-Cookie: sid=...; (sem Secure)',
        },
      ],
    },
    {
      type: 'deps',
      target: 'projeto-api (package-lock.json)',
      offsetMin: 32,
      findings: [
        {
          severity: 'critical',
          title: 'lodash <4.17.21 — Prototype Pollution (CVE-2020-8203)',
          detail: 'Versão vulnerável a poluição de protótipo permitindo execução de código.',
          recommendation: 'Atualize lodash para >= 4.17.21',
          evidence: 'lodash@4.17.15',
        },
        {
          severity: 'medium',
          title: 'axios <0.21.1 — SSRF (CVE-2020-28168)',
          detail: 'Requisições podem ser redirecionadas para hosts internos.',
          recommendation: 'Atualize axios para >= 0.21.1',
          evidence: 'axios@0.19.2',
        },
      ],
    },
    {
      type: 'server',
      target: 'localhost (servidor STRIIS)',
      offsetMin: 90,
      findings: [
        {
          severity: 'medium',
          title: 'Porta 22 (SSH) exposta',
          detail: 'SSH acessível — garanta autenticação por chave e fail2ban.',
          recommendation: 'Desative login por senha e restrinja IPs de acesso.',
          evidence: 'tcp/22 aberta',
        },
        {
          severity: 'info',
          title: 'Sistema operacional detectado',
          detail: 'Linux — mantenha os pacotes atualizados regularmente.',
          recommendation: 'Automatize atualizações de segurança.',
          evidence: 'linux',
        },
      ],
    },
  ];

  for (const m of mocks) {
    const finishedAt = new Date(now - m.offsetMin * 60_000).toISOString();
    const startedAt = new Date(now - m.offsetMin * 60_000 - 4200).toISOString();
    saveScan({
      type: m.type,
      target: m.target,
      findings: m.findings,
      startedAt,
      finishedAt,
    });
  }
}
