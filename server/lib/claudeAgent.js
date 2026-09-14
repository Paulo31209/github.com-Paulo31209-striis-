// Adaptador do Claude Code local (headless) como engine de análise de segurança.
// Usa a CLI `claude -p` (que roda na assinatura do usuário, SEM API key) para
// analisar os dados de reconhecimento de um alvo e retornar falhas estruturadas.
//
// Requisitos no servidor:
//   - Claude Code instalado e logado (claude /login)
//   - CLAUDE_BIN apontando para o binário (o serviço systemd não vê o PATH do usuário)
//     ex.: CLAUDE_BIN=/home/saulo/.local/node/bin/claude

import { spawn, spawnSync } from 'node:child_process';
import https from 'node:https';
import http from 'node:http';
import os from 'node:os';
import { finding, SEVERITY } from './findings.js';

const BIN = process.env.CLAUDE_BIN || 'claude';
const TIMEOUT_MS = Number(process.env.CLAUDE_TIMEOUT_MS || 240_000);

/** Verifica se a CLI do Claude está disponível. */
export function getClaudeStatus() {
  const r = spawnSync(BIN, ['--version'], { timeout: 8000, encoding: 'utf8' });
  const available = !r.error && r.status === 0;
  return {
    available,
    version: available ? (r.stdout || '').trim() : null,
    bin: BIN,
    reason: available
      ? ''
      : 'CLI do Claude não encontrada ou sem login. Defina CLAUDE_BIN e rode `claude /login`.',
  };
}

function normalizeUrl(input) {
  let u = String(input || '').trim();
  if (!u) throw new Error('URL vazia.');
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  return new URL(u);
}

// Coleta dados do alvo (IPv4, User-Agent, segue redirects) — mesma robustez do urlScanner.
function fetchTarget(url, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    const client = url.protocol === 'https:' ? https : http;
    const req = client.request(
      url,
      {
        method: 'GET',
        timeout: 15_000,
        rejectUnauthorized: false,
        family: 4,
        headers: { 'User-Agent': 'STRIIS-Scanner/0.1 (+seguranca)', Accept: '*/*' },
      },
      (res) => {
        const status = res.statusCode;
        if (status >= 300 && status < 400 && res.headers.location && redirectsLeft > 0) {
          res.resume();
          let next;
          try {
            next = new URL(res.headers.location, url);
          } catch {
            return resolve({ status, headers: res.headers, body: '', tls: null });
          }
          return resolve(fetchTarget(next, redirectsLeft - 1));
        }
        const tls =
          url.protocol === 'https:' && res.socket.getPeerCertificate
            ? res.socket.getPeerCertificate()
            : null;
        let body = '';
        res.on('data', (c) => {
          if (body.length < 4000) body += c.toString('utf8');
        });
        res.on('end', () => resolve({ status, headers: res.headers, body: body.slice(0, 4000), tls }));
      },
    );
    req.on('timeout', () => req.destroy(new Error('Tempo esgotado ao conectar.')));
    req.on('error', reject);
    req.end();
  });
}

function buildPrompt(target, recon) {
  const headers = JSON.stringify(recon.headers || {});
  const tls =
    recon.tls && recon.tls.valid_to
      ? `valid_to=${recon.tls.valid_to} issuer=${JSON.stringify(recon.tls.issuer || {})}`
      : 'n/a';
  const body = String(recon.body || '').replace(/\s+/g, ' ').slice(0, 2500);
  return [
    'Você é um analista de segurança de aplicações (AppSec). Analise os dados de',
    'reconhecimento abaixo de um alvo web e identifique falhas e riscos de segurança.',
    '',
    `ALVO: ${target}`,
    `HTTP_STATUS: ${recon.status}`,
    `HEADERS: ${headers}`,
    `TLS: ${tls}`,
    `TRECHO_HTML: ${body}`,
    '',
    'Analise: headers de segurança ausentes (HSTS, CSP, X-Frame-Options, X-Content-Type-Options),',
    'cookies inseguros, exposição de tecnologia (Server/X-Powered-By), problemas de TLS, e indícios',
    'no HTML (formulários sem CSRF aparente, comentários sensíveis, bibliotecas desatualizadas).',
    'Não invente vulnerabilidades sem base nos dados fornecidos. NÃO use ferramentas nem execute',
    'comandos — apenas analise o texto acima.',
    '',
    'Responda APENAS com um array JSON válido (sem markdown, sem comentários, sem texto antes ou',
    'depois). Cada item deve ter exatamente estes campos:',
    '[{"severity":"critical|high|medium|low|info","title":"curto","detail":"explicação",',
    '"recommendation":"como corrigir","evidence":"evidência técnica"}]',
    'Se não houver nada relevante, retorne [].',
  ].join('\n');
}

function parseFindings(out) {
  let text = String(out || '').trim();
  const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) text = fence[1].trim();
  const start = text.indexOf('[');
  const end = text.lastIndexOf(']');
  if (start === -1 || end === -1 || end < start) return [];
  let arr;
  try {
    arr = JSON.parse(text.slice(start, end + 1));
  } catch {
    return [];
  }
  if (!Array.isArray(arr)) return [];
  return arr
    .filter((v) => v && (v.title || v.detail))
    .map((v) => {
      const sev = String(v.severity || 'info').toLowerCase();
      return finding({
        severity: Object.values(SEVERITY).includes(sev) ? sev : SEVERITY.INFO,
        title: v.title || 'Achado',
        detail: v.detail || '',
        recommendation: v.recommendation || '',
        evidence: v.evidence || '',
      });
    });
}

/**
 * Roda a análise de segurança com o Claude local.
 * @param {object} opts
 * @param {string} opts.target
 * @param {(l:string)=>void} [opts.onLog]
 */
export async function runClaudeReview({ target, onLog } = {}) {
  if (!target) throw new Error('Alvo (target) é obrigatório.');
  const log = (l) => onLog && onLog(l);

  const url = normalizeUrl(target);
  log(`🔎 Coletando dados de ${url.origin}…`);
  let recon;
  try {
    recon = await fetchTarget(url);
    log(`HTTP ${recon.status} · ${Object.keys(recon.headers || {}).length} headers coletados`);
  } catch (e) {
    recon = { status: 0, headers: {}, body: '', tls: null };
    log(`(aviso: falha ao coletar dados: ${e.message})`);
  }

  const prompt = buildPrompt(target, recon);
  log(`🤖 Enviando para o Claude local (${BIN})… isso pode levar alguns segundos.`);

  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), TIMEOUT_MS);
  let stdout = '';
  try {
    stdout = await new Promise((resolve, reject) => {
      // cwd em /tmp para não carregar CLAUDE.md/skills do repositório.
      const child = spawn(BIN, ['-p', prompt, '--output-format', 'text'], {
        cwd: os.tmpdir(),
        env: process.env,
        signal: ac.signal,
      });
      let out = '';
      let err = '';
      child.stdin.end(); // evita o aviso "no stdin data received in 3s"
      child.stdout.on('data', (d) => (out += d));
      child.stderr.on('data', (d) => {
        err += d;
        String(d)
          .split('\n')
          .forEach((l) => l.trim() && log(l.trim()));
      });
      child.on('error', reject);
      child.on('close', (code) => {
        if (code !== 0 && !out.trim()) {
          reject(new Error(`claude encerrou com código ${code}: ${err.slice(0, 300)}`));
        } else {
          resolve(out);
        }
      });
    });
  } finally {
    clearTimeout(timer);
  }

  log('✅ Resposta recebida. Processando achados…');
  const findings = parseFindings(stdout);

  if (findings.length === 0) {
    findings.push(
      finding({
        severity: SEVERITY.INFO,
        title: 'Análise do Claude concluída (sem achados estruturados)',
        detail:
          (stdout || '').trim().slice(0, 800) ||
          'O Claude não retornou achados no formato esperado.',
        recommendation: 'Tente novamente ou refine o alvo.',
        evidence: 'resposta do Claude local',
      }),
    );
  }

  return { findings };
}
