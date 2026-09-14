// Conversa com o Claude local (headless) como analista de segurança.
// - Primeira mensagem da sessão: coleta recon do alvo e gera o RELATÓRIO.
// - Mensagens seguintes: continuam a mesma conversa (Claude lembra do contexto)
//   via `--resume <session_id>`.
// - Memória com TTL: após 5 min de inatividade a sessão expira (perde a memória)
//   e a próxima mensagem começa do zero.

import { spawn } from 'node:child_process';
import https from 'node:https';
import http from 'node:http';
import os from 'node:os';
import { extractTarget } from './intent.js';

const BIN = process.env.CLAUDE_BIN || 'claude';
const TTL_MS = Number(process.env.CLAUDE_SESSION_TTL_MS || 5 * 60 * 1000);

const SYSTEM_PROMPT = [
  'Você é o STRIIS, um analista de segurança ofensiva.',
  'REGRAS IMPORTANTES:',
  '- NUNCA se apresente, não diga que é uma IA, não se anuncie. Vá direto ao conteúdo.',
  '- Responda sempre em português, objetivo e técnico.',
  '- Na PRIMEIRA mensagem, com base nos dados de reconhecimento fornecidos, produza um',
  '  RELATÓRIO de segurança do alvo: liste os principais riscos, cada um com severidade',
  '  (crítica/alta/média/baixa), o problema e como corrigir. Seja direto.',
  '- Nas mensagens seguintes, comente e aprofunde os principais erros conforme perguntado.',
  '- Não invente vulnerabilidades sem base nos dados. Não use ferramentas nem execute comandos.',
].join('\n');

const conversations = new Map(); // id -> { sessionId, lastActivity, target }

function isExpired(c) {
  return !c || Date.now() - c.lastActivity > TTL_MS;
}

function sweep() {
  const now = Date.now();
  for (const [id, c] of conversations) {
    if (now - c.lastActivity > TTL_MS) conversations.delete(id);
  }
}

function normalizeUrl(input) {
  let u = String(input || '').trim();
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  return new URL(u);
}

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
            return resolve({ status, headers: res.headers, body: '' });
          }
          return resolve(fetchTarget(next, redirectsLeft - 1));
        }
        let body = '';
        res.on('data', (c) => {
          if (body.length < 4000) body += c.toString('utf8');
        });
        res.on('end', () => resolve({ status, headers: res.headers, body: body.slice(0, 4000) }));
      },
    );
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end();
  });
}

function runClaude(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(BIN, args, { cwd: os.tmpdir(), env: process.env });
    let out = '';
    let err = '';
    child.stdin.end(); // sem stdin → evita o aviso de 3s
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));
    child.on('error', reject);
    child.on('close', (code) =>
      code !== 0 && !out.trim() ? reject(new Error(err.slice(0, 300) || `código ${code}`)) : resolve(out),
    );
  });
}

function parseResult(out) {
  const t = String(out || '').trim();
  try {
    const obj = JSON.parse(t);
    return {
      reply: obj.result || obj.text || '',
      sessionId: obj.session_id || null,
      isError: Boolean(obj.is_error),
    };
  } catch {
    return { reply: t, sessionId: null, isError: false };
  }
}

async function reconText(target) {
  try {
    const recon = await fetchTarget(normalizeUrl(target));
    const html = String(recon.body || '').replace(/\s+/g, ' ').slice(0, 2500);
    return (
      `DADOS DE RECONHECIMENTO DO ALVO ${target}:\n` +
      `HTTP_STATUS=${recon.status}\n` +
      `HEADERS=${JSON.stringify(recon.headers || {})}\n` +
      `TRECHO_HTML=${html}`
    );
  } catch (e) {
    return `(não foi possível coletar dados de ${target}: ${e.message})`;
  }
}

/**
 * Envia uma mensagem para a conversa.
 * @param {object} opts
 * @param {string} [opts.conversationId] identificador da conversa (por navegador).
 * @param {string} opts.message texto do usuário.
 * @returns {Promise<{reply:string, isFirst:boolean, target:string|null, reset:boolean}>}
 */
export async function chat({ conversationId = 'default', message } = {}) {
  sweep();
  const msg = String(message || '').trim();
  if (!msg) throw new Error('Mensagem vazia.');

  let c = conversations.get(conversationId);
  const wasExpired = isExpired(c);
  if (c && wasExpired) conversations.delete(conversationId);

  const target = extractTarget(msg);

  // Primeira mensagem (ou sessão expirada) → gera o relatório.
  if (!c || wasExpired) {
    let content = msg;
    if (target) {
      const recon = await reconText(target);
      content = `${recon}\n\nTAREFA DO USUÁRIO: ${msg}\n\nProduza o relatório de segurança do alvo com base nos dados acima.`;
    }
    const out = await runClaude([
      '-p',
      content,
      '--append-system-prompt',
      SYSTEM_PROMPT,
      '--output-format',
      'json',
    ]);
    const { reply, sessionId, isError } = parseResult(out);
    if (sessionId) {
      conversations.set(conversationId, {
        sessionId,
        lastActivity: Date.now(),
        target: target || null,
      });
    }
    return { reply, isFirst: true, target: target || null, reset: wasExpired && Boolean(target) };
  }

  // Continuação → resume a sessão existente.
  let content = msg;
  if (target && target !== c.target) {
    // Usuário trouxe um alvo novo no meio da conversa → injeta o recon dele.
    const recon = await reconText(target);
    content = `${recon}\n\n${msg}`;
    c.target = target;
  }

  let out;
  try {
    out = await runClaude(['-p', content, '--resume', c.sessionId, '--output-format', 'json']);
  } catch {
    // Sessão perdida no Claude → recomeça do zero.
    conversations.delete(conversationId);
    return chat({ conversationId, message: msg });
  }
  const { reply, sessionId, isError } = parseResult(out);
  c.lastActivity = Date.now();
  if (sessionId) c.sessionId = sessionId;
  return { reply, isFirst: false, target: c.target || null, reset: false };
}
