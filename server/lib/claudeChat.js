// Conversa com o Claude local (headless) como analista de segurança.
// Suporta 3 tipos de alvo:
//   - URL/site  → coleta recon (headers/TLS/HTML) e gera relatório
//   - repo Git  → clona o repositório e o Claude LÊ O CÓDIGO (revisão SAST completa)
//   - caminho local → o Claude lê o código do diretório
// A conversa mantém contexto via `--resume` do Claude Code, com memória (TTL) de 5 min.

import { spawn } from 'node:child_process';
import https from 'node:https';
import http from 'node:http';
import os from 'node:os';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { extractTarget } from './intent.js';

const BIN = process.env.CLAUDE_BIN || 'claude';
const TTL_MS = Number(process.env.CLAUDE_SESSION_TTL_MS || 5 * 60 * 1000);
const TIMEOUT_MS = Number(process.env.CLAUDE_TIMEOUT_MS || 300_000);
// Ferramentas de LEITURA apenas (o Claude explora o código sem executar nada).
const READ_TOOLS = 'Read Grep Glob LS';

const SYSTEM_URL = [
  'Você é o STRIIS, um analista de segurança ofensiva.',
  'REGRAS: NUNCA se apresente nem se anuncie — vá direto ao conteúdo. Responda em português,',
  'objetivo e técnico. Na PRIMEIRA mensagem, com base nos dados de reconhecimento fornecidos,',
  'produza um RELATÓRIO de segurança do alvo: principais riscos, cada um com severidade',
  '(crítica/alta/média/baixa), o problema e como corrigir. Nas mensagens seguintes, aprofunde',
  'conforme perguntado. Não invente vulnerabilidades sem base. Não execute comandos.',
].join('\n');

const SYSTEM_CODE = [
  'Você é o STRIIS, um analista de segurança de aplicações (revisão de código / SAST).',
  'REGRAS: NUNCA se apresente nem se anuncie — vá direto ao conteúdo. Responda em português.',
  'Você tem acesso de LEITURA ao código do repositório (ferramentas Read/Grep/Glob/LS).',
  'Explore os arquivos relevantes e faça uma REVISÃO DE SEGURANÇA COMPLETA. Procure:',
  '- Injeção (SQL, comando, template), XSS, SSRF, path traversal, deserialização insegura',
  '- Segredos/credenciais hardcoded (chaves, senhas, tokens)',
  '- Autenticação/autorização falha, IDOR, CSRF',
  '- Criptografia fraca, uso inseguro de aleatoriedade, dependências perigosas',
  '- Configurações inseguras e validação de entrada ausente',
  'Na PRIMEIRA mensagem, produza um RELATÓRIO: liste os achados por severidade, cada um com',
  'arquivo:linha, o problema e a correção. Priorize o que é real e explorável; não invente.',
  'Nas mensagens seguintes, aprofunde os pontos conforme perguntado. NUNCA execute comandos',
  'nem edite arquivos — apenas leia e analise.',
].join('\n');

const conversations = new Map(); // id -> { sessionId, lastActivity, target, workdir, cleanupDir, mode }

function isExpired(c) {
  return !c || Date.now() - c.lastActivity > TTL_MS;
}

async function cleanupConvo(c) {
  if (c && c.cleanupDir) {
    await fsp.rm(c.cleanupDir, { recursive: true, force: true }).catch(() => {});
  }
}

function sweep() {
  const now = Date.now();
  for (const [id, c] of conversations) {
    if (now - c.lastActivity > TTL_MS) {
      cleanupConvo(c);
      conversations.delete(id);
    }
  }
}

// ---------- Detecção de alvo ----------
const GIT_URL_RE =
  /(?:https?:\/\/)?(?:www\.)?(github\.com|gitlab\.com|bitbucket\.org)\/([A-Za-z0-9._-]+)\/([A-Za-z0-9._-]+?)(?:\.git)?(?=[\s/?#]|$)/i;
const GIT_SSH_RE = /\bgit@[^\s:]+:[^\s]+?\.git\b/i;
const LOCAL_PATH_RE = /(?:^|\s)((?:\/|\.\/|~\/)[^\s]+)/;

function detectTarget(msg) {
  const g = msg.match(GIT_URL_RE);
  if (g) {
    const url = `https://${g[1]}/${g[2]}/${g[3]}`;
    return { kind: 'git', value: `${g[2]}/${g[3]}`, cloneUrl: url };
  }
  const s = msg.match(GIT_SSH_RE);
  if (s) return { kind: 'git', value: s[0], cloneUrl: s[0] };
  const p = msg.match(LOCAL_PATH_RE);
  if (p) {
    const dir = p[1].replace(/^~/, os.homedir());
    if (fs.existsSync(dir) && fs.statSync(dir).isDirectory()) {
      return { kind: 'path', value: dir, dir };
    }
  }
  const t = extractTarget(msg);
  if (t) return { kind: 'url', value: t };
  return null;
}

// ---------- Recon de URL ----------
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

async function reconText(target) {
  try {
    const recon = await fetchTarget(normalizeUrl(target));
    const html = String(recon.body || '').replace(/\s+/g, ' ').slice(0, 2500);
    return (
      `DADOS DE RECONHECIMENTO DO ALVO ${target}:\n` +
      `HTTP_STATUS=${recon.status}\nHEADERS=${JSON.stringify(recon.headers || {})}\nTRECHO_HTML=${html}`
    );
  } catch (e) {
    return `(não foi possível coletar dados de ${target}: ${e.message})`;
  }
}

// ---------- Git ----------
function cloneRepo(cloneUrl, onLog) {
  const dir = path.join(os.tmpdir(), 'striis-repo-' + Math.random().toString(36).slice(2, 10));
  onLog && onLog(`📦 Clonando ${cloneUrl}…`);
  return new Promise((resolve, reject) => {
    const child = spawn('git', ['clone', '--depth', '1', cloneUrl, dir], { env: process.env });
    let err = '';
    child.stderr.on('data', (d) => (err += d));
    child.on('error', reject);
    child.on('close', (code) =>
      code === 0 ? resolve(dir) : reject(new Error('git clone falhou: ' + err.slice(0, 300))),
    );
  });
}

// ---------- Chamada ao Claude ----------
function runClaude(args, cwd) {
  return new Promise((resolve, reject) => {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), TIMEOUT_MS);
    const child = spawn(BIN, args, { cwd: cwd || os.tmpdir(), env: process.env, signal: ac.signal });
    let out = '';
    let err = '';
    child.stdin.end();
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));
    child.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0 && !out.trim()) reject(new Error(err.slice(0, 300) || `código ${code}`));
      else resolve(out);
    });
  });
}

function parseResult(out) {
  const t = String(out || '').trim();
  try {
    const obj = JSON.parse(t);
    return { reply: obj.result || obj.text || '', sessionId: obj.session_id || null };
  } catch {
    return { reply: t, sessionId: null };
  }
}

/**
 * Envia uma mensagem para a conversa.
 * @returns {Promise<{reply, isFirst, target, kind, reset, log?}>}
 */
export async function chat({ conversationId = 'default', message } = {}) {
  sweep();
  const msg = String(message || '').trim();
  if (!msg) throw new Error('Mensagem vazia.');

  let c = conversations.get(conversationId);
  const wasExpired = isExpired(c);
  if (c && wasExpired) {
    await cleanupConvo(c);
    conversations.delete(conversationId);
    c = null;
  }

  const detected = detectTarget(msg);
  const log = [];
  const addLog = (l) => log.push(l);

  // -------- Primeira mensagem (nova sessão) --------
  if (!c) {
    // Alvo é código (Git ou caminho local) → revisão de código.
    if (detected && (detected.kind === 'git' || detected.kind === 'path')) {
      let dir = detected.dir;
      let cleanupDir = null;
      if (detected.kind === 'git') {
        dir = await cloneRepo(detected.cloneUrl, addLog);
        cleanupDir = dir;
      }
      addLog('🔎 Analisando o código…');
      const prompt =
        `${msg}\n\nFaça a revisão de segurança completa deste repositório/código. ` +
        `Explore os arquivos e produza o relatório com os achados.`;
      const out = await runClaude(
        ['-p', prompt, '--append-system-prompt', SYSTEM_CODE, '--allowedTools', READ_TOOLS, '--output-format', 'json'],
        dir,
      );
      const { reply, sessionId } = parseResult(out);
      if (sessionId) {
        conversations.set(conversationId, {
          sessionId,
          lastActivity: Date.now(),
          target: detected.value,
          workdir: dir,
          cleanupDir,
          mode: 'code',
        });
      } else if (cleanupDir) {
        await fsp.rm(cleanupDir, { recursive: true, force: true }).catch(() => {});
      }
      return { reply, isFirst: true, target: detected.value, kind: detected.kind, reset: false, log };
    }

    // Alvo é URL (ou conversa geral).
    let content = msg;
    let target = null;
    if (detected && detected.kind === 'url') {
      target = detected.value;
      addLog(`🔎 Coletando dados de ${target}…`);
      const recon = await reconText(target);
      content = `${recon}\n\nTAREFA DO USUÁRIO: ${msg}\n\nProduza o relatório de segurança do alvo.`;
    }
    const out = await runClaude(
      ['-p', content, '--append-system-prompt', SYSTEM_URL, '--output-format', 'json'],
    );
    const { reply, sessionId } = parseResult(out);
    if (sessionId) {
      conversations.set(conversationId, {
        sessionId,
        lastActivity: Date.now(),
        target,
        workdir: null,
        cleanupDir: null,
        mode: 'url',
      });
    }
    return { reply, isFirst: true, target, kind: detected ? detected.kind : 'chat', reset: false, log };
  }

  // -------- Continuação (resume) --------
  const args = ['-p', msg, '--resume', c.sessionId, '--output-format', 'json'];
  if (c.mode === 'code') args.push('--allowedTools', READ_TOOLS);
  let out;
  try {
    out = await runClaude(args, c.workdir || undefined);
  } catch {
    await cleanupConvo(c);
    conversations.delete(conversationId);
    return chat({ conversationId, message: msg });
  }
  const { reply, sessionId } = parseResult(out);
  c.lastActivity = Date.now();
  if (sessionId) c.sessionId = sessionId;
  return { reply, isFirst: false, target: c.target, kind: c.mode, reset: false, log };
}

/**
 * Inicia (ou reinicia) uma conversa de revisão de código sobre um diretório já
 * disponível no disco (ex.: um .zip que o usuário subiu e foi extraído).
 * @param {object} opts
 * @param {string} [opts.conversationId]
 * @param {string} opts.dir        Diretório com o código a revisar.
 * @param {string} [opts.label]    Rótulo amigável (nome do zip).
 * @param {string} [opts.cleanupDir] Diretório a apagar quando a sessão expirar.
 */
export async function reviewCodeDir({
  conversationId = 'default',
  dir,
  label,
  cleanupDir = null,
  message = 'Analise a segurança desta aplicação e encontre todas as falhas.',
} = {}) {
  sweep();
  if (!dir || !fs.existsSync(dir)) throw new Error('Diretório de código inválido.');

  // Encerra qualquer conversa anterior deste id (e limpa o diretório dela).
  const prev = conversations.get(conversationId);
  if (prev) {
    await cleanupConvo(prev);
    conversations.delete(conversationId);
  }

  const prompt =
    `${message}\n\nFaça a revisão de segurança completa deste código${label ? ` (${label})` : ''}. ` +
    `Explore os arquivos e produza o relatório com os achados por severidade (arquivo:linha, problema, correção).`;
  const out = await runClaude(
    ['-p', prompt, '--append-system-prompt', SYSTEM_CODE, '--allowedTools', READ_TOOLS, '--output-format', 'json'],
    dir,
  );
  const { reply, sessionId } = parseResult(out);
  if (sessionId) {
    conversations.set(conversationId, {
      sessionId,
      lastActivity: Date.now(),
      target: label || 'código enviado',
      workdir: dir,
      cleanupDir,
      mode: 'code',
    });
  } else if (cleanupDir) {
    await fsp.rm(cleanupDir, { recursive: true, force: true }).catch(() => {});
  }
  return { reply, isFirst: true, target: label || 'código enviado', kind: 'upload', reset: false };
}
