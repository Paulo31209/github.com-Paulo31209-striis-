// STRIIS dashboard — lógica de UI.

const $ = (sel) => document.querySelector(sel);

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_LABEL = {
  critical: 'Crítica',
  high: 'Alta',
  medium: 'Média',
  low: 'Baixa',
  info: 'Info',
};
const TYPE_LABEL = { url: 'URL', server: 'Servidor', deps: 'Deps', strix: 'Strix AI', claude: 'Claude' };

let engineAvailable = false; // Strix pronto no servidor?
let deepMode = false; // usar modo profundo (Strix)?
let deepInitialized = false; // já definiu o padrão do toggle?

async function api(path, options) {
  const res = await fetch(`/api${path}`, options);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }
  return res.json();
}

function timeAgo(iso) {
  if (!iso) return '—';
  const diff = Date.now() - new Date(iso).getTime();
  const min = Math.round(diff / 60000);
  if (min < 1) return 'agora mesmo';
  if (min < 60) return `há ${min} min`;
  const h = Math.round(min / 60);
  if (h < 24) return `há ${h}h`;
  return `há ${Math.round(h / 24)}d`;
}

function riskColor(score) {
  if (score >= 70) return 'var(--critical)';
  if (score >= 40) return 'var(--high)';
  if (score >= 15) return 'var(--medium)';
  return 'var(--accent)';
}

// ----- Resumo -----
async function loadSummary() {
  try {
    const s = await api('/summary');
    setStatus(true);
    $('#total-scans').textContent = s.totalScans;
    $('#avg-risk').textContent = s.avgRisk;
    $('#count-critical').textContent = s.totals.critical;
    $('#count-high').textContent = s.totals.high;
    $('#count-medium').textContent = s.totals.medium;
    $('#count-low').textContent = s.totals.low;
    const fill = $('#risk-fill');
    fill.style.width = `${s.avgRisk}%`;
    fill.style.background = riskColor(s.avgRisk);
    $('#avg-risk').style.color = riskColor(s.avgRisk);
  } catch (e) {
    setStatus(false);
  }
}

function setStatus(online) {
  const el = $('#status');
  el.className = `status ${online ? 'online' : 'offline'}`;
  el.innerHTML = `<span class="dot"></span> ${online ? 'STRIIS online' : 'sem conexão'}`;
}

// ----- Engine (badge do topo mostra o Claude, engine principal da conversa) -----
async function loadEngine() {
  const badge = $('#engine-badge');
  try {
    const e = await api('/engine');
    const claudeOn = !!(e.claude && e.claude.available);
    engineAvailable = claudeOn;
    if (claudeOn) {
      badge.className = 'engine-badge on';
      badge.innerHTML = '🤖 Claude conectado';
      badge.title = 'Analista de segurança rodando no seu Claude do servidor.';
    } else {
      badge.className = 'engine-badge off';
      badge.innerHTML = '⚠️ Claude off';
      badge.title = (e.claude && e.claude.reason) || 'Claude local indisponível.';
    }
  } catch {
    badge.className = 'engine-badge off';
    badge.innerHTML = '⚠️ sem conexão';
  }
  // O toggle de "modo profundo" era do Strix; na conversa não se aplica.
  const dm = document.querySelector('.deep-mode');
  if (dm) dm.hidden = true;
}

// ----- Lista de scans -----
async function loadScans() {
  const container = $('#scans-container');
  try {
    const scans = await api('/scans');
    if (!scans.length) {
      container.innerHTML = '<p class="empty">Nenhum scan ainda. Execute um ao lado.</p>';
      return;
    }
    container.innerHTML = scans.map(scanItemHtml).join('');
    container.querySelectorAll('.scan-item').forEach((el) => {
      el.addEventListener('click', () => showFindings(el.dataset.id));
    });
  } catch (e) {
    container.innerHTML = `<p class="empty">Erro ao carregar: ${e.message}</p>`;
  }
}

function scanItemHtml(scan) {
  const badges = SEV_ORDER.slice(0, 4)
    .map((sev) => {
      const n = scan.counts[sev] || 0;
      return `<span class="badge ${sev} ${n === 0 ? 'zero' : ''}">${n}</span>`;
    })
    .join('');
  return `
    <div class="scan-item" data-id="${scan.id}">
      <span class="scan-type ${scan.type}">${TYPE_LABEL[scan.type] || scan.type}</span>
      <div class="scan-meta">
        <div class="scan-target">${escapeHtml(scan.target)}</div>
        <div class="scan-time">${timeAgo(scan.finishedAt)} · risco ${scan.riskScore}</div>
      </div>
      <div class="scan-badges">${badges}</div>
    </div>`;
}

// ----- Findings -----
async function showFindings(id) {
  const panel = $('#findings-panel');
  const container = $('#findings-container');
  panel.hidden = false;
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  container.innerHTML = '<p class="empty">Carregando…</p>';
  try {
    const scan = await api(`/scans/${id}`);
    $('#findings-title').textContent = `${TYPE_LABEL[scan.type]} · ${scan.target}`;
    const sorted = [...scan.findings].sort(
      (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity),
    );
    container.innerHTML = sorted.map(findingHtml).join('');
  } catch (e) {
    container.innerHTML = `<p class="empty">Erro: ${e.message}</p>`;
  }
}

function findingHtml(f) {
  return `
    <div class="finding ${f.severity}">
      <div class="finding-top">
        <span class="sev-tag ${f.severity}">${SEV_LABEL[f.severity]}</span>
        <span class="finding-title">${escapeHtml(f.title)}</span>
      </div>
      <div class="finding-detail">${escapeHtml(f.detail)}</div>
      ${f.recommendation ? `<div class="finding-rec">${escapeHtml(f.recommendation)}</div>` : ''}
      ${f.evidence ? `<div class="finding-evidence">${escapeHtml(f.evidence)}</div>` : ''}
    </div>`;
}

// ----- Executar scans -----
async function runScan(type) {
  const statusEl = $('#runner-status');
  const buttons = document.querySelectorAll('.btn[data-scan]');
  buttons.forEach((b) => (b.disabled = true));
  statusEl.className = 'runner-status working';
  statusEl.textContent = `⏳ Executando scan de ${TYPE_LABEL[type]}…`;

  try {
    let body = {};
    if (type === 'url') {
      const target = $('#url-input').value.trim();
      if (!target) throw new Error('Informe uma URL para escanear.');
      body = { target };
    } else if (type === 'deps') {
      const p = $('#deps-input').value.trim();
      if (p) body = { path: p };
    }

    const scan = await api(`/scans/${type}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });

    const total = scan.findings.length;
    statusEl.className = 'runner-status';
    statusEl.textContent = `✅ Scan concluído: ${total} achado(s), risco ${scan.riskScore}.`;
    await Promise.all([loadSummary(), loadScans()]);
    showFindings(scan.id);
  } catch (e) {
    statusEl.className = 'runner-status error';
    statusEl.textContent = `❌ ${e.message}`;
  } finally {
    buttons.forEach((b) => (b.disabled = false));
  }
}

// ----- Assistente (linguagem natural) -----
function addMessage(role, html) {
  const log = $('#assistant-log');
  const div = document.createElement('div');
  div.className = `msg ${role}`;
  div.innerHTML = html;
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
  return div;
}

// Renderiza markdown simples (títulos, listas, negrito, itálico, código).
function formatReply(text) {
  const lines = escapeHtml(String(text || '')).split('\n');
  const html = lines.map((line) => {
    let l = line
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.+?)\*/g, '<em>$1</em>');
    let m;
    if ((m = l.match(/^###\s+(.*)$/))) return `<div class="md-h3">${m[1]}</div>`;
    if ((m = l.match(/^##\s+(.*)$/))) return `<div class="md-h2">${m[1]}</div>`;
    if ((m = l.match(/^#\s+(.*)$/))) return `<div class="md-h1">${m[1]}</div>`;
    if ((m = l.match(/^\s*[-*]\s+(.*)$/))) return `<div class="md-li">${m[1]}</div>`;
    if (l.trim() === '') return '<div class="md-sp"></div>';
    return `<div>${l}</div>`;
  });
  return html.join('');
}

// Identificador de conversa (memória de 5 min no servidor), por navegador.
let conversationId = 'default';
try {
  conversationId =
    localStorage.getItem('striis_convo') ||
    (self.crypto?.randomUUID ? self.crypto.randomUUID() : 'c' + Date.now());
  localStorage.setItem('striis_convo', conversationId);
} catch {
  conversationId = 'c' + Date.now();
}

// Conversa com o analista (Claude local). 1ª msg gera o relatório; depois aprofunda.
async function sendChat(text) {
  if (!text.trim()) return;
  addMessage('user', escapeHtml(text));
  $('#command-input').value = '';
  const typing = addMessage('bot typing', '💭 analisando…');
  try {
    const data = await api('/chat', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: text, conversationId }),
    });
    // Análise de código/repo roda em background → acompanha o job.
    if (data.job) {
      await pollChatResult(data.job.id, typing);
      return;
    }
    typing.remove();
    if (data.reset) {
      addMessage('bot muted', '🕔 (nova sessão — a memória anterior expirou após 5 min)');
    }
    addMessage('bot', formatReply(data.reply || '(sem resposta)'));
  } catch (e) {
    typing.remove();
    addMessage('bot', `❌ ${escapeHtml(e.message)}`);
  }
}

// Acompanha um job de conversa/upload (análise demorada em background).
async function pollChatResult(jobId, typingEl) {
  while (true) {
    let job;
    try {
      job = await api(`/jobs/${jobId}`);
    } catch (e) {
      if (typingEl) typingEl.remove();
      addMessage('bot', `❌ ${escapeHtml(e.message)}`);
      return;
    }
    if (job.status === 'done') {
      if (typingEl) typingEl.remove();
      addMessage('bot', formatReply((job.result && job.result.reply) || '(sem resposta)'));
      await Promise.all([loadSummary(), loadScans()]).catch(() => {});
      return;
    }
    if (job.status === 'error') {
      if (typingEl) typingEl.remove();
      addMessage('bot', `❌ ${escapeHtml(job.error || 'erro na análise')}`);
      return;
    }
    // Mostra a última linha de progresso no balão de "digitando".
    if (typingEl && job.log && job.log.length) {
      typingEl.textContent = job.log[job.log.length - 1];
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
}

let lastReport = null; // guarda o último relatório { md, name } para download

// Cria um balão com barra de progresso e narração do que está acontecendo.
function addProgress(status) {
  const el = addMessage('bot progress-msg', '');
  el.innerHTML =
    '<div class="prog-status"></div>' +
    '<div class="prog-bar"><div class="prog-fill"></div></div>' +
    '<div class="prog-pct">0%</div>';
  const statusEl = el.querySelector('.prog-status');
  const fillEl = el.querySelector('.prog-fill');
  const pctEl = el.querySelector('.prog-pct');
  const api2 = {
    el,
    setStatus: (t) => (statusEl.textContent = t),
    setPct: (p) => {
      fillEl.style.width = p + '%';
      pctEl.textContent = p + '%';
    },
    remove: () => el.remove(),
  };
  api2.setStatus(status || '⏳ Iniciando…');
  return api2;
}

// Monta o markdown do relatório e faz o download no navegador.
function downloadMd(reply, name) {
  const base = (name || 'relatorio').replace(/\.zip$/i, '');
  const md =
    `# Relatório de Segurança — ${base}\n\n` +
    `_Gerado pelo STRIIS em ${new Date().toLocaleString('pt-BR')}_\n\n---\n\n` +
    `${reply}\n`;
  const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `striis-${base}-${new Date().toISOString().slice(0, 10)}.md`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

// Mostra o relatório + botão de baixar .md.
function addReport(reply, name) {
  addMessage('bot', formatReply(reply));
  lastReport = { reply, name };
  const bar = document.createElement('div');
  bar.className = 'report-actions';
  const btn = document.createElement('button');
  btn.className = 'btn primary';
  btn.textContent = '📥 Baixar relatório (.md)';
  btn.addEventListener('click', () => downloadMd(reply, name));
  bar.appendChild(btn);
  $('#assistant-log').appendChild(bar);
  $('#assistant-log').scrollTop = $('#assistant-log').scrollHeight;
}

// Acompanha o job de upload com barra de progresso animada + narração.
async function pollWithProgress(jobId, prog, name) {
  let pct = 6;
  const anim = setInterval(() => {
    pct += (93 - pct) * 0.045; // sobe suave até ~93% enquanto processa
    prog.setPct(Math.round(pct));
  }, 400);
  try {
    while (true) {
      let job;
      try {
        job = await api(`/jobs/${jobId}`);
      } catch (e) {
        clearInterval(anim);
        prog.remove();
        addMessage('bot', `❌ ${escapeHtml(e.message)}`);
        return;
      }
      if (job.log && job.log.length) prog.setStatus(job.log[job.log.length - 1]);
      if (job.status === 'done') {
        clearInterval(anim);
        prog.setPct(100);
        prog.setStatus('✅ Concluído!');
        const reply = (job.result && job.result.reply) || '(sem resposta)';
        setTimeout(() => prog.remove(), 700);
        addReport(reply, name);
        await Promise.all([loadSummary(), loadScans()]).catch(() => {});
        return;
      }
      if (job.status === 'error') {
        clearInterval(anim);
        prog.remove();
        addMessage('bot', `❌ ${escapeHtml(job.error || 'erro na análise')}`);
        return;
      }
      await new Promise((r) => setTimeout(r, 2500));
    }
  } finally {
    clearInterval(anim);
  }
}

// Upload de um .zip do código → revisão de segurança completa pelo Claude.
async function uploadZip(file) {
  if (!file) return;
  if (!/\.zip$/i.test(file.name)) {
    addMessage('bot', '❌ Envie um arquivo <strong>.zip</strong> do código.');
    return;
  }
  addMessage('user', '📎 ' + escapeHtml(file.name));
  const prog = addProgress('📦 Enviando o arquivo…');
  try {
    const res = await fetch(
      `/api/chat/upload?conversationId=${encodeURIComponent(conversationId)}&name=${encodeURIComponent(file.name)}`,
      { method: 'POST', headers: { 'content-type': 'application/zip' }, body: file },
    );
    if (!res.ok) {
      const e = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(e.error || `HTTP ${res.status}`);
    }
    const data = await res.json();
    if (data.job) {
      await pollWithProgress(data.job.id, prog, file.name);
      return;
    }
    prog.remove();
    addReport(data.reply || '(sem resposta)', file.name);
  } catch (e) {
    prog.remove();
    addMessage('bot', `❌ ${escapeHtml(e.message)}`);
  }
}

// Liga o botão/zona de upload de .zip (definidos no HTML) + arrastar-e-soltar.
function setupUpload() {
  const zone = document.getElementById('upload-zone');
  const input = document.getElementById('zip-input');
  const cta = document.getElementById('upload-cta');
  if (!input || !cta) return;

  cta.addEventListener('click', () => input.click());
  input.addEventListener('change', () => {
    if (input.files && input.files[0]) uploadZip(input.files[0]);
    input.value = '';
  });

  if (zone) {
    ['dragenter', 'dragover'].forEach((ev) =>
      zone.addEventListener(ev, (e) => {
        e.preventDefault();
        zone.classList.add('dragover');
      }),
    );
    ['dragleave', 'drop'].forEach((ev) =>
      zone.addEventListener(ev, (e) => {
        e.preventDefault();
        zone.classList.remove('dragover');
      }),
    );
    zone.addEventListener('drop', (e) => {
      const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
      if (f) uploadZip(f);
    });
  }
}

async function sendCommand(text) {
  if (!text.trim()) return;
  addMessage('user', escapeHtml(text));
  $('#command-input').value = '';
  const typing = addMessage('bot typing', '🔎 Analisando…');

  try {
    const data = await api('/command', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ text, engine: deepMode ? 'strix' : 'builtin' }),
    });
    typing.remove();
    addMessage('bot', formatReply(data.reply));

    // Scan do Strix roda em background → acompanha o job ao vivo.
    if (data.job) {
      await pollJob(data.job.id);
      return;
    }

    // Atualiza painel e histórico; abre os detalhes do primeiro scan.
    await Promise.all([loadSummary(), loadScans()]);
    if (data.scans && data.scans.length) {
      showFindings(data.scans[0].id);
    }
  } catch (e) {
    typing.remove();
    addMessage('bot', `❌ Deu erro ao processar: ${escapeHtml(e.message)}`);
  }
}

// Acompanha um job assíncrono (Strix), mostrando o log ao vivo.
async function pollJob(jobId) {
  const logBox = addMessage('bot terminal', '<div class="term-line">⏳ Iniciando…</div>');
  logBox.classList.add('terminal');
  let since = 0;

  while (true) {
    let job;
    try {
      job = await api(`/jobs/${jobId}?since=${since}`);
    } catch (e) {
      logBox.innerHTML += `<div class="term-line err">erro ao consultar job: ${escapeHtml(e.message)}</div>`;
      return;
    }

    for (const line of job.log) {
      const div = document.createElement('div');
      div.className = 'term-line';
      div.textContent = line;
      logBox.appendChild(div);
    }
    since = job.logTotal;
    $('#assistant-log').scrollTop = $('#assistant-log').scrollHeight;

    if (job.status === 'done') {
      await Promise.all([loadSummary(), loadScans()]);
      addMessage('bot', '✅ Pentest concluído! Abri os resultados abaixo. 👇');
      if (job.scanId) showFindings(job.scanId);
      return;
    }
    if (job.status === 'error') {
      addMessage('bot', `❌ O Strix falhou: ${escapeHtml(job.error || 'erro desconhecido')}`);
      return;
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]),
  );
}

// ----- Init -----
function init() {
  document.querySelectorAll('.btn[data-scan]').forEach((btn) => {
    btn.addEventListener('click', () => runScan(btn.dataset.scan));
  });
  $('#close-findings').addEventListener('click', () => {
    $('#findings-panel').hidden = true;
  });
  $('#url-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') runScan('url');
  });

  // Conversa com o analista (Claude local).
  $('#assistant-form').addEventListener('submit', (e) => {
    e.preventDefault();
    sendChat($('#command-input').value);
  });
  $('#suggestions').querySelectorAll('button').forEach((btn) => {
    btn.addEventListener('click', () => sendChat(btn.dataset.cmd));
  });
  setupUpload(); // botão 📎 de upload de .zip do código
  // Esconde o toggle do Strix (a conversa não usa) — imediatamente.
  const dm0 = document.querySelector('.deep-mode');
  if (dm0) dm0.hidden = true;
  // Toggle de modo profundo (legado do Strix) — guardado caso exista.
  const deepToggle = $('#deep-toggle');
  if (deepToggle) {
    deepToggle.addEventListener('change', (e) => {
      deepMode = e.target.checked;
    });
  }
  $('#footer-time').textContent = new Date().toLocaleString('pt-BR');

  loadEngine();
  loadSummary();
  loadScans();
  // Atualiza o resumo a cada 30s.
  setInterval(loadSummary, 30_000);
  setInterval(loadEngine, 30_000);
}

document.addEventListener('DOMContentLoaded', init);
