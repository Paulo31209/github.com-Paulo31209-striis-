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

// ----- Engine (Strix) -----
async function loadEngine() {
  const badge = $('#engine-badge');
  const toggle = $('#deep-toggle');
  try {
    const e = await api('/engine');
    engineAvailable = e.available;
    if (e.available) {
      badge.className = 'engine-badge on';
      badge.innerHTML = `🧠 Strix conectado${e.model ? ` · ${escapeHtml(e.model)}` : ''}`;
      badge.title = 'Engine de pentest com IA pronto no servidor.';
      toggle.disabled = false;
      // Strix pronto → liga o modo profundo por padrão (só na 1ª vez).
      if (!deepInitialized) {
        toggle.checked = true;
        deepMode = true;
        deepInitialized = true;
      }
    } else {
      badge.className = 'engine-badge off';
      badge.innerHTML = '⚡ Modo rápido (Strix off)';
      badge.title = e.reason || 'Strix não configurado.';
      // Sem Strix, o toggle fica desabilitado mas explica como ligar.
      toggle.disabled = true;
      deepMode = false;
      $('#deep-toggle').checked = false;
    }
  } catch {
    badge.className = 'engine-badge off';
    badge.innerHTML = '⚡ Modo rápido';
  }
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

// Converte **negrito** e *itálico* simples em HTML (após escapar).
function formatReply(text) {
  return escapeHtml(text)
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    .replace(/\n/g, '<br>');
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
  const logBox = addMessage('bot terminal', '<div class="term-line">⏳ Iniciando engine Strix…</div>');
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

  // Assistente em linguagem natural.
  $('#assistant-form').addEventListener('submit', (e) => {
    e.preventDefault();
    sendCommand($('#command-input').value);
  });
  $('#suggestions').querySelectorAll('button').forEach((btn) => {
    btn.addEventListener('click', () => sendCommand(btn.dataset.cmd));
  });
  // Toggle de modo profundo (Strix).
  $('#deep-toggle').addEventListener('change', (e) => {
    deepMode = e.target.checked;
  });
  $('#footer-time').textContent = new Date().toLocaleString('pt-BR');

  loadEngine();
  loadSummary();
  loadScans();
  // Atualiza o resumo a cada 30s.
  setInterval(loadSummary, 30_000);
  setInterval(loadEngine, 30_000);
}

document.addEventListener('DOMContentLoaded', init);
