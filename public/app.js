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
const TYPE_LABEL = { url: 'URL', server: 'Servidor', deps: 'Deps' };

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
      body: JSON.stringify({ text }),
    });
    typing.remove();
    addMessage('bot', formatReply(data.reply));

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
  $('#footer-time').textContent = new Date().toLocaleString('pt-BR');

  loadSummary();
  loadScans();
  // Atualiza o resumo a cada 30s.
  setInterval(loadSummary, 30_000);
}

document.addEventListener('DOMContentLoaded', init);
