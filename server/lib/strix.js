// Adaptador do STRIX (usestrix/strix) — o engine real de pentest com IA.
// O STRIIS (nossa casca) dispara o CLI do Strix no servidor e lê os resultados.
//
// Requisitos no servidor onde isto roda:
//   - Docker instalado e com o daemon rodando
//   - CLI do Strix instalado (pip install strix-agent  |  curl -sSL https://strix.ai/install | bash)
//   - Variáveis: STRIX_LLM (ex.: "openai/gpt-4.1") e LLM_API_KEY
//
// Config opcional via env:
//   STRIX_BIN       caminho do binário do strix (default: "strix")
//   STRIX_WORKDIR   diretório onde ficará ./strix_runs (default: cwd do processo)
//   STRIX_SCAN_MODE quick | standard | deep (default: "standard")
//   STRIX_MAX_BUDGET teto de custo em USD por scan (opcional)

import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { finding, SEVERITY } from './findings.js';

const BIN = process.env.STRIX_BIN || 'strix';
const WORKDIR = process.env.STRIX_WORKDIR || process.cwd();
const RUNS_DIR = path.join(WORKDIR, 'strix_runs');
const DEFAULT_MODE = process.env.STRIX_SCAN_MODE || 'standard';

/**
 * Checa se o Strix está pronto para uso no servidor.
 * Retorna um objeto de status que o front usa para mostrar o estado do engine.
 */
export function getEngineStatus() {
  const status = {
    available: false,
    strixInstalled: false,
    dockerInstalled: false,
    dockerRunning: false,
    llmConfigured: false,
    model: process.env.STRIX_LLM || null,
    scanMode: DEFAULT_MODE,
    reason: '',
  };

  // Strix instalado?
  const strixCheck = spawnSync(BIN, ['--version'], { timeout: 5000, encoding: 'utf8' });
  status.strixInstalled = strixCheck.status === 0 || !strixCheck.error;
  if (strixCheck.stdout) status.strixVersion = strixCheck.stdout.trim().split('\n')[0];

  // Docker instalado / rodando?
  const dockerV = spawnSync('docker', ['--version'], { timeout: 5000, encoding: 'utf8' });
  status.dockerInstalled = dockerV.status === 0 && !dockerV.error;
  if (status.dockerInstalled) {
    const dockerInfo = spawnSync('docker', ['info'], { timeout: 8000, encoding: 'utf8' });
    status.dockerRunning = dockerInfo.status === 0;
  }

  // LLM configurado?
  status.llmConfigured = Boolean(process.env.STRIX_LLM && process.env.LLM_API_KEY);

  status.available =
    status.strixInstalled && status.dockerRunning && status.llmConfigured;

  if (!status.available) {
    const faltando = [];
    if (!status.strixInstalled) faltando.push('CLI do Strix (pip install strix-agent)');
    if (!status.dockerInstalled) faltando.push('Docker');
    else if (!status.dockerRunning) faltando.push('daemon do Docker rodando');
    if (!status.llmConfigured) faltando.push('STRIX_LLM + LLM_API_KEY');
    status.reason = `Faltando: ${faltando.join(', ')}.`;
  }

  return status;
}

// Lista os nomes de run existentes (para detectar a run nova após o scan).
async function listRunDirs() {
  try {
    const entries = await fsp.readdir(RUNS_DIR, { withFileTypes: true });
    return new Set(entries.filter((e) => e.isDirectory()).map((e) => e.name));
  } catch {
    return new Set();
  }
}

// Mapeia uma vulnerabilidade do Strix para o formato de "finding" do STRIIS.
function vulnToFinding(v) {
  const sev = String(v.severity || 'info').toLowerCase();
  const severity = Object.values(SEVERITY).includes(sev) ? sev : SEVERITY.INFO;

  // Monta uma linha de evidência com metadados úteis.
  const meta = [];
  if (v.cve) meta.push(`CVE: ${v.cve}`);
  if (v.cwe) meta.push(`CWE: ${v.cwe}`);
  if (v.cvss) meta.push(`CVSS: ${v.cvss}`);
  if (v.confidence) meta.push(`Confiança: ${v.confidence}`);
  if (v.endpoint) meta.push(`Endpoint: ${v.method || ''} ${v.endpoint}`.trim());
  if (v.target) meta.push(`Alvo: ${v.target}`);
  const dep = v.dependency_metadata || {};
  if (dep.package_name) {
    meta.push(
      `Pacote: ${dep.package_name}@${dep.installed_version || '?'}` +
        (dep.fixed_version ? ` → corrigido em ${dep.fixed_version}` : ''),
    );
  }
  const evidenceParts = [];
  if (meta.length) evidenceParts.push(meta.join(' | '));
  if (v.evidence) evidenceParts.push(String(v.evidence).slice(0, 500));
  if (v.poc_description) evidenceParts.push(`PoC: ${String(v.poc_description).slice(0, 300)}`);

  return finding({
    severity,
    title: v.title || 'Vulnerabilidade',
    detail: v.description || v.impact || 'Sem descrição fornecida pelo Strix.',
    recommendation: v.remediation_steps || v.remediation || '',
    evidence: evidenceParts.join('\n') || `id: ${v.id || '?'}`,
  });
}

/**
 * Roda um scan do Strix contra um alvo e retorna os findings mapeados.
 * @param {object} opts
 * @param {string} opts.target       URL, repo, diretório, spec de API ou IP.
 * @param {string} [opts.scanMode]   quick | standard | deep.
 * @param {string} [opts.instruction] Instrução extra em linguagem natural.
 * @param {(line: string) => void} [opts.onLog]  Callback para stream de saída.
 * @param {AbortSignal} [opts.signal]
 * @returns {Promise<{findings: object[], runName: string, runDir: string, reportPath: string|null}>}
 */
export async function runStrixScan({ target, scanMode, instruction, onLog, signal } = {}) {
  if (!target) throw new Error('Alvo (target) é obrigatório para o Strix.');
  const mode = scanMode || DEFAULT_MODE;
  const log = (line) => {
    if (onLog) onLog(line);
  };

  await fsp.mkdir(RUNS_DIR, { recursive: true }).catch(() => {});
  const before = await listRunDirs();

  const args = ['-n', '--scan-mode', mode, '--target', target];
  if (instruction) args.push('--instruction', instruction);
  if (process.env.STRIX_MAX_BUDGET) args.push('--max-budget', process.env.STRIX_MAX_BUDGET);

  log(`$ ${BIN} ${args.join(' ')}`);
  log(`(modo: ${mode} · workdir: ${WORKDIR})`);

  const code = await new Promise((resolve, reject) => {
    const child = spawn(BIN, args, {
      cwd: WORKDIR,
      env: process.env,
      signal,
    });
    child.stdout.on('data', (d) => String(d).split('\n').forEach((l) => l && log(l)));
    child.stderr.on('data', (d) => String(d).split('\n').forEach((l) => l && log(l)));
    child.on('error', reject);
    child.on('close', resolve);
  });

  // Descobre a run recém-criada.
  const after = await listRunDirs();
  const novas = [...after].filter((n) => !before.has(n));
  let runName = novas[0];
  if (!runName) {
    // Fallback: pega a mais recente por mtime.
    const all = [...after];
    let latest = null;
    let latestTime = 0;
    for (const name of all) {
      const st = fs.statSync(path.join(RUNS_DIR, name));
      if (st.mtimeMs > latestTime) {
        latestTime = st.mtimeMs;
        latest = name;
      }
    }
    runName = latest;
  }

  if (!runName) {
    throw new Error(
      `O Strix terminou (código ${code}) mas nenhuma run foi encontrada em ${RUNS_DIR}. ` +
        `Verifique a saída acima.`,
    );
  }

  const runDir = path.join(RUNS_DIR, runName);
  const vulnPath = path.join(runDir, 'vulnerabilities.json');
  let findings = [];
  try {
    const raw = await fsp.readFile(vulnPath, 'utf8');
    const vulns = JSON.parse(raw);
    findings = Array.isArray(vulns) ? vulns.map(vulnToFinding) : [];
  } catch (err) {
    log(`(aviso: não foi possível ler ${vulnPath}: ${err.message})`);
  }

  if (findings.length === 0) {
    if (code !== 0) {
      // O Strix encerrou com erro antes de gerar resultados — não é "limpo".
      findings.push(
        finding({
          severity: SEVERITY.INFO,
          title: 'Scan do Strix não concluído (erro)',
          detail:
            'O Strix encerrou com erro antes de confirmar vulnerabilidades. ' +
            'Causas comuns: limite de contexto do modelo local, timeout do LLM ou ' +
            'falha de conexão. Veja o log acima para o motivo exato.',
          recommendation:
            'Ajuste o modelo/contexto (ex.: aumentar num_ctx no Ollama) e rode novamente.',
          evidence: `exit code ${code} · run ${runName}`,
        }),
      );
    } else {
      findings.push(
        finding({
          severity: SEVERITY.INFO,
          title: 'Nenhuma vulnerabilidade confirmada pelo Strix',
          detail:
            'O Strix concluiu o scan sem confirmar vulnerabilidades (com PoC). ' +
            'Veja o relatório completo para detalhes da cobertura.',
          recommendation: 'Rode em modo "deep" para uma análise mais profunda.',
          evidence: `run: ${runName}`,
        }),
      );
    }
  }

  const reportPath = path.join(runDir, 'penetration_test_report.md');
  const hasReport = fs.existsSync(reportPath);

  return {
    findings,
    runName,
    runDir,
    reportPath: hasReport ? reportPath : null,
  };
}
