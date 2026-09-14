// Scanner de dependências vulneráveis.
// Lê o lockfile de um projeto Node (package-lock.json) e consulta a base pública
// OSV.dev (https://osv.dev) em busca de CVEs conhecidas para cada versão.
// Usa fetch nativo do Node 18+. Se não houver rede, degrada com aviso informativo.

import fs from 'node:fs/promises';
import path from 'node:path';
import { finding, SEVERITY } from '../lib/findings.js';

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';

// Mapeia a severidade do OSV/CVSS para a escala do STRIIS.
function mapSeverity(osvSeverity) {
  const s = String(osvSeverity || '').toUpperCase();
  if (s === 'CRITICAL') return SEVERITY.CRITICAL;
  if (s === 'HIGH') return SEVERITY.HIGH;
  if (s === 'MODERATE' || s === 'MEDIUM') return SEVERITY.MEDIUM;
  if (s === 'LOW') return SEVERITY.LOW;
  return SEVERITY.MEDIUM; // padrão quando o OSV não classifica
}

// Extrai um rótulo de severidade a partir do objeto de vulnerabilidade do OSV.
function severityFromVuln(vuln) {
  const dbSev = vuln.database_specific?.severity;
  if (dbSev) return mapSeverity(dbSev);
  // Tenta inferir de CVSS score se presente.
  const cvss = vuln.severity?.find((x) => x.type?.startsWith('CVSS'));
  if (cvss?.score) {
    const base = parseFloat(String(cvss.score).split('/')[0]) || 0;
    if (base >= 9) return SEVERITY.CRITICAL;
    if (base >= 7) return SEVERITY.HIGH;
    if (base >= 4) return SEVERITY.MEDIUM;
    return SEVERITY.LOW;
  }
  return SEVERITY.MEDIUM;
}

/** Lê um package-lock.json e retorna [{ name, version }]. */
async function readLockfile(lockPath) {
  const raw = await fs.readFile(lockPath, 'utf8');
  const json = JSON.parse(raw);
  const pkgs = [];

  // lockfile v2/v3 usa a chave "packages".
  if (json.packages) {
    for (const [key, info] of Object.entries(json.packages)) {
      if (!key || key === '') continue; // pacote raiz
      const name = key.replace(/^.*node_modules\//, '');
      if (info.version) pkgs.push({ name, version: info.version });
    }
  } else if (json.dependencies) {
    // lockfile v1
    const walk = (deps) => {
      for (const [name, info] of Object.entries(deps)) {
        if (info.version) pkgs.push({ name, version: info.version });
        if (info.dependencies) walk(info.dependencies);
      }
    };
    walk(json.dependencies);
  }

  // Remove duplicatas (name@version).
  const seen = new Set();
  return pkgs.filter((p) => {
    const k = `${p.name}@${p.version}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/**
 * Escaneia dependências.
 * @param {string} projectPath  Caminho para a pasta do projeto (que contém package-lock.json)
 *                              ou diretamente para o lockfile.
 */
export async function scanDeps(projectPath) {
  const findings = [];
  const target = projectPath || process.cwd();

  // Descobre o caminho do lockfile.
  let lockPath = target;
  try {
    const stat = await fs.stat(target);
    if (stat.isDirectory()) lockPath = path.join(target, 'package-lock.json');
  } catch {
    findings.push(
      finding({
        severity: SEVERITY.INFO,
        title: 'Projeto não encontrado',
        detail: `Não foi possível acessar "${target}".`,
        recommendation: 'Informe o caminho de um projeto Node com package-lock.json.',
        evidence: target,
      }),
    );
    return findings;
  }

  let pkgs;
  try {
    pkgs = await readLockfile(lockPath);
  } catch (err) {
    findings.push(
      finding({
        severity: SEVERITY.INFO,
        title: 'Lockfile não encontrado ou inválido',
        detail: `Não foi possível ler ${lockPath}: ${err.message}`,
        recommendation: 'Gere o package-lock.json com "npm install" e tente novamente.',
        evidence: lockPath,
      }),
    );
    return findings;
  }

  if (pkgs.length === 0) {
    findings.push(
      finding({
        severity: SEVERITY.INFO,
        title: 'Nenhuma dependência encontrada',
        detail: 'O lockfile não listou pacotes.',
        recommendation: 'Verifique se as dependências estão instaladas.',
        evidence: lockPath,
      }),
    );
    return findings;
  }

  // Consulta o OSV em lote.
  let osvResults;
  try {
    const body = {
      queries: pkgs.map((p) => ({
        version: p.version,
        package: { name: p.name, ecosystem: 'npm' },
      })),
    };
    const resp = await fetch(OSV_BATCH_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(15_000),
    });
    if (!resp.ok) throw new Error(`OSV respondeu HTTP ${resp.status}`);
    const data = await resp.json();
    osvResults = data.results || [];
  } catch (err) {
    findings.push(
      finding({
        severity: SEVERITY.INFO,
        title: 'Consulta de CVE indisponível',
        detail: `Não foi possível consultar a base OSV: ${err.message}. ${pkgs.length} dependências foram lidas, mas não verificadas.`,
        recommendation: 'Garanta acesso de rede a api.osv.dev ou rode "npm audit" localmente.',
        evidence: `${pkgs.length} pacotes lidos de ${path.basename(lockPath)}`,
      }),
    );
    return findings;
  }

  // Casa os resultados com os pacotes.
  let vulnCount = 0;
  osvResults.forEach((result, i) => {
    const pkg = pkgs[i];
    if (!result.vulns || result.vulns.length === 0) return;
    for (const vuln of result.vulns) {
      vulnCount += 1;
      const id = vuln.id || 'OSV';
      findings.push(
        finding({
          severity: severityFromVuln(vuln),
          title: `${pkg.name}@${pkg.version} — ${id}`,
          detail: vuln.summary || 'Vulnerabilidade conhecida reportada no OSV.',
          recommendation:
            'Atualize o pacote para uma versão corrigida (veja o aviso no OSV/GitHub Advisory).',
          evidence: `${pkg.name}@${pkg.version} — https://osv.dev/vulnerability/${id}`,
        }),
      );
    }
  });

  if (vulnCount === 0) {
    findings.push(
      finding({
        severity: SEVERITY.INFO,
        title: 'Nenhuma vulnerabilidade conhecida',
        detail: `${pkgs.length} dependências verificadas na base OSV sem CVEs conhecidas.`,
        recommendation: 'Continue rodando o scan a cada atualização de dependências.',
        evidence: `${pkgs.length} pacotes verificados`,
      }),
    );
  }

  return findings;
}
