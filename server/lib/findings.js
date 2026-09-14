// Modelo de "achado" (finding) e níveis de severidade usados por todos os scanners.

export const SEVERITY = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info',
};

// Peso numérico para ordenar / calcular score de risco.
export const SEVERITY_WEIGHT = {
  critical: 100,
  high: 40,
  medium: 10,
  low: 3,
  info: 0,
};

/**
 * Cria um achado padronizado.
 * @param {object} opts
 * @param {string} opts.severity  Um valor de SEVERITY.
 * @param {string} opts.title     Título curto do problema.
 * @param {string} opts.detail    Descrição do que foi encontrado.
 * @param {string} [opts.recommendation] Como corrigir.
 * @param {string} [opts.evidence]       Evidência técnica (header, versão, porta...).
 */
export function finding({ severity, title, detail, recommendation = '', evidence = '' }) {
  return {
    severity,
    title,
    detail,
    recommendation,
    evidence,
  };
}

/** Calcula um score de risco de 0 (perfeito) a 100 (crítico) a partir dos achados. */
export function riskScore(findings) {
  if (!findings.length) return 0;
  const total = findings.reduce((sum, f) => sum + (SEVERITY_WEIGHT[f.severity] || 0), 0);
  // Normaliza de forma logarítmica leve para não estourar em 100 com poucos criticals.
  return Math.min(100, Math.round(total));
}

/** Conta achados por severidade. */
export function countBySeverity(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    if (counts[f.severity] !== undefined) counts[f.severity] += 1;
  }
  return counts;
}
