// Scanner de URL/site alvo.
// Faz uma requisição HTTPS e analisa headers de segurança, TLS e cookies.
// Usa apenas módulos nativos do Node (https/http/tls) — sem dependências externas.

import https from 'node:https';
import http from 'node:http';
import { finding, SEVERITY } from '../lib/findings.js';

// Headers de segurança recomendados e a severidade quando estão ausentes.
const SECURITY_HEADERS = [
  {
    name: 'strict-transport-security',
    label: 'HSTS (Strict-Transport-Security)',
    severity: SEVERITY.HIGH,
    recommendation:
      'Adicione: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload',
  },
  {
    name: 'content-security-policy',
    label: 'Content-Security-Policy',
    severity: SEVERITY.MEDIUM,
    recommendation: "Defina uma CSP restritiva, ex.: default-src 'self'",
  },
  {
    name: 'x-frame-options',
    label: 'X-Frame-Options',
    severity: SEVERITY.MEDIUM,
    recommendation: 'Adicione: X-Frame-Options: DENY (protege contra clickjacking)',
  },
  {
    name: 'x-content-type-options',
    label: 'X-Content-Type-Options',
    severity: SEVERITY.LOW,
    recommendation: 'Adicione: X-Content-Type-Options: nosniff',
  },
  {
    name: 'referrer-policy',
    label: 'Referrer-Policy',
    severity: SEVERITY.LOW,
    recommendation: 'Adicione: Referrer-Policy: strict-origin-when-cross-origin',
  },
  {
    name: 'permissions-policy',
    label: 'Permissions-Policy',
    severity: SEVERITY.INFO,
    recommendation: 'Restrinja recursos do navegador via Permissions-Policy.',
  },
];

function normalizeUrl(input) {
  let url = String(input || '').trim();
  if (!url) throw new Error('URL vazia.');
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  return new URL(url);
}

function request(url, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    const client = url.protocol === 'https:' ? https : http;
    const options = {
      method: 'GET',
      timeout: 15_000,
      rejectUnauthorized: false,
      // Força IPv4: alguns servidores têm rota IPv6 quebrada que trava a conexão
      // (o curl usa IPv4 e funciona; o Node tentaria IPv6 e daria timeout).
      family: 4,
      headers: {
        'User-Agent': 'STRIIS-Scanner/0.1 (+seguranca)',
        Accept: '*/*',
      },
    };
    const req = client.request(url, options, (res) => {
      const status = res.statusCode;

      // Segue redirecionamentos (http→https, apex→www, etc.).
      if (status >= 300 && status < 400 && res.headers.location && redirectsLeft > 0) {
        res.resume();
        let next;
        try {
          next = new URL(res.headers.location, url);
        } catch {
          return resolve({ statusCode: status, headers: res.headers, tlsInfo: null, finalUrl: url });
        }
        return resolve(request(next, redirectsLeft - 1));
      }

      // Não precisamos do corpo; só headers e conexão TLS.
      const tlsInfo =
        url.protocol === 'https:' && res.socket.getPeerCertificate
          ? res.socket.getPeerCertificate()
          : null;
      res.resume(); // descarta o corpo
      resolve({ statusCode: status, headers: res.headers, tlsInfo, finalUrl: url });
    });
    req.on('timeout', () => req.destroy(new Error('Tempo esgotado ao conectar (15s).')));
    req.on('error', reject);
    req.end();
  });
}

export async function scanUrl(target) {
  const url = normalizeUrl(target);
  const findings = [];

  // 1) Site sem HTTPS
  if (url.protocol !== 'https:') {
    findings.push(
      finding({
        severity: SEVERITY.HIGH,
        title: 'Site sem HTTPS',
        detail: 'O alvo usa HTTP puro — o tráfego pode ser interceptado e alterado.',
        recommendation: 'Habilite HTTPS/TLS e redirecione todo o HTTP para HTTPS.',
        evidence: url.origin,
      }),
    );
  }

  let res;
  try {
    res = await request(url);
  } catch (err) {
    findings.push(
      finding({
        severity: SEVERITY.INFO,
        title: 'Não foi possível conectar ao alvo',
        detail: `Falha ao acessar ${url.origin}: ${err.message}`,
        recommendation: 'Verifique se a URL está correta e acessível a partir do servidor.',
        evidence: err.message,
      }),
    );
    return findings;
  }

  const headers = res.headers || {};

  // 2) Headers de segurança ausentes
  for (const h of SECURITY_HEADERS) {
    if (!headers[h.name]) {
      findings.push(
        finding({
          severity: h.severity,
          title: `Header ${h.label} ausente`,
          detail: `O alvo não envia o header de segurança "${h.label}".`,
          recommendation: h.recommendation,
          evidence: `${h.label}: (não presente)`,
        }),
      );
    }
  }

  // 3) Cookies inseguros
  const setCookie = headers['set-cookie'] || [];
  for (const cookie of setCookie) {
    const lower = cookie.toLowerCase();
    const name = cookie.split('=')[0];
    if (!lower.includes('secure')) {
      findings.push(
        finding({
          severity: SEVERITY.MEDIUM,
          title: `Cookie "${name}" sem flag Secure`,
          detail: 'Cookie pode trafegar em conexões não criptografadas.',
          recommendation: 'Marque cookies com Secure; HttpOnly; SameSite=Strict.',
          evidence: cookie,
        }),
      );
    }
    if (!lower.includes('httponly')) {
      findings.push(
        finding({
          severity: SEVERITY.LOW,
          title: `Cookie "${name}" sem flag HttpOnly`,
          detail: 'Cookie acessível via JavaScript — risco em caso de XSS.',
          recommendation: 'Adicione a flag HttpOnly em cookies de sessão.',
          evidence: cookie,
        }),
      );
    }
  }

  // 4) Exposição de tecnologia (fingerprinting)
  if (headers['server']) {
    findings.push(
      finding({
        severity: SEVERITY.LOW,
        title: 'Header Server expõe a tecnologia',
        detail: 'O header Server revela software/versão, ajudando atacantes.',
        recommendation: 'Remova ou ofusque o header Server.',
        evidence: `Server: ${headers['server']}`,
      }),
    );
  }
  if (headers['x-powered-by']) {
    findings.push(
      finding({
        severity: SEVERITY.LOW,
        title: 'Header X-Powered-By expõe a tecnologia',
        detail: 'Revela o framework/linguagem usados.',
        recommendation: 'Remova o header X-Powered-By.',
        evidence: `X-Powered-By: ${headers['x-powered-by']}`,
      }),
    );
  }

  // 5) Validade do certificado TLS
  if (res.tlsInfo && res.tlsInfo.valid_to) {
    const validTo = new Date(res.tlsInfo.valid_to);
    const daysLeft = Math.round((validTo - Date.now()) / 86_400_000);
    if (daysLeft < 0) {
      findings.push(
        finding({
          severity: SEVERITY.CRITICAL,
          title: 'Certificado TLS expirado',
          detail: `O certificado venceu em ${validTo.toISOString().slice(0, 10)}.`,
          recommendation: 'Renove o certificado TLS imediatamente.',
          evidence: `valid_to: ${res.tlsInfo.valid_to}`,
        }),
      );
    } else if (daysLeft < 21) {
      findings.push(
        finding({
          severity: SEVERITY.MEDIUM,
          title: 'Certificado TLS perto de expirar',
          detail: `Faltam ${daysLeft} dias para o certificado vencer.`,
          recommendation: 'Programe a renovação do certificado.',
          evidence: `valid_to: ${res.tlsInfo.valid_to}`,
        }),
      );
    }
  }

  // 6) Se nada foi encontrado, registra um "tudo certo" informativo.
  if (findings.length === 0) {
    findings.push(
      finding({
        severity: SEVERITY.INFO,
        title: 'Nenhuma falha comum detectada',
        detail: 'Os headers de segurança básicos e o TLS parecem em ordem.',
        recommendation: 'Continue monitorando periodicamente.',
        evidence: `HTTP ${res.statusCode}`,
      }),
    );
  }

  return findings;
}
