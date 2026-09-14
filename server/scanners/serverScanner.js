// Scanner do próprio servidor onde o STRIIS roda.
// Verifica portas locais abertas, informações do SO e sinais de configuração fraca.
// Usa módulos nativos (net/os) — sem varredura agressiva, apenas checagem local segura.

import net from 'node:net';
import os from 'node:os';
import { finding, SEVERITY } from '../lib/findings.js';

// Portas comuns e o risco associado quando estão abertas em localhost.
const COMMON_PORTS = [
  { port: 21, name: 'FTP', severity: SEVERITY.HIGH, note: 'FTP transmite credenciais em texto claro.' },
  { port: 22, name: 'SSH', severity: SEVERITY.MEDIUM, note: 'Garanta autenticação por chave e restrição de IP.' },
  { port: 23, name: 'Telnet', severity: SEVERITY.CRITICAL, note: 'Telnet é inseguro — desative imediatamente.' },
  { port: 25, name: 'SMTP', severity: SEVERITY.LOW, note: 'Verifique se não é um relay aberto.' },
  { port: 3306, name: 'MySQL', severity: SEVERITY.HIGH, note: 'Banco de dados não deve ficar exposto na rede.' },
  { port: 5432, name: 'PostgreSQL', severity: SEVERITY.HIGH, note: 'Banco de dados não deve ficar exposto na rede.' },
  { port: 6379, name: 'Redis', severity: SEVERITY.CRITICAL, note: 'Redis sem senha exposto permite acesso total aos dados.' },
  { port: 27017, name: 'MongoDB', severity: SEVERITY.HIGH, note: 'MongoDB exposto sem auth é um risco crítico.' },
  { port: 3389, name: 'RDP', severity: SEVERITY.HIGH, note: 'RDP exposto é alvo frequente de força bruta.' },
  { port: 9200, name: 'Elasticsearch', severity: SEVERITY.HIGH, note: 'Elasticsearch aberto vaza dados indexados.' },
];

function checkPort(port, host = '127.0.0.1', timeout = 800) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let done = false;
    const finish = (open) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(open);
    };
    socket.setTimeout(timeout);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
    socket.connect(port, host);
  });
}

export async function scanServer() {
  const findings = [];

  // 1) Info do SO (informativo)
  findings.push(
    finding({
      severity: SEVERITY.INFO,
      title: 'Sistema operacional detectado',
      detail: `${os.type()} ${os.release()} (${os.arch()}) — mantenha os pacotes atualizados.`,
      recommendation: 'Automatize atualizações de segurança do sistema.',
      evidence: `${os.platform()} ${os.release()}`,
    }),
  );

  // 2) Uptime muito alto pode indicar kernel sem patches recentes.
  const uptimeDays = Math.round(os.uptime() / 86_400);
  if (uptimeDays > 180) {
    findings.push(
      finding({
        severity: SEVERITY.LOW,
        title: 'Servidor sem reinicialização há muito tempo',
        detail: `Uptime de ${uptimeDays} dias pode indicar patches de kernel pendentes.`,
        recommendation: 'Aplique atualizações de kernel e reinicie em janela de manutenção.',
        evidence: `${uptimeDays} dias de uptime`,
      }),
    );
  }

  // 3) Rodando como root (em Linux/Mac) é risco de privilégio.
  if (typeof process.getuid === 'function' && process.getuid() === 0) {
    findings.push(
      finding({
        severity: SEVERITY.MEDIUM,
        title: 'Processo rodando como root',
        detail: 'O STRIIS está rodando como root — reduz o isolamento em caso de comprometimento.',
        recommendation: 'Execute a aplicação com um usuário dedicado sem privilégios.',
        evidence: 'uid=0',
      }),
    );
  }

  // 4) Varredura leve de portas locais.
  const results = await Promise.all(
    COMMON_PORTS.map(async (p) => ({ ...p, open: await checkPort(p.port) })),
  );
  const openPorts = results.filter((r) => r.open);

  for (const p of openPorts) {
    findings.push(
      finding({
        severity: p.severity,
        title: `Porta ${p.port} (${p.name}) aberta`,
        detail: p.note,
        recommendation:
          'Feche a porta se não for necessária ou restrinja o acesso via firewall.',
        evidence: `tcp/${p.port} aberta em 127.0.0.1`,
      }),
    );
  }

  if (openPorts.length === 0) {
    findings.push(
      finding({
        severity: SEVERITY.INFO,
        title: 'Nenhuma porta sensível comum aberta',
        detail: 'Nenhuma das portas de serviço monitoradas está aberta em localhost.',
        recommendation: 'Continue monitorando periodicamente.',
        evidence: 'scan local concluído',
      }),
    );
  }

  return findings;
}
