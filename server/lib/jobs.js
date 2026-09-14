// Jobs assíncronos — para scans demorados (Strix pode levar minutos).
// O front inicia um job, recebe o id na hora e faz polling do progresso.

import { randomUUID } from 'node:crypto';

const jobs = new Map();
const MAX_LOG_LINES = 500;

export function createJob({ type, target }) {
  const id = randomUUID();
  jobs.set(id, {
    id,
    type,
    target,
    status: 'running', // running | done | error
    log: [],
    scanId: null,
    runName: null,
    error: null,
    startedAt: new Date().toISOString(),
    finishedAt: null,
  });
  return jobs.get(id);
}

export function getJob(id) {
  return jobs.get(id) || null;
}

export function appendLog(id, line) {
  const job = jobs.get(id);
  if (!job) return;
  job.log.push(line);
  if (job.log.length > MAX_LOG_LINES) job.log.splice(0, job.log.length - MAX_LOG_LINES);
}

export function finishJob(id, { scanId, runName }) {
  const job = jobs.get(id);
  if (!job) return;
  job.status = 'done';
  job.scanId = scanId;
  job.runName = runName;
  job.finishedAt = new Date().toISOString();
}

export function failJob(id, error) {
  const job = jobs.get(id);
  if (!job) return;
  job.status = 'error';
  job.error = String(error?.message || error);
  job.finishedAt = new Date().toISOString();
}

// Retorna uma visão leve do job para o polling (tail do log a partir de `since`).
export function jobView(id, since = 0) {
  const job = jobs.get(id);
  if (!job) return null;
  return {
    id: job.id,
    type: job.type,
    target: job.target,
    status: job.status,
    scanId: job.scanId,
    runName: job.runName,
    error: job.error,
    startedAt: job.startedAt,
    finishedAt: job.finishedAt,
    logFrom: since,
    log: job.log.slice(since),
    logTotal: job.log.length,
  };
}
