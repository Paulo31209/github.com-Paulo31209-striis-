// STRIIS — servidor principal.
// Serve a API de scans e o dashboard web estático.

import './lib/loadEnv.js'; // carrega .env antes de tudo
import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { api } from './routes/api.js';
import { seedMockData } from './lib/store.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;

const app = express();
app.use(express.json());

// API.
app.use('/api', api);

// Dashboard estático.
app.use(express.static(path.join(__dirname, '..', 'public')));

// Popula dados de exemplo para o dashboard já nascer preenchido.
// Defina STRIIS_NO_SEED=1 para começar vazio.
if (!process.env.STRIIS_NO_SEED) {
  seedMockData();
}

app.listen(PORT, () => {
  console.log(`\n  🛡️  STRIIS rodando em http://localhost:${PORT}`);
  console.log(`     Dashboard: http://localhost:${PORT}`);
  console.log(`     API:       http://localhost:${PORT}/api/health\n`);
});
