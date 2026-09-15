// Service worker do STRIIS (PWA) — network-first (sempre busca a versão fresca).
// Cache serve só como fallback offline. Nunca intercepta /api/.
// (v2: corrige cache ruim da v1 que podia guardar a tela de login no lugar dos assets.)

const CACHE = 'striis-v2';

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      // Limpa TODOS os caches antigos (inclui a v1 que podia estar corrompida).
      const keys = await caches.keys();
      await Promise.all(keys.map((k) => caches.delete(k)));
      await self.clients.claim();
    })(),
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  if (url.origin !== self.location.origin) return; // só o próprio domínio
  if (url.pathname.startsWith('/api/')) return; // API sempre na rede
  if (req.method !== 'GET') return;

  // Network-first: tenta a rede (versão sempre atual); cacheia; cai pro cache só offline.
  event.respondWith(
    (async () => {
      try {
        const res = await fetch(req);
        if (res && res.status === 200 && res.type === 'basic') {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {});
        }
        return res;
      } catch {
        const cached = await caches.match(req);
        return cached || Response.error();
      }
    })(),
  );
});
