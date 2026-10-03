/* Daily Brief service worker.
   Shell is precached. The encrypted payload is cached as ciphertext so offline
   opens still require the passcode or the stored device key. */
const VERSION = 'daily-brief-v2';
const SHELL = VERSION + '-shell';
const DATA  = VERSION + '-data';

const SHELL_FILES = [
  './',
  './index.html',
  './manifest.json',
  './icon-192.png',
  './icon-512.png',
  './icon-maskable-512.png',
  './apple-touch-icon.png'
];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(SHELL)
      .then((c) => c.addAll(SHELL_FILES))
      .then(() => self.skipWaiting())
      .catch(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys.filter((k) => k !== SHELL && k !== DATA).map((k) => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

function isPayload(url) {
  return url.hostname === 'api.github.com' ||
         url.hostname === 'gist.githubusercontent.com';
}

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);

  // Encrypted payload: network first, fall back to the last ciphertext we stored.
  if (isPayload(url)) {
    e.respondWith((async () => {
      const cache = await caches.open(DATA);
      try {
        const fresh = await fetch(req);
        if (fresh && fresh.ok) {
          // Key by URL string so request cache-mode never blocks the put.
          cache.put(new Request(url.href), fresh.clone()).catch(() => {});
        }
        return fresh;
      } catch (err) {
        const hit = await cache.match(new Request(url.href));
        if (hit) {
          const h = new Headers(hit.headers);
          h.set('X-Daily-Brief-Offline', '1');
          return new Response(await hit.blob(), {
            status: hit.status, statusText: hit.statusText, headers: h
          });
        }
        throw err;
      }
    })());
    return;
  }

  if (url.origin === self.location.origin) {
    // index.html is network-first so a redeployed shell shows up immediately.
    // Icons and the manifest stay cache-first - they essentially never change.
    const isDoc = req.mode === 'navigate' ||
                  url.pathname.endsWith('/') ||
                  url.pathname.endsWith('/index.html');
    e.respondWith((async () => {
      const cache = await caches.open(SHELL);
      if (isDoc) {
        try {
          const fresh = await fetch(req, { cache: 'no-store' });
          if (fresh && fresh.ok) {
            cache.put(req, fresh.clone()).catch(() => {});
            return fresh;
          }
        } catch (err) { /* offline - fall through to cache */ }
        return (await cache.match(req, { ignoreSearch: true }))
            || new Response('Offline', { status: 503 });
      }
      const hit = await cache.match(req, { ignoreSearch: true });
      const net = fetch(req).then((r) => {
        if (r && r.ok) cache.put(req, r.clone()).catch(() => {});
        return r;
      }).catch(() => null);
      return hit || (await net) || new Response('Offline', { status: 503 });
    })());
  }
});

self.addEventListener('message', (e) => {
  if (e.data === 'skipWaiting') self.skipWaiting();
});
