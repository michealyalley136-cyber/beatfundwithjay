const CACHE_NAME = "beatfund-pwa-v2";
const PRECACHE_URLS = [
  "/",
  "/offline",
  "/static/manifest.webmanifest",
  "/static/app.css",
  "/static/style.css",
  "/static/pwa.js",
  "/static/img/favicon/icon-192.png",
  "/static/img/favicon/icon-512.png",
  "/static/img/favicon/icon-180.png",
  "/static/img/favicon/icon-32.png",
  "/static/img/favicon/icon-16.png"
];

const NAV_TIMEOUT_MS = 4000;

function isSensitivePath(pathname) {
  return (
    pathname.startsWith("/admin") ||
    pathname.startsWith("/api") ||
    pathname.startsWith("/login") ||
    pathname.startsWith("/logout") ||
    pathname.startsWith("/register") ||
    pathname.startsWith("/download") ||
    pathname.startsWith("/stripe") ||
    pathname.startsWith("/webhook") ||
    pathname.startsWith("/create-checkout-session") ||
    pathname.startsWith("/checkout") ||
    pathname.startsWith("/wallet") ||
    pathname.startsWith("/payment") ||
    pathname.startsWith("/payments")
  );
}

function isStaticAsset(request) {
  return request.destination === "style" ||
    request.destination === "script" ||
    request.destination === "image" ||
    request.destination === "font";
}

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(PRECACHE_URLS))
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.map((key) => (key === CACHE_NAME ? null : caches.delete(key))))
    )
  );
  self.clients.claim();
});

async function staleWhileRevalidate(request) {
  const cache = await caches.open(CACHE_NAME);
  const cached = await cache.match(request);
  const fetchPromise = fetch(request)
    .then((response) => {
      if (response && response.status === 200) {
        cache.put(request, response.clone());
      }
      return response;
    })
    .catch(() => null);

  return cached || fetchPromise || Response.error();
}

async function networkFirst(request) {
  const cache = await caches.open(CACHE_NAME);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), NAV_TIMEOUT_MS);

  try {
    const response = await fetch(request, { signal: controller.signal });
    clearTimeout(timeoutId);
    if (response && response.status === 200) {
      cache.put(request, response.clone());
    }
    return response;
  } catch (err) {
    clearTimeout(timeoutId);
    const cached = await cache.match(request);
    if (cached) return cached;
    return cache.match("/offline");
  }
}

self.addEventListener("fetch", (event) => {
  const { request } = event;
  if (request.method !== "GET") {
    return;
  }

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) {
    return;
  }

  if (isSensitivePath(url.pathname)) {
    return;
  }

  if (request.mode === "navigate") {
    event.respondWith(networkFirst(request));
    return;
  }

  if (isStaticAsset(request) || url.pathname.startsWith("/static/")) {
    event.respondWith(staleWhileRevalidate(request));
  }
});
