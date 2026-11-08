// Keeps the app itself on this device so the journal opens offline. The
// pages are in IndexedDB; this only caches the app's own files. A new
// version takes over when VERSION changes.
const VERSION = "tekkoh-web-2";
const FILES = ["./", "index.html", "app.css", "manifest.webmanifest", "icon-192.png", "icon-512.png", "vendor/qrcode.js",
  "js/main.js", "js/journal.js", "js/crypto.js", "js/api.js", "js/db.js"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(VERSION).then((c) => c.addAll(FILES)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  // The API is another origin: never cached here.
  if (e.request.method !== "GET" || url.origin !== location.origin) return;
  e.respondWith(caches.match(e.request, { ignoreSearch: true }).then((hit) => hit || fetch(e.request)));
});
