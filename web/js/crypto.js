// Tekkoh's crypto in the browser, matching the app's Crypto.swift and
// Transport.swift byte for byte (tests/vectors.mjs checks it against
// vectors the Swift code made). WebCrypto only; nothing hand-rolled.
//
// The journal key never exists here as bytes after it's imported: it lives
// as two non-extractable CryptoKeys (HKDF and AES-GCM), so the page's own
// script can use it but can't read it out.

const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();
export const utf8 = (s) => te.encode(s);

// ---- bytes ----

export function b64(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s);
}

export function unb64(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export const b64url = (bytes) => b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
export const unb64url = (s) => unb64(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) { out.set(p, i); i += p.length; }
  return out;
}

export const random = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

// ---- primitives, as CryptoKit does them ----

async function hkdfBits(keyOrBytes, info, salt = new Uint8Array(0), bits = 256) {
  const key = keyOrBytes instanceof CryptoKey ? keyOrBytes : await subtle.importKey("raw", keyOrBytes, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: utf8(info) }, key, bits));
}

const aesKey = (bytes, usages = ["encrypt", "decrypt"]) => subtle.importKey("raw", bytes, "AES-GCM", false, usages);

// AES-GCM as CryptoKit's `combined`: nonce (12) ‖ ciphertext ‖ tag (16).
export async function seal(key, plain, aad) {
  const k = key instanceof CryptoKey ? key : await aesKey(key);
  const iv = random(12);
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv, additionalData: utf8(aad) }, k, plain));
  return concat(iv, ct);
}

export async function open(key, combined, aad) {
  const k = key instanceof CryptoKey ? key : await aesKey(key);
  return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: combined.slice(0, 12), additionalData: utf8(aad) }, k, combined.slice(12)));
}

// ---- the journal key ----

// The journal key as non-extractable keys, plus what's derived from it.
export async function importJournalKey(raw) {
  const hkdf = await subtle.importKey("raw", raw, "HKDF", false, ["deriveBits"]);
  const aes = await aesKey(raw);
  const idKey = await subtle.importKey("raw", await hkdfBits(hkdf, "tekkoh/entry-id/v1"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return { hkdf, aes, idKey };
}

export const authToken = (jk) => hkdfBits(jk.hkdf, "tekkoh/auth/v1");

// A day's entry id: base64url of the first 24 bytes of HMAC("day:" + date).
export async function entryID(jk, day) {
  const mac = new Uint8Array(await subtle.sign("HMAC", jk.idKey, utf8(`day:${day}`)));
  return b64url(mac.slice(0, 24));
}

// An entry's envelope: {"v": 1, "k": entry key sealed with the journal key,
// "c": the JSON sealed with the entry key}.
export async function sealEntry(jk, id, plainJSON) {
  const entryKey = random(32);
  const k = await seal(jk.aes, entryKey, `tekkoh/entry-key/${id}`);
  const c = await seal(entryKey, plainJSON, `tekkoh/entry/${id}`);
  entryKey.fill(0);
  return utf8(JSON.stringify({ v: 1, k: b64(k), c: b64(c) }));
}

export async function openEntry(jk, id, envelope) {
  const env = JSON.parse(new TextDecoder().decode(envelope));
  const entryKey = await open(jk.aes, unb64(env.k), `tekkoh/entry-key/${id}`);
  return open(entryKey, unb64(env.c), `tekkoh/entry/${id}`);
}

export const sealPhoto = (photoKey, jpeg, id) => seal(photoKey, jpeg, `tekkoh/photo/${id}`);
export const openPhoto = (photoKey, sealed, id) => open(photoKey, sealed, `tekkoh/photo/${id}`);

// ---- the PIN ----

export async function stretch(pin, salt, iterations) {
  const base = await subtle.importKey("raw", utf8(pin), "PBKDF2", false, ["deriveBits"]);
  const s = new Uint8Array(await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, base, 256));
  const verifier = await hkdfBits(s, "tekkoh/pin-verifier/v1");
  const wrap = await hkdfBits(s, "tekkoh/pin-wrap/v1");
  s.fill(0);
  return { verifier, wrap };
}

export const unlock = (blob, derived, handle) => open(derived.wrap, blob, `tekkoh/recovery/${handle}`);

// ---- boxes to an X25519 key (the server's, or a browser's when linking) ----
//
// k = HKDF(X25519(eph, to), salt: eph ‖ to, info: "tekkoh/transport/v1/" + purpose)
// box = AES-GCM(k, plain, aad: purpose); a reply uses aad purpose + "/reply".

async function boxKey(sharedBits, ephPub, toPub, purpose) {
  return aesKey(await hkdfBits(sharedBits, `tekkoh/transport/v1/${purpose}`, concat(ephPub, toPub)));
}

export async function sealTo(toPubRaw, purpose, plain) {
  const eph = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const ephPub = new Uint8Array(await subtle.exportKey("raw", eph.publicKey));
  const to = await subtle.importKey("raw", toPubRaw, { name: "X25519" }, false, []);
  const shared = new Uint8Array(await subtle.deriveBits({ name: "X25519", public: to }, eph.privateKey, 256));
  const key = await boxKey(shared, ephPub, toPubRaw, purpose);
  shared.fill(0);
  return { eph: ephPub, box: await seal(key, plain, purpose), key };
}

export async function openReply(key, purpose, reply) {
  return open(key, reply, `${purpose}/reply`);
}

// A browser's linking key pair; the private half never leaves the page.
export async function linkingKeyPair() {
  const kp = await subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  return { privateKey: kp.privateKey, publicRaw: new Uint8Array(await subtle.exportKey("raw", kp.publicKey)) };
}

// Opens what the phone sealed to this browser: eph (32) ‖ AES-GCM box.
export async function openFromPhone(privateKey, myPubRaw, sealed) {
  const ephPub = sealed.slice(0, 32);
  const eph = await subtle.importKey("raw", ephPub, { name: "X25519" }, false, []);
  const shared = new Uint8Array(await subtle.deriveBits({ name: "X25519", public: eph }, privateKey, 256));
  const key = await boxKey(shared, ephPub, myPubRaw, "pair");
  shared.fill(0);
  return open(key, sealed.slice(32), "pair");
}

// Constant-time-ish comparison of two byte arrays.
export function same(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

// Six digits both screens show, so you can see the phone found this page.
export async function linkCode(pubRaw) {
  const h = new Uint8Array(await subtle.digest("SHA-256", pubRaw));
  return String(((h[0] << 16) | (h[1] << 8) | h[2]) % 1_000_000).padStart(6, "0");
}
