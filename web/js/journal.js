// The journal in the browser: the same pages, rules and sync as the app's
// Journal.swift. Pages are kept sealed in IndexedDB and opened in memory;
// sync pushes this browser's changes and pulls everyone else's, and when
// two devices both changed a day since they last agreed, their words are
// put one after the other.
import * as c from "./crypto.js";
import * as db from "./db.js";
import { API, ApiError, Offline } from "./api.js";

const REF = 978307200; // Swift dates are seconds since 2001-01-01
export const toSwift = (ms) => ms / 1000 - REF;
export const fromSwift = (s) => (s + REF) * 1000;
export const DIVIDER = "\n\n· · ·\n\n";

// ---- days, in this browser's time zone ----

export function dayKey(d = new Date()) {
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}
export const dayDate = (k) => { const [y, m, d] = k.split("-").map(Number); return new Date(y, m - 1, d); };
export const addDays = (k, n) => { const d = dayDate(k); d.setDate(d.getDate() + n); return dayKey(d); };
export const today = () => dayKey();

export function blankEntry(day) {
  const now = toSwift(Date.now());
  return { created: now, day, photos: [], places: [], removedPhotos: [], text: "", updated: now };
}

export const hasContent = (e) => !!e && (e.text.trim() !== "" || e.photos.length > 0);
const v = (e) => e.version ?? 0;

// ---- merging (Entry.merge in Models.swift) ----

function combinePlaces(a, b) {
  const out = [];
  for (const p of [...a, ...b]) {
    const i = out.findIndex((q) => q.id === p.id);
    if (i < 0) out.push({ ...p });
  }
  return out.sort((x, y) => (x.arrived ?? Infinity) - (y.arrived ?? Infinity));
}

export function merge(remote, local, base) {
  const out = { ...local };
  const r = remote.text.trim(), l = local.text.trim();
  if (base && remote.text === base.text) out.text = local.text;
  else if (base && local.text === base.text) out.text = remote.text;
  else if (!r || l.startsWith(r)) out.text = local.text;
  else if (!l || r.startsWith(l) || r.includes(l)) out.text = remote.text;
  else if (l.includes(r)) out.text = local.text;
  else out.text = r + DIVIDER + l;
  const removed = new Set([...(remote.removedPhotos || []), ...(local.removedPhotos || [])]);
  out.removedPhotos = [...removed].sort();
  const photos = new Map();
  for (const p of [...remote.photos, ...local.photos]) {
    if (removed.has(p.id)) continue;
    const cur = photos.get(p.id);
    if (!cur || p.updated > cur.updated) photos.set(p.id, p);
  }
  out.photos = [...photos.values()];
  out.places = combinePlaces(remote.places, local.places);
  if (remote.health && (!local.health || remote.health.asOf > local.health.asOf)) out.health = remote.health;
  out.sun = local.sun ?? remote.sun;
  out.created = Math.min(remote.created, local.created);
  out.updated = Math.max(remote.updated, local.updated, toSwift(Date.now()));
  out.version = Math.max(v(remote), v(local)) + 1;
  return out;
}

// ---- the journal ----

export class Journal extends EventTarget {
  static async open() {
    const id = await db.get("kv", "identity");
    if (!id) return null;
    const j = new Journal(id);
    await j.load();
    return j;
  }

  constructor(id) {
    super();
    this.handle = id.handle;
    this.label = id.label;
    this.keys = id.keys;
    this.api = new API(id.handle, id.session);
    this.entries = new Map(); // day → entry
    this.records = new Map(); // id → {id, sealed, rev, dirty, base}
    this.dayOf = new Map();
    this.state = { cursor: 0, uploads: [], removals: [] };
    this.urls = new Map();
    this.syncing = false;
    this.online = navigator.onLine;
    this.lastSynced = null;
    this.error = null;
    addEventListener("online", () => { this.online = true; this.sync(); });
    addEventListener("offline", () => { this.online = false; this.changed(); });
  }

  changed() { this.dispatchEvent(new Event("change")); }

  async load() {
    this.state = (await db.get("kv", "state")) || this.state;
    for (const rec of await db.all("entries")) {
      this.records.set(rec.id, rec);
      try {
        const e = JSON.parse(new TextDecoder().decode(await c.openEntry(this.keys, rec.id, rec.sealed)));
        this.entries.set(e.day, e);
        this.dayOf.set(rec.id, e.day);
      } catch {}
    }
  }

  saveState() { return db.put("kv", this.state, "state"); }
  entry(day) { return this.entries.get(day) || blankEntry(day); }
  get pending() { return [...this.records.values()].filter((r) => r.dirty).length + this.state.uploads.length; }

  async sealed(e) {
    const id = await c.entryID(this.keys, e.day);
    return { id, sealed: await c.sealEntry(this.keys, id, c.utf8(JSON.stringify(e))) };
  }

  // Saves a page here and queues it for the server.
  async save(e) {
    const cur = this.entries.get(e.day);
    if (cur && JSON.stringify(cur) === JSON.stringify(e)) return;
    e = { ...e, updated: toSwift(Date.now()), version: Math.max(v(e), cur ? v(cur) : 0) + 1 };
    if (!cur) e.created = toSwift(Date.now());
    this.entries.set(e.day, e);
    const { id, sealed } = await this.sealed(e);
    this.dayOf.set(id, e.day);
    const rec = { ...(this.records.get(id) || { id, rev: 0 }), sealed, dirty: true };
    this.records.set(id, rec);
    await db.put("entries", rec);
    this.changed();
    this.schedule();
  }

  async update(day, fn) {
    const e = structuredClone(this.entry(day));
    fn(e);
    await this.save(e);
  }

  schedule() {
    clearTimeout(this.timer);
    this.timer = setTimeout(() => this.sync(), 2000);
  }

  // ---- photos ----

  async addPhoto(file, day) {
    const bmp = await createImageBitmap(file, { imageOrientation: "from-image" });
    const k = Math.min(1, 2048 / Math.max(bmp.width, bmp.height));
    const w = Math.round(bmp.width * k), h = Math.round(bmp.height * k);
    const canvas = new OffscreenCanvas(w, h);
    canvas.getContext("2d").drawImage(bmp, 0, 0, w, h);
    // Re-encoding drops EXIF and GPS before anything is sealed.
    const jpeg = new Uint8Array(await (await canvas.convertToBlob({ type: "image/jpeg", quality: 0.82 })).arrayBuffer());
    const id = "p_" + c.b64url(c.random(16));
    const key = c.random(32);
    await db.put("photos", await c.sealPhoto(key, jpeg, id), id);
    this.state.uploads.push(id);
    await this.saveState();
    this.urls.set(id, URL.createObjectURL(new Blob([jpeg], { type: "image/jpeg" })));
    const photo = { caption: "", height: h, id, key: c.b64(key), updated: toSwift(Date.now()), width: w };
    if (file.lastModified) photo.takenAt = toSwift(file.lastModified);
    await this.update(day, (e) => e.photos.push(photo));
  }

  async removePhoto(p, day) {
    await this.update(day, (e) => {
      e.photos = e.photos.filter((x) => x.id !== p.id);
      if (!e.removedPhotos.includes(p.id)) e.removedPhotos.push(p.id);
    });
    await db.del("photos", p.id);
    this.state.uploads = this.state.uploads.filter((x) => x !== p.id);
    this.state.removals.push(p.id);
    await this.saveState();
  }

  caption(p, day, text) {
    return this.update(day, (e) => {
      const x = e.photos.find((q) => q.id === p.id);
      if (x && x.caption !== text) { x.caption = text; x.updated = toSwift(Date.now()); }
    });
  }

  // An object URL for a photo, from memory, IndexedDB, or the server.
  async image(p) {
    if (this.urls.has(p.id)) return this.urls.get(p.id);
    let sealed = await db.get("photos", p.id);
    if (!sealed) {
      sealed = await this.api.blob(p.id);
      await db.put("photos", sealed, p.id);
    }
    const jpeg = await c.openPhoto(c.unb64(p.key), sealed, p.id);
    const url = URL.createObjectURL(new Blob([jpeg], { type: "image/jpeg" }));
    this.urls.set(p.id, url);
    return url;
  }

  // ---- sync ----

  async sync() {
    if (this.syncing) return;
    this.syncing = true;
    this.changed();
    try {
      for (const id of [...this.state.uploads]) {
        const b = await db.get("photos", id);
        if (b) await this.api.putBlob(id, b);
        this.state.uploads = this.state.uploads.filter((x) => x !== id);
        await this.saveState();
      }
      for (let i = 0; i < 3; i++) {
        await this.pull();
        if (await this.push()) break;
      }
      for (const id of [...this.state.removals]) {
        try { await this.api.deleteBlob(id); } catch (e) { if (!(e instanceof ApiError && e.status === 404)) throw e; }
        this.state.removals = this.state.removals.filter((x) => x !== id);
        await this.saveState();
      }
      this.lastSynced = new Date();
      this.error = null;
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        this.dispatchEvent(new Event("revoked"));
      } else if (!(e instanceof Offline)) {
        this.error = e.message;
      }
    } finally {
      this.syncing = false;
      this.changed();
    }
  }

  async pull() {
    for (let more = true; more;) {
      const page = await this.api.changes(this.state.cursor);
      for (const r of page.entries) await this.apply(r);
      this.state.cursor = page.cursor;
      more = page.more;
      await this.saveState();
    }
  }

  async apply(r) {
    const local = this.records.get(r.id);
    if (local && r.rev <= local.rev) return; // our own upload, or older
    if (r.deleted) {
      // The app never deletes a page: a deletion is forged. Keep ours, put it back.
      if (local && this.dayOf.has(r.id)) { local.rev = r.rev; local.dirty = true; await db.put("entries", local); }
      return;
    }
    const data = c.unb64(r.data);
    let remote;
    try { remote = JSON.parse(new TextDecoder().decode(await c.openEntry(this.keys, r.id, data))); } catch { return; }
    if ((await c.entryID(this.keys, remote.day)) !== r.id) return; // a page moved to another day
    this.dayOf.set(r.id, remote.day);
    const mine = this.entries.get(remote.day);
    let rec;
    if (local?.dirty && mine) {
      let base = null;
      if (local.base) { try { base = JSON.parse(new TextDecoder().decode(await c.openEntry(this.keys, r.id, local.base))); } catch {} }
      const merged = merge(remote, mine, base);
      this.entries.set(remote.day, merged);
      rec = { id: r.id, rev: r.rev, dirty: JSON.stringify(merged) !== JSON.stringify(remote), base: data, sealed: (await this.sealed(merged)).sealed };
    } else if (mine && v(remote) < v(mine)) {
      // An older version than we have: a replay. Keep ours, put it back.
      rec = { ...local, id: r.id, rev: r.rev, dirty: true };
    } else {
      this.entries.set(remote.day, remote);
      rec = { id: r.id, rev: r.rev, dirty: false, base: data, sealed: data };
    }
    this.records.set(r.id, rec);
    await db.put("entries", rec);
  }

  async push() {
    for (const rec of [...this.records.values()].filter((r) => r.dirty)) {
      try {
        const sent = rec.sealed;
        const res = await this.api.putEntry(rec.id, sent, rec.rev);
        const now = this.records.get(rec.id);
        now.rev = res.rev;
        now.base = sent;
        if (now.sealed === sent) now.dirty = false; // unless it changed while uploading
        await db.put("entries", now);
      } catch (e) {
        if (e instanceof ApiError && e.status === 409) return false;
        throw e;
      }
    }
    return true;
  }

  // ---- streaks ----

  get writtenDays() { return new Set([...this.entries.values()].filter(hasContent).map((e) => e.day)); }

  streak(day = today()) {
    const days = this.writtenDays;
    let d = days.has(day) ? day : addDays(day, -1), n = 0;
    while (days.has(d)) { n++; d = addDays(d, -1); }
    return n;
  }

  runEndingAt(day) {
    const days = this.writtenDays;
    let d = day, n = 0;
    while (days.has(d)) { n++; d = addDays(d, -1); }
    return n;
  }

  get longest() {
    const days = this.writtenDays;
    let best = 0;
    for (const d of days) {
      if (days.has(addDays(d, -1))) continue;
      let n = 1, cur = d;
      while (days.has(addDays(cur, 1))) { n++; cur = addDays(cur, 1); }
      best = Math.max(best, n);
    }
    return best;
  }

  // ---- leaving ----

  async signOut() {
    try { await this.api.signOut(); } catch {}
    for (const u of this.urls.values()) URL.revokeObjectURL(u);
    await db.wipe();
  }
}

// ---- linking: username and PIN, then the phone, and they must agree ----

export async function linkStart(handle, pin) {
  const api = new API();
  const params = await api.params(handle);
  const d = await c.stretch(pin, params.salt, params.iterations);
  const blob = await api.recover(handle, d.verifier); // throws 403 for a wrong PIN
  const fromPIN = await c.unlock(blob, d, handle);
  d.wrap.fill(0);
  const kp = await c.linkingKeyPair();
  const slot = await api.openSlot();
  return { api, handle, fromPIN, kp, slot: slot.id, expiresIn: slot.expiresIn, qr: `tekkoh-link:1:${slot.id}:${c.b64url(kp.publicRaw)}`, code: await c.linkCode(kp.publicRaw) };
}

// Waits for the phone; then checks it's the same journal the PIN opened.
export async function linkFinish(link, label, signal) {
  for (;;) {
    if (signal?.aborted) throw new Error("cancelled");
    const o = await link.api.takeSlot(link.slot);
    if (o.status === 200) {
      const payload = JSON.parse(new TextDecoder().decode(await c.openFromPhone(link.kp.privateKey, link.kp.publicRaw, c.unb64(o.box))));
      const fromPhone = c.unb64(payload.key);
      const agree = payload.handle === link.handle && o.handle === link.handle && c.same(fromPhone, link.fromPIN);
      link.fromPIN.fill(0);
      if (!agree) { fromPhone.fill(0); throw new Error("mismatch"); }
      const keys = await c.importJournalKey(fromPhone);
      fromPhone.fill(0);
      const owner = new API(link.handle, await c.authToken(keys));
      const s = await owner.createSession(label);
      await db.put("kv", { handle: link.handle, label, session: c.unb64(s.token), keys }, "identity");
      return Journal.open();
    }
    await new Promise((r) => setTimeout(r, 1500));
  }
}

export function browserLabel() {
  const ua = navigator.userAgent;
  const browser = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "A browser";
  const os = /iPhone/.test(ua) ? "iPhone" : /iPad/.test(ua) ? "iPad" : /Mac OS X/.test(ua) ? "Mac" : /Android/.test(ua) ? "Android" : /Windows/.test(ua) ? "Windows" : /Linux/.test(ua) ? "Linux" : "";
  return os ? `${browser} on ${os}` : browser;
}
