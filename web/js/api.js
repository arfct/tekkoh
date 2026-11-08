// The Tekkoh server, from the browser. It only ever sees ciphertext.
import * as c from "./crypto.js";

export const BASE = "https://tekkoh.cronbon.com";
// GET /v1/transport-key, built in (as in the app) so a server can't swap it.
const SERVER_KEY = c.unb64("SiOqxMKXLVclQsetdJkLdHhmk1TgexDAZZSlF/i6O2E=");

export class ApiError extends Error {
  constructor(status, message, body = {}) { super(message); this.status = status; this.body = body; }
}
export class Offline extends Error {}

export class API {
  constructor(handle = null, token = null) { this.handle = handle; this.token = token; }

  async req(method, path, { json, body, raw } = {}) {
    const headers = {};
    if (this.handle && this.token) headers.Authorization = `Tekkoh ${this.handle} ${c.b64(this.token)}`;
    if (json !== undefined) { headers["Content-Type"] = "application/json"; body = JSON.stringify(json); }
    else if (body) headers["Content-Type"] = "application/octet-stream";
    let res;
    try {
      res = await fetch(BASE + path, { method, headers, body, cache: "no-store", referrerPolicy: "no-referrer" });
    } catch {
      throw new Offline("Can't reach Tekkoh's server.");
    }
    if (!res.ok && res.status !== 202) {
      let obj = {};
      try { obj = await res.json(); } catch {}
      throw new ApiError(res.status, obj.error || `The server said ${res.status}.`, obj);
    }
    if (raw) return new Uint8Array(await res.arrayBuffer());
    return { status: res.status, ...(await res.json().catch(() => ({}))) };
  }

  // ---- recovery: the PIN's verifier and the locked key travel boxed ----

  async params(handle) {
    const o = await this.req("POST", "/v1/recovery/params", { json: { handle } });
    const salt = c.unb64(o.salt || "");
    if (salt.length < 16 || !(o.iterations >= 600000 && o.iterations <= 20000000)) throw new ApiError(0, "The server asked for unsafe PIN settings.");
    return { salt, iterations: o.iterations, attemptsLeft: o.attemptsLeft };
  }

  async recover(handle, verifier) {
    const sealed = await c.sealTo(SERVER_KEY, "recover", c.utf8(JSON.stringify({ verifier: c.b64(verifier) })));
    const o = await this.req("POST", "/v1/recovery", { json: { handle, proof: { eph: c.b64(sealed.eph), box: c.b64(sealed.box) } } });
    const reply = JSON.parse(new TextDecoder().decode(await c.openReply(sealed.key, "recover", c.unb64(o.reply))));
    return c.unb64(reply.blob);
  }

  // ---- linking ----

  openSlot() { return this.req("POST", "/v1/pair"); }
  takeSlot(id) { return this.req("GET", `/v1/pair/${id}`); }
  createSession(label) { return this.req("POST", "/v1/sessions", { json: { label } }); }
  signOut() { return this.req("DELETE", "/v1/sessions/current"); }
  me() { return this.req("GET", "/v1/me"); }

  // ---- pages and photos ----

  changes(after) { return this.req("GET", `/v1/entries?after=${after}`); }
  putEntry(id, data, rev) { return this.req("PUT", `/v1/entries/${id}`, { json: { data: c.b64(data), rev } }); }
  putBlob(id, bytes) { return this.req("PUT", `/v1/blobs/${id}`, { body: bytes }); }
  blob(id) { return this.req("GET", `/v1/blobs/${id}`, { raw: true }); }
  deleteBlob(id) { return this.req("DELETE", `/v1/blobs/${id}`); }
}
