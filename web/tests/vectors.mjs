// Checks web/js/crypto.js against vectors the iOS app's Swift code made
// (tekkoh-ios Checks/vectors), and seals a page for the Swift to open.
// Run: node web/tests/vectors.mjs (Node 22+, for WebCrypto X25519).
import { readFileSync, writeFileSync } from "node:fs";
import * as c from "../js/crypto.js";

const v = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url)));
let failed = 0;
const check = (ok, what) => { console.log(ok ? "ok   " : "FAIL ", what); if (!ok) failed++; };
const eq = (a, b) => c.same(new Uint8Array(a), new Uint8Array(b));

const raw = c.unb64(v.key);
const jk = await c.importJournalKey(raw);
check(c.b64(await c.authToken(jk)) === v.authToken, "sign-in token matches Swift");
check(await c.entryID(jk, v.day) === v.entryID, "entry id matches Swift");
const plain = new TextDecoder().decode(await c.openEntry(jk, v.entryID, c.unb64(v.sealedEntry)));
check(plain === v.entryJSON, "opens Swift's sealed page to the same JSON");
check(new TextDecoder().decode(await c.openPhoto(new Uint8Array(32).fill(7), c.unb64(v.photo), "p_test")) === "jpeg bytes", "opens Swift's sealed photo");
let movedOpened = true;
try { await c.openEntry(jk, await c.entryID(jk, "2026-11-09"), c.unb64(v.sealedEntry)); } catch { movedOpened = false; }
check(!movedOpened, "a page won't open under another day's id");

const d = await c.stretch(v.pin, c.unb64(v.salt), 600000);
check(c.b64(d.verifier) === v.verifier, "PIN verifier matches Swift");
check(eq(await c.unlock(c.unb64(v.blob), d, "kiko"), raw), "PIN unlocks Swift's locked key");
let wrongOpened = true;
try { await c.unlock(c.unb64(v.blob), await c.stretch("000000", c.unb64(v.salt), 600000), "kiko"); } catch { wrongOpened = false; }
check(!wrongOpened, "a wrong PIN doesn't");

const priv = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "X25519", d: v.browserPrivate, x: v.browserPublic }, { name: "X25519" }, false, ["deriveBits"]);
const pubRaw = c.unb64url(v.browserPublic);
const payload = JSON.parse(new TextDecoder().decode(await c.openFromPhone(priv, pubRaw, c.unb64(v.pairBox))));
check(payload.handle === "kiko" && eq(c.unb64(payload.key), raw), "opens the phone's pairing box: same username and key");
check(await c.linkCode(pubRaw) === v.linkCode, "link code matches the phone's");

// The other way: the web seals a page for Swift to open.
const entry = JSON.parse(v.entryJSON);
entry.text = "Written in a browser.";
entry.photos[0].caption = "from the web";
entry.version = 4;
const sealed = await c.sealEntry(jk, v.entryID, c.utf8(JSON.stringify(entry)));
writeFileSync(new URL("./fromweb.json", import.meta.url), JSON.stringify({ entryID: v.entryID, sealedEntry: c.b64(sealed), text: entry.text }));
check(true, "sealed a page for the Swift to open (fromweb.json)");

console.log(failed ? `\n${failed} FAILED` : "\nALL PASSED");
process.exit(failed ? 1 : 0);
