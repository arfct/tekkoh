// The web app's account, linking and sync code against the live server,
// playing the phone's part too, with a throwaway account it deletes.
// Run: node web/tests/live.mjs (Node 22+).
import * as c from "../js/crypto.js";
import { API, ApiError } from "../js/api.js";
import { linkStart, merge, DIVIDER } from "../js/journal.js";

let failed = 0;
const check = (ok, what) => { console.log(ok ? "ok   " : "FAIL ", what); if (!ok) failed++; };
const SERVER_KEY = c.unb64((await (await fetch("https://tekkoh.cronbon.com/v1/transport-key")).json()).key);

// The phone: a journal key and an account, its recovery boxed to the server.
async function makeAccount(handle, pin) {
  const K = c.random(32);
  const salt = c.random(16);
  const d = await c.stretch(pin, salt, 600000);
  const blob = await c.seal(d.wrap, K, `tekkoh/recovery/${handle}`);
  const rec = await c.sealTo(SERVER_KEY, "create", c.utf8(JSON.stringify({ salt: c.b64(salt), iterations: 600000, verifier: c.b64(d.verifier), blob: c.b64(blob) })));
  const keys = await c.importJournalKey(K);
  const token = await c.authToken(keys);
  await new API().req("POST", "/v1/accounts", { json: { handle, auth: c.b64(token), recovery: { eph: c.b64(rec.eph), box: c.b64(rec.box) } } });
  return { K, keys, owner: new API(handle, token) };
}

// What the phone does when it scans the code: seal {handle, key} to the browser.
async function phoneLinks(owner, handle, K, qr) {
  const [, , slot, pub] = qr.split(":");
  const s = await c.sealTo(c.unb64url(pub), "pair", c.utf8(JSON.stringify({ handle, key: c.b64(K) })));
  await owner.req("PUT", `/v1/pair/${slot}`, { json: { box: c.b64(c.concat(s.eph, s.box)) } });
  return slot;
}

const handle = "webtest" + c.b64url(c.random(4)).toLowerCase().replace(/[^a-z0-9]/g, "a");
const pin = "374912";
const phone = await makeAccount(handle, pin);
check(true, `made ${handle} as the phone would`);

try {
  // Wrong PIN first: refused, and nothing to show the phone.
  try { await linkStart(handle, "508263"); check(false, "wrong PIN refused"); }
  catch (e) { check(e instanceof ApiError && e.status === 403 && e.body.attemptsLeft === 9, "wrong PIN refused, 9 tries left"); }

  // Right PIN: a code to scan.
  const link = await linkStart(handle, pin);
  check(c.same(link.fromPIN, phone.K) && link.qr.startsWith("tekkoh-link:1:") && /^\d{6}$/.test(link.code), "the PIN opens the key; the page shows a code");
  const waiting = await link.api.takeSlot(link.slot);
  check(waiting.status === 202, "the slot waits for the phone");
  await phoneLinks(phone.owner, handle, phone.K, link.qr);
  const got = await link.api.takeSlot(link.slot);
  const payload = JSON.parse(new TextDecoder().decode(await c.openFromPhone(link.kp.privateKey, link.kp.publicRaw, c.unb64(got.box))));
  check(got.handle === handle && payload.handle === handle && c.same(c.unb64(payload.key), link.fromPIN), "the phone's key and username match the PIN's");
  try { await link.api.takeSlot(link.slot); check(false, "slot used once"); } catch (e) { check(e.status === 404, "the slot can't be collected twice"); }

  // A phone from another journal: the keys don't agree.
  const other = await makeAccount(handle + "x", pin);
  const link2 = await linkStart(handle, pin);
  await phoneLinks(other.owner, handle + "x", other.K, link2.qr);
  const got2 = await link2.api.takeSlot(link2.slot);
  const p2 = JSON.parse(new TextDecoder().decode(await c.openFromPhone(link2.kp.privateKey, link2.kp.publicRaw, c.unb64(got2.box))));
  check(!(p2.handle === handle && got2.handle === handle && c.same(c.unb64(p2.key), link2.fromPIN)), "another journal's phone doesn't match");
  await other.owner.req("DELETE", "/v1/me");

  // A browser session: reads and writes, can't rule the journal.
  const s = await phone.owner.createSession("Node on a test");
  const browser = new API(handle, c.unb64(s.token));
  const id = await c.entryID(phone.keys, "2026-11-08");
  const page = { created: 0, day: "2026-11-08", photos: [], places: [], removedPhotos: [], text: "From the web test.", updated: 0, version: 1 };
  const put = await browser.putEntry(id, await c.sealEntry(phone.keys, id, c.utf8(JSON.stringify(page))), 0);
  check(put.rev === 1, "a browser session writes a page");
  const ch = await phone.owner.changes(0);
  const back = JSON.parse(new TextDecoder().decode(await c.openEntry(phone.keys, ch.entries[0].id, c.unb64(ch.entries[0].data))));
  check(back.text === page.text, "the phone reads it back");
  try { await browser.req("DELETE", "/v1/me"); check(false, "session can't delete"); } catch (e) { check(e.status === 403, "a browser session can't delete the journal"); }
  await browser.signOut();
  try { await browser.me(); check(false, "signed out"); } catch (e) { check(e.status === 401, "a browser can sign itself out"); }

  // Merging, as the app does it.
  const base = { ...page, text: "Morning walk." };
  check(merge({ ...base, text: "Morning walk. Tea." }, { ...base }, base).text === "Morning walk. Tea.", "one side changed: theirs stands");
  check(merge({ ...base, text: "From the phone." }, { ...base, text: "From the web." }, base).text === "From the phone." + DIVIDER + "From the web.", "both changed: concatenated");
} finally {
  await phone.owner.req("DELETE", "/v1/me");
  check(true, "deleted the test account");
}
console.log(failed ? `\n${failed} FAILED` : "\nALL PASSED");
process.exit(failed ? 1 : 0);
