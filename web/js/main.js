// Tekkoh on the web: the same pages as the app, linked from the phone.
import { Journal, linkStart, linkFinish, browserLabel, dayKey, dayDate, addDays, today, hasContent, fromSwift } from "./journal.js";
import { ApiError, Offline } from "./api.js";

const $ = (sel, root = document) => root.querySelector(sel);
const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) n.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat()) if (k != null && k !== false) n.append(k.nodeType ? k : document.createTextNode(k));
  return n;
};

const KANJI = ["日", "月", "火", "水", "木", "金", "土"];
const app = $("#app");
let journal = null;
let day = today();

// ---- the ensō: a brush circle left open ----

function enso(size = 120) {
  const cv = el("canvas", { width: size * 2, height: size * 2, class: "enso", "aria-hidden": "true" });
  cv.style.width = cv.style.height = `${size}px`;
  const ctx = cv.getContext("2d");
  const color = getComputedStyle(document.documentElement).getPropertyValue("--vermillion").trim() || "#c8432b";
  const c = size, r = size * 0.8;
  ctx.lineCap = "round";
  for (let i = 0; i < 140; i++) {
    const t0 = i / 140, t1 = (i + 1) / 140;
    const a0 = ((-70 + 330 * t0) * Math.PI) / 180, a1 = ((-70 + 330 * t1) * Math.PI) / 180;
    let w = r * (0.2 - 0.17 * t0);
    if (t0 < 0.05) w *= 0.4 + 0.6 * (t0 / 0.05);
    ctx.strokeStyle = color;
    ctx.globalAlpha = 0.88 - 0.25 * t0;
    ctx.lineWidth = Math.max(w, 2);
    ctx.beginPath();
    ctx.arc(c, c, r + Math.sin(t0 * 9) * r * 0.012, a0, a1);
    ctx.stroke();
  }
  return cv;
}

// ---- start ----

async function start() {
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});
  journal = await Journal.open();
  if (!journal) return showLink();
  wire(journal);
  render();
  // Has the phone signed this browser out?
  try { await journal.api.me(); } catch (e) { if (e instanceof ApiError && e.status === 401) return revoked(); }
  journal.sync();
}

function wire(j) {
  j.addEventListener("change", () => renderChrome());
  j.addEventListener("revoked", revoked);
  addEventListener("focus", () => j.sync());
}

async function revoked() {
  await journal?.signOut();
  journal = null;
  showLink("This browser was signed out from your phone, so its copy of the journal has been removed.");
}

// ---- linking ----

function showLink(note) {
  app.replaceChildren(
    el("main", { class: "link" },
      enso(130),
      el("h1", {}, "Tekkoh"),
      el("p", { class: "kanji" }, "日記"),
      el("p", { class: "lede" }, "Read and write your journal here. It's linked from your phone, and stays encrypted with a key only you hold."),
      note ? el("p", { class: "note" }, note) : null,
      linkForm(),
    ),
  );
  $("#handle")?.focus();
}

function linkForm() {
  const err = el("p", { class: "error", role: "alert" });
  const form = el("form", { class: "link-form", onsubmit: async (ev) => {
    ev.preventDefault();
    const handle = $("#handle").value.trim().toLowerCase(), pin = $("#pin").value.trim();
    if (!/^[a-z0-9][a-z0-9_.-]{2,29}$/.test(handle)) return (err.textContent = "That isn't a username.");
    if (!/^\d{6}$/.test(pin)) return (err.textContent = "Your PIN is six digits.");
    err.textContent = "";
    form.querySelector("button").disabled = true;
    form.querySelector("button").textContent = "Checking…";
    try {
      showQR(await linkStart(handle, pin));
    } catch (e) {
      form.querySelector("button").disabled = false;
      form.querySelector("button").textContent = "Next";
      if (e instanceof ApiError && e.status === 403) err.textContent = `Wrong PIN. ${e.body.attemptsLeft} ${e.body.attemptsLeft === 1 ? "try" : "tries"} left.`;
      else if (e instanceof ApiError && e.status === 429) err.textContent = "Too many wrong PINs. Wait a while, then try again.";
      else if (e instanceof ApiError && e.status === 410) err.textContent = "Too many wrong PINs: this journal now opens only on a device that still has its key.";
      else if (e instanceof Offline) err.textContent = "Can't reach Tekkoh. Check your connection.";
      else err.textContent = e.message || "Something went wrong.";
    }
  } },
    el("label", { for: "handle" }, "Username"),
    el("input", { id: "handle", autocomplete: "username", autocapitalize: "none", spellcheck: "false", required: true }),
    el("label", { for: "pin" }, "PIN"),
    el("input", { id: "pin", type: "password", inputmode: "numeric", autocomplete: "current-password", maxlength: 6, pattern: "\\d{6}", required: true }),
    err,
    el("button", { type: "submit", class: "primary" }, "Next"),
  );
  return form;
}

function showQR(link) {
  const qr = qrcode(0, "M");
  qr.addData(link.qr);
  qr.make();
  const ctl = new AbortController();
  const status = el("p", { class: "waiting" }, "Waiting for your phone…");
  app.replaceChildren(
    el("main", { class: "link" },
      el("h2", {}, "Scan with your phone"),
      el("p", { class: "lede" }, "In Tekkoh on your phone, open Settings, then Link a browser, and point it at this code."),
      el("img", { class: "qr", src: qr.createDataURL(6, 2), alt: "Linking code" }),
      el("p", { class: "code" }, "Your phone will show ", el("b", {}, link.code.replace(/(\d{3})(\d{3})/, "$1 $2"))),
      status,
      el("button", { class: "quiet", onclick: () => { ctl.abort(); showLink(); } }, "Cancel"),
    ),
  );
  linkFinish(link, browserLabel(), ctl.signal).then((j) => {
    journal = j;
    wire(j);
    day = today();
    render();
    j.sync();
  }).catch((e) => {
    if (e.message === "cancelled") return;
    if (e.message === "mismatch") return showLink("That phone's journal doesn't match this username and PIN, so nothing was linked.");
    if (e instanceof ApiError && e.status === 404) return showLink("The code expired. Start again.");
    showLink(e.message || "Linking didn't finish.");
  });
}

// ---- the journal ----

function render() {
  app.replaceChildren(el("header", { class: "bar" }), el("div", { class: "spread" }));
  renderChrome();
  renderPage();
}

function renderChrome() {
  const bar = $(".bar");
  if (!bar || !journal) return;
  const status = journal.syncing ? "Saving…" : journal.pending ? (journal.online ? "Saving" : "Offline · saved here") : journal.error ? "Not synced" : "Saved";
  bar.replaceChildren(
    el("nav", {},
      el("button", { class: "icon", title: "Previous day (←)", "aria-label": "Previous day", onclick: () => go(-1) }, "‹"),
      el("button", { class: "icon", title: "Next day (→)", "aria-label": "Next day", disabled: day >= today(), onclick: () => go(1) }, "›"),
      day !== today() ? el("button", { class: "icon", title: "Today", "aria-label": "Go to today", onclick: () => { day = today(); renderPage(); renderChrome(); } }, "⇥") : null,
    ),
    el("span", { class: "sync" }, status),
    el("nav", {},
      el("button", { class: "icon", title: "Index", "aria-label": "Index", onclick: showIndex }, "▦"),
      el("button", { class: "icon", title: "Settings", "aria-label": "Settings", onclick: showSettings }, "⚙"),
    ),
  );
  // Another device's words may have arrived for the open page.
  const ta = $("textarea");
  if (ta && document.activeElement !== ta) {
    const t = journal.entry(day).text;
    if (ta.value !== t) ta.value = t;
  }
  const stamp = $(".stamp-slot");
  if (stamp) stamp.replaceChildren(stampFor(day));
}

function go(n) {
  const next = addDays(day, n);
  if (next > today()) return;
  day = next;
  renderPage();
  renderChrome();
}

addEventListener("keydown", (e) => {
  if (!journal || e.target.closest?.("textarea, input")) return;
  if (e.key === "ArrowLeft") go(-1);
  if (e.key === "ArrowRight") go(1);
});

function stampFor(d) {
  const written = hasContent(journal.entries.get(d));
  if (d !== today() && !written) return "";
  const n = d === today() ? journal.streak() : journal.runEndingAt(d);
  return el("div", { class: `stamp${written ? "" : " unlit"}`, role: "img", "aria-label": `${n}-day streak` }, el("b", {}, String(n)), el("small", {}, "連続"));
}

function renderPage() {
  const spread = $(".spread");
  if (!spread) return;
  const e = journal.entry(day);
  const date = dayDate(day);
  const wd = date.getDay();
  const dayOfYear = Math.round((date - new Date(date.getFullYear(), 0, 1)) / 864e5) + 1;
  const daysInYear = new Date(date.getFullYear(), 1, 29).getDate() === 29 ? 366 : 365;

  const header = el("div", { class: `date wd${wd}` },
    el("span", { class: "num" }, String(date.getDate())),
    el("div", { class: "meta" },
      el("span", { class: "label" }, date.toLocaleDateString(undefined, { month: "long", year: "numeric" }).toUpperCase()),
      el("span", {}, el("span", { class: "kanji" }, KANJI[wd]), " ", el("span", { class: "label muted" }, date.toLocaleDateString(undefined, { weekday: "long" }).toUpperCase())),
      el("span", { class: "label faint" }, `${dayOfYear} / ${daysInYear}`),
    ),
    el("div", { class: "stamp-slot" }, stampFor(day)),
  );

  const margin = el("div", { class: "margin" }, ...marginNotes(e));
  const photos = photoShelf(e);
  const writing = el("div", { class: "writing" }, writingArea(e));
  spread.replaceChildren(
    el("section", { class: "page left" }, header, margin, photos),
    el("section", { class: "page right" }, writing),
  );
}

function marginNotes(e) {
  const out = [];
  for (const p of e.places.slice(0, 8)) {
    out.push(el("p", { class: "place" }, el("i", { class: "pin" }), el("span", {}, p.name), p.detail ? el("span", { class: "muted" }, ` ${p.detail}`) : null,
      p.arrived ? el("span", { class: "label faint time" }, new Date(fromSwift(p.arrived)).toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" })) : null));
  }
  const bits = [];
  const t = (s) => new Date(fromSwift(s)).toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
  if (e.sun?.rise && e.sun?.set) bits.push(`☼ ${t(e.sun.rise)} – ${t(e.sun.set)}`);
  if (e.health?.steps) bits.push(`${e.health.steps.toLocaleString()} steps`);
  if (e.health?.meters > 100) {
    const mi = navigator.language === "en-US";
    bits.push(mi ? `${(e.health.meters / 1609.344).toFixed(1)} mi` : `${(e.health.meters / 1000).toFixed(1)} km`);
  }
  if (e.health?.flights) bits.push(`${e.health.flights} fl`);
  if (bits.length) out.push(el("p", { class: "label muted stats" }, bits.join("   ")));
  for (const w of (e.health?.workouts || []).slice(0, 3)) out.push(el("p", { class: "label workout" }, `${w.kind} ${Math.round(w.minutes)} min`));
  if (!out.length && day === today()) out.push(el("p", { class: "label faint" }, "Places and activity come from your phone."));
  return out;
}

function writingArea(e) {
  const ta = el("textarea", { "aria-label": "This day's writing", placeholder: day === today() ? "Today…" : "This day…", spellcheck: "true" });
  ta.value = e.text;
  const thisDay = day;
  let timer;
  const save = () => journal.update(thisDay, (x) => { x.text = ta.value; });
  ta.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(save, 700); });
  ta.addEventListener("blur", () => { clearTimeout(timer); if (ta.value !== journal.entry(thisDay).text) save(); });
  return ta;
}

function photoShelf(e) {
  const thisDay = day;
  const input = el("input", { type: "file", accept: "image/*", multiple: true, hidden: true, onchange: async () => {
    for (const f of input.files) { try { await journal.addPhoto(f, thisDay); } catch {} }
    input.value = "";
    if (day === thisDay) renderPage();
  } });
  const cards = e.photos.map((p, i) => {
    const img = el("img", { alt: p.caption || "Photo" });
    journal.image(p).then((u) => (img.src = u)).catch(() => {});
    const cap = el("input", { class: "caption", value: p.caption, placeholder: "add a caption", "aria-label": "Caption" });
    cap.addEventListener("change", () => journal.caption(p, thisDay, cap.value));
    return el("figure", { class: `print t${i % 5}` },
      img,
      cap,
      el("button", { class: "remove", "aria-label": "Remove photo", title: "Remove", onclick: async () => { await journal.removePhoto(p, thisDay); renderPage(); } }, "×"),
    );
  });
  return el("div", { class: "shelf" }, ...cards,
    el("button", { class: "add", onclick: () => input.click() }, el("span", {}, "+"), el("small", { class: "label" }, "PHOTO")), input);
}

// ---- index: a month, or the year ----

function showIndex() {
  let zoom = "month", month = day.slice(0, 7);
  const dlg = el("dialog", { class: "sheet" });
  const draw = () => {
    const written = journal.writtenDays;
    const thisMonth = today().slice(0, 7);
    const year = month.slice(0, 4);
    const step = (n) => {
      if (zoom === "month") { const d = dayDate(month + "-01"); d.setMonth(d.getMonth() + n); month = dayKey(d).slice(0, 7); }
      else month = `${+year + n}-${month.slice(5)}`;
      if (month > thisMonth) month = thisMonth;
      draw();
    };
    const pick = (d) => { day = d; dlg.close(); renderPage(); renderChrome(); };
    const body = zoom === "month" ? monthGrid(month, written, pick, true) : el("div", { class: "year" },
      ...Array.from({ length: 12 }, (_, i) => {
        const m = `${year}-${String(i + 1).padStart(2, "0")}`;
        return el("button", { class: "mini", disabled: m > thisMonth, onclick: () => { month = m; zoom = "month"; draw(); } }, miniMonth(m, written));
      }));
    const pages = [...written].filter((d) => d.startsWith(zoom === "month" ? month : year)).length;
    dlg.replaceChildren(
      el("div", { class: "sheet-head" },
        el("div", { class: "seg" },
          el("button", { class: zoom === "month" ? "on" : "", onclick: () => { zoom = "month"; draw(); } }, "Month"),
          el("button", { class: zoom === "year" ? "on" : "", onclick: () => { zoom = "year"; draw(); } }, "Year")),
        el("button", { class: "quiet", onclick: () => dlg.close() }, "Done")),
      el("div", { class: "summary" },
        stampBig(),
        el("div", {},
          el("p", {}, hasContent(journal.entries.get(today())) ? "Today's page is written." : journal.streak() ? "Write today to keep it going." : "Begin a streak today."),
          el("p", { class: "stats" }, el("span", {}, el("b", {}, String(written.size)), el("small", { class: "label" }, "PAGES")), el("span", {}, el("b", {}, String(journal.longest)), el("small", { class: "label" }, "LONGEST"))))),
      el("div", { class: "pager" },
        el("button", { class: "icon", "aria-label": "Previous", onclick: () => step(-1) }, "‹"),
        el("div", {}, el("div", { class: zoom === "month" ? "label big" : "year-num" }, zoom === "month" ? dayDate(month + "-01").toLocaleDateString(undefined, { month: "long" }).toUpperCase() : year),
          el("div", { class: "label vermillion" }, pages ? `${pages} ${pages === 1 ? "page" : "pages"}` : zoom === "month" ? year : "")),
        el("button", { class: "icon", "aria-label": "Next", disabled: zoom === "month" ? month >= thisMonth : year >= thisMonth.slice(0, 4), onclick: () => step(1) }, "›")),
      body,
    );
  };
  draw();
  document.body.append(dlg);
  dlg.addEventListener("close", () => dlg.remove());
  dlg.showModal();
}

function stampBig() {
  const n = journal.streak();
  return el("div", { class: `stamp big${n ? "" : " unlit"}` }, el("b", {}, String(n)), el("small", {}, "連続"));
}

function monthGrid(month, written, pick) {
  const first = dayDate(month + "-01");
  const count = new Date(first.getFullYear(), first.getMonth() + 1, 0).getDate();
  const cells = [...KANJI.map((k, i) => el("span", { class: `wh wd${i}` }, k))];
  for (let i = 0; i < first.getDay(); i++) cells.push(el("span"));
  for (let d = 1; d <= count; d++) {
    const k = `${month}-${String(d).padStart(2, "0")}`;
    cells.push(el("button", { class: `cell wd${dayDate(k).getDay()}${written.has(k) ? " written" : ""}${k === today() ? " today" : ""}${k === day ? " sel" : ""}`, disabled: k > today(), onclick: () => pick(k) },
      el("span", {}, String(d)), el("i")));
  }
  return el("div", { class: "month" }, ...cells);
}

function miniMonth(month, written) {
  const first = dayDate(month + "-01");
  const count = new Date(first.getFullYear(), first.getMonth() + 1, 0).getDate();
  const cells = [];
  for (let i = 0; i < first.getDay(); i++) cells.push(el("span"));
  let n = 0;
  for (let d = 1; d <= count; d++) {
    const k = `${month}-${String(d).padStart(2, "0")}`;
    if (written.has(k)) n++;
    cells.push(el("span", { class: `${written.has(k) ? "w" : ""}${k === today() ? " t" : ""}` }, String(d)));
  }
  return [el("div", { class: "mini-head" }, el("span", { class: "label" }, first.toLocaleDateString(undefined, { month: "short" }).toUpperCase()), n ? el("span", { class: "label vermillion" }, String(n)) : ""),
    el("div", { class: "mini-grid" }, ...cells)];
}

// ---- settings ----

function showSettings() {
  const dlg = el("dialog", { class: "sheet small" },
    el("div", { class: "sheet-head" }, el("h2", {}, "This browser"), el("button", { class: "quiet", onclick: () => dlg.close() }, "Done")),
    el("dl", {},
      el("dt", {}, "Journal"), el("dd", {}, journal.handle),
      el("dt", {}, "Linked as"), el("dd", {}, journal.label || "A browser"),
      el("dt", {}, "Pages"), el("dd", {}, String(journal.writtenDays.size)),
      el("dt", {}, "Sync"), el("dd", {}, journal.error || (journal.lastSynced ? `Up to date · ${journal.lastSynced.toLocaleTimeString()}` : journal.online ? "Up to date" : "Offline"))),
    el("p", { class: "fine" }, "Everything is encrypted in this browser before it's sent. Your phone can sign this browser out (Settings, Linked browsers); it can't change your PIN or delete the journal from here."),
    el("button", { class: "danger", onclick: async () => {
      if (journal.pending && !confirm(`${journal.pending} changes haven't reached the server yet and will be lost. Sign out anyway?`)) return;
      dlg.close();
      await journal.signOut();
      journal = null;
      showLink("Signed out. This browser's copy of the journal has been removed.");
    } }, "Sign out of this browser"),
  );
  document.body.append(dlg);
  dlg.addEventListener("close", () => dlg.remove());
  dlg.showModal();
}

start();
