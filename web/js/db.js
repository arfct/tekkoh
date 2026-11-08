// The journal in the browser's IndexedDB, for reading and writing offline.
// Pages and photos are stored as the same sealed bytes the server holds;
// the keys are non-extractable CryptoKeys (structured-cloned, never bytes).

const NAME = "tekkoh";
let dbp = null;

function db() {
  dbp ??= new Promise((resolve, reject) => {
    const r = indexedDB.open(NAME, 1);
    r.onupgradeneeded = () => {
      const d = r.result;
      d.createObjectStore("kv");
      d.createObjectStore("entries", { keyPath: "id" });
      d.createObjectStore("photos");
    };
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
  return dbp;
}

function run(store, mode, fn) {
  return db().then((d) => new Promise((resolve, reject) => {
    const tx = d.transaction(store, mode);
    const out = fn(tx.objectStore(store));
    tx.oncomplete = () => resolve(out && "result" in out ? out.result : undefined);
    tx.onerror = () => reject(tx.error);
  }));
}

export const get = (store, key) => run(store, "readonly", (s) => s.get(key));
export const put = (store, value, key) => run(store, "readwrite", (s) => (key === undefined ? s.put(value) : s.put(value, key)));
export const del = (store, key) => run(store, "readwrite", (s) => s.delete(key));
export const all = (store) => run(store, "readonly", (s) => s.getAll());

// Signing out: everything goes.
export async function wipe() {
  const d = await db();
  d.close();
  dbp = null;
  await new Promise((resolve) => {
    const r = indexedDB.deleteDatabase(NAME);
    r.onsuccess = r.onerror = r.onblocked = () => resolve();
  });
}
