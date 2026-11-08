package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// box does what the phone does: encrypt a recovery field to the server's
// transport key. It returns the box and the key a reply is sealed with.
func box(t *testing.T, s *Server, purpose string, v any) (map[string]any, []byte) {
	t.Helper()
	eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	srv, _ := ecdh.X25519().NewPublicKey(s.TransportPublic())
	shared, _ := eph.ECDH(srv)
	salt := append(eph.PublicKey().Bytes(), srv.Bytes()...)
	k, _ := hkdf.Key(sha256.New, shared, salt, "tekkoh/transport/v1/"+purpose, 32)
	plain, _ := json.Marshal(v)
	g := gcmFor(k)
	nonce := random(g.NonceSize())
	return map[string]any{"eph": enc(eph.PublicKey().Bytes()), "box": enc(g.Seal(nonce, nonce, plain, []byte(purpose)))}, k
}

func openReply(t *testing.T, k []byte, purpose string, reply string) map[string]any {
	t.Helper()
	b, _ := base64.StdEncoding.DecodeString(reply)
	g := gcmFor(k)
	plain, err := g.Open(nil, b[:g.NonceSize()], b[g.NonceSize():], []byte(purpose+"/reply"))
	if err != nil {
		t.Fatalf("reply doesn't open: %v", err)
	}
	var out map[string]any
	json.Unmarshal(plain, &out)
	return out
}

func init() { backoff = func(int) time.Duration { return 0 } }

type client struct {
	t   *testing.T
	srv *httptest.Server
	ip  int
}

var current *Server

// testStore is memory, or Postgres when TEKKOH_TEST_DATABASE_URL names a
// scratch database (its tables are emptied first).
func testStore(t *testing.T) Store {
	url := os.Getenv("TEKKOH_TEST_DATABASE_URL")
	if url == "" {
		return newMemStore()
	}
	pg, err := openPG(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pg.db.Exec(`truncate accounts cascade`); err != nil {
		t.Fatal(err)
	}
	return pg
}

func newClient(t *testing.T) (*client, Store, *Server) {
	store := testStore(t)
	secret := make([]byte, 32)
	rand.Read(secret)
	s := NewServer(store, secret)
	current = s
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)
	return &client{t: t, srv: srv}, store, s
}

func (c *client) do(method, path string, body any, auth string) (int, map[string]any) {
	c.t.Helper()
	var r *bytes.Reader
	if b, ok := body.([]byte); ok {
		r = bytes.NewReader(b)
	} else {
		j, _ := json.Marshal(body)
		r = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, c.srv.URL+path, r)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	c.ip++
	req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.0.0.%d", c.ip%250))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func random(n int) []byte { b := make([]byte, n); rand.Read(b); return b }
func enc(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

type account struct {
	handle          string
	token, verifier []byte
	blob, salt      []byte
	header          string
}

func signUp(t *testing.T, c *client, handle string) account {
	t.Helper()
	a := account{handle: handle, token: random(32), verifier: random(32), blob: random(60), salt: random(16)}
	a.header = "Tekkoh " + handle + " " + enc(a.token)
	rec, _ := box(t, current, "create", map[string]any{"salt": enc(a.salt), "iterations": 600000, "verifier": enc(a.verifier), "blob": enc(a.blob)})
	code, out := c.do("POST", "/v1/accounts", map[string]any{"handle": handle, "auth": enc(a.token), "recovery": rec}, "")
	if code != 201 {
		t.Fatalf("sign up: %d %v", code, out)
	}
	return a
}

// guess sends a PIN verifier the way the phone does, and opens the reply.
func guess(t *testing.T, c *client, handle string, verifier []byte) (int, map[string]any) {
	t.Helper()
	proof, k := box(t, current, "recover", map[string]any{"verifier": enc(verifier)})
	code, out := c.do("POST", "/v1/recovery", map[string]any{"handle": handle, "proof": proof}, "")
	if code == 200 {
		return code, openReply(t, k, "recover", out["reply"].(string))
	}
	return code, out
}

func newPIN(t *testing.T, c *client, header string, verifier []byte) int {
	t.Helper()
	rec, _ := box(t, current, "set-recovery", map[string]any{"salt": enc(random(16)), "iterations": 600000, "verifier": enc(verifier), "blob": enc(random(60))})
	code, _ := c.do("PUT", "/v1/recovery", rec, header)
	return code
}

func TestRecoveryReleasesTheKeyOnlyForTheRightPIN(t *testing.T) {
	c, store, _ := newClient(t)
	a := signUp(t, c, "kiko")

	code, out := c.do("POST", "/v1/recovery/params", map[string]any{"handle": "kiko"}, "")
	if code != 200 || out["salt"] != enc(a.salt) || out["attemptsLeft"].(float64) != MaxAttempts {
		t.Fatalf("params: %d %v", code, out)
	}
	code, out = guess(t, c, "kiko", random(32))
	if code != 403 || out["attemptsLeft"].(float64) != MaxAttempts-1 {
		t.Fatalf("wrong PIN: %d %v", code, out)
	}
	code, out = guess(t, c, "KIKO", a.verifier)
	if code != 200 || out["blob"] != enc(a.blob) {
		t.Fatalf("right PIN: %d %v", code, out)
	}
	if acc, _ := store.Account(context.Background(), "kiko"); acc.Attempts != 0 {
		t.Fatalf("attempts not reset: %d", acc.Attempts)
	}
	acc, _ := store.Account(context.Background(), "kiko")
	if bytes.Contains(acc.Sealed, a.blob) || bytes.Equal(acc.VerifierMAC, a.verifier) {
		t.Fatal("stored the blob or verifier in the clear")
	}
}

// What travels can't be used to test PINs: the verifier and the locked key
// are only ever inside boxes to the server's key, and the reply is boxed.
func TestRecoveryMaterialNeverTravelsInTheClear(t *testing.T) {
	c, _, s := newClient(t)
	a := account{handle: "aki", token: random(32), verifier: random(32), blob: random(60), salt: random(16)}
	rec, _ := box(t, s, "create", map[string]any{"salt": enc(a.salt), "iterations": 600000, "verifier": enc(a.verifier), "blob": enc(a.blob)})
	body, _ := json.Marshal(map[string]any{"handle": "aki", "auth": enc(a.token), "recovery": rec})
	for _, secret := range [][]byte{a.verifier, a.blob} {
		if bytes.Contains(body, []byte(enc(secret))) || bytes.Contains(body, secret) {
			t.Fatal("sign-up body carries recovery material in the clear")
		}
	}
	if code, _ := c.do("POST", "/v1/accounts", json.RawMessage(body), ""); code != 201 {
		t.Fatalf("sign up: %d", code)
	}
	proof, _ := box(t, s, "recover", map[string]any{"verifier": enc(a.verifier)})
	code, out := c.do("POST", "/v1/recovery", map[string]any{"handle": "aki", "proof": proof}, "")
	raw, _ := json.Marshal(out)
	if code != 200 || bytes.Contains(raw, []byte(enc(a.blob))) {
		t.Fatalf("reply carries the locked key in the clear: %d %s", code, raw)
	}
	// Plain fields are refused, and a box for one purpose won't open as another.
	if code, _ := c.do("POST", "/v1/recovery", map[string]any{"handle": "aki", "verifier": enc(a.verifier)}, ""); code != 400 {
		t.Fatalf("plain verifier accepted: %d", code)
	}
	wrong, _ := box(t, s, "create", map[string]any{"verifier": enc(a.verifier)})
	if code, _ := c.do("POST", "/v1/recovery", map[string]any{"handle": "aki", "proof": wrong}, ""); code != 400 {
		t.Fatalf("box for another purpose opened: %d", code)
	}
	// Tampering is caught.
	proof, _ = box(t, s, "recover", map[string]any{"verifier": enc(a.verifier)})
	bx, _ := base64.StdEncoding.DecodeString(proof["box"].(string))
	bx[len(bx)-1] ^= 1
	proof["box"] = enc(bx)
	if code, _ := c.do("POST", "/v1/recovery", map[string]any{"handle": "aki", "proof": proof}, ""); code != 400 {
		t.Fatalf("tampered box opened: %d", code)
	}
}

func TestTooManyWrongPINsWipeTheKey(t *testing.T) {
	c, _, _ := newClient(t)
	a := signUp(t, c, "sora")
	for i := 1; i < MaxAttempts; i++ {
		if code, _ := guess(t, c, "sora", random(32)); code != 403 {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	if code, _ := guess(t, c, "sora", random(32)); code != 410 {
		t.Fatalf("last attempt should wipe: %d", code)
	}
	if code, _ := guess(t, c, "sora", a.verifier); code != 410 {
		t.Fatalf("after wipe: %d", code)
	}
	if code, out := c.do("GET", "/v1/me", nil, a.header); code != 200 || out["recovery"] != false {
		t.Fatalf("me: %d %v", code, out)
	}
	nv := random(32)
	if code := newPIN(t, c, a.header, nv); code != 200 {
		t.Fatalf("new PIN: %d", code)
	}
	if code, _ := guess(t, c, "sora", nv); code != 200 {
		t.Fatalf("new PIN works: %d", code)
	}
}

// After three wrong PINs each try must wait longer: 1, 2, 4… minutes.
func TestWrongPINsBackOff(t *testing.T) {
	defer func(f func(int) time.Duration) { backoff = f }(backoff)
	backoff = func(n int) time.Duration {
		if n < 3 {
			return 0
		}
		return time.Minute << (n - 3)
	}
	c, store, _ := newClient(t)
	signUp(t, c, "uta")
	for i := 0; i < 3; i++ {
		guess(t, c, "uta", random(32))
	}
	code, out := guess(t, c, "uta", random(32))
	if code != 429 || out["retryAfter"].(float64) < 50 {
		t.Fatalf("fourth try straight away: %d %v", code, out)
	}
	if acc, _ := store.Account(context.Background(), "uta"); acc.Attempts != 3 {
		t.Fatalf("a refused try counted: %d", acc.Attempts)
	}
}

// A username that doesn't exist answers like one that does.
func TestUnknownUsernamesLookReal(t *testing.T) {
	c, _, _ := newClient(t)
	signUp(t, c, "real")
	_, realP := c.do("POST", "/v1/recovery/params", map[string]any{"handle": "real"}, "")
	code, ghost := c.do("POST", "/v1/recovery/params", map[string]any{"handle": "ghost"}, "")
	if code != 200 || ghost["iterations"] != realP["iterations"] || ghost["attemptsLeft"] != realP["attemptsLeft"] || len(ghost["salt"].(string)) != len(realP["salt"].(string)) {
		t.Fatalf("params differ: %v vs %v", ghost, realP)
	}
	if _, again := c.do("POST", "/v1/recovery/params", map[string]any{"handle": "ghost"}, ""); again["salt"] != ghost["salt"] {
		t.Fatal("ghost salt not stable")
	}
	rc, rOut := guess(t, c, "real", random(32))
	gc, gOut := guess(t, c, "ghost", random(32))
	if rc != gc || rOut["attemptsLeft"] != gOut["attemptsLeft"] {
		t.Fatalf("wrong PIN answers differ: %d %v vs %d %v", rc, rOut, gc, gOut)
	}
}

// A copy of the database is useless without the server secret.
func TestADatabaseAloneCantTestPINs(t *testing.T) {
	c, store, _ := newClient(t)
	a := signUp(t, c, "ren")
	thief := NewServer(store, random(32))
	acc, _ := store.Account(context.Background(), "ren")
	if bytes.Equal(thief.verifierMAC("ren", a.verifier), acc.VerifierMAC) {
		t.Fatal("verifier MAC doesn't depend on the secret")
	}
	if _, err := thief.unseal("ren", acc.Sealed); err == nil {
		t.Fatal("sealed key opened without the secret")
	}
}

func TestAuthAndHandles(t *testing.T) {
	c, _, s := newClient(t)
	a := signUp(t, c, "mio")
	create := func(h string, iterations int) int {
		rec, _ := box(t, s, "create", map[string]any{"salt": enc(random(16)), "iterations": iterations, "verifier": enc(random(32)), "blob": enc(random(60))})
		code, _ := c.do("POST", "/v1/accounts", map[string]any{"handle": h, "auth": enc(random(32)), "recovery": rec}, "")
		return code
	}
	if code := create("mio", 600000); code != 409 {
		t.Fatalf("duplicate: %d", code)
	}
	for _, h := range []string{"a", "has space", "UPPER!"} {
		if code := create(h, 600000); code != 400 {
			t.Fatalf("handle %q: %d", h, code)
		}
	}
	if code := create("weak", 1000); code != 400 {
		t.Fatalf("weak stretching accepted: %d", code)
	}
	if code, _ := c.do("GET", "/v1/me", nil, "Tekkoh mio "+enc(random(32))); code != 401 {
		t.Fatalf("wrong token: %d", code)
	}
	if code, _ := c.do("GET", "/v1/me", nil, a.header); code != 200 {
		t.Fatalf("right token: %d", code)
	}
}

func TestTransportKeyIsStableAndPublished(t *testing.T) {
	c, store, s := newClient(t)
	_, out := c.do("GET", "/v1/transport-key", nil, "")
	if out["key"] != enc(s.TransportPublic()) || len(s.TransportPublic()) != 32 {
		t.Fatalf("published key: %v", out)
	}
	if !bytes.Equal(NewServer(store, s.secret).TransportPublic(), s.TransportPublic()) {
		t.Fatal("transport key not derived from the secret")
	}
}

func TestEntriesSyncWithRevisions(t *testing.T) {
	c, _, _ := newClient(t)
	a := signUp(t, c, "yui")
	b := signUp(t, c, "haru")
	id := "Zx3_k9Q2abcdEFGH1234"
	code, out := c.do("PUT", "/v1/entries/"+id, map[string]any{"data": enc([]byte("ciphertext-1")), "rev": 0}, a.header)
	if code != 200 || out["rev"].(float64) != 1 {
		t.Fatalf("create: %d %v", code, out)
	}
	if code, _ := c.do("PUT", "/v1/entries/"+id, map[string]any{"data": enc([]byte("stale")), "rev": 0}, a.header); code != 409 {
		t.Fatalf("stale write: %d", code)
	}
	code, out = c.do("PUT", "/v1/entries/"+id, map[string]any{"data": enc([]byte("ciphertext-2")), "rev": 1}, a.header)
	if code != 200 || out["rev"].(float64) != 2 {
		t.Fatalf("update: %d %v", code, out)
	}
	code, out = c.do("GET", "/v1/entries?after=0", nil, a.header)
	es := out["entries"].([]any)
	if code != 200 || len(es) != 1 || es[0].(map[string]any)["data"] != enc([]byte("ciphertext-2")) {
		t.Fatalf("list: %d %v", code, out)
	}
	cursor := out["cursor"].(float64)
	if _, out := c.do("GET", fmt.Sprintf("/v1/entries?after=%d", int(cursor)), nil, a.header); len(out["entries"].([]any)) != 0 {
		t.Fatalf("nothing new after the cursor: %v", out)
	}
	// Another account sees nothing, and its numbering is its own.
	if code, out := c.do("PUT", "/v1/entries/"+id, map[string]any{"data": enc([]byte("theirs")), "rev": 0}, b.header); code != 200 || out["seq"].(float64) != 1 {
		t.Fatalf("other journal's first change: %d %v", code, out)
	}
	if _, out := c.do("GET", "/v1/entries?after=0", nil, b.header); len(out["entries"].([]any)) != 1 || out["entries"].([]any)[0].(map[string]any)["data"] != enc([]byte("theirs")) {
		t.Fatalf("leaked across accounts: %v", out)
	}
	code, out = c.do("DELETE", "/v1/entries/"+id+"?rev=2", nil, a.header)
	if code != 200 {
		t.Fatalf("delete: %d %v", code, out)
	}
	_, out = c.do("GET", fmt.Sprintf("/v1/entries?after=%d", int(cursor)), nil, a.header)
	if es := out["entries"].([]any); len(es) != 1 || es[0].(map[string]any)["deleted"] != true {
		t.Fatalf("tombstone: %v", out)
	}
}

func TestBlobs(t *testing.T) {
	c, _, _ := newClient(t)
	a := signUp(t, c, "nao")
	photo := random(5000)
	if code, _ := c.do("PUT", "/v1/blobs/photo_0123456789abcdef", photo, a.header); code != 200 {
		t.Fatalf("put: %d", code)
	}
	req, _ := http.NewRequest("GET", c.srv.URL+"/v1/blobs/photo_0123456789abcdef", nil)
	req.Header.Set("Authorization", a.header)
	res, _ := http.DefaultClient.Do(req)
	var got bytes.Buffer
	got.ReadFrom(res.Body)
	res.Body.Close()
	if !bytes.Equal(got.Bytes(), photo) {
		t.Fatal("blob didn't round-trip")
	}
	if code, _ := c.do("DELETE", "/v1/blobs/photo_0123456789abcdef", nil, a.header); code != 200 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := c.do("GET", "/v1/blobs/photo_0123456789abcdef", nil, a.header); code != 404 {
		t.Fatalf("after delete: %d", code)
	}
}

func TestClientIPIgnoresSpoofedHops(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.9")
	if got := clientIP(r); got != "203.0.113.9" {
		t.Fatalf("took the client-supplied hop: %s", got)
	}
	r.Header.Set("Cf-Connecting-Ip", "198.51.100.7")
	if got := clientIP(r); got != "198.51.100.7" {
		t.Fatalf("Cloudflare's address not preferred: %s", got)
	}
}

func TestRecoveryIsRateLimitedPerIP(t *testing.T) {
	l := newLimiter(3, 3600e9)
	for i := 0; i < 3; i++ {
		if !l.allow("x") {
			t.Fatal("blocked early")
		}
	}
	if l.allow("x") {
		t.Fatal("not limited")
	}
	if !l.allow("y") {
		t.Fatal("limited another key")
	}
}

func TestPairingHandsOverOnceThroughTheOwner(t *testing.T) {
	c, _, _ := newClient(t)
	a := signUp(t, c, "pia")
	code, out := c.do("POST", "/v1/pair", nil, "")
	if code != 201 {
		t.Fatalf("open: %d %v", code, out)
	}
	id := out["id"].(string)
	if code, out := c.do("GET", "/v1/pair/"+id, nil, ""); code != 202 || out["waiting"] != true {
		t.Fatalf("before the phone: %d %v", code, out)
	}
	box := enc(random(80))
	if code, _ := c.do("PUT", "/v1/pair/"+id, map[string]any{"box": box}, ""); code != 401 {
		t.Fatalf("filled without signing in: %d", code)
	}
	if code, _ := c.do("PUT", "/v1/pair/"+id, map[string]any{"box": box}, a.header); code != 200 {
		t.Fatalf("fill: %d", code)
	}
	if code, _ := c.do("PUT", "/v1/pair/"+id, map[string]any{"box": enc(random(80))}, a.header); code != 409 {
		t.Fatalf("refilled: %d", code)
	}
	code, out = c.do("GET", "/v1/pair/"+id, nil, "")
	if code != 200 || out["box"] != box || out["handle"] != "pia" {
		t.Fatalf("take: %d %v", code, out)
	}
	if code, _ := c.do("GET", "/v1/pair/"+id, nil, ""); code != 404 {
		t.Fatalf("taken twice: %d", code)
	}
	if code, _ := c.do("PUT", "/v1/pair/nosuchslot1234567890", map[string]any{"box": box}, a.header); code != 404 {
		t.Fatalf("unknown slot: %d", code)
	}
}

func TestBrowserSessionsCanWriteButNotRuleTheJournal(t *testing.T) {
	c, _, _ := newClient(t)
	a := signUp(t, c, "rio")
	code, out := c.do("POST", "/v1/sessions", map[string]any{"label": "Safari on a Mac"}, a.header)
	if code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	browser := "Tekkoh rio " + out["token"].(string)
	// A browser reads and writes.
	if code, _ := c.do("PUT", "/v1/entries/abcdefghijklmnop1234", map[string]any{"data": enc([]byte("x")), "rev": 0}, browser); code != 200 {
		t.Fatalf("browser write: %d", code)
	}
	if code, out := c.do("GET", "/v1/me", nil, browser); code != 200 || out["session"] == nil {
		t.Fatalf("browser me: %d %v", code, out)
	}
	// But can't change the PIN, delete the journal, link or list browsers.
	for _, req := range [][2]string{{"DELETE", "/v1/me"}, {"POST", "/v1/sessions"}, {"GET", "/v1/sessions"}} {
		if code, _ := c.do(req[0], req[1], map[string]any{}, browser); code != 403 {
			t.Fatalf("browser %s %s: %d", req[0], req[1], code)
		}
	}
	if code := newPIN(t, c, browser, random(32)); code != 403 {
		t.Fatalf("browser changed the PIN: %d", code)
	}
	// The phone sees it, and revoking it signs it out.
	_, list := c.do("GET", "/v1/sessions", nil, a.header)
	sessions := list["sessions"].([]any)
	if len(sessions) != 1 || sessions[0].(map[string]any)["label"] != "Safari on a Mac" {
		t.Fatalf("list: %v", list)
	}
	if code, _ := c.do("DELETE", "/v1/sessions/"+sessions[0].(map[string]any)["id"].(string), nil, a.header); code != 200 {
		t.Fatalf("revoke: %d", code)
	}
	if code, _ := c.do("GET", "/v1/me", nil, browser); code != 401 {
		t.Fatalf("revoked browser still in: %d", code)
	}
	// A browser can sign itself out, not another.
	_, o2 := c.do("POST", "/v1/sessions", map[string]any{"label": "two"}, a.header)
	_, o3 := c.do("POST", "/v1/sessions", map[string]any{"label": "three"}, a.header)
	two, three := "Tekkoh rio "+o2["token"].(string), o3["id"].(string)
	if code, _ := c.do("DELETE", "/v1/sessions/"+three, nil, two); code != 403 {
		t.Fatalf("browser signed out another: %d", code)
	}
	if code, _ := c.do("DELETE", "/v1/sessions/current", nil, two); code != 200 {
		t.Fatalf("sign self out: %d", code)
	}
	if code, _ := c.do("GET", "/v1/me", nil, two); code != 401 {
		t.Fatalf("still in after signing out: %d", code)
	}
}

func TestOnlyTheWebAppsOriginMayCallFromABrowser(t *testing.T) {
	c, _, _ := newClient(t)
	pre := func(origin string) *http.Response {
		req, _ := http.NewRequest("OPTIONS", c.srv.URL+"/v1/entries", nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("Access-Control-Request-Headers", "authorization")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res
	}
	if res := pre("https://tekkoh-web.cronbon.com"); res.StatusCode != 204 || res.Header.Get("Access-Control-Allow-Origin") != "https://tekkoh-web.cronbon.com" {
		t.Fatalf("web app's origin: %d %v", res.StatusCode, res.Header)
	}
	if res := pre("https://evil.example"); res.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("another origin allowed: %v", res.Header)
	}
}
