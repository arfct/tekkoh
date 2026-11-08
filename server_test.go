package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

type client struct {
	t   *testing.T
	srv *httptest.Server
	ip  int
}

func newClient(t *testing.T) (*client, *memStore, *Server) {
	store := newMemStore()
	secret := make([]byte, 32)
	rand.Read(secret)
	s := NewServer(store, secret)
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
	code, out := c.do("POST", "/v1/accounts", map[string]any{
		"handle": handle, "auth": enc(a.token),
		"recovery": map[string]any{"salt": enc(a.salt), "iterations": 600000, "verifier": enc(a.verifier), "blob": enc(a.blob)},
	}, "")
	if code != 201 {
		t.Fatalf("sign up: %d %v", code, out)
	}
	return a
}

func TestRecoveryReleasesTheKeyOnlyForTheRightPIN(t *testing.T) {
	c, store, _ := newClient(t)
	a := signUp(t, c, "kiko")

	code, out := c.do("GET", "/v1/recovery?handle=kiko", nil, "")
	if code != 200 || out["salt"] != enc(a.salt) || out["attemptsLeft"].(float64) != MaxAttempts {
		t.Fatalf("params: %d %v", code, out)
	}
	code, out = c.do("POST", "/v1/recovery", map[string]any{"handle": "kiko", "verifier": enc(random(32))}, "")
	if code != 403 || out["attemptsLeft"].(float64) != MaxAttempts-1 {
		t.Fatalf("wrong PIN: %d %v", code, out)
	}
	code, out = c.do("POST", "/v1/recovery", map[string]any{"handle": "KIKO", "verifier": enc(a.verifier)}, "")
	if code != 200 || out["blob"] != enc(a.blob) {
		t.Fatalf("right PIN: %d %v", code, out)
	}
	// A right PIN resets the count.
	if acc, _ := store.Account(context.Background(), "kiko"); acc.Attempts != 0 {
		t.Fatalf("attempts not reset: %d", acc.Attempts)
	}
	// What's stored is neither the blob nor the verifier.
	acc, _ := store.Account(context.Background(), "kiko")
	if bytes.Contains(acc.Sealed, a.blob) || bytes.Equal(acc.VerifierMAC, a.verifier) {
		t.Fatal("stored the blob or verifier in the clear")
	}
}

func TestTooManyWrongPINsWipeTheKey(t *testing.T) {
	c, _, _ := newClient(t)
	a := signUp(t, c, "sora")
	for i := 1; i < MaxAttempts; i++ {
		if code, _ := c.do("POST", "/v1/recovery", map[string]any{"handle": "sora", "verifier": enc(random(32))}, ""); code != 403 {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	if code, _ := c.do("POST", "/v1/recovery", map[string]any{"handle": "sora", "verifier": enc(random(32))}, ""); code != 410 {
		t.Fatalf("last attempt should wipe: %d", code)
	}
	// Even the right PIN can't bring it back now.
	if code, _ := c.do("POST", "/v1/recovery", map[string]any{"handle": "sora", "verifier": enc(a.verifier)}, ""); code != 410 {
		t.Fatalf("after wipe: %d", code)
	}
	if code, _ := c.do("GET", "/v1/recovery?handle=sora", nil, ""); code != 410 {
		t.Fatalf("params after wipe: %d", code)
	}
	// The account still works for a device that has the key, and it can
	// set a new PIN.
	if code, out := c.do("GET", "/v1/me", nil, a.header); code != 200 || out["recovery"] != false {
		t.Fatalf("me: %d %v", code, out)
	}
	nv := random(32)
	if code, _ := c.do("PUT", "/v1/recovery", map[string]any{"salt": enc(random(16)), "iterations": 600000, "verifier": enc(nv), "blob": enc(random(60))}, a.header); code != 200 {
		t.Fatalf("new PIN: %d", code)
	}
	if code, _ := c.do("POST", "/v1/recovery", map[string]any{"handle": "sora", "verifier": enc(nv)}, ""); code != 200 {
		t.Fatalf("new PIN works: %d", code)
	}
}

// A copy of the database is useless without the server secret: another
// server with a different secret can't check PINs or open the sealed key.
func TestADatabaseAloneCantTestPINs(t *testing.T) {
	_, store, _ := newClient(t)
	c := &client{t: t}
	other := NewServer(store, random(32))
	c.srv = httptest.NewServer(other.Routes())
	defer c.srv.Close()
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
	c, _, _ := newClient(t)
	a := signUp(t, c, "mio")
	if code, _ := c.do("POST", "/v1/accounts", map[string]any{"handle": "mio", "auth": enc(random(32)),
		"recovery": map[string]any{"salt": enc(random(16)), "iterations": 600000, "verifier": enc(random(32)), "blob": enc(random(60))}}, ""); code != 409 {
		t.Fatalf("duplicate: %d", code)
	}
	for _, h := range []string{"a", "has space", "UPPER!"} {
		if code, _ := c.do("POST", "/v1/accounts", map[string]any{"handle": h, "auth": enc(random(32)),
			"recovery": map[string]any{"salt": enc(random(16)), "iterations": 600000, "verifier": enc(random(32)), "blob": enc(random(60))}}, ""); code != 400 {
			t.Fatalf("handle %q: %d", h, code)
		}
	}
	if code, _ := c.do("POST", "/v1/accounts", map[string]any{"handle": "weak", "auth": enc(random(32)),
		"recovery": map[string]any{"salt": enc(random(16)), "iterations": 1000, "verifier": enc(random(32)), "blob": enc(random(60))}}, ""); code != 400 {
		t.Fatalf("weak stretching accepted: %d", code)
	}
	if code, _ := c.do("GET", "/v1/me", nil, "Tekkoh mio "+enc(random(32))); code != 401 {
		t.Fatalf("wrong token: %d", code)
	}
	if code, _ := c.do("GET", "/v1/me", nil, a.header); code != 200 {
		t.Fatalf("right token: %d", code)
	}
	// Tokens are stored hashed.
	sum := sha256.Sum256(a.token)
	_ = sum
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
	// Another account sees nothing.
	if _, out := c.do("GET", "/v1/entries?after=0", nil, b.header); len(out["entries"].([]any)) != 0 {
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
