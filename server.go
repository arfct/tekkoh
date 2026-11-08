package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// MaxAttempts wrong PINs wipe the sealed key: after that only a device
	// that still holds the key (or iCloud Keychain) can open the journal.
	MaxAttempts = 10
	// MinIterations is the least PIN stretching the server accepts.
	MinIterations = 200_000
	maxEntry      = 2 << 20  // 2 MB of encrypted text and metadata
	maxBlob       = 12 << 20 // 12 MB encrypted photo
)

var (
	handleRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{2,29}$`)
	idRE     = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)
)

type Server struct {
	store  Store
	secret []byte // TEKKOH_SECRET: seals recovery keys, keys the verifier MACs
	limit  *limiter
}

func NewServer(store Store, secret []byte) *Server {
	return &Server{store: store, secret: secret, limit: newLimiter(20, time.Hour)}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]any{"ok": true}) })
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/plain; charset=utf-8")
		io.WriteString(w, "Tekkoh: an encrypted daily journal. This server only ever sees ciphertext.\n")
	})
	mux.HandleFunc("POST /v1/accounts", s.createAccount)
	mux.HandleFunc("GET /v1/recovery", s.recoveryParams)
	mux.HandleFunc("POST /v1/recovery", s.recover)
	mux.HandleFunc("PUT /v1/recovery", s.auth(s.setRecovery))
	mux.HandleFunc("GET /v1/me", s.auth(s.me))
	mux.HandleFunc("DELETE /v1/me", s.auth(s.deleteMe))
	mux.HandleFunc("GET /v1/entries", s.auth(s.entries))
	mux.HandleFunc("PUT /v1/entries/{id}", s.auth(s.putEntry))
	mux.HandleFunc("DELETE /v1/entries/{id}", s.auth(s.deleteEntry))
	mux.HandleFunc("PUT /v1/blobs/{id}", s.auth(s.putBlob))
	mux.HandleFunc("GET /v1/blobs/{id}", s.auth(s.getBlob))
	mux.HandleFunc("DELETE /v1/blobs/{id}", s.auth(s.deleteBlob))
	return logRequests(mux)
}

// ---- recovery sealing ----

func (s *Server) derive(info string) []byte {
	k, err := hkdf.Key(sha256.New, s.secret, nil, info, 32)
	if err != nil {
		panic(err)
	}
	return k
}

// verifierMAC binds what the phone derived from the PIN to the handle under
// the server secret.
func (s *Server) verifierMAC(handle string, verifier []byte) []byte {
	m := hmac.New(sha256.New, s.derive("tekkoh/verifier/v1"))
	m.Write([]byte(handle))
	m.Write([]byte{0})
	m.Write(verifier)
	return m.Sum(nil)
}

func (s *Server) gcm(handle string) cipher.AEAD {
	block, _ := aes.NewCipher(s.derive("tekkoh/seal/v1/" + handle))
	g, _ := cipher.NewGCM(block)
	return g
}

func (s *Server) seal(handle string, blob []byte) []byte {
	g := s.gcm(handle)
	nonce := make([]byte, g.NonceSize())
	rand.Read(nonce)
	return g.Seal(nonce, nonce, blob, []byte(handle))
}

func (s *Server) unseal(handle string, sealed []byte) ([]byte, error) {
	g := s.gcm(handle)
	if len(sealed) < g.NonceSize() {
		return nil, errors.New("short")
	}
	return g.Open(nil, sealed[:g.NonceSize()], sealed[g.NonceSize():], []byte(handle))
}

// ---- accounts ----

type recoveryBody struct {
	Salt       b64 `json:"salt"`
	Iterations int `json:"iterations"`
	Verifier   b64 `json:"verifier"`
	// Blob is the journal key locked with a key derived from the PIN on
	// the phone. The server seals it again before storing it.
	Blob b64 `json:"blob"`
}

func (r recoveryBody) valid() error {
	switch {
	case len(r.Salt) < 16 || len(r.Salt) > 64:
		return errors.New("salt must be 16-64 bytes")
	case r.Iterations < MinIterations || r.Iterations > 50_000_000:
		return errors.New("iterations out of range")
	case len(r.Verifier) != 32:
		return errors.New("verifier must be 32 bytes")
	case len(r.Blob) < 32 || len(r.Blob) > 512:
		return errors.New("blob must be 32-512 bytes")
	}
	return nil
}

func (s *Server) createAccount(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Handle   string       `json:"handle"`
		Auth     b64          `json:"auth"`
		Recovery recoveryBody `json:"recovery"`
	}
	if !readJSON(w, r, &body, 16<<10) {
		return
	}
	h := strings.ToLower(strings.TrimSpace(body.Handle))
	if !handleRE.MatchString(h) {
		fail(w, 400, "a username is 3-30 letters, digits, dots, dashes or underscores")
		return
	}
	if len(body.Auth) != 32 {
		fail(w, 400, "auth must be 32 bytes")
		return
	}
	if err := body.Recovery.valid(); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if !s.limit.allow("create:" + clientIP(r)) {
		fail(w, 429, "too many tries; wait a while")
		return
	}
	sum := sha256.Sum256(body.Auth)
	a := &Account{
		Handle: h, AuthHash: sum[:], Salt: body.Recovery.Salt, Iterations: body.Recovery.Iterations,
		VerifierMAC: s.verifierMAC(h, body.Recovery.Verifier), Sealed: s.seal(h, body.Recovery.Blob),
	}
	if err := s.store.CreateAccount(r.Context(), a); err != nil {
		if errors.Is(err, ErrExists) {
			fail(w, 409, "that username is taken")
			return
		}
		serverError(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"handle": h})
}

// recoveryParams gives a new phone what it needs to stretch the PIN.
func (s *Server) recoveryParams(w http.ResponseWriter, r *http.Request) {
	h := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("handle")))
	if !s.limit.allow("params:" + clientIP(r)) {
		fail(w, 429, "too many tries; wait a while")
		return
	}
	a, err := s.store.Account(r.Context(), h)
	if errors.Is(err, ErrNotFound) {
		fail(w, 404, "no journal with that username")
		return
	} else if err != nil {
		serverError(w, err)
		return
	}
	if a.Sealed == nil {
		fail(w, 410, "too many wrong PINs: this journal can only be opened on a device that still has its key")
		return
	}
	writeJSON(w, 200, map[string]any{"salt": b64(a.Salt), "iterations": a.Iterations, "attemptsLeft": MaxAttempts - a.Attempts})
}

func (s *Server) recover(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Handle   string `json:"handle"`
		Verifier b64    `json:"verifier"`
	}
	if !readJSON(w, r, &body, 4<<10) {
		return
	}
	h := strings.ToLower(strings.TrimSpace(body.Handle))
	if !s.limit.allow("recover:" + clientIP(r)) {
		fail(w, 429, "too many tries; wait a while")
		return
	}
	mac := s.verifierMAC(h, body.Verifier)
	a, ok, err := s.store.Attempt(r.Context(), h, func(a *Account) bool {
		return subtle.ConstantTimeCompare(mac, a.VerifierMAC) == 1
	}, MaxAttempts)
	if errors.Is(err, ErrNotFound) {
		fail(w, 404, "no journal with that username")
		return
	} else if err != nil {
		serverError(w, err)
		return
	}
	if !ok {
		if a.Sealed == nil {
			fail(w, 410, "too many wrong PINs: this journal can only be opened on a device that still has its key")
			return
		}
		writeJSON(w, 403, map[string]any{"error": "wrong PIN", "attemptsLeft": MaxAttempts - a.Attempts})
		return
	}
	blob, err := s.unseal(h, a.Sealed)
	if err != nil {
		serverError(w, errors.New("sealed key doesn't open: has TEKKOH_SECRET changed?"))
		return
	}
	writeJSON(w, 200, map[string]any{"blob": b64(blob)})
}

func (s *Server) setRecovery(w http.ResponseWriter, r *http.Request, h string) {
	var body recoveryBody
	if !readJSON(w, r, &body, 16<<10) {
		return
	}
	if err := body.valid(); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if err := s.store.SetRecovery(r.Context(), h, body.Salt, body.Iterations, s.verifierMAC(h, body.Verifier), s.seal(h, body.Blob)); err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request, h string) {
	a, err := s.store.Account(r.Context(), h)
	if err != nil {
		serverError(w, err)
		return
	}
	n, _ := s.store.CountEntries(r.Context(), h)
	writeJSON(w, 200, map[string]any{"handle": a.Handle, "createdAt": a.CreatedAt, "entries": n, "recovery": a.Sealed != nil})
}

func (s *Server) deleteMe(w http.ResponseWriter, r *http.Request, h string) {
	if err := s.store.DeleteAccount(r.Context(), h); err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- entries: opaque, ids chosen by the phone (a keyed hash of the day) ----

func (s *Server) entries(w http.ResponseWriter, r *http.Request, h string) {
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	es, err := s.store.Entries(r.Context(), h, after, 200)
	if err != nil {
		serverError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(es))
	cursor := after
	for _, e := range es {
		m := map[string]any{"id": e.ID, "rev": e.Rev, "seq": e.Seq, "updatedAt": e.UpdatedAt}
		if e.Deleted {
			m["deleted"] = true
		} else {
			m["data"] = b64(e.Data)
		}
		out = append(out, m)
		cursor = e.Seq
	}
	writeJSON(w, 200, map[string]any{"entries": out, "cursor": cursor, "more": len(es) == 200})
}

func (s *Server) putEntry(w http.ResponseWriter, r *http.Request, h string) {
	id := r.PathValue("id")
	if !idRE.MatchString(id) {
		fail(w, 400, "bad id")
		return
	}
	var body struct {
		Data b64 `json:"data"`
		Rev  int `json:"rev"`
	}
	if !readJSON(w, r, &body, maxEntry*2) {
		return
	}
	if len(body.Data) == 0 || len(body.Data) > maxEntry {
		fail(w, 400, "entry is empty or too big")
		return
	}
	e, err := s.store.PutEntry(r.Context(), h, id, body.Data, body.Rev)
	if errors.Is(err, ErrConflict) {
		fail(w, 409, "changed elsewhere; sync and try again")
		return
	} else if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"id": e.ID, "rev": e.Rev, "seq": e.Seq, "updatedAt": e.UpdatedAt})
}

func (s *Server) deleteEntry(w http.ResponseWriter, r *http.Request, h string) {
	rev, _ := strconv.Atoi(r.URL.Query().Get("rev"))
	e, err := s.store.DeleteEntry(r.Context(), h, r.PathValue("id"), rev)
	switch {
	case errors.Is(err, ErrNotFound):
		fail(w, 404, "no such entry")
	case errors.Is(err, ErrConflict):
		fail(w, 409, "changed elsewhere; sync and try again")
	case err != nil:
		serverError(w, err)
	default:
		writeJSON(w, 200, map[string]any{"id": e.ID, "rev": e.Rev, "seq": e.Seq, "deleted": true})
	}
}

// ---- photos: encrypted bytes ----

func (s *Server) putBlob(w http.ResponseWriter, r *http.Request, h string) {
	id := r.PathValue("id")
	if !idRE.MatchString(id) {
		fail(w, 400, "bad id")
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBlob))
	if err != nil {
		fail(w, 413, "photo too big")
		return
	}
	if len(data) == 0 {
		fail(w, 400, "empty")
		return
	}
	if err := s.store.PutBlob(r.Context(), h, id, data); err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"id": id, "size": len(data)})
}

func (s *Server) getBlob(w http.ResponseWriter, r *http.Request, h string) {
	b, err := s.store.Blob(r.Context(), h, r.PathValue("id"))
	if errors.Is(err, ErrNotFound) {
		fail(w, 404, "no such photo")
		return
	} else if err != nil {
		serverError(w, err)
		return
	}
	w.Header().Set("content-type", "application/octet-stream")
	w.Header().Set("cache-control", "private, max-age=31536000, immutable")
	w.Write(b)
}

func (s *Server) deleteBlob(w http.ResponseWriter, r *http.Request, h string) {
	if err := s.store.DeleteBlob(r.Context(), h, r.PathValue("id")); err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- auth: `Authorization: Tekkoh <handle> <base64 token>` ----

func (s *Server) auth(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f := strings.Fields(r.Header.Get("Authorization"))
		if len(f) != 3 || f[0] != "Tekkoh" {
			fail(w, 401, "sign in")
			return
		}
		tok, err := base64.StdEncoding.DecodeString(f[2])
		if err != nil || len(tok) != 32 {
			fail(w, 401, "sign in")
			return
		}
		a, err := s.store.Account(r.Context(), f[1])
		if err != nil {
			fail(w, 401, "sign in")
			return
		}
		sum := sha256.Sum256(tok)
		if subtle.ConstantTimeCompare(sum[:], a.AuthHash) != 1 {
			fail(w, 401, "sign in")
			return
		}
		next(w, r, a.Handle)
	}
}

// ---- plumbing ----

// b64 is bytes as standard base64 in JSON.
type b64 []byte

func (b b64) MarshalJSON() ([]byte, error) { return json.Marshal(base64.StdEncoding.EncodeToString(b)) }
func (b *b64) UnmarshalJSON(d []byte) error {
	var s string
	if err := json.Unmarshal(d, &s); err != nil {
		return err
	}
	v, err := base64.StdEncoding.DecodeString(s)
	*b = v
	return err
}

func readJSON(w http.ResponseWriter, r *http.Request, v any, max int64) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, max)).Decode(v); err != nil {
		fail(w, 400, "bad request: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func serverError(w http.ResponseWriter, err error) {
	slog.Error("request", "err", err)
	fail(w, 500, "something went wrong")
}

func clientIP(r *http.Request) string {
	// Berth's proxy (Caddy) sets X-Forwarded-For; the first hop is the client.
	if f := r.Header.Get("X-Forwarded-For"); f != "" {
		return strings.TrimSpace(strings.Split(f, ",")[0])
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := time.Now()
		rec := &statusRecorder{ResponseWriter: w, code: 200}
		h.ServeHTTP(rec, r)
		// Paths only: no usernames from query strings, no bodies.
		slog.Info("http", "method", r.Method, "path", r.URL.Path, "status", rec.code, "ms", time.Since(t).Milliseconds())
	})
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(c int) { s.code = c; s.ResponseWriter.WriteHeader(c) }

// limiter allows n events per key per window.
type limiter struct {
	mu     sync.Mutex
	n      int
	window time.Duration
	hits   map[string][]time.Time
}

func newLimiter(n int, window time.Duration) *limiter {
	return &limiter{n: n, window: window, hits: map[string][]time.Time{}}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	h := l.hits[key]
	i := 0
	for i < len(h) && now.Sub(h[i]) > l.window {
		i++
	}
	h = h[i:]
	if len(h) >= l.n {
		l.hits[key] = h
		return false
	}
	l.hits[key] = append(h, now)
	return true
}
