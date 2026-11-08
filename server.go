package main

import (
	"context"
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
	// Per journal: a page a day for decades, and a lot of photos.
	maxEntries   = 40_000
	maxBlobs     = 60_000
	maxBlobBytes = 20 << 30
	// Failed recoveries allowed across every account in an hour: guessing
	// a few common PINs against many usernames runs into this.
	maxFailuresPerHour = 200
)

// backoff is how long to wait after the nth wrong PIN before the next
// try: none for the first three, then 1, 2, 4… minutes, so ten take hours.
var backoff = func(attempts int) time.Duration {
	if attempts < 3 {
		return 0
	}
	return time.Minute << (attempts - 3)
}

var (
	handleRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{2,29}$`)
	idRE     = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)
)

type Server struct {
	store  Store
	secret []byte // TEKKOH_SECRET: seals recovery keys, keys the verifier MACs
	limit  *limiter
	// Failures across all accounts, and per-username counts for names
	// that don't exist (so they answer like ones that do).
	failures *limiter
	ghosts   *limiter
	pair     *pairing
	origins  map[string]bool
}

func NewServer(store Store, secret []byte) *Server {
	return &Server{store: store, secret: secret, limit: newLimiter(20, time.Hour),
		failures: newLimiter(maxFailuresPerHour, time.Hour), ghosts: newLimiter(MaxAttempts, 24*time.Hour),
		pair: newPairing(), origins: webOrigins()}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]any{"ok": true}) })
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/plain; charset=utf-8")
		io.WriteString(w, "Tekkoh: an encrypted daily journal. This server only ever sees ciphertext.\n")
	})
	mux.HandleFunc("GET /v1/transport-key", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"key": b64(s.TransportPublic())})
	})
	mux.HandleFunc("POST /v1/accounts", s.createAccount)
	mux.HandleFunc("POST /v1/recovery/params", s.recoveryParams)
	mux.HandleFunc("POST /v1/recovery", s.recover)
	mux.HandleFunc("PUT /v1/recovery", s.owner(s.setRecovery))
	mux.HandleFunc("GET /v1/me", s.auth(s.me))
	mux.HandleFunc("DELETE /v1/me", s.owner(s.deleteMe))
	mux.HandleFunc("POST /v1/pair", s.openSlot)
	mux.HandleFunc("PUT /v1/pair/{id}", s.owner(s.fillSlot))
	mux.HandleFunc("GET /v1/pair/{id}", s.takeSlot)
	mux.HandleFunc("POST /v1/sessions", s.owner(s.createSession))
	mux.HandleFunc("GET /v1/sessions", s.owner(s.listSessions))
	mux.HandleFunc("DELETE /v1/sessions/{id}", s.auth(s.deleteSession))
	mux.HandleFunc("GET /v1/entries", s.auth(s.entries))
	mux.HandleFunc("PUT /v1/entries/{id}", s.auth(s.putEntry))
	mux.HandleFunc("DELETE /v1/entries/{id}", s.auth(s.deleteEntry))
	mux.HandleFunc("PUT /v1/blobs/{id}", s.auth(s.putBlob))
	mux.HandleFunc("GET /v1/blobs/{id}", s.auth(s.getBlob))
	mux.HandleFunc("DELETE /v1/blobs/{id}", s.auth(s.deleteBlob))
	return logRequests(cors(s.origins, mux))
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
		Handle   string    `json:"handle"`
		Auth     b64       `json:"auth"`
		Recovery sealedBox `json:"recovery"`
	}
	if !readJSON(w, r, &body, 16<<10) {
		return
	}
	var rec recoveryBody
	if _, err := s.open("create", body.Recovery, &rec); err != nil {
		fail(w, 400, "recovery: "+err.Error())
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
	if err := rec.valid(); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if !s.limit.allow("create:" + clientIP(r)) {
		fail(w, 429, "too many tries; wait a while")
		return
	}
	sum := sha256.Sum256(body.Auth)
	a := &Account{
		Handle: h, AuthHash: sum[:], Salt: rec.Salt, Iterations: rec.Iterations,
		VerifierMAC: s.verifierMAC(h, rec.Verifier), Sealed: s.seal(h, rec.Blob),
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
	// In the body, so the username stays out of access logs.
	var body struct {
		Handle string `json:"handle"`
	}
	if !readJSON(w, r, &body, 4<<10) {
		return
	}
	h := strings.ToLower(strings.TrimSpace(body.Handle))
	if !s.limit.allow("params:" + clientIP(r)) {
		fail(w, 429, "too many tries; wait a while")
		return
	}
	a, err := s.store.Account(r.Context(), h)
	if errors.Is(err, ErrNotFound) {
		// Answer as if it existed, so usernames can't be listed.
		writeJSON(w, 200, map[string]any{"salt": b64(s.ghostSalt(h)), "iterations": 600_000, "attemptsLeft": MaxAttempts - s.ghosts.count(h)})
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
		Handle string    `json:"handle"`
		Proof  sealedBox `json:"proof"`
	}
	if !readJSON(w, r, &body, 4<<10) {
		return
	}
	h := strings.ToLower(strings.TrimSpace(body.Handle))
	var proof struct {
		Verifier b64 `json:"verifier"`
	}
	k, err := s.open("recover", body.Proof, &proof)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	if !s.limit.allow("recover:"+clientIP(r)) || s.failures.count("all") >= maxFailuresPerHour {
		fail(w, 429, "too many tries; wait a while")
		return
	}
	mac := s.verifierMAC(h, proof.Verifier)
	var wait time.Duration
	a, ok, err := s.store.Attempt(r.Context(), h, func(a *Account) bool {
		wait = time.Until(a.LastAttempt.Add(backoff(a.Attempts)))
		return wait <= 0
	}, func(a *Account) bool {
		return subtle.ConstantTimeCompare(mac, a.VerifierMAC) == 1
	}, MaxAttempts)
	switch {
	case errors.Is(err, ErrNotFound):
		// Like a wrong PIN on a real journal, counting down the same way.
		s.failures.allow("all")
		if !s.ghosts.allow(h) {
			fail(w, 410, wiped)
			return
		}
		writeJSON(w, 403, map[string]any{"error": "wrong PIN", "attemptsLeft": MaxAttempts - s.ghosts.count(h)})
		return
	case errors.Is(err, ErrTooSoon):
		writeJSON(w, 429, map[string]any{"error": "too many wrong PINs; wait before trying again", "retryAfter": int(wait.Seconds()) + 1})
		return
	case err != nil:
		serverError(w, err)
		return
	}
	if !ok {
		s.failures.allow("all")
		if a.Sealed == nil {
			fail(w, 410, wiped)
			return
		}
		writeJSON(w, 403, map[string]any{"error": "wrong PIN", "attemptsLeft": MaxAttempts - a.Attempts, "retryAfter": int(backoff(a.Attempts).Seconds())})
		return
	}
	blob, err := s.unseal(h, a.Sealed)
	if err != nil {
		serverError(w, errors.New("sealed key doesn't open: has TEKKOH_SECRET changed?"))
		return
	}
	reply, err := sealReply(k, "recover", map[string]any{"blob": b64(blob)})
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"reply": reply})
}

const wiped = "too many wrong PINs: this journal can only be opened on a device that still has its key"

// ghostSalt is a stable salt for a username that doesn't exist.
func (s *Server) ghostSalt(handle string) []byte {
	m := hmac.New(sha256.New, s.derive("tekkoh/ghost-salt/v1"))
	m.Write([]byte(handle))
	return m.Sum(nil)[:16]
}

func (s *Server) setRecovery(w http.ResponseWriter, r *http.Request, h string) {
	var box sealedBox
	if !readJSON(w, r, &box, 16<<10) {
		return
	}
	var body recoveryBody
	if _, err := s.open("set-recovery", box, &body); err != nil {
		fail(w, 400, err.Error())
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
	out := map[string]any{"handle": a.Handle, "createdAt": a.CreatedAt, "entries": n, "recovery": a.Sealed != nil}
	if sess, _ := r.Context().Value(sessionKey{}).(*Session); sess != nil {
		out["session"] = sess
	}
	writeJSON(w, 200, out)
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
	if body.Rev == 0 {
		if n, _, _, err := s.store.Usage(r.Context(), h); err == nil && n >= maxEntries {
			fail(w, 507, "this journal is full")
			return
		}
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
	if _, n, bytes, err := s.store.Usage(r.Context(), h); err == nil && (n >= maxBlobs || bytes+int64(len(data)) > maxBlobBytes) {
		fail(w, 507, "no more room for photos in this journal")
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

// owner: only the journal's own token (derived from the journal key), not a
// linked browser's session.
func (s *Server) owner(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return s.auth(func(w http.ResponseWriter, r *http.Request, h string) {
		if r.Context().Value(sessionKey{}) != nil {
			fail(w, 403, "only your phone can do that")
			return
		}
		next(w, r, h)
	})
}

// auth: the journal's own token, or a linked browser's session token.
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
			sess, err := s.store.Session(r.Context(), a.Handle, sum[:])
			if err != nil {
				fail(w, 401, "sign in")
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), sessionKey{}, sess))
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

// clientIP is who's asking, for rate limits. A client can put anything in
// X-Forwarded-For and the proxies append to it, so the first hop is
// whatever an attacker likes. Cloudflare sets Cf-Connecting-Ip itself
// (replacing any the client sent) when requests come through the tunnel;
// otherwise the last hop, which the proxy in front of us added, is the one
// to believe.
func clientIP(r *http.Request) string {
	if ip := strings.TrimSpace(r.Header.Get("Cf-Connecting-Ip")); ip != "" {
		return ipKey(ip)
	}
	if f := r.Header.Get("X-Forwarded-For"); f != "" {
		hops := strings.Split(f, ",")
		return ipKey(strings.TrimSpace(hops[len(hops)-1]))
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

// ipKey groups IPv6 addresses by /64: a host usually has a whole /64 to
// rotate through.
func ipKey(ip string) string {
	a := net.ParseIP(ip)
	if a == nil || a.To4() != nil {
		return ip
	}
	return a.Mask(net.CIDRMask(64, 128)).String() + "/64"
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
	calls  int
}

func newLimiter(n int, window time.Duration) *limiter {
	return &limiter{n: n, window: window, hits: map[string][]time.Time{}}
}

// count is how many events key has had in the window.
func (l *limiter) count(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, t := range l.hits[key] {
		if time.Since(t) <= l.window {
			n++
		}
	}
	return n
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	// Now and then, forget keys that have gone quiet.
	if l.calls++; l.calls%1000 == 0 {
		for k, h := range l.hits {
			if len(h) == 0 || now.Sub(h[len(h)-1]) > l.window {
				delete(l.hits, k)
			}
		}
	}
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
