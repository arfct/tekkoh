package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Linking a browser. The browser opens a slot here and shows a QR code
// holding the slot's id and a one-time X25519 public key it made. The phone
// scans it and puts the journal key in the slot, sealed to that public key;
// the browser collects it once. The server only ever holds the sealed box.
//
// The browser then checks the key against the one the username and PIN
// unlock (the ordinary recovery path), so linking needs the phone and the
// PIN, and they must be the same journal's.

const pairTTL = 5 * time.Minute

type pairSlot struct {
	created time.Time
	box     []byte
	handle  string
}

type pairing struct {
	mu    sync.Mutex
	slots map[string]*pairSlot
}

func newPairing() *pairing { return &pairing{slots: map[string]*pairSlot{}} }

func (p *pairing) sweep() {
	for id, s := range p.slots {
		if time.Since(s.created) > pairTTL {
			delete(p.slots, id)
		}
	}
}

// openSlot: a browser starts linking.
func (s *Server) openSlot(w http.ResponseWriter, r *http.Request) {
	if !s.limit.allow("pair:" + clientIP(r)) {
		fail(w, 429, "too many tries; wait a while")
		return
	}
	s.pair.mu.Lock()
	defer s.pair.mu.Unlock()
	s.pair.sweep()
	if len(s.pair.slots) > 2000 {
		fail(w, 503, "busy; try again in a minute")
		return
	}
	id := randomID()
	s.pair.slots[id] = &pairSlot{created: time.Now()}
	writeJSON(w, 201, map[string]any{"id": id, "expiresIn": int(pairTTL.Seconds())})
}

// fillSlot: the phone, signed in as the journal's owner, puts the sealed
// key in.
func (s *Server) fillSlot(w http.ResponseWriter, r *http.Request, h string) {
	var body struct {
		Box b64 `json:"box"`
	}
	if !readJSON(w, r, &body, 8<<10) {
		return
	}
	if len(body.Box) < 32 || len(body.Box) > 4096 {
		fail(w, 400, "bad box")
		return
	}
	s.pair.mu.Lock()
	defer s.pair.mu.Unlock()
	s.pair.sweep()
	slot, ok := s.pair.slots[r.PathValue("id")]
	if !ok {
		fail(w, 404, "that code has expired; show a new one")
		return
	}
	if slot.box != nil {
		fail(w, 409, "already linked")
		return
	}
	slot.box, slot.handle = body.Box, h
	writeJSON(w, 200, map[string]any{"ok": true})
}

// takeSlot: the browser collects the box, once.
func (s *Server) takeSlot(w http.ResponseWriter, r *http.Request) {
	s.pair.mu.Lock()
	defer s.pair.mu.Unlock()
	s.pair.sweep()
	id := r.PathValue("id")
	slot, ok := s.pair.slots[id]
	switch {
	case !ok:
		fail(w, 404, "that code has expired")
	case slot.box == nil:
		writeJSON(w, 202, map[string]any{"waiting": true})
	default:
		delete(s.pair.slots, id)
		writeJSON(w, 200, map[string]any{"box": b64(slot.box), "handle": slot.handle})
	}
}

// ---- sessions ----

func (s *Server) createSession(w http.ResponseWriter, r *http.Request, h string) {
	var body struct {
		Label string `json:"label"`
	}
	if !readJSON(w, r, &body, 4<<10) {
		return
	}
	label := strings.TrimSpace(body.Label)
	if len(label) > 80 {
		label = label[:80]
	}
	if label == "" {
		label = "A browser"
	}
	tok := make([]byte, 32)
	rand.Read(tok)
	sum := sha256.Sum256(tok)
	sess := &Session{ID: randomID(), Handle: h, TokenHash: sum[:], Label: label, CreatedAt: time.Now().UTC(), LastUsed: time.Now().UTC()}
	if err := s.store.CreateSession(r.Context(), sess); err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"id": sess.ID, "token": b64(tok)})
}

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request, h string) {
	list, err := s.store.Sessions(r.Context(), h)
	if err != nil {
		serverError(w, err)
		return
	}
	if list == nil {
		list = []Session{}
	}
	writeJSON(w, 200, map[string]any{"sessions": list})
}

func (s *Server) deleteSession(w http.ResponseWriter, r *http.Request, h string) {
	id := r.PathValue("id")
	sess, _ := r.Context().Value(sessionKey{}).(*Session)
	switch {
	case id == "current" && sess == nil:
		fail(w, 400, "not a browser session")
		return
	case id == "current":
		id = sess.ID
	case sess != nil && id != sess.ID:
		// A browser can sign itself out, not others.
		fail(w, 403, "only your phone can do that")
		return
	}
	if err := s.store.DeleteSession(r.Context(), h, id); err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

type sessionKey struct{}

func randomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ---- the web app, on another origin ----

// webOrigins are where the web app is served from (TEKKOH_WEB_ORIGINS,
// comma-separated). Only they may call the API from a browser.
func webOrigins() map[string]bool {
	list := os.Getenv("TEKKOH_WEB_ORIGINS")
	if list == "" {
		list = "https://tekkoh-web.cronbon.com"
	}
	out := map[string]bool{}
	for _, o := range strings.Split(list, ",") {
		if o = strings.TrimSpace(o); o != "" {
			out[o] = true
		}
	}
	return out
}

func cors(origins map[string]bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); origins[o] {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", o)
			h.Set("Vary", "Origin")
			if r.Method == http.MethodOptions {
				h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
				h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				h.Set("Access-Control-Max-Age", "600")
				w.WriteHeader(204)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
