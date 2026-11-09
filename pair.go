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
//
// An agent's slot lasts longer: the agent sends you a link in a chat, and
// you may not tap it for a few minutes. You approve it in the app, which
// already holds the key, so it needs no PIN.

const (
	pairTTL      = 5 * time.Minute
	agentPairTTL = 15 * time.Minute
)

type pairSlot struct {
	created time.Time
	ttl     time.Duration
	box     []byte
	handle  string
	taken   bool // collected: kept until it expires, so its page can say so
}

type pairing struct {
	mu    sync.Mutex
	slots map[string]*pairSlot
}

func newPairing() *pairing { return &pairing{slots: map[string]*pairSlot{}} }

func (p *pairing) sweep() {
	for id, s := range p.slots {
		if time.Since(s.created) > s.ttl {
			delete(p.slots, id)
		}
	}
}

// openSlot: a browser, or an agent ({"for": "agent"}), starts linking.
func (s *Server) openSlot(w http.ResponseWriter, r *http.Request) {
	if !s.limit.allow("pair:" + clientIP(r)) {
		fail(w, 429, "too many tries; wait a while")
		return
	}
	var body struct {
		For string `json:"for"`
	}
	if r.ContentLength != 0 && !readJSON(w, r, &body, 1<<10) {
		return
	}
	ttl := pairTTL
	if body.For == "agent" {
		ttl = agentPairTTL
	}
	s.pair.mu.Lock()
	defer s.pair.mu.Unlock()
	s.pair.sweep()
	if len(s.pair.slots) > 2000 {
		fail(w, 503, "busy; try again in a minute")
		return
	}
	id := randomID()
	s.pair.slots[id] = &pairSlot{created: time.Now(), ttl: ttl}
	writeJSON(w, 201, map[string]any{"id": id, "expiresIn": int(ttl.Seconds())})
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
	if slot.box != nil || slot.taken {
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
	case !ok || slot.taken:
		fail(w, 404, "that code has expired")
	case slot.box == nil:
		writeJSON(w, 202, map[string]any{"waiting": true})
	default:
		box := slot.box
		slot.box, slot.taken = nil, true
		writeJSON(w, 200, map[string]any{"box": b64(box), "handle": slot.handle})
	}
}

// slotState: how a link is getting on, for the page an agent's link opens
// (on tekkoh.com, so any origin may ask). It says only "waiting",
// "approved" (the phone has filled it), "linked" (the agent has collected
// it) or "expired"; never whose it is, and it doesn't use the slot up.
func (s *Server) slotState(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	s.pair.mu.Lock()
	defer s.pair.mu.Unlock()
	s.pair.sweep()
	state := "expired"
	if slot, ok := s.pair.slots[r.PathValue("id")]; ok {
		switch {
		case slot.taken:
			state = "linked"
		case slot.box != nil:
			state = "approved"
		default:
			state = "waiting"
		}
	}
	writeJSON(w, 200, map[string]any{"state": state})
}

// ---- sessions ----

func (s *Server) createSession(w http.ResponseWriter, r *http.Request, h string) {
	var body struct {
		Label string `json:"label"`
		Kind  string `json:"kind"`
	}
	if !readJSON(w, r, &body, 4<<10) {
		return
	}
	kind := body.Kind
	switch kind {
	case "":
		kind = "browser"
	case "browser", "agent":
	default:
		fail(w, 400, "kind is browser or agent")
		return
	}
	label := strings.TrimSpace(body.Label)
	if len(label) > 80 {
		label = label[:80]
	}
	if label == "" {
		label = map[string]string{"browser": "A browser", "agent": "An agent"}[kind]
	}
	tok := make([]byte, 32)
	rand.Read(tok)
	sum := sha256.Sum256(tok)
	sess := &Session{ID: randomID(), Handle: h, TokenHash: sum[:], Label: label, Kind: kind, CreatedAt: time.Now().UTC(), LastUsed: time.Now().UTC()}
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
