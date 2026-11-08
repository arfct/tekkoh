package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLive runs the whole cycle against the real server with a throwaway
// journal it deletes afterwards: TEKKOH_LIVE=1 go test -run Live ./cmd/tekkoh
func TestLive(t *testing.T) {
	if os.Getenv("TEKKOH_LIVE") == "" {
		t.Skip("set TEKKOH_LIVE=1 to run against the server")
	}
	t.Setenv("TEKKOH_HOME", t.TempDir())
	api := newClient("")
	handle := "cli" + strings.ToLower(strings.NewReplacer("-", "a", "_", "b").Replace(b64url.EncodeToString(random(5))))
	pin := "382914"

	// A journal, made as the app makes one.
	K := journalKey(random(32))
	salt := random(16)
	d := stretch(pin, salt, 600000)
	blob := seal(d.wrap, K, "tekkoh/recovery/"+handle)
	fields, _ := json.Marshal(map[string]any{"salt": salt, "iterations": 600000, "verifier": d.verifier, "blob": blob})
	box, err := sealTo(api.key, "create", fields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.do("POST", "/v1/accounts", map[string]any{"handle": handle, "auth": K.authToken(), "recovery": map[string][]byte{"eph": box.eph, "box": box.box}}, nil); err != nil {
		t.Fatal("create:", err)
	}
	owner := api.signedIn(handle, K.authToken())
	defer func() {
		if _, err := owner.do("DELETE", "/v1/me", nil, nil); err != nil {
			t.Error("delete the test journal:", err)
		}
	}()

	// A wrong PIN doesn't start linking.
	if _, err := startLink(api, handle, "000000"); err == nil || !strings.Contains(err.Error(), "don't match") {
		t.Fatalf("wrong PIN: %v", err)
	}

	// Linking: the PIN, then "the phone" seals the key to the code's key.
	l, err := startLink(api, handle, pin)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(l.qr, ":")
	if len(parts) != 5 || parts[4] != "agent" {
		t.Fatalf("qr: %s", l.qr)
	}
	pub, _ := b64url.DecodeString(parts[3])
	phone := func(key []byte, h string) {
		payload, _ := json.Marshal(map[string]any{"handle": h, "key": key, "tz": "Asia/Tokyo"})
		s, err := sealTo(pub, "pair", payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := owner.do("PUT", "/v1/pair/"+parts[2], map[string]any{"box": append(s.eph, s.box...)}, nil); err != nil {
			t.Fatal("phone:", err)
		}
	}
	phone(K, handle)
	id, err := l.finish("Test agent", 300*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if id.TimeZone != "Asia/Tokyo" || id.Label != "Test agent" {
		t.Fatalf("identity: %+v", id)
	}
	if err := saveIdentity(id); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(home() + "/identity.json"); fi.Mode().Perm() != 0o600 {
		t.Fatalf("identity.json mode %v", fi.Mode())
	}

	// A phone that sends a different journal's key doesn't link.
	l2, _ := startLink(api, handle, pin)
	pub, _ = b64url.DecodeString(strings.Split(l2.qr, ":")[3])
	parts = strings.Split(l2.qr, ":")
	phone(random(32), handle)
	if _, err := l2.finish("Imposter", 300*time.Millisecond); err == nil || !strings.Contains(err.Error(), "different journals") {
		t.Fatalf("mismatched key linked: %v", err)
	}

	cli := func(args ...string) string {
		var out bytes.Buffer
		if err := run(args, strings.NewReader(""), &out); err != nil {
			t.Fatalf("tekkoh %v: %v", args, err)
		}
		return out.String()
	}

	// The phone sees it as an agent.
	var list struct{ Sessions []map[string]any }
	owner.do("GET", "/v1/sessions", nil, &list)
	if len(list.Sessions) != 1 || list.Sessions[0]["kind"] != "agent" {
		t.Fatalf("sessions: %v", list)
	}

	cli("write", "2026-11-08", "Rain all morning.")
	cli("write", "2026-11-08", "Then the market.")
	cli("note", "2026-11-08", "Booked the dentist for Tuesday.")
	cli("note", "2026-11-08", "Renewed the library books.")

	// Meanwhile "the phone" edits the same page.
	rid := K.entryID("2026-11-08")
	var ch struct{ Entries []remote }
	owner.do("GET", "/v1/entries?after=0", nil, &ch)
	p, _ := parsePage(must(K.openEntry(rid, ch.Entries[0].Data)))
	p.Text += "\n\nWritten on the phone."
	p.Version++
	if _, err := owner.putEntry(rid, K.sealEntry(rid, p.encode()), ch.Entries[0].Rev); err != nil {
		t.Fatal(err)
	}
	// The agent's next write is refused (409), pulls, and makes its edit again.
	cli("note", "2026-11-08", "Paid the water bill.")

	var v pageView
	json.Unmarshal([]byte(cli("read", "2026-11-08", "--json")), &v)
	if v.Text != "Rain all morning.\n\nThen the market.\n\nWritten on the phone." {
		t.Fatalf("text: %q", v.Text)
	}
	if len(v.AgentNotes) != 1 || v.AgentNotes[0].Text != "Booked the dentist for Tuesday.\nRenewed the library books.\nPaid the water bill." || !v.AgentNotes[0].Mine {
		t.Fatalf("notes: %+v", v.AgentNotes)
	}
	if out := cli("search", "dentist"); !strings.Contains(out, "2026-11-08") {
		t.Fatalf("search: %s", out)
	}
	cli("note", "2026-11-08", "--replace", "Just the one thing.")
	json.Unmarshal([]byte(cli("read", "2026-11-08", "--json")), &v)
	if v.AgentNotes[0].Text != "Just the one thing." {
		t.Fatalf("replace: %+v", v.AgentNotes)
	}

	// What the server holds is sealed: no words in it.
	owner.do("GET", "/v1/entries?after=0", nil, &ch)
	for _, e := range ch.Entries {
		if bytes.Contains(e.Data, []byte("dentist")) || bytes.Contains(e.Data, []byte("Rain")) {
			t.Fatal("plain text on the server")
		}
	}

	// Signed out from the phone, the agent can't read any more.
	owner.do("DELETE", "/v1/sessions/"+id.ID, nil, nil)
	var out bytes.Buffer
	if err := run([]string{"read"}, strings.NewReader(""), &out); err == nil || !strings.Contains(err.Error(), "signed out") {
		t.Fatalf("after sign-out: %v", err)
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}
