package main

import (
	"crypto/ecdh"
	"encoding/json"
	"os"
	"testing"
)

// The vectors the iOS app's Swift code made (tekkoh-ios Checks/vectors),
// shared with the web's tests.
func vectors(t *testing.T) map[string]string {
	d, err := os.ReadFile("../../web/tests/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]string
	if err := json.Unmarshal(d, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func dec(t *testing.T, s string) []byte {
	b, err := b64.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMatchesTheApp(t *testing.T) {
	v := vectors(t)
	k := journalKey(dec(t, v["key"]))
	if got := b64.EncodeToString(k.authToken()); got != v["authToken"] {
		t.Errorf("sign-in token: %s", got)
	}
	if got := k.entryID(v["day"]); got != v["entryID"] {
		t.Errorf("entry id: %s", got)
	}
	plain, err := k.openEntry(v["entryID"], dec(t, v["sealedEntry"]))
	if err != nil || string(plain) != v["entryJSON"] {
		t.Errorf("opening Swift's page: %v", err)
	}
	if _, err := k.openEntry(k.entryID("2026-11-09"), dec(t, v["sealedEntry"])); err == nil {
		t.Error("a page opened under another day's id")
	}
	photoKey := make([]byte, 32)
	for i := range photoKey {
		photoKey[i] = 7
	}
	if p, err := openPhoto(photoKey, dec(t, v["photo"]), "p_test"); err != nil || string(p) != "jpeg bytes" {
		t.Errorf("photo: %v", err)
	}
	// Our sealing round-trips.
	again, err := k.openEntry(v["entryID"], k.sealEntry(v["entryID"], []byte(v["entryJSON"])))
	if err != nil || string(again) != v["entryJSON"] {
		t.Errorf("round trip: %v", err)
	}
}

func TestPINMatchesTheApp(t *testing.T) {
	v := vectors(t)
	d := stretch(v["pin"], dec(t, v["salt"]), 600000)
	if got := b64.EncodeToString(d.verifier); got != v["verifier"] {
		t.Errorf("verifier: %s", got)
	}
	key, err := unlock(dec(t, v["blob"]), d, "kiko")
	if err != nil || !same(key, dec(t, v["key"])) {
		t.Errorf("unlock: %v", err)
	}
	if _, err := unlock(dec(t, v["blob"]), stretch("000000", dec(t, v["salt"]), 600000), "kiko"); err == nil {
		t.Error("a wrong PIN unlocked")
	}
}

func TestOpensThePhonesPairingBox(t *testing.T) {
	v := vectors(t)
	privRaw, _ := b64url.DecodeString(v["browserPrivate"])
	priv, err := ecdh.X25519().NewPrivateKey(privRaw)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := b64url.DecodeString(v["browserPublic"])
	if !same(priv.PublicKey().Bytes(), pub) {
		t.Fatal("public key")
	}
	plain, err := openFromPhone(priv, dec(t, v["pairBox"]))
	if err != nil {
		t.Fatal(err)
	}
	var p struct{ Handle, Key string }
	json.Unmarshal(plain, &p)
	if p.Handle != "kiko" || p.Key != v["key"] {
		t.Errorf("payload: %+v", p)
	}
	if got := linkCode(pub); got != v["linkCode"] {
		t.Errorf("link code: %s", got)
	}
}
