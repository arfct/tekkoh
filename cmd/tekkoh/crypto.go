package main

// Tekkoh's crypto, matching the app's Crypto.swift and Transport.swift and
// the web's crypto.js byte for byte (crypto_test.go checks the vectors the
// Swift code made). Standard library only.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

var (
	b64    = base64.StdEncoding
	b64url = base64.RawURLEncoding
)

func random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func hkdfKey(secret []byte, info string, salt []byte) []byte {
	k, err := hkdf.Key(sha256.New, secret, salt, info, 32)
	if err != nil {
		panic(err)
	}
	return k
}

// seal is AES-GCM as CryptoKit's `combined`: nonce (12) ‖ ciphertext ‖ tag.
func seal(key, plain []byte, aad string) []byte {
	gcm := mustGCM(key)
	nonce := random(12)
	return gcm.Seal(nonce, nonce, plain, []byte(aad))
}

func open(key, combined []byte, aad string) ([]byte, error) {
	if len(combined) < 12+16 {
		return nil, errors.New("too short")
	}
	return mustGCM(key).Open(nil, combined[:12], combined[12:], []byte(aad))
}

func mustGCM(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return gcm
}

// ---- the journal key ----

type journalKey []byte

func (k journalKey) authToken() []byte { return hkdfKey(k, "tekkoh/auth/v1", nil) }

// entryID is a day's id: base64url of the first 24 bytes of
// HMAC(HKDF(K, "tekkoh/entry-id/v1"), "day:" + date).
func (k journalKey) entryID(day string) string {
	m := hmac.New(sha256.New, hkdfKey(k, "tekkoh/entry-id/v1", nil))
	m.Write([]byte("day:" + day))
	return b64url.EncodeToString(m.Sum(nil)[:24])
}

type envelope struct {
	V int    `json:"v"`
	K string `json:"k"`
	C string `json:"c"`
}

// sealEntry: {"v":1, "k": a fresh entry key sealed with K, "c": the page's
// JSON sealed with the entry key}.
func (k journalKey) sealEntry(id string, plain []byte) []byte {
	ek := random(32)
	env, _ := json.Marshal(envelope{
		V: 1,
		K: b64.EncodeToString(seal(k, ek, "tekkoh/entry-key/"+id)),
		C: b64.EncodeToString(seal(ek, plain, "tekkoh/entry/"+id)),
	})
	clear(ek)
	return env
}

func (k journalKey) openEntry(id string, data []byte) ([]byte, error) {
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, err
	}
	kk, err1 := b64.DecodeString(env.K)
	cc, err2 := b64.DecodeString(env.C)
	if err1 != nil || err2 != nil {
		return nil, errors.New("bad envelope")
	}
	ek, err := open(k, kk, "tekkoh/entry-key/"+id)
	if err != nil {
		return nil, err
	}
	defer clear(ek)
	return open(ek, cc, "tekkoh/entry/"+id)
}

func openPhoto(photoKey, sealed []byte, id string) ([]byte, error) {
	return open(photoKey, sealed, "tekkoh/photo/"+id)
}

// ---- the PIN ----

type stretched struct{ verifier, wrap []byte }

func stretch(pin string, salt []byte, iterations int) stretched {
	s, err := pbkdf2.Key(sha256.New, pin, salt, iterations, 32)
	if err != nil {
		panic(err)
	}
	defer clear(s)
	return stretched{hkdfKey(s, "tekkoh/pin-verifier/v1", nil), hkdfKey(s, "tekkoh/pin-wrap/v1", nil)}
}

func unlock(blob []byte, d stretched, handle string) ([]byte, error) {
	return open(d.wrap, blob, "tekkoh/recovery/"+handle)
}

// ---- boxes to an X25519 key ----
//
// k = HKDF(X25519(eph, to), salt: eph ‖ to, info: "tekkoh/transport/v1/" + purpose)
// box = AES-GCM(k, plain, aad: purpose); a reply uses aad purpose + "/reply".

type sealed struct{ eph, box, key []byte }

func sealTo(toPub []byte, purpose string, plain []byte) (sealed, error) {
	to, err := ecdh.X25519().NewPublicKey(toPub)
	if err != nil {
		return sealed{}, err
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return sealed{}, err
	}
	shared, err := eph.ECDH(to)
	if err != nil {
		return sealed{}, err
	}
	ephPub := eph.PublicKey().Bytes()
	key := hkdfKey(shared, "tekkoh/transport/v1/"+purpose, append(append([]byte{}, ephPub...), toPub...))
	clear(shared)
	return sealed{eph: ephPub, box: seal(key, plain, purpose), key: key}, nil
}

func openReply(key []byte, purpose string, reply []byte) ([]byte, error) {
	return open(key, reply, purpose+"/reply")
}

// openFromPhone opens what the phone sealed to this tool's linking key:
// eph (32) ‖ AES-GCM box, purpose "pair".
func openFromPhone(priv *ecdh.PrivateKey, data []byte) ([]byte, error) {
	if len(data) < 32+28 {
		return nil, errors.New("box too short")
	}
	eph, err := ecdh.X25519().NewPublicKey(data[:32])
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(eph)
	if err != nil {
		return nil, err
	}
	defer clear(shared)
	salt := append(append([]byte{}, data[:32]...), priv.PublicKey().Bytes()...)
	return open(hkdfKey(shared, "tekkoh/transport/v1/pair", salt), data[32:], "pair")
}

// linkCode is the six digits both screens show.
func linkCode(pub []byte) string {
	h := sha256.Sum256(pub)
	return fmt.Sprintf("%06d", (int(h[0])<<16|int(h[1])<<8|int(h[2]))%1_000_000)
}

func same(a, b []byte) bool { return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1 }
