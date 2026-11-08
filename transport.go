package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
)

// Recovery fields (the PIN verifier and the PIN-locked key) are encrypted
// by the phone to this server's X25519 key, which the app has built in, so
// that nothing between the phone and this process (Cloudflare's edge, a
// TLS-intercepting proxy, a log) ever sees them: either one is enough to
// try every PIN offline.
//
// The key pair comes from TEKKOH_SECRET, so it needs no storage of its own
// and changes only if the secret does. GET /v1/transport-key shows the
// public half.
//
// A box is {eph, box}: the phone's one-time public key, and
// AES-256-GCM(k, JSON, aad: purpose) where
// k = HKDF-SHA256(X25519(eph, server), salt: eph ‖ server, info: "tekkoh/transport/v1/" + purpose).
// A reply is sealed with the same k and aad purpose + "/reply".

type sealedBox struct {
	Eph b64 `json:"eph"`
	Box b64 `json:"box"`
}

func (s *Server) transportKey() *ecdh.PrivateKey {
	k, err := ecdh.X25519().NewPrivateKey(s.derive("tekkoh/transport/v1"))
	if err != nil {
		panic(err)
	}
	return k
}

func (s *Server) TransportPublic() []byte { return s.transportKey().PublicKey().Bytes() }

// open decrypts a box into v, returning the key to seal the reply with.
func (s *Server) open(purpose string, b sealedBox, v any) ([]byte, error) {
	eph, err := ecdh.X25519().NewPublicKey(b.Eph)
	if err != nil {
		return nil, errors.New("bad key")
	}
	priv := s.transportKey()
	shared, err := priv.ECDH(eph)
	if err != nil {
		return nil, errors.New("bad key")
	}
	salt := append(append([]byte{}, b.Eph...), priv.PublicKey().Bytes()...)
	k, err := hkdf.Key(sha256.New, shared, salt, "tekkoh/transport/v1/"+purpose, 32)
	if err != nil {
		return nil, err
	}
	g := gcmFor(k)
	if len(b.Box) < g.NonceSize()+g.Overhead() {
		return nil, errors.New("short box")
	}
	plain, err := g.Open(nil, b.Box[:g.NonceSize()], b.Box[g.NonceSize():], []byte(purpose))
	if err != nil {
		return nil, errors.New("box doesn't open")
	}
	return k, json.Unmarshal(plain, v)
}

func sealReply(k []byte, purpose string, v any) (b64, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	g := gcmFor(k)
	nonce := make([]byte, g.NonceSize())
	rand.Read(nonce)
	return g.Seal(nonce, nonce, plain, []byte(purpose+"/reply")), nil
}

func gcmFor(k []byte) cipher.AEAD {
	block, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(block)
	return g
}
