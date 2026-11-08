package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const defaultServer = "https://tekkoh.cronbon.com"

// serverKey is the server's transport key, built in (as in the app and the
// web) so a server can't swap it to read the PIN's boxed fields.
const serverKey = "SiOqxMKXLVclQsetdJkLdHhmk1TgexDAZZSlF/i6O2E="

type apiError struct {
	status int
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func isStatus(err error, code int) bool {
	var e *apiError
	return errors.As(err, &e) && e.status == code
}

type client struct {
	base   string
	key    []byte // the server's transport key
	handle string
	token  []byte
	http   *http.Client
}

func newClient(base string) *client {
	if base == "" {
		base = os.Getenv("TEKKOH_SERVER")
	}
	if base == "" {
		base = defaultServer
	}
	k, _ := b64.DecodeString(serverKey)
	// Another server (self-hosted, or a test one) has its own transport key.
	if base != defaultServer {
		if o, err := b64.DecodeString(os.Getenv("TEKKOH_SERVER_KEY")); err == nil && len(o) == 32 {
			k = o
		}
	}
	return &client{base: base, key: k, http: &http.Client{Timeout: 30 * time.Second}}
}

func (c *client) signedIn(handle string, token []byte) *client {
	n := *c
	n.handle, n.token = handle, token
	return &n
}

// do sends JSON (or raw bytes) and decodes a JSON reply into out.
func (c *client) do(method, path string, body any, out any) (int, error) {
	var rd io.Reader
	ctype := ""
	switch b := body.(type) {
	case nil:
	case []byte:
		rd, ctype = bytes.NewReader(b), "application/octet-stream"
	default:
		j, err := json.Marshal(b)
		if err != nil {
			return 0, err
		}
		rd, ctype = bytes.NewReader(j), "application/json"
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return 0, err
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if c.handle != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Tekkoh %s %s", c.handle, b64.EncodeToString(c.token)))
	}
	req.Header.Set("User-Agent", "tekkoh-cli/1")
	res, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("can't reach Tekkoh's server: %w", err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 64<<20))
	if err != nil {
		return res.StatusCode, err
	}
	if res.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = fmt.Sprintf("the server said %d", res.StatusCode)
		}
		return res.StatusCode, &apiError{res.StatusCode, e.Error}
	}
	if raw, ok := out.(*[]byte); ok {
		*raw = data
		return res.StatusCode, nil
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return res.StatusCode, err
		}
	}
	return res.StatusCode, nil
}

// ---- recovery: the PIN's verifier and the locked key travel boxed ----

type params struct {
	Salt         []byte `json:"salt"`
	Iterations   int    `json:"iterations"`
	AttemptsLeft int    `json:"attemptsLeft"`
}

func (c *client) params(handle string) (params, error) {
	var p params
	_, err := c.do("POST", "/v1/recovery/params", map[string]string{"handle": handle}, &p)
	if err != nil {
		return p, err
	}
	if len(p.Salt) < 16 || p.Iterations < 600000 || p.Iterations > 20000000 {
		return p, errors.New("the server asked for unsafe PIN settings")
	}
	return p, nil
}

func (c *client) recover(handle string, verifier []byte) ([]byte, error) {
	plain, _ := json.Marshal(map[string]string{"verifier": b64.EncodeToString(verifier)})
	s, err := sealTo(c.key, "recover", plain)
	if err != nil {
		return nil, err
	}
	var o struct {
		Reply []byte `json:"reply"`
	}
	if _, err := c.do("POST", "/v1/recovery", map[string]any{"handle": handle, "proof": map[string][]byte{"eph": s.eph, "box": s.box}}, &o); err != nil {
		return nil, err
	}
	r, err := openReply(s.key, "recover", o.Reply)
	if err != nil {
		return nil, err
	}
	var reply struct {
		Blob []byte `json:"blob"`
	}
	if err := json.Unmarshal(r, &reply); err != nil {
		return nil, err
	}
	return reply.Blob, nil
}

// ---- linking ----

type slot struct {
	ID        string `json:"id"`
	ExpiresIn int    `json:"expiresIn"`
}

func (c *client) openSlot() (slot, error) {
	var s slot
	_, err := c.do("POST", "/v1/pair", nil, &s)
	return s, err
}

// takeSlot returns the sealed box once the phone has filled the slot, or
// nil while it's still waiting.
func (c *client) takeSlot(id string) (box []byte, handle string, err error) {
	var o struct {
		Box    []byte `json:"box"`
		Handle string `json:"handle"`
	}
	code, err := c.do("GET", "/v1/pair/"+id, nil, &o)
	if err != nil || code == 202 {
		return nil, "", err
	}
	return o.Box, o.Handle, nil
}

func (c *client) createSession(label, kind string) (id string, token []byte, err error) {
	var o struct {
		ID    string `json:"id"`
		Token []byte `json:"token"`
	}
	_, err = c.do("POST", "/v1/sessions", map[string]string{"label": label, "kind": kind}, &o)
	return o.ID, o.Token, err
}

func (c *client) signOut() error {
	_, err := c.do("DELETE", "/v1/sessions/current", nil, nil)
	return err
}

// ---- pages and photos ----

type remote struct {
	ID      string `json:"id"`
	Rev     int    `json:"rev"`
	Seq     int64  `json:"seq"`
	Deleted bool   `json:"deleted"`
	Data    []byte `json:"data"`
}

func (c *client) changes(after int64) (list []remote, cursor int64, more bool, err error) {
	var o struct {
		Entries []remote `json:"entries"`
		Cursor  int64    `json:"cursor"`
		More    bool     `json:"more"`
	}
	_, err = c.do("GET", fmt.Sprintf("/v1/entries?after=%d", after), nil, &o)
	return o.Entries, o.Cursor, o.More, err
}

func (c *client) putEntry(id string, data []byte, rev int) (int, error) {
	var o struct {
		Rev int `json:"rev"`
	}
	_, err := c.do("PUT", "/v1/entries/"+id, map[string]any{"data": data, "rev": rev}, &o)
	return o.Rev, err
}

func (c *client) blob(id string) ([]byte, error) {
	var b []byte
	_, err := c.do("GET", "/v1/blobs/"+id, nil, &b)
	return b, err
}
