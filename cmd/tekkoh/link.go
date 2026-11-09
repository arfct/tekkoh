package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"
	"rsc.io/qr"
)

// Linking an agent. Usually the agent runs in a chat, with no terminal you
// can type into, so by default it's done by link and approved on the phone:
//
//  1. `tekkoh link` makes a one-time key and opens a slot on the server,
//     then prints a link holding the slot and the public key (after the #,
//     so no server sees it). It keeps the private key in pending.json.
//  2. You tap the link on your iPhone. Tekkoh opens, already holding the
//     journal key, shows the agent's name and six digits, and asks for
//     Face ID. It seals the key to the one-time key and fills the slot.
//     (On a computer, the page shows the link as a QR code to scan.)
//  3. `tekkoh link --wait` collects it. The server says which journal
//     filled the slot, and the key must sign in to that journal.
//
// No PIN is typed anywhere: the phone holding the journal is what approves.
//
// With a terminal, `tekkoh link --pin` works as linking a browser does, and
// needs the same three things, all of the same journal:
//
//  1. your username and PIN, which unlock the journal key through the
//     ordinary recovery path (boxed to the server, ten tries, backoff);
//  2. your phone, which scans the QR code this prints, shows the same six
//     digits, and sends the key sealed to a one-time key made here;
//  3. a match: the key from the phone must be the key the PIN unlocked,
//     and the usernames must agree.
//
// Either way, the agent then gets its own session, which the phone lists
// and can sign out.

type prompter struct {
	in  *bufio.Reader
	out io.Writer
}

func (p prompter) line(q string) (string, error) {
	fmt.Fprint(p.out, q)
	s, err := p.in.ReadString('\n')
	if err != nil && s == "" {
		return "", err
	}
	return strings.TrimSpace(s), nil
}

// secret reads without echo on a terminal; from a pipe, a line.
func (p prompter) secret(q string) (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(p.out, q)
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(p.out)
		return strings.TrimSpace(string(b)), err
	}
	return p.line(q)
}

// linkPage opens Tekkoh on an iPhone (a Universal Link), or shows a code to
// scan on anything else.
const linkPage = "https://tekkoh.com/link"

type linkStart struct {
	api     *client
	handle  string // when linking with the PIN: the journal it opened
	fromPIN []byte // and its key
	priv    *ecdh.PrivateKey
	slot    string
	expires time.Time
	qr      string // the code for the phone to scan in the terminal flow
	url     string // the link for the phone to tap
	code    string // six digits both sides show
}

var errStillWaiting = errors.New("not approved yet")

// startAppLink: no PIN, approved on the phone.
func startAppLink(api *client, name string) (*linkStart, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	s, err := api.openSlotFor("agent")
	if err != nil {
		return nil, err
	}
	l := &linkStart{api: api, priv: priv, slot: s.ID, expires: time.Now().Add(time.Duration(s.ExpiresIn) * time.Second)}
	l.fill(name)
	return l, nil
}

func (l *linkStart) fill(name string) {
	pub := l.priv.PublicKey().Bytes()
	l.qr = fmt.Sprintf("tekkoh-link:1:%s:%s:agent", l.slot, b64url.EncodeToString(pub))
	l.code = linkCode(pub)
	v := url.Values{"s": {l.slot}, "k": {b64url.EncodeToString(pub)}, "n": {name}}
	l.url = linkPage + "#" + strings.ReplaceAll(v.Encode(), "+", "%20")
}

// pending is a link waiting to be approved, between `tekkoh link` and
// `tekkoh link --wait`. It holds the one-time private key, so it's kept
// like the identity: this user only, and deleted when it's done.
type pending struct {
	Server  string    `json:"server"`
	Slot    string    `json:"slot"`
	Priv    []byte    `json:"priv"`
	Expires time.Time `json:"expires"`
	Name    string    `json:"name"`
}

func pendingPath() string { return filepath.Join(home(), "pending.json") }

func (l *linkStart) save(name string) error {
	if err := os.MkdirAll(home(), 0o700); err != nil {
		return err
	}
	d, _ := json.MarshalIndent(pending{Server: l.api.base, Slot: l.slot, Priv: l.priv.Bytes(), Expires: l.expires, Name: name}, "", "  ")
	return writeFile(pendingPath(), d)
}

// loadPending returns the link still waiting, or nil (forgetting one that
// has expired).
func loadPending() (*linkStart, string) {
	d, err := os.ReadFile(pendingPath())
	if err != nil {
		return nil, ""
	}
	var p pending
	if json.Unmarshal(d, &p) != nil || time.Now().After(p.Expires) {
		os.Remove(pendingPath())
		return nil, ""
	}
	priv, err := ecdh.X25519().NewPrivateKey(p.Priv)
	if err != nil {
		os.Remove(pendingPath())
		return nil, ""
	}
	l := &linkStart{api: newClient(p.Server), priv: priv, slot: p.Slot, expires: p.Expires}
	l.fill(p.Name)
	return l, p.Name
}

func startLink(api *client, handle, pin string) (*linkStart, error) {
	p, err := api.params(handle)
	if err != nil {
		return nil, err
	}
	d := stretch(pin, p.Salt, p.Iterations)
	blob, err := api.recover(handle, d.verifier)
	if isStatus(err, 403) {
		return nil, errors.New("that username and PIN don't match")
	} else if err != nil {
		return nil, err
	}
	key, err := unlock(blob, d, handle)
	clear(d.wrap)
	if err != nil {
		return nil, errors.New("the PIN didn't open the journal key")
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	s, err := api.openSlot()
	if err != nil {
		return nil, err
	}
	l := &linkStart{api: api, handle: handle, fromPIN: key, priv: priv, slot: s.ID,
		expires: time.Now().Add(time.Duration(s.ExpiresIn) * time.Second)}
	// The trailing ":agent" in the code tells the phone what it's linking.
	l.fill("")
	return l, nil
}

// finish waits for the phone until the code expires.
func (l *linkStart) finish(label string, poll time.Duration) (*identity, error) {
	return l.collect(label, poll, l.expires)
}

// collect waits for the phone until the given time, then checks what it
// sent: the journal the PIN opened, or (with no PIN) the journal the
// server says filled the slot, whose key must then sign in to it.
func (l *linkStart) collect(label string, poll time.Duration, until time.Time) (*identity, error) {
	if until.After(l.expires) {
		until = l.expires
	}
	for {
		box, handle, err := l.api.takeSlot(l.slot)
		if isStatus(err, 404) {
			return nil, errLinkGone
		} else if err != nil {
			return nil, err
		}
		if box == nil {
			if time.Now().Add(poll).After(until) {
				break
			}
			time.Sleep(poll)
			continue
		}
		plain, err := openFromPhone(l.priv, box)
		if err != nil {
			return nil, errors.New("couldn't open what the phone sent")
		}
		var payload struct {
			Handle   string `json:"handle"`
			Key      []byte `json:"key"`
			TimeZone string `json:"tz"`
		}
		if err := json.Unmarshal(plain, &payload); err != nil {
			return nil, err
		}
		if l.fromPIN != nil {
			agree := payload.Handle == l.handle && handle == l.handle && same(payload.Key, l.fromPIN)
			clear(l.fromPIN)
			if !agree {
				clear(payload.Key)
				return nil, errors.New("the phone and the PIN opened different journals, so nothing was linked")
			}
		} else if payload.Handle != handle || handle == "" || len(payload.Key) != 32 {
			clear(payload.Key)
			return nil, errors.New("the phone sent a different journal from the one that approved, so nothing was linked")
		}
		k := journalKey(payload.Key)
		owner := l.api.signedIn(handle, k.authToken())
		id, token, err := owner.createSession(label, "agent")
		if isStatus(err, 401) {
			return nil, errors.New("the key the phone sent doesn't open that journal, so nothing was linked")
		} else if err != nil {
			return nil, err
		}
		return &identity{
			Handle: handle, Key: payload.Key, Session: token, ID: id, Label: label,
			TimeZone: payload.TimeZone, Server: strings.TrimSuffix(l.api.base, "/"),
			Linked: time.Now().UTC().Format(time.RFC3339),
		}, nil
	}
	if time.Now().Before(l.expires) {
		return nil, errStillWaiting
	}
	return nil, errLinkGone
}

var errLinkGone = errors.New("the link expired before it was approved; run `tekkoh link` for a new one")

// qrBlock draws a QR code with half-height blocks, dark on light whatever
// the terminal's colours, with the quiet zone scanners need.
func qrBlock(text string) (string, error) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	const quiet = 2
	n := c.Size
	dark := func(x, y int) bool {
		x, y = x-quiet, y-quiet
		return x >= 0 && y >= 0 && x < n && y < n && c.Black(x, y)
	}
	var b strings.Builder
	for y := 0; y < n+2*quiet; y += 2 {
		b.WriteString("\x1b[30;47m") // black on white
		for x := 0; x < n+2*quiet; x++ {
			top, bottom := dark(x, y), dark(x, y+1)
			switch {
			case top && bottom:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bottom:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString("\x1b[0m\n")
	}
	return b.String(), nil
}
