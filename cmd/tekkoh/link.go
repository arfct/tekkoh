package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
	"rsc.io/qr"
)

// Linking an agent works as linking a browser does, and needs the same
// three things, all of the same journal:
//
//  1. your username and PIN, which unlock the journal key through the
//     ordinary recovery path (boxed to the server, ten tries, backoff);
//  2. your phone, which scans the QR code this prints, shows the same six
//     digits, and sends the key sealed to a one-time key made here;
//  3. a match: the key from the phone must be the key the PIN unlocked,
//     and the usernames must agree.
//
// Only then does the agent get its own session, which the phone lists and
// can sign out.

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

type linkStart struct {
	api      *client
	handle   string
	fromPIN  []byte
	priv     *ecdh.PrivateKey
	slot     string
	expires  time.Duration
	qr, code string
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
	pub := priv.PublicKey().Bytes()
	return &linkStart{
		api: api, handle: handle, fromPIN: key, priv: priv, slot: s.ID,
		expires: time.Duration(s.ExpiresIn) * time.Second,
		// The trailing ":agent" tells the phone what it's linking.
		qr:   fmt.Sprintf("tekkoh-link:1:%s:%s:agent", s.ID, b64url.EncodeToString(pub)),
		code: linkCode(pub),
	}, nil
}

// finish waits for the phone, then checks it sent the journal the PIN opened.
func (l *linkStart) finish(label string, poll time.Duration) (*identity, error) {
	deadline := time.Now().Add(l.expires)
	for time.Now().Before(deadline) {
		box, handle, err := l.api.takeSlot(l.slot)
		if err != nil {
			return nil, err
		}
		if box == nil {
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
		agree := payload.Handle == l.handle && handle == l.handle && same(payload.Key, l.fromPIN)
		clear(l.fromPIN)
		if !agree {
			clear(payload.Key)
			return nil, errors.New("the phone and the PIN opened different journals, so nothing was linked")
		}
		k := journalKey(payload.Key)
		owner := l.api.signedIn(l.handle, k.authToken())
		id, token, err := owner.createSession(label, "agent")
		if err != nil {
			return nil, err
		}
		return &identity{
			Handle: l.handle, Key: payload.Key, Session: token, ID: id, Label: label,
			TimeZone: payload.TimeZone, Server: strings.TrimSuffix(l.api.base, "/"),
			Linked: time.Now().UTC().Format(time.RFC3339),
		}, nil
	}
	return nil, errors.New("the code expired before the phone scanned it; run `tekkoh link` again")
}

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
