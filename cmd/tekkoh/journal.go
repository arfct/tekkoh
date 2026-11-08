package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// What linking leaves on this machine, in identity.json (mode 0600): the
// journal key, this agent's own session token, and the time zone the phone
// reported, so "today" means your today. The cache holds pages only as the
// sealed envelopes the server has.
type identity struct {
	Handle   string `json:"handle"`
	Key      []byte `json:"key"`
	Session  []byte `json:"session"`
	ID       string `json:"sessionId"`
	Label    string `json:"label"`
	TimeZone string `json:"timeZone,omitempty"`
	Server   string `json:"server,omitempty"`
	Linked   string `json:"linked"`
}

func home() string {
	if d := os.Getenv("TEKKOH_HOME"); d != "" {
		return d
	}
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "tekkoh")
	}
	return ".tekkoh"
}

var errNotLinked = errors.New("not linked to a journal yet: run `tekkoh link`")

func loadIdentity() (*identity, error) {
	d, err := os.ReadFile(filepath.Join(home(), "identity.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, errNotLinked
	} else if err != nil {
		return nil, err
	}
	var id identity
	if err := json.Unmarshal(d, &id); err != nil {
		return nil, err
	}
	if len(id.Key) != 32 || id.Handle == "" {
		return nil, errors.New("identity.json is damaged; run `tekkoh link` again")
	}
	return &id, nil
}

func saveIdentity(id *identity) error {
	if err := os.MkdirAll(home(), 0o700); err != nil {
		return err
	}
	d, _ := json.MarshalIndent(id, "", "  ")
	return writeFile(filepath.Join(home(), "identity.json"), d)
}

// writeFile writes atomically, readable only by this user.
func writeFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ---- the journal ----

type record struct {
	Rev  int    `json:"rev"`
	Data []byte `json:"data"` // sealed, as the server holds it
}

type cache struct {
	Cursor  int64              `json:"cursor"`
	Records map[string]*record `json:"records"`
}

type journal struct {
	id    *identity
	key   journalKey
	api   *client
	loc   *time.Location
	cache cache
	pages map[string]*page // by day
}

func openJournal(id *identity, tz string) (*journal, error) {
	j := &journal{id: id, key: journalKey(id.Key), pages: map[string]*page{}}
	j.api = newClient(id.Server).signedIn(id.Handle, id.Session)
	if tz == "" {
		tz = os.Getenv("TEKKOH_TZ")
	}
	if tz == "" {
		tz = id.TimeZone
	}
	j.loc = time.Local
	if tz != "" {
		loc, err := time.LoadLocation(tz)
		if err != nil {
			return nil, fmt.Errorf("unknown time zone %q", tz)
		}
		j.loc = loc
	}
	j.cache.Records = map[string]*record{}
	if d, err := os.ReadFile(j.cachePath()); err == nil {
		json.Unmarshal(d, &j.cache)
		if j.cache.Records == nil {
			j.cache.Records = map[string]*record{}
		}
	}
	for rid, r := range j.cache.Records {
		if p := j.open(rid, r.Data); p != nil {
			j.pages[p.Day] = p
		}
	}
	return j, nil
}

func (j *journal) cachePath() string { return filepath.Join(home(), "cache.json") }

func (j *journal) saveCache() error {
	d, _ := json.Marshal(j.cache)
	return writeFile(j.cachePath(), d)
}

// open decrypts a page, and refuses one filed under another day's id.
func (j *journal) open(rid string, data []byte) *page {
	plain, err := j.key.openEntry(rid, data)
	if err != nil {
		return nil
	}
	p, err := parsePage(plain)
	if err != nil || j.key.entryID(p.Day) != rid {
		return nil
	}
	return p
}

// pull brings in everything that changed since the last time.
func (j *journal) pull() error {
	for {
		list, cursor, more, err := j.api.changes(j.cache.Cursor)
		if isStatus(err, 401) {
			return errors.New("this agent has been signed out of the journal (from the phone, in Settings); run `tekkoh link` to link it again")
		} else if err != nil {
			return err
		}
		for _, r := range list {
			j.apply(r)
		}
		j.cache.Cursor = cursor
		if !more {
			break
		}
	}
	return j.saveCache()
}

func (j *journal) apply(r remote) {
	have := j.cache.Records[r.ID]
	if have != nil && r.Rev <= have.Rev {
		return
	}
	mine := (*page)(nil)
	if have != nil {
		mine = j.open(r.ID, have.Data)
	}
	if r.Deleted {
		// The app never deletes a page, so a deletion is forged: keep ours,
		// and a later write here puts it back.
		if have != nil {
			have.Rev = r.Rev
		}
		return
	}
	p := j.open(r.ID, r.Data)
	if p == nil {
		return
	}
	if mine != nil && p.Version < mine.Version {
		// An older version than we've seen: a replay. Keep ours.
		have.Rev = r.Rev
		return
	}
	j.cache.Records[r.ID] = &record{Rev: r.Rev, Data: r.Data}
	j.pages[p.Day] = p
}

func (j *journal) page(day string) *page {
	if p, ok := j.pages[day]; ok {
		return p
	}
	return blankPage(day)
}

// change edits a day's page and saves it to the server. If another device
// saved the page meanwhile, it pulls theirs and makes the same edit again,
// so nobody's words are lost.
func (j *journal) change(day string, edit func(p *page) bool) (*page, error) {
	for attempt := 0; attempt < 5; attempt++ {
		cur := j.page(day)
		plain, err := parsePage(cur.encode())
		if err != nil {
			return nil, err
		}
		if !edit(plain) {
			return cur, nil // nothing to change
		}
		plain.Version = cur.Version + 1
		plain.raw["updated"] = jsonOf(swiftNow())
		rid := j.key.entryID(day)
		sealed := j.key.sealEntry(rid, plain.encode())
		rev := 0
		if r := j.cache.Records[rid]; r != nil {
			rev = r.Rev
		}
		newRev, err := j.api.putEntry(rid, sealed, rev)
		if isStatus(err, 409) {
			if err := j.pull(); err != nil {
				return nil, err
			}
			continue
		} else if err != nil {
			return nil, err
		}
		j.cache.Records[rid] = &record{Rev: newRev, Data: sealed}
		j.pages[day] = plain
		return plain, j.saveCache()
	}
	return nil, errors.New("the page kept changing on another device; try again")
}

// ---- days, in your time zone ----

func (j *journal) today() string { return time.Now().In(j.loc).Format("2006-01-02") }

// day reads "today", "yesterday", "-3" (days ago) or YYYY-MM-DD.
func (j *journal) day(s string) (string, error) {
	now := time.Now().In(j.loc)
	switch s {
	case "", "today":
		return now.Format("2006-01-02"), nil
	case "yesterday":
		return now.AddDate(0, 0, -1).Format("2006-01-02"), nil
	}
	var n int
	if _, err := fmt.Sscanf(s, "-%d", &n); err == nil && n >= 0 && !strings.Contains(s[1:], "-") {
		return now.AddDate(0, 0, -n).Format("2006-01-02"), nil
	}
	t, err := time.ParseInLocation("2006-01-02", s, j.loc)
	if err != nil {
		return "", fmt.Errorf("%q isn't a day: use today, yesterday, -N or YYYY-MM-DD", s)
	}
	return t.Format("2006-01-02"), nil
}

func (j *journal) days() []string {
	var out []string
	for d, p := range j.pages {
		if p.hasContent() || len(p.AgentNotes) > 0 {
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

func (j *journal) written() map[string]bool {
	w := map[string]bool{}
	for d, p := range j.pages {
		if p.hasContent() {
			w[d] = true
		}
	}
	return w
}

func addDays(day string, n int) string {
	t, _ := time.Parse("2006-01-02", day)
	return t.AddDate(0, 0, n).Format("2006-01-02")
}

// streak: days in a row up to today, or yesterday if today isn't written.
func (j *journal) streak() int {
	w := j.written()
	d := j.today()
	if !w[d] {
		d = addDays(d, -1)
	}
	n := 0
	for w[d] {
		n++
		d = addDays(d, -1)
	}
	return n
}
