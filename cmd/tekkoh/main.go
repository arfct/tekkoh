// Command tekkoh reads and writes a Tekkoh journal from a terminal, for a
// personal agent (in a confidential VM, say) working on your behalf. It
// links like a browser does (username, PIN and your phone), holds the
// journal key on this machine, and does all the encryption here: the
// server sees only sealed pages, as it does from the app.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/term"
)

const usage = `tekkoh: your Tekkoh journal, for an agent working on your behalf.

Linking (once; the person approves it on their phone):
  tekkoh link [--name NAME]          print a one-time link to send them; on
                                     their iPhone it opens Tekkoh to approve
  tekkoh link --wait [--timeout 90s] finish once they've approved; run it
                                     again if it times out
  tekkoh link --pin [--name NAME]    or, in a terminal they type into: their
                                     username, PIN, and a code to scan
  tekkoh status                      which journal, as which agent
  tekkoh unlink                      sign out and forget the key here

Reading:
  tekkoh read [DAY]                  a day's page: words, places, activity,
                                     photos' captions, and agents' notes
  tekkoh days [--from DAY] [--to DAY] the days with something on them
  tekkoh search WORDS...             pages whose words, captions or notes
                                     contain all the words
  tekkoh streak                      days written in a row
  tekkoh photos [DAY] --out DIR      save a day's photos, decrypted

Writing:
  tekkoh write [DAY] [--replace] [TEXT | -]
                                     add to the day's words (or replace them)
  tekkoh note [DAY] [--replace | --clear] [TEXT | -]
                                     say what you did for the user that day:
                                     shown beside the page, apart from their
                                     own words

DAY is today (the default), yesterday, -N (N days ago) or YYYY-MM-DD, in the
time zone the phone reported when linking (or --tz / $TEKKOH_TZ). TEXT is the
rest of the arguments, or stdin with -. Add --json to any reading command
for output a program can parse.

The key and this agent's session live in $TEKKOH_HOME (default
~/.config/tekkoh), readable only by this user.
`

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "tekkoh:", err)
		os.Exit(1)
	}
}

// args: the command's positionals and flags, flags anywhere.
type args struct {
	pos   []string
	flags map[string]string
}

func parseArgs(list []string, valued map[string]bool) (args, error) {
	a := args{flags: map[string]string{}}
	for i := 0; i < len(list); i++ {
		s := list[i]
		if s == "--" {
			a.pos = append(a.pos, list[i+1:]...)
			break
		}
		if !strings.HasPrefix(s, "--") || s == "-" {
			a.pos = append(a.pos, s)
			continue
		}
		name, val, has := strings.Cut(s[2:], "=")
		if valued[name] && !has {
			if i+1 >= len(list) {
				return a, fmt.Errorf("--%s needs a value", name)
			}
			i++
			val = list[i]
		}
		a.flags[name] = val
	}
	return a, nil
}

func (a args) has(f string) bool { _, ok := a.flags[f]; return ok }

var dayRE = regexp.MustCompile(`^(today|yesterday|-\d+|\d{4}-\d{2}-\d{2})$`)

// dayFirst takes a leading DAY positional, if there is one.
func (a *args) dayFirst() string {
	if len(a.pos) > 0 && dayRE.MatchString(a.pos[0]) {
		d := a.pos[0]
		a.pos = a.pos[1:]
		return d
	}
	return ""
}

// text: the positionals, or stdin with "-" (or nothing, from a pipe).
func (a args) text(stdin io.Reader) (string, error) {
	if len(a.pos) == 1 && a.pos[0] == "-" || len(a.pos) == 0 && !isTerminal(stdin) {
		b, err := io.ReadAll(io.LimitReader(stdin, 1<<20))
		return strings.TrimRight(string(b), "\n"), err
	}
	return strings.Join(a.pos, " "), nil
}

func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

func run(argv []string, stdin io.Reader, out io.Writer) error {
	if len(argv) == 0 || argv[0] == "help" || argv[0] == "-h" || argv[0] == "--help" {
		fmt.Fprint(out, usage)
		return nil
	}
	cmd := argv[0]
	a, err := parseArgs(argv[1:], map[string]bool{"name": true, "from": true, "to": true, "out": true, "tz": true, "username": true, "server": true, "timeout": true})
	if err != nil {
		return err
	}
	if cmd == "link" {
		return link(a, stdin, out)
	}
	id, err := loadIdentity()
	if err != nil {
		if l, name := loadPending(); l != nil && cmd == "status" {
			fmt.Fprintf(out, "Not linked yet. A link for %q is waiting for approval until %s:\n  %s\nRun `tekkoh link --wait` once it's approved.\n", name, l.expires.Local().Format("15:04 MST"), l.url)
			return nil
		}
		return err
	}
	if cmd == "status" {
		return status(id, a, out)
	}
	if cmd == "unlink" {
		err := newClient(id.Server).signedIn(id.Handle, id.Session).signOut()
		if err != nil && !isStatus(err, 401) {
			return err
		}
		os.Remove(filepath.Join(home(), "cache.json"))
		if err := os.Remove(filepath.Join(home(), "identity.json")); err != nil {
			return err
		}
		fmt.Fprintln(out, "Signed out. The journal key is gone from this machine.")
		return nil
	}
	j, err := openJournal(id, a.flags["tz"])
	if err != nil {
		return err
	}
	if err := j.pull(); err != nil {
		return err
	}
	switch cmd {
	case "read":
		return read(j, a, out)
	case "days":
		return days(j, a, out)
	case "search":
		return search(j, a, out)
	case "streak":
		if a.has("json") {
			return emit(out, map[string]any{"streak": j.streak(), "today": j.today(), "writtenToday": j.written()[j.today()]})
		}
		fmt.Fprintf(out, "%d days in a row\n", j.streak())
		return nil
	case "photos":
		return photos(j, a, out)
	case "write":
		return write(j, a, stdin, out)
	case "note":
		return note(j, a, stdin, out)
	}
	return fmt.Errorf("no command %q; see `tekkoh help`", cmd)
}

func emit(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// ---- linking ----

func link(a args, stdin io.Reader, out io.Writer) error {
	if old, err := loadIdentity(); err == nil {
		return fmt.Errorf("already linked to %s's journal as %q; run `tekkoh unlink` first", old.Handle, old.Label)
	}
	if a.has("pin") {
		return linkWithPIN(a, stdin, out)
	}
	if a.has("wait") {
		return linkWait(a, out)
	}
	name := strings.TrimSpace(a.flags["name"])
	if name == "" {
		host, _ := os.Hostname()
		name = "Agent on " + strings.Split(host, ".")[0]
	}
	if len(name) > 60 {
		name = name[:60]
	}
	// The same link again, while it lasts: the person may already have it.
	l, was := loadPending()
	if l == nil || was != name || a.has("new") {
		var err error
		if l, err = startAppLink(newClient(a.flags["server"]), name); err != nil {
			return err
		}
		if err := l.save(name); err != nil {
			return err
		}
	}
	if a.has("json") {
		return emit(out, map[string]any{"url": l.url, "code": l.code, "name": name, "expires": l.expires.Format(time.RFC3339)})
	}
	fmt.Fprintf(out, `Send this link to the person whose journal it is:

  %s

On their iPhone it opens Tekkoh, which asks them to approve %q. On a
computer it shows a code to scan with the phone. Tell them the phone will
show %s %s. The link works once, until %s.

Then run: tekkoh link --wait
`, l.url, name, l.code[:3], l.code[3:], l.expires.Local().Format("15:04 MST"))
	return nil
}

// linkWait collects an approved link. It gives up after --timeout (90s by
// default, inside most agents' limits on a command) and can be run again.
func linkWait(a args, out io.Writer) error {
	l, name := loadPending()
	if l == nil {
		return errors.New("no link is waiting (or it expired); run `tekkoh link` for one")
	}
	wait := 90 * time.Second
	if t := a.flags["timeout"]; t != "" {
		d, err := time.ParseDuration(t)
		if err != nil {
			return fmt.Errorf("--timeout: %w", err)
		}
		wait = d
	}
	id, err := l.collect(name, 1500*time.Millisecond, time.Now().Add(wait))
	if errors.Is(err, errStillWaiting) {
		return fmt.Errorf("not approved yet; the link works until %s, so run `tekkoh link --wait` again (or `tekkoh link` to see it)", l.expires.Local().Format("15:04 MST"))
	}
	os.Remove(pendingPath())
	if err != nil {
		return err
	}
	return linked(id, out)
}

// linkWithPIN: in a terminal, with the username, PIN and the phone's camera.
func linkWithPIN(a args, stdin io.Reader, out io.Writer) error {
	p := prompter{bufio.NewReader(stdin), out}
	name := a.flags["name"]
	if name == "" {
		host, _ := os.Hostname()
		name = "Agent on " + strings.Split(host, ".")[0]
	}
	handle := a.flags["username"]
	var err error
	if handle == "" {
		if handle, err = p.line("Username: "); err != nil {
			return err
		}
	}
	handle = strings.ToLower(strings.TrimSpace(handle))
	pin, err := p.secret("PIN: ")
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "Checking the PIN…")
	l, err := startLink(newClient(a.flags["server"]), handle, pin)
	if err != nil {
		return err
	}
	block, err := qrBlock(l.qr)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "\nOn your phone, open Tekkoh, then Settings, Link a browser or agent, and scan this:\n\n%s\n", block)
	fmt.Fprintf(out, "Check the phone shows %s %s. Waiting…\n", l.code[:3], l.code[3:])
	id, err := l.finish(name, 1500*time.Millisecond)
	if err != nil {
		return err
	}
	return linked(id, out)
}

func linked(id *identity, out io.Writer) error {
	if err := saveIdentity(id); err != nil {
		return err
	}
	tz := id.TimeZone
	if tz == "" {
		tz = "this machine's"
	}
	fmt.Fprintf(out, "Linked to %s's journal as %q, in %s time zone.\nThe key is in %s, readable only by you. Their phone can sign this agent out at any time.\n",
		id.Handle, id.Label, tz, filepath.Join(home(), "identity.json"))
	return nil
}

func status(id *identity, a args, out io.Writer) error {
	j, err := openJournal(id, a.flags["tz"])
	if err != nil {
		return err
	}
	_, err = j.api.do("GET", "/v1/me", nil, nil)
	state := "active"
	if isStatus(err, 401) {
		state = "signed out from the phone"
	} else if err != nil {
		state = "can't reach the server: " + err.Error()
	}
	if a.has("json") {
		return emit(out, map[string]any{"username": id.Handle, "agent": id.Label, "agentId": id.ID, "timeZone": j.loc.String(), "today": j.today(), "linked": id.Linked, "session": state})
	}
	fmt.Fprintf(out, "Journal:   %s\nAgent:     %s\nTime zone: %s (today is %s)\nLinked:    %s\nSession:   %s\n", id.Handle, id.Label, j.loc, j.today(), id.Linked, state)
	return nil
}

// ---- reading ----

type pageView struct {
	Day        string        `json:"day"`
	Weekday    string        `json:"weekday"`
	Text       string        `json:"text"`
	Places     []placeView   `json:"places"`
	Activity   *activityView `json:"activity,omitempty"`
	Sun        *sunView      `json:"sun,omitempty"`
	Photos     []photoView   `json:"photos"`
	AgentNotes []noteView    `json:"agentNotes"`
}

type placeView struct {
	Name    string  `json:"name"`
	Detail  string  `json:"detail,omitempty"`
	Arrived string  `json:"arrived,omitempty"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
}

type activityView struct {
	Steps    *int     `json:"steps,omitempty"`
	Km       *float64 `json:"km,omitempty"`
	Floors   *int     `json:"floors,omitempty"`
	Workouts []string `json:"workouts,omitempty"`
}

type sunView struct {
	Rise string `json:"rise,omitempty"`
	Set  string `json:"set,omitempty"`
}

type photoView struct {
	N       int    `json:"n"`
	Caption string `json:"caption"`
	TakenAt string `json:"takenAt,omitempty"`
	Width   int    `json:"width"`
	Height  int    `json:"height"`
}

type noteView struct {
	Agent   string `json:"agent"`
	Text    string `json:"text"`
	Updated string `json:"updated"`
	Mine    bool   `json:"mine"`
}

func (j *journal) clock(s *float64) string {
	if s == nil {
		return ""
	}
	return fromSwift(*s).In(j.loc).Format("15:04")
}

func (j *journal) view(p *page) pageView {
	t, _ := time.ParseInLocation("2006-01-02", p.Day, j.loc)
	v := pageView{Day: p.Day, Weekday: t.Weekday().String(), Text: p.Text, Places: []placeView{}, Photos: []photoView{}, AgentNotes: []noteView{}}
	for _, pl := range p.Places {
		v.Places = append(v.Places, placeView{pl.Name, pl.Detail, j.clock(pl.Arrived), pl.Lat, pl.Lon})
	}
	if h := p.Health; h != nil {
		a := &activityView{Steps: h.Steps, Floors: h.Flights}
		if h.Meters != nil {
			km := float64(int(*h.Meters/100)) / 10
			a.Km = &km
		}
		for _, w := range h.Workouts {
			a.Workouts = append(a.Workouts, fmt.Sprintf("%s %d min", w.Kind, int(w.Minutes)))
		}
		v.Activity = a
	}
	if s := p.Sun; s != nil {
		v.Sun = &sunView{j.clock(s.Rise), j.clock(s.Set)}
	}
	for i, ph := range p.Photos {
		v.Photos = append(v.Photos, photoView{i + 1, ph.Caption, j.clock(ph.TakenAt), ph.Width, ph.Height})
	}
	for _, n := range p.AgentNotes {
		if strings.TrimSpace(n.Text) == "" {
			continue
		}
		v.AgentNotes = append(v.AgentNotes, noteView{n.Agent, n.Text, fromSwift(n.Updated).In(j.loc).Format(time.RFC3339), n.ID == j.id.ID})
	}
	return v
}

func read(j *journal, a args, out io.Writer) error {
	day, err := j.day(a.dayFirst())
	if err != nil {
		return err
	}
	v := j.view(j.page(day))
	if a.has("json") {
		return emit(out, v)
	}
	t, _ := time.Parse("2006-01-02", day)
	fmt.Fprintf(out, "%s\n\n", t.Format("Monday 2 January 2006"))
	if len(v.Places) > 0 {
		var names []string
		for _, p := range v.Places {
			s := p.Name
			if p.Detail != "" {
				s += " (" + p.Detail + ")"
			}
			if p.Arrived != "" {
				s += " " + p.Arrived
			}
			names = append(names, s)
		}
		fmt.Fprintf(out, "Places:   %s\n", strings.Join(names, " · "))
	}
	if ac := v.Activity; ac != nil {
		var parts []string
		if ac.Steps != nil {
			parts = append(parts, fmt.Sprintf("%d steps", *ac.Steps))
		}
		if ac.Km != nil {
			parts = append(parts, fmt.Sprintf("%.1f km", *ac.Km))
		}
		if ac.Floors != nil {
			parts = append(parts, fmt.Sprintf("%d floors", *ac.Floors))
		}
		parts = append(parts, ac.Workouts...)
		fmt.Fprintf(out, "Activity: %s\n", strings.Join(parts, " · "))
	}
	if v.Sun != nil && v.Sun.Rise != "" {
		fmt.Fprintf(out, "Sun:      %s – %s\n", v.Sun.Rise, v.Sun.Set)
	}
	for _, p := range v.Photos {
		c := p.Caption
		if c == "" {
			c = "(no caption)"
		}
		fmt.Fprintf(out, "Photo %d:  %s\n", p.N, c)
	}
	if len(v.Places)+len(v.Photos) > 0 || v.Activity != nil {
		fmt.Fprintln(out)
	}
	if strings.TrimSpace(v.Text) == "" {
		fmt.Fprintln(out, "(nothing written)")
	} else {
		fmt.Fprintln(out, v.Text)
	}
	for _, n := range v.AgentNotes {
		fmt.Fprintf(out, "\n— %s:\n%s\n", n.Agent, n.Text)
	}
	return nil
}

func days(j *journal, a args, out io.Writer) error {
	from, to := "", "9999"
	var err error
	if f := a.flags["from"]; f != "" {
		if from, err = j.day(f); err != nil {
			return err
		}
	}
	if t := a.flags["to"]; t != "" {
		if to, err = j.day(t); err != nil {
			return err
		}
	}
	type row struct {
		Day       string `json:"day"`
		Written   bool   `json:"written"`
		Words     int    `json:"words"`
		Photos    int    `json:"photos"`
		Notes     int    `json:"agentNotes"`
		FirstLine string `json:"firstLine"`
	}
	rows := []row{}
	for _, d := range j.days() {
		if d < from || d > to {
			continue
		}
		p := j.pages[d]
		first, _, _ := strings.Cut(strings.TrimSpace(p.Text), "\n")
		rows = append(rows, row{d, p.hasContent(), len(strings.Fields(p.Text)), len(p.Photos), len(p.AgentNotes), first})
	}
	if a.has("json") {
		return emit(out, rows)
	}
	for _, r := range rows {
		first := r.FirstLine
		if len([]rune(first)) > 70 {
			first = string([]rune(first)[:69]) + "…"
		}
		fmt.Fprintf(out, "%s  %s\n", r.Day, first)
	}
	return nil
}

func search(j *journal, a args, out io.Writer) error {
	if len(a.pos) == 0 {
		return errors.New("search for what?")
	}
	var words []string
	for _, w := range a.pos {
		words = append(words, strings.ToLower(w))
	}
	type hit struct {
		Day     string `json:"day"`
		Snippet string `json:"snippet"`
	}
	hits := []hit{}
	ds := j.days()
	sort.Sort(sort.Reverse(sort.StringSlice(ds)))
	for _, d := range ds {
		p := j.pages[d]
		all := p.Text
		for _, ph := range p.Photos {
			all += "\n" + ph.Caption
		}
		for _, n := range p.AgentNotes {
			all += "\n" + n.Text
		}
		low := strings.ToLower(all)
		ok := true
		for _, w := range words {
			if !strings.Contains(low, w) {
				ok = false
				break
			}
		}
		if ok {
			hits = append(hits, hit{d, snippet(all, words[0])})
		}
	}
	if a.has("json") {
		return emit(out, hits)
	}
	for _, h := range hits {
		fmt.Fprintf(out, "%s  %s\n", h.Day, h.Snippet)
	}
	if len(hits) == 0 {
		fmt.Fprintln(out, "Nothing found.")
	}
	return nil
}

func snippet(s, word string) string {
	r := []rune(strings.Join(strings.Fields(s), " "))
	low := []rune(strings.ToLower(string(r)))
	i := strings.Index(string(low), word)
	if i < 0 {
		i = 0
	}
	at := len([]rune(string(low)[:i]))
	start, end := max(0, at-30), min(len(r), at+60)
	out := string(r[start:end])
	if start > 0 {
		out = "…" + out
	}
	if end < len(r) {
		out += "…"
	}
	return out
}

func photos(j *journal, a args, out io.Writer) error {
	day, err := j.day(a.dayFirst())
	if err != nil {
		return err
	}
	dir := a.flags["out"]
	if dir == "" {
		return errors.New("where to? --out DIR")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	p := j.page(day)
	for i, ph := range p.Photos {
		sealed, err := j.api.blob(ph.ID)
		if err != nil {
			return fmt.Errorf("photo %d: %w", i+1, err)
		}
		jpeg, err := openPhoto(ph.Key, sealed, ph.ID)
		if err != nil {
			return fmt.Errorf("photo %d didn't open", i+1)
		}
		name := filepath.Join(dir, fmt.Sprintf("%s-%d.jpg", day, i+1))
		if err := os.WriteFile(name, jpeg, 0o600); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s  %s\n", name, ph.Caption)
	}
	if len(p.Photos) == 0 {
		fmt.Fprintln(out, "No photos that day.")
	}
	return nil
}

// ---- writing ----

func write(j *journal, a args, stdin io.Reader, out io.Writer) error {
	day, err := j.day(a.dayFirst())
	if err != nil {
		return err
	}
	text, err := a.text(stdin)
	if err != nil {
		return err
	}
	if strings.TrimSpace(text) == "" && !a.has("replace") {
		return errors.New("write what? give the words, or - to read them from stdin")
	}
	_, err = j.change(day, func(p *page) bool {
		old := p.Text
		switch {
		case a.has("replace"):
			p.Text = text
		case strings.TrimSpace(p.Text) == "":
			p.Text = text
		default:
			p.Text = strings.TrimRight(p.Text, "\n") + "\n\n" + text
		}
		return p.Text != old
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Saved to %s.\n", day)
	return nil
}

func note(j *journal, a args, stdin io.Reader, out io.Writer) error {
	day, err := j.day(a.dayFirst())
	if err != nil {
		return err
	}
	text := ""
	if !a.has("clear") {
		if text, err = a.text(stdin); err != nil {
			return err
		}
		if strings.TrimSpace(text) == "" {
			return errors.New("note what? give the words, or - to read them from stdin")
		}
	}
	_, err = j.change(day, func(p *page) bool {
		n := p.note(j.id.ID)
		if n == nil {
			if a.has("clear") {
				return false
			}
			p.AgentNotes = append(p.AgentNotes, agentNote{ID: j.id.ID})
			n = &p.AgentNotes[len(p.AgentNotes)-1]
		}
		old := n.Text
		switch {
		case a.has("clear"), a.has("replace"), strings.TrimSpace(n.Text) == "":
			n.Text = text
		default:
			n.Text = strings.TrimRight(n.Text, "\n") + "\n" + text
		}
		if n.Text == old && n.Agent == j.id.Label {
			return false
		}
		n.Agent = j.id.Label
		n.Updated = swiftNow()
		return true
	})
	if err != nil {
		return err
	}
	if a.has("clear") {
		fmt.Fprintf(out, "Cleared this agent's note on %s.\n", day)
	} else {
		fmt.Fprintf(out, "Noted on %s.\n", day)
	}
	return nil
}
