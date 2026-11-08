package main

import (
	"bytes"
	"encoding/json"
	"time"
)

// A page, as the app writes it (Entry in Models.swift). Fields this tool
// doesn't use are kept as they came, so saving a page never drops anything
// a newer app added.
type page struct {
	raw map[string]json.RawMessage

	Day        string      `json:"-"`
	Text       string      `json:"-"`
	Version    int         `json:"-"`
	Photos     []photo     `json:"-"`
	Places     []place     `json:"-"`
	Health     *health     `json:"-"`
	Sun        *sun        `json:"-"`
	AgentNotes []agentNote `json:"-"`
}

type photo struct {
	ID      string   `json:"id"`
	Key     []byte   `json:"key"`
	Caption string   `json:"caption"`
	TakenAt *float64 `json:"takenAt,omitempty"`
	Width   int      `json:"width"`
	Height  int      `json:"height"`
}

type place struct {
	Name    string   `json:"name"`
	Detail  string   `json:"detail"`
	Lat     float64  `json:"lat"`
	Lon     float64  `json:"lon"`
	Arrived *float64 `json:"arrived,omitempty"`
}

type workout struct {
	Kind    string   `json:"kind"`
	Minutes float64  `json:"minutes"`
	Meters  *float64 `json:"meters,omitempty"`
}

type health struct {
	Steps    *int      `json:"steps,omitempty"`
	Meters   *float64  `json:"meters,omitempty"`
	Flights  *int      `json:"flights,omitempty"`
	Workouts []workout `json:"workouts"`
}

type sun struct {
	Rise *float64 `json:"rise,omitempty"`
	Set  *float64 `json:"set,omitempty"`
}

// An agent's note on a day: what it did for you. One per agent per day,
// keyed by the agent's session id; the newest edit wins when devices merge.
type agentNote struct {
	ID      string  `json:"id"`
	Agent   string  `json:"agent"`
	Text    string  `json:"text"`
	Updated float64 `json:"updated"`
}

// Swift dates are seconds since 2001-01-01.
const swiftEpoch = 978307200

func swiftNow() float64             { return float64(time.Now().UnixNano())/1e9 - swiftEpoch }
func fromSwift(s float64) time.Time { return time.Unix(0, int64((s+swiftEpoch)*1e9)) }

func blankPage(day string) *page {
	now, _ := json.Marshal(swiftNow())
	return &page{Day: day, raw: map[string]json.RawMessage{
		"day": jsonOf(day), "text": jsonOf(""), "photos": jsonOf([]any{}), "removedPhotos": jsonOf([]any{}),
		"places": jsonOf([]any{}), "created": now, "updated": now,
	}}
}

func jsonOf(v any) json.RawMessage {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	return bytes.TrimRight(buf.Bytes(), "\n")
}

func parsePage(data []byte) (*page, error) {
	p := &page{}
	if err := json.Unmarshal(data, &p.raw); err != nil {
		return nil, err
	}
	get := func(k string, v any) { json.Unmarshal(p.raw[k], v) }
	get("day", &p.Day)
	get("text", &p.Text)
	get("version", &p.Version)
	get("photos", &p.Photos)
	get("places", &p.Places)
	get("agentNotes", &p.AgentNotes)
	if _, ok := p.raw["health"]; ok {
		p.Health = &health{}
		get("health", p.Health)
	}
	if _, ok := p.raw["sun"]; ok {
		p.Sun = &sun{}
		get("sun", p.Sun)
	}
	return p, nil
}

// encode writes back the fields this tool changes; the rest are as read.
// Keys come out sorted, as the app's encoder writes them.
func (p *page) encode() []byte {
	p.raw["text"] = jsonOf(p.Text)
	p.raw["version"] = jsonOf(p.Version)
	if len(p.AgentNotes) > 0 {
		p.raw["agentNotes"] = jsonOf(p.AgentNotes)
	} else {
		delete(p.raw, "agentNotes")
	}
	return jsonOf(p.raw)
}

// hasContent: what counts toward the streak, as in the app: words or a
// photo. An agent's note doesn't.
func (p *page) hasContent() bool {
	return len(bytes.TrimSpace([]byte(p.Text))) > 0 || len(p.Photos) > 0
}

func (p *page) note(id string) *agentNote {
	for i := range p.AgentNotes {
		if p.AgentNotes[i].ID == id {
			return &p.AgentNotes[i]
		}
	}
	return nil
}
