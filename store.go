package main

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// What the server keeps. Every byte of journal content arrives encrypted on
// the phone; the server stores it as given and can't read it.

type Account struct {
	Handle     string
	AuthHash   []byte // SHA-256 of the login token the phone derives from the journal key
	Salt       []byte // PIN stretching salt, given to the phone so it can stretch again
	Iterations int
	// VerifierMAC is an HMAC, under the server secret, of what the phone
	// derives from the PIN. Without the secret a copy of the database can't
	// be used to test PINs.
	VerifierMAC []byte
	// Sealed is the journal key, locked with the PIN on the phone and then
	// sealed again here with the server secret. nil once wiped.
	Sealed    []byte
	Attempts  int
	CreatedAt time.Time
}

type Entry struct {
	ID        string    `json:"id"`
	Data      []byte    `json:"data,omitempty"`
	Rev       int       `json:"rev"`
	Seq       int64     `json:"seq"`
	UpdatedAt time.Time `json:"updatedAt"`
	Deleted   bool      `json:"deleted,omitempty"`
}

var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("already exists")
	ErrConflict = errors.New("conflict")
)

type Store interface {
	CreateAccount(ctx context.Context, a *Account) error
	Account(ctx context.Context, handle string) (*Account, error)
	// Attempt records a recovery attempt under a lock: check says whether the
	// PIN matched; on a miss the count goes up and, at max, the sealed key is
	// wiped. It returns the account as it stands after.
	Attempt(ctx context.Context, handle string, check func(*Account) bool, max int) (*Account, bool, error)
	SetRecovery(ctx context.Context, handle string, salt []byte, iterations int, verifierMAC, sealed []byte) error
	DeleteAccount(ctx context.Context, handle string) error

	// PutEntry stores data at rev+1 if the entry is at rev (0: new).
	PutEntry(ctx context.Context, handle, id string, data []byte, rev int) (*Entry, error)
	DeleteEntry(ctx context.Context, handle, id string, rev int) (*Entry, error)
	// Entries returns changes after seq, oldest first.
	Entries(ctx context.Context, handle string, after int64, limit int) ([]Entry, error)
	CountEntries(ctx context.Context, handle string) (int, error)

	PutBlob(ctx context.Context, handle, id string, data []byte) error
	Blob(ctx context.Context, handle, id string) ([]byte, error)
	DeleteBlob(ctx context.Context, handle, id string) error
}

// ---- memory, for tests and running without a database ----

type memStore struct {
	mu       sync.Mutex
	accounts map[string]*Account
	entries  map[string]map[string]*Entry
	blobs    map[string]map[string][]byte
	seq      int64
}

func newMemStore() *memStore {
	return &memStore{accounts: map[string]*Account{}, entries: map[string]map[string]*Entry{}, blobs: map[string]map[string][]byte{}}
}

func (m *memStore) CreateAccount(_ context.Context, a *Account) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.accounts[a.Handle]; ok {
		return ErrExists
	}
	c := *a
	m.accounts[a.Handle] = &c
	return nil
}

func (m *memStore) Account(_ context.Context, handle string) (*Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.accounts[handle]
	if !ok {
		return nil, ErrNotFound
	}
	c := *a
	return &c, nil
}

func (m *memStore) Attempt(_ context.Context, handle string, check func(*Account) bool, max int) (*Account, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.accounts[handle]
	if !ok {
		return nil, false, ErrNotFound
	}
	if a.Sealed == nil {
		c := *a
		return &c, false, nil
	}
	if check(a) {
		a.Attempts = 0
		c := *a
		return &c, true, nil
	}
	a.Attempts++
	if a.Attempts >= max {
		a.Sealed = nil
	}
	c := *a
	return &c, false, nil
}

func (m *memStore) SetRecovery(_ context.Context, handle string, salt []byte, iterations int, verifierMAC, sealed []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.accounts[handle]
	if !ok {
		return ErrNotFound
	}
	a.Salt, a.Iterations, a.VerifierMAC, a.Sealed, a.Attempts = salt, iterations, verifierMAC, sealed, 0
	return nil
}

func (m *memStore) DeleteAccount(_ context.Context, handle string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.accounts, handle)
	delete(m.entries, handle)
	delete(m.blobs, handle)
	return nil
}

func (m *memStore) PutEntry(_ context.Context, handle, id string, data []byte, rev int) (*Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	es := m.entries[handle]
	if es == nil {
		es = map[string]*Entry{}
		m.entries[handle] = es
	}
	cur := 0
	if e, ok := es[id]; ok {
		cur = e.Rev
	}
	if cur != rev {
		return nil, ErrConflict
	}
	m.seq++
	e := &Entry{ID: id, Data: data, Rev: rev + 1, Seq: m.seq, UpdatedAt: time.Now().UTC()}
	es[id] = e
	c := *e
	return &c, nil
}

func (m *memStore) DeleteEntry(_ context.Context, handle, id string, rev int) (*Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[handle][id]
	if !ok {
		return nil, ErrNotFound
	}
	if e.Rev != rev {
		return nil, ErrConflict
	}
	m.seq++
	*e = Entry{ID: id, Rev: rev + 1, Seq: m.seq, UpdatedAt: time.Now().UTC(), Deleted: true}
	c := *e
	return &c, nil
}

func (m *memStore) Entries(_ context.Context, handle string, after int64, limit int) ([]Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Entry
	for _, e := range m.entries[handle] {
		if e.Seq > after {
			out = append(out, *e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *memStore) CountEntries(_ context.Context, handle string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, e := range m.entries[handle] {
		if !e.Deleted {
			n++
		}
	}
	return n, nil
}

func (m *memStore) PutBlob(_ context.Context, handle, id string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.blobs[handle] == nil {
		m.blobs[handle] = map[string][]byte{}
	}
	m.blobs[handle][id] = append([]byte(nil), data...)
	return nil
}

func (m *memStore) Blob(_ context.Context, handle, id string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.blobs[handle][id]
	if !ok {
		return nil, ErrNotFound
	}
	return b, nil
}

func (m *memStore) DeleteBlob(_ context.Context, handle, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.blobs[handle], id)
	return nil
}
