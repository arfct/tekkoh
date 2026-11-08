package main

import (
	"context"
	"database/sql"
	"errors"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type pgStore struct{ db *sql.DB }

const schema = `
create table if not exists accounts (
  handle       text primary key,
  auth_hash    bytea not null,
  salt         bytea not null,
  iterations   int not null,
  verifier_mac bytea not null,
  sealed       bytea,
  attempts     int not null default 0,
  created_at   timestamptz not null default now()
);
create table if not exists entries (
  handle     text not null references accounts(handle) on delete cascade,
  id         text not null,
  data       bytea,
  rev        int not null,
  seq        bigint not null,
  updated_at timestamptz not null default now(),
  deleted    boolean not null default false,
  primary key (handle, id)
);
create index if not exists entries_seq on entries (handle, seq);
-- Changes are numbered per journal, so one account's cursor says nothing
-- about how much anyone else writes. (Earlier versions used one global
-- sequence; the column starts each account above what it already has.)
alter table accounts add column if not exists next_seq bigint not null default 0;
alter table accounts add column if not exists last_attempt timestamptz;
update accounts a set next_seq = coalesce((select max(seq) from entries e where e.handle = a.handle), 0) where next_seq = 0;
create table if not exists sessions (
  id         text primary key,
  handle     text not null references accounts(handle) on delete cascade,
  token_hash bytea not null unique,
  label      text not null default '',
  created_at timestamptz not null default now(),
  last_used  timestamptz not null default now()
);
create table if not exists blobs (
  handle     text not null references accounts(handle) on delete cascade,
  id         text not null,
  data       bytea not null,
  created_at timestamptz not null default now(),
  primary key (handle, id)
);`

func openPG(ctx context.Context, url string) (*pgStore, error) {
	db, err := sql.Open("pgx", url)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	db.SetConnMaxIdleTime(5 * time.Minute)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, schema); err != nil {
		return nil, err
	}
	return &pgStore{db: db}, nil
}

func (p *pgStore) CreateAccount(ctx context.Context, a *Account) error {
	res, err := p.db.ExecContext(ctx, `insert into accounts (handle, auth_hash, salt, iterations, verifier_mac, sealed)
		values ($1, $2, $3, $4, $5, $6) on conflict (handle) do nothing`,
		a.Handle, a.AuthHash, a.Salt, a.Iterations, a.VerifierMAC, a.Sealed)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrExists
	}
	return nil
}

func scanAccount(row interface{ Scan(...any) error }) (*Account, error) {
	a := &Account{}
	var last sql.NullTime
	err := row.Scan(&a.Handle, &a.AuthHash, &a.Salt, &a.Iterations, &a.VerifierMAC, &a.Sealed, &a.Attempts, &last, &a.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	a.LastAttempt = last.Time
	return a, err
}

const accountCols = `handle, auth_hash, salt, iterations, verifier_mac, sealed, attempts, last_attempt, created_at`

func (p *pgStore) Account(ctx context.Context, handle string) (*Account, error) {
	return scanAccount(p.db.QueryRowContext(ctx, `select `+accountCols+` from accounts where handle = $1`, handle))
}

func (p *pgStore) Attempt(ctx context.Context, handle string, ready func(*Account) bool, check func(*Account) bool, max int) (*Account, bool, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	// The row lock makes concurrent guesses count one at a time.
	a, err := scanAccount(tx.QueryRowContext(ctx, `select `+accountCols+` from accounts where handle = $1 for update`, handle))
	if err != nil {
		return nil, false, err
	}
	if a.Sealed == nil {
		return a, false, tx.Commit()
	}
	if !ready(a) {
		return a, false, ErrTooSoon
	}
	ok := check(a)
	if ok {
		a.Attempts = 0
	} else {
		a.Attempts++
		a.LastAttempt = time.Now()
		if a.Attempts >= max {
			a.Sealed = nil
		}
	}
	if _, err := tx.ExecContext(ctx, `update accounts set attempts = $2, sealed = $3, last_attempt = $4 where handle = $1`,
		handle, a.Attempts, a.Sealed, sql.NullTime{Time: a.LastAttempt, Valid: !a.LastAttempt.IsZero()}); err != nil {
		return nil, false, err
	}
	return a, ok, tx.Commit()
}

func (p *pgStore) SetRecovery(ctx context.Context, handle string, salt []byte, iterations int, verifierMAC, sealed []byte) error {
	res, err := p.db.ExecContext(ctx, `update accounts set salt = $2, iterations = $3, verifier_mac = $4, sealed = $5, attempts = 0 where handle = $1`,
		handle, salt, iterations, verifierMAC, sealed)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *pgStore) DeleteAccount(ctx context.Context, handle string) error {
	_, err := p.db.ExecContext(ctx, `delete from accounts where handle = $1`, handle)
	return err
}

func (p *pgStore) PutEntry(ctx context.Context, handle, id string, data []byte, rev int) (*Entry, error) {
	e := &Entry{ID: id}
	var err error
	if rev == 0 {
		err = p.db.QueryRowContext(ctx, nextSeq+` insert into entries (handle, id, data, rev, seq)
			select $1, $2, $3, 1, n.next_seq from n where not exists (select 1 from entries where handle = $1 and id = $2)
			returning rev, seq, updated_at`, handle, id, data).Scan(&e.Rev, &e.Seq, &e.UpdatedAt)
	} else {
		err = p.db.QueryRowContext(ctx, nextSeq+` update entries set data = $3, rev = rev + 1, seq = (select next_seq from n), updated_at = now(), deleted = false
			where handle = $1 and id = $2 and rev = $4 returning rev, seq, updated_at`, handle, id, data, rev).Scan(&e.Rev, &e.Seq, &e.UpdatedAt)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrConflict
	}
	return e, err
}

func (p *pgStore) DeleteEntry(ctx context.Context, handle, id string, rev int) (*Entry, error) {
	e := &Entry{ID: id, Deleted: true}
	err := p.db.QueryRowContext(ctx, nextSeq+` update entries set data = null, deleted = true, rev = rev + 1, seq = (select next_seq from n), updated_at = now()
		where handle = $1 and id = $2 and rev = $3 returning rev, seq, updated_at`, handle, id, rev).Scan(&e.Rev, &e.Seq, &e.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		var exists bool
		p.db.QueryRowContext(ctx, `select true from entries where handle = $1 and id = $2`, handle, id).Scan(&exists)
		if !exists {
			return nil, ErrNotFound
		}
		return nil, ErrConflict
	}
	return e, err
}

func (p *pgStore) Entries(ctx context.Context, handle string, after int64, limit int) ([]Entry, error) {
	rows, err := p.db.QueryContext(ctx, `select id, data, rev, seq, updated_at, deleted from entries
		where handle = $1 and seq > $2 order by seq limit $3`, handle, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.Data, &e.Rev, &e.Seq, &e.UpdatedAt, &e.Deleted); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (p *pgStore) CountEntries(ctx context.Context, handle string) (int, error) {
	var n int
	err := p.db.QueryRowContext(ctx, `select count(*) from entries where handle = $1 and not deleted`, handle).Scan(&n)
	return n, err
}

// nextSeq numbers a change within its journal ($1 is the handle): a WITH
// clause, n, in front of the statement that uses it.
const nextSeq = `with n as (update accounts set next_seq = next_seq + 1 where handle = $1 returning next_seq)`

func (p *pgStore) Usage(ctx context.Context, handle string) (entries, blobs int, bytes int64, err error) {
	err = p.db.QueryRowContext(ctx, `select (select count(*) from entries where handle = $1),
		(select count(*) from blobs where handle = $1), (select coalesce(sum(length(data)), 0) from blobs where handle = $1)`, handle).Scan(&entries, &blobs, &bytes)
	return
}

func (p *pgStore) CreateSession(ctx context.Context, s *Session) error {
	_, err := p.db.ExecContext(ctx, `insert into sessions (id, handle, token_hash, label) values ($1, $2, $3, $4)`, s.ID, s.Handle, s.TokenHash, s.Label)
	return err
}

func (p *pgStore) Session(ctx context.Context, handle string, tokenHash []byte) (*Session, error) {
	s := &Session{Handle: handle, TokenHash: tokenHash}
	// Noting the use at most every few minutes keeps reads from writing.
	err := p.db.QueryRowContext(ctx, `update sessions set last_used = case when last_used < now() - interval '5 minutes' then now() else last_used end
		where handle = $1 and token_hash = $2 returning id, label, created_at, last_used`, handle, tokenHash).Scan(&s.ID, &s.Label, &s.CreatedAt, &s.LastUsed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return s, err
}

func (p *pgStore) Sessions(ctx context.Context, handle string) ([]Session, error) {
	rows, err := p.db.QueryContext(ctx, `select id, label, created_at, last_used from sessions where handle = $1 order by created_at`, handle)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		s := Session{Handle: handle}
		if err := rows.Scan(&s.ID, &s.Label, &s.CreatedAt, &s.LastUsed); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (p *pgStore) DeleteSession(ctx context.Context, handle, id string) error {
	_, err := p.db.ExecContext(ctx, `delete from sessions where handle = $1 and id = $2`, handle, id)
	return err
}

func (p *pgStore) PutBlob(ctx context.Context, handle, id string, data []byte) error {
	_, err := p.db.ExecContext(ctx, `insert into blobs (handle, id, data) values ($1, $2, $3)
		on conflict (handle, id) do update set data = excluded.data, created_at = now()`, handle, id, data)
	return err
}

func (p *pgStore) Blob(ctx context.Context, handle, id string) ([]byte, error) {
	var b []byte
	err := p.db.QueryRowContext(ctx, `select data from blobs where handle = $1 and id = $2`, handle, id).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return b, err
}

func (p *pgStore) DeleteBlob(ctx context.Context, handle, id string) error {
	_, err := p.db.ExecContext(ctx, `delete from blobs where handle = $1 and id = $2`, handle, id)
	return err
}
