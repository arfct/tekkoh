# tekkoh-berth

The server for [Tekkoh](https://github.com/dps/tekkoh-ios), an encrypted
daily journal. It stores accounts, entries and photos, and gives a new phone
its journal key back for the right PIN. Everything a person writes is
encrypted on their phone first: the server holds ciphertext it can't read.

Runs on [Berth](https://github.com/arfct/berth): `go build`, Postgres via
`berth pg:link`, and one secret.

## How the keys work

On the phone, a journal has a random 256-bit **journal key**. It never
leaves the phone unencrypted.

- **Entries** are encrypted on the phone, each with its own key, which the
  journal key wraps. An entry's id is a keyed hash of its day, so the server
  can't tell which days someone wrote.
- **Photos** are encrypted the same way and stored as opaque blobs.
- **Signing in** uses a token the phone derives from the journal key (HKDF).
  The server stores its SHA-256, and learns nothing about the key from it.
- **Your own devices** share the journal key through iCloud Keychain.
- **A 6-digit PIN** recovers the key when every device is lost:
  1. The phone stretches the PIN (PBKDF2-SHA256, 600,000 rounds, random salt)
     into two halves: a *verifier* and a *wrapping key*.
  2. It locks the journal key with the wrapping key and sends the locked
     key and the verifier at sign-up, boxed to this server's X25519 key
     (derived from `TEKKOH_SECRET`, built into the app; see `transport.go`)
     so nothing in between can read them.
  3. The server stores an HMAC of the verifier and seals the locked key
     again (AES-GCM), both under `TEKKOH_SECRET`, which lives in Berth's
     config, not the database.
  4. To recover, a phone stretches the PIN again and sends the verifier. The
     server releases the locked key only if it matches, boxed back. After
     three wrong PINs each try waits longer (1, 2, 4… minutes); **10 wrong
     PINs wipe it** (a device that still has the key can set a new PIN).
     Unknown usernames answer like real ones, and failures across all
     accounts are capped per hour.

A copy of the database alone can't be used to test PINs or open a key: it
needs the secret too. Someone with the database *and* the secret (the live
server, or a Berth backup, which holds both) could try all million PINs
offline. See the app's SECURITY.md for the full picture.

## The web app

`web/` is Tekkoh in a browser, deployed as its own Berth app
(`berth create tekkoh-web --repo dps/tekkoh-berth --path web`) at
https://tekkoh-web.cronbon.com: static files behind Caddy with a strict
Content-Security-Policy, the crypto in WebCrypto, pages sealed in
IndexedDB. A browser links with the username, the PIN and the phone (a QR
code with a one-time X25519 key); it gets its own session, which the phone
can revoke. Tests: `node web/tests/vectors.mjs` (crypto against the
app's Swift) and `node web/tests/live.mjs` (linking and sync against the
live server). The app's SECURITY.md covers what the web can and can't
promise.

## The command-line tool, for agents

`cmd/tekkoh` lets a personal agent (in a confidential VM, say) read and
write the journal, and note what it did for you each day. It's one static
binary. All the encryption happens in it, with the same crypto as the app,
checked against the Swift vectors in `crypto_test.go`.

```sh
GOOS=linux GOARCH=amd64 go build -o tekkoh ./cmd/tekkoh   # for the VM
```

Or have the agent install it from https://tekkoh.com/setup.txt, which
says how. The binaries there are reproducible builds of this command.

**Link it once.** The agent prints a one-time link and sends it to you; you
approve it on your phone. No PIN is typed anywhere:

```sh
tekkoh link --name "Morning agent"
# https://tekkoh.com/link#s=…&k=…&n=Morning%20agent: on the iPhone it opens
# Tekkoh, which shows the agent's name and six digits and asks for Face ID.
# On a computer, the page shows the link as a code for the phone's camera.
tekkoh link --wait        # collects it once approved (gives up after 90s;
                          # run it again; the link lasts 15 minutes)
```

With a terminal you can type into, `tekkoh link --pin` links as a browser
does instead: username, PIN, and a QR code to scan with the phone.

**Then the agent can:**

```sh
tekkoh read                      # today's page: words, places, activity, photos' captions, notes
tekkoh read yesterday --json     # the same, for a program
tekkoh days --from -30 --json    # the last month's days with anything on them
tekkoh search dentist            # pages mentioning it
tekkoh streak
tekkoh photos 2026-11-08 --out ./photos

tekkoh write "Picked up the dry cleaning."    # adds to today's words
echo "..." | tekkoh write yesterday --replace -
tekkoh note "Booked the dentist for Tuesday at 10. Paid the water bill."
tekkoh note --replace "Today: renewed the car insurance."
```

A note is the agent's own: one per agent per day, kept inside the
encrypted page apart from your words, and shown in the margin in the app
and on the web. `note` adds a line to it; `--replace` or `--clear` change
it. Days are in the time zone the phone reported when linking (`--tz` or
`$TEKKOH_TZ` override it).

The key lives in `~/.config/tekkoh/identity.json` (or `$TEKKOH_HOME`),
mode 0600. Anything holding it can read everything, and can act as your
phone. Link only agents you trust with the whole journal: see the app's
SECURITY.md, "Agents". `tekkoh unlink` signs it out and deletes the key;
the phone can sign it out too.

Tests: `go test ./cmd/tekkoh` checks the crypto against the app's
vectors. `TEKKOH_LIVE=1 go test -run Live ./cmd/tekkoh` runs the whole
cycle on a throwaway journal against the server and then deletes it: both
ways of linking, write, a concurrent edit, notes, search, and sign-out. Set `TEKKOH_SERVER`
and `TEKKOH_SERVER_KEY` to run it against another server.

## API

| | |
|---|---|
| `POST /v1/accounts` | `{handle, auth, recovery: {eph, box}}`; the box holds `{salt, iterations, verifier, blob}` |
| `GET /v1/transport-key` | the server's X25519 public key |
| `POST /v1/recovery/params` | `{handle}` → `{salt, iterations, attemptsLeft}` |
| `POST /v1/recovery` | `{handle, proof: {eph, box}}` → `{reply}` (boxed `{blob}`), or 403 `{attemptsLeft}`, 429 `{retryAfter}`, 410 once wiped |
| `PUT /v1/recovery` | (signed in) `{eph, box}`: a new PIN |
| `GET /v1/me`, `DELETE /v1/me` | the account; delete it and everything in it |
| `GET /v1/entries?after=<seq>` | changes since a cursor: `{entries: [{id, data, rev, seq, deleted}], cursor, more}` |
| `PUT /v1/entries/:id` | `{data, rev}`; 409 if `rev` isn't current |
| `DELETE /v1/entries/:id?rev=` | leaves a tombstone for other devices |
| `PUT/GET/DELETE /v1/blobs/:id` | encrypted photo bytes |
| `POST /v1/pair` | a browser opens a linking slot: `{id, expiresIn}` |
| `PUT /v1/pair/:id` | (the phone) `{box}`: the journal key sealed to the browser |
| `GET /v1/pair/:id` | the browser collects it once: `{box, handle}`, or 202 while waiting |
| `POST /v1/sessions`, `GET /v1/sessions` | (the phone) link a browser's or agent's session (`kind`: `browser` or `agent`); list them |
| `DELETE /v1/sessions/:id` | the phone signs a browser out; a browser signs itself out with `current` |

Signed-in requests send `Authorization: Tekkoh <handle> <base64 token>`.
Recovery and sign-up are rate limited per IP.

## Running

```sh
TEKKOH_SECRET=$(openssl rand -base64 32) go run .   # memory store, port 8080
go test ./...
```

On Berth:

```sh
berth create tekkoh --repo dps/tekkoh-berth
berth pg:create tekkoh-db && berth pg:link tekkoh-db tekkoh
berth config:set tekkoh TEKKOH_SECRET=$(openssl rand -base64 32)
```

Changing `TEKKOH_SECRET` makes every stored PIN recovery unusable (devices
can set new PINs); keep it with Berth's backups.
