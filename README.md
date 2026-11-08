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
     key and the verifier at sign-up.
  3. The server stores an HMAC of the verifier and seals the locked key
     again (AES-GCM), both under `TEKKOH_SECRET`, which lives in Berth's
     config, not the database.
  4. To recover, a phone stretches the PIN again and sends the verifier. The
     server releases the locked key only if it matches; **10 wrong PINs wipe
     it** (a device that still has the key can set a new PIN).

A copy of the database alone can't be used to test PINs or open a key: it
needs the secret too. Someone who controls the live server *and* its secret
could try all million PINs offline, so the PIN protects against stolen
data, not against the server's operator; iCloud Keychain and the device
keep the key otherwise.

## API

| | |
|---|---|
| `POST /v1/accounts` | `{handle, auth, recovery: {salt, iterations, verifier, blob}}` (base64) |
| `GET /v1/recovery?handle=` | `{salt, iterations, attemptsLeft}` |
| `POST /v1/recovery` | `{handle, verifier}` → `{blob}`, or 403 `{attemptsLeft}`, or 410 once wiped |
| `PUT /v1/recovery` | (signed in) a new PIN |
| `GET /v1/me`, `DELETE /v1/me` | the account; delete it and everything in it |
| `GET /v1/entries?after=<seq>` | changes since a cursor: `{entries: [{id, data, rev, seq, deleted}], cursor, more}` |
| `PUT /v1/entries/:id` | `{data, rev}`; 409 if `rev` isn't current |
| `DELETE /v1/entries/:id?rev=` | leaves a tombstone for other devices |
| `PUT/GET/DELETE /v1/blobs/:id` | encrypted photo bytes |

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
