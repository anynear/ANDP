# ANDP – anynear Distributed Protocol, version v1

Status: version v1, in use on the anynear network since November 2026. Security considerations: §16.

ANDP is a content-blind, replicated object store. Clients write immutable **objects** into **spaces**. A space is an
Ed25519 public key; its **owner** holds the private key and may hand out **grants**. Relays of one **network** keep
three copies of every object, at three different operators, and repair each other without consensus. ANDP never
sees plaintext: what an object means is the application's business (for anynear: ANMP).

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Conventions

| Item | Rule |
|---|---|
| Base64url | `b64u`: RFC 4648 §5 alphabet, **no padding**. Decoders MUST reject padding and non-canonical encodings (re-encoding must give the same string). |
| Integers | ASCII decimal, no sign, no leading zeros (`0` is `0`), at most 2^63−1. |
| Time | Unix seconds (`ts`, `until`) unless noted. `issued` in network lists is Unix milliseconds. |
| Hash | SHA-256. |
| Signature | Ed25519 (RFC 8032), 64 bytes. |
| Keys | 32-byte Ed25519 public keys, written as b64u (43 characters). |
| Signing bytes | UTF-8 text: a **domain** (e.g. `andp/v1/obj`) followed by fields, each preceded by `\n` (0x0A). No trailing newline. An absent optional field is an empty line. |
| CBOR | RFC 8949, deterministic encoding (§4.2.1): definite lengths, shortest integers, map keys sorted. Maps use unsigned integer keys. Decoders MUST reject input that does not re-encode to the same bytes, and trailing bytes. |
| JSON | UTF-8. Field names are case-sensitive and MUST match exactly. A document with duplicate keys is invalid and MUST be rejected. Unknown fields MUST be ignored. Binary values are b64u strings. |

Example: `sign("andp/v1/del", space, id, ts)` means signing the bytes `andp/v1/del\n<space>\n<id>\n<ts>`.

## 2. Identifiers

| Name | Definition |
|---|---|
| `space` | b64u of the owner's Ed25519 public key. |
| `id` | b64u(SHA-256(bytes)) of an object. Always 43 characters. |
| `node` | b64u of a relay's Ed25519 public key (node key). |
| `network` | b64u of the network key (Ed25519 public key that signs the network list). |
| network ID | b64u(SHA-256(raw first network key)), i.e. of the key that signed the network's first list. Never changes, not even on key rotation; carried as `id` in every network list. Used in contact codes and links. |
| grant hash | b64u(SHA-256(grant body bytes)), see §4. |
| watch ID | b64u(SHA-256(push token bytes)[0..16]). |

## 3. Objects

An object is `(space, id, bytes, metadata)`. The bytes are opaque. The metadata is signed by the **writer**:

| Field | Type | Meaning |
|---|---|---|
| `space` | key | space the object belongs to |
| `id` | id | SHA-256 of the bytes |
| `size` | int | length of the bytes |
| `ts` | int | time of writing, Unix seconds |
| `until` | int | expiry, Unix seconds; `0` = no expiry (kept subject to quota and policy) |
| `placement` | `space` \| `object` | where the object lives, §6 |
| `refs` | list of `{id, size}` | only for entries (`placement: space`): contents of the same space this entry refers to; empty otherwise |
| `revokes` | grant hash | optional; marks this object as a revocation (§4.3) |
| `writer` | key | key that signed the metadata (owner or grantee) |
| `grant` | grant | the writer's grant; MUST be absent when the writer is the owner |
| `sig` | signature | `sign("andp/v1/obj", space, id, size, ts, until, placement, refsDigest, revokes)` by `writer` |

The **refs CBOR** is the CBOR array of `[id-bytes, size]` pairs (bstr 32, uint) in the order given; it is never
empty. `refsDigest` is b64u(SHA-256(refs CBOR)), or the empty string when `refs` is empty. `revokes` is the grant
hash or the empty string.

Terms used below:

- **entry**: an object with `placement: space`. Small, listed, may carry `refs`.
- **content**: an object with `placement: object`. Large, not listed, referenced by entries.

Rules:

1. A relay MUST check that SHA-256 of the received bytes equals `id` and that `size` matches.
2. Objects are immutable. Writing the same `(space, id)` again with identical bytes succeeds. The relay keeps the
   stored metadata unless the new `until` is later (`0` counts as latest) or the stored copy has expired; then the
   new signed metadata replaces it. Writing it again with a different `placement` is rejected (409). Different bytes
   cannot have the same `id`.
3. A content MUST have empty `refs` and empty `revokes`. An entry's `refs` MUST point to contents in the same space.
4. `until`, when not `0`, MUST be greater than `ts` and at most `ts + max_until` (policy, §11). A relay MUST NOT
   deliver an object after its `until`.
5. A relay accepts a client write only if `|ts − now| ≤ 300` seconds. A write arriving from another relay
   (repair, §8) is accepted with any past `ts`, as long as the signature and the grant validity at `ts` hold.
6. The object size limit is `max_object_bytes` (policy). Clients split larger data into contents and describe the
   order themselves; ANDP has no notion of files.

## 4. Spaces, rights and grants

### 4.1 Rights

| Right | Bit | Allows |
|---|---|---|
| `read` | 1 | GET of entries; `status` |
| `list` | 2 | `list`; `watch` |
| `write` | 4 | PUT of objects |
| `delete` | 8 | DELETE of objects |

The owner (holder of the space key) has all rights. Contents (`placement: object`) can be read by anyone who
knows their `id`: their bytes are ciphertext and their `id` is not guessable.

### 4.2 Grant

A grant body is a CBOR map:

| Key | Field | Type | |
|---|---|---|---|
| 1 | `space` | bstr 32 | required |
| 2 | `rights` | uint (bit set, §4.1) | required, not 0 |
| 3 | `grantee` | bstr 32 | absent = anyone (`"*"`) |
| 4 | `scope` | bstr 32 (raw object id) | absent = whole space |
| 5 | `until` | uint (Unix seconds) | required |
| 6 | `issued` | uint (Unix seconds) | required |

Unknown keys MUST be rejected.

A grant is the CBOR array `[body: bstr, sig: bstr 64]`, where `sig = sign("andp/v1/grant", b64u(body))` by the owner
(the key in field 1). On the wire a grant is b64u of that array.

A grant is **valid at time t** if the signature holds, `issued ≤ t ≤ until`, and no revocation for its hash is
known to the space holders (§4.3). A grant with `grantee` set only authorizes requests signed by that key; a
grant without `grantee` authorizes any key. A `scope` restricts the grant to the object with that id.

Version v1 has no delegation: only the owner issues grants.

### 4.3 Revocation

A revocation is an entry written by the **owner** with `revokes = <grant hash>`, whose bytes are the 32 raw bytes of
the grant hash (so its `id` is SHA-256 of the grant hash). Space holders MUST refuse requests and writes that rely
on a revoked grant from the moment they store the revocation. Revocation is not retroactive: objects written
before keep their validity. Content holders do not check revocations: a content
is ciphertext that anyone who knows its `id` may read, and a holder of contents need not hold the space's entries.

### 4.4 Authorization header

Every request that needs a right, and every request between relays, carries:

```
Authorization: ANDP key=<b64u key>, ts=<int>, sig=<b64u>[, grant=<b64u grant>]
```

with `sig = sign("andp/v1/req", METHOD, path, ts)` by `key`. `path` is the request path without query string,
exactly as sent (e.g. `/andp/v1/s/<space>/<id>`). `METHOD` is upper case. The relay accepts `|ts − now| ≤ 300`.
Parameters are separated by `, ` and may appear in any order. Unknown parameters are ignored.

The caller is authorized if `key` is the space key, or `grant` is valid now for this space, contains the needed
right, names `key` as grantee (or no grantee) and, when scoped, matches the object. A scoped grant authorizes only
requests on that object's path `/andp/v1/s/{space}/{id}`, never `list`, `status` or `watch`.

A request is a **peer request** if `key` is the `node` of a relay in the current network list (any state). Peer
requests need no grant; they are allowed on PUT for repair (§8), on GET of any object and on the relay-to-relay
endpoints under `/andp/v1/peer/`. Those endpoints are specified in ANDP Peer, a separate document for relay
implementations; clients never send peer requests.

## 5. HTTP API

All paths start with `/andp/v1`. Relays MUST support HTTP/1.1 and SHOULD support HTTP/2. Errors are JSON
`{"error": "<code>", "message": "<text>"}`.

### 5.1 Overview

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/andp/v1/info` | – | node, network, policy, extensions |
| GET | `/andp/v1/net` | – | current network list |
| POST | `/andp/v1/net` | – (signed body) | offer a newer network list |
| GET | `/andp/v1/radio` | – | extension radio: current radio list (§5.9) |
| POST | `/andp/v1/radio` | – (signed body) | extension radio: offer a newer radio list |
| GET | `/andp/v1/s/{space}` | `list` | list entries |
| PUT | `/andp/v1/s/{space}/{id}` | `write` or peer | write an object |
| GET | `/andp/v1/s/{space}/{id}` | `read` (entries) / none (contents) | read an object |
| DELETE | `/andp/v1/s/{space}/{id}` | `delete` | delete an object |
| POST | `/andp/v1/s/{space}/status` | `read` | state of many objects |
| POST | `/andp/v1/watch` | `list` | extension watch (§10) |
| GET | `/andp/v1/stream` | stream key | extension stream: events for the device (§18) |
| GET | `/andp/v1/view` | – | extension view: cards of all relays (§17) |

Relays also serve each other under `/andp/v1/peer/` (repair, gossip, notifications). These endpoints are part of
ANDP Peer and not of this document.

### 5.2 GET /andp/v1/info

```json
{
  "node": "<b64u>",
  "network": "<b64u network key>",
  "policy": {
    "max_object_bytes": 52429824,
    "max_until": 2592000,
    "inline_bytes": 65536,
    "orphan_grace": 86400,
    "quota_space_bytes": 1073741824,
    "writer_daily_bytes": 1073741824,
    "cors_origins": ["*"],
    "repair_interval": 60
  },
  "extensions": ["watch", "webpush", "radio", "view", "stream"],
  "webpush": "<b64u VAPID public key>",
  "stream": {"ping": 180, "clients": false},
  "clients": {"min": 1}
}
```

All policy values are relay or network decisions; clients MUST read them instead of assuming constants.

`clients.min` is the lowest **client level** the network still serves fully (optional, absent means `1`). Every client
implementation has a fixed client level, an integer that starts at `1` and grows only when the network needs newer
clients. A client whose level is lower keeps working as far as it can and asks the user
to update the app; it MUST NOT stop silently. Relays take the value from relay policy.

### 5.3 PUT /andp/v1/s/{space}/{id}

Body: the object bytes. Headers (all required unless noted):

| Header | Value |
|---|---|
| `Authorization` | §4.4; for repair the relay's own node key |
| `ANDP-Writer` | writer key |
| `ANDP-Ts` | `ts` |
| `ANDP-Until` | `until` |
| `ANDP-Placement` | `space` or `object` |
| `ANDP-Refs` | b64u of the refs CBOR (§3); omitted when `refs` is empty |
| `ANDP-Revokes` | grant hash; omitted when empty |
| `ANDP-Grant` | the writer's grant (b64u); omitted when the writer is the owner |
| `ANDP-Sig` | object signature (§3) |
| `ANDP-Notify` | optional, `none` to suppress watch notifications, `alarm` to wake with alarm priority, `quiet` to wake without showing anything (§10) |
| `ANDP-Watch-Skip` | optional, a watch ID that is not notified (the writer's own) |

For a client write the `Authorization` key MUST equal `ANDP-Writer`, and the writer must hold `write` (via grant
or as owner) at `ts`. The right comes from `ANDP-Grant`; `Authorization` needs no `grant` parameter on PUT. For a peer write `Authorization` is the sending relay; the object's own signature and grant
are checked as above, but against `ts` instead of now.

The relay accepts the object only if it is a holder for it (§6) or the request is a client write (a client may
write to any relay of the network; the relay then forwards it to the holders by repair, §8).

Responses:

| Status | Meaning |
|---|---|
| 200 | stored durably. Body `{"node": "<b64u>", "receipt": "<b64u sig>"}` with `receipt = sign("andp/v1/receipt", space, id, until)` by the node key, `until` as in the request's `ANDP-Until`. |
| 400 | malformed request, wrong hash or size, invalid or past `until`, refs on a content, client write with `ts` more than 300 s from the relay's clock |
| 401 | missing or invalid `Authorization` |
| 403 | no `write` right, invalid grant, revoked grant, invalid object signature, `Authorization` key is not the writer |
| 409 | the object exists here with a different `placement` |
| 410 | a tombstone exists for this object |
| 413 | larger than `max_object_bytes` |
| 421 | peer write to a relay that is not a holder of the object (§6) |
| 429 | rate limit, including `writer_daily_bytes` |
| 507 | quota of the space or disk reserve exhausted |

A relay MUST reply 200 only after bytes and metadata are durably stored (fsync).

### 5.4 GET /andp/v1/s/{space}/{id}

Entries need `read`; contents need no authorization. Response 200 with the bytes and the metadata headers of §5.3
(`ANDP-Writer`, `ANDP-Ts`, `ANDP-Until`, `ANDP-Placement`, `ANDP-Refs`, `ANDP-Revokes`, `ANDP-Grant`, `ANDP-Sig`) so that
any reader can write the object unchanged to another relay.

If the relay does not hold the object (§9, read via any relay):

| Status | Body | Meaning |
|---|---|---|
| 404 | `{"error":"not_found","holders":[<relay>…]}` | not here; `holders` lists relays (as in the network list) that have it |
| 404 | `{"error":"not_found","holders":[]}` | nobody has it |
| 410 | | deleted |

### 5.5 DELETE /andp/v1/s/{space}/{id}

Needs `delete` (a scoped grant suffices). Headers: `Authorization`, `ANDP-Del-Sig` =
`sign("andp/v1/del", space, id, ts)` by the `Authorization` key with the `ts` of the `Authorization` header. The
relay stores a **tombstone** `{space, id, ts, key, grant, sig}` (`grant` omitted when `key` is the owner), removes the
bytes and returns 204, also when it never held the object. Tombstones are passed on between relays (§8).

A tombstone for an object with `until > 0` MAY be dropped after `until`. A tombstone for an object without expiry
is kept (policy may cap the count per space; a DELETE beyond the cap gets 507).

### 5.6 GET /andp/v1/s/{space}

Needs `list`. Query: `after` (cursor, default empty = from the start), `wait` (0–25 seconds, long poll),
`limit` (1–200, default 200).

```json
{
  "objects": [
    {"seq": 17, "id": "…", "size": 312, "ts": 1761200000, "until": 1763792000,
     "placement": "space", "refs": [{"id": "…", "size": 482113}], "revokes": "…",
     "writer": "…", "grant": "…", "sig": "…", "data": "<b64u bytes>"}
  ],
  "next": "17"
}
```

- Only entries are listed. `data` is included when `size ≤ inline_bytes`, otherwise the client fetches the entry
  by GET.
- `refs`, `revokes`, `grant` and `data` are omitted when empty. Clients verify each item like a GET (§3).
- `next` is the cursor for the following call; without new entries it is the cursor that was sent.
- The cursor is opaque and only valid at the relay that issued it. A client keeps one cursor per relay and
  starts from the empty cursor at a relay it has not used before.
- With `wait > 0` and no new entries, the relay holds the request up to `wait` seconds.
- Revocation entries are listed like any entry.

### 5.7 POST /andp/v1/s/{space}/status

Needs `read`. Body `{"ids": ["…"]}` (at most 1000). Response `{"objects": {"<id>": "here" | "gone" | "missing"}}`.

### 5.8 Network list

`GET /andp/v1/net` returns the newest network list the relay knows:

```json
{"list": "<JSON text>", "sig": "<b64u>"}
```

`sig = sign("andp/v1/net", list)` by the network key, over the exact text of `list`. The list text is:

```json
{
  "v": 1,
  "id": "<b64u network ID>",
  "network": "<b64u network key>",
  "issued": 1761200000000,
  "next": "<b64u next network key>",
  "relays": [
    {"site": "xx-abc-01", "addr": "192.0.2.10:443", "key": "<b64u SHA-256 of TLS SPKI>",
     "host": "xx-abc-01.relay.example.net", "node": "<b64u>", "op": "a1b2", "state": "active"}
  ]
}
```

| Field | Rule |
|---|---|
| `v` | `1` |
| `id` | required; the network ID (§2). The first list of a network has `id = b64u(SHA-256(network))`; later lists keep it unchanged |
| `network` | the key that signed this list (the current network key) |
| `issued` | Unix milliseconds; a receiver accepts a list only if `issued` is strictly greater than its current one |
| `next` | optional; announces the next network key. A list signed by `next` is accepted from then on; `network` in that list is the new key, `id` stays |
| `relays[].site` | optional label for humans (e.g. country, place and a number); not used by the protocol |
| `relays[].addr` | `host:port` with an IP address, for apps (pinned TLS) |
| `relays[].key` | b64u(SHA-256(SubjectPublicKeyInfo)) of the relay's TLS key for `addr` |
| `relays[].host` | optional DNS name for browsers (Web PKI certificate, §12) |
| `relays[].node` | node key |
| `relays[].op` | operator code, failure domain for placement |
| `relays[].state` | `candidate`, `active` or `draining`; other values are allowed (see below) |

A receiver accepts a list only if its `id` equals the network ID it knows, it is signed by `network`, `network` is the
receiver's current network key or that key's announced `next`, and `issued` is strictly greater than its current
one. A receiver without a list (first contact) knows the network ID and the current network key from its
configuration.

Node keys are unique within a list; a list with a repeated node key or an unknown `v` is rejected as a whole. A relay
entry that is invalid (malformed `addr`, `key`, `node` or `host`, missing `op`) is skipped, the rest of the list
counts. A relay with an unknown `state` is kept in the list (its node key still makes peer requests, §4.4) but is not
active: it is never placed (§6), never a repair target (§8) and never asked by clients. So a state added later does
not cut off older clients.

`POST /andp/v1/net` with the same body offers a list to a relay. 200 if accepted, 409 if not newer, 403 if the
signature fails or the list belongs to another network, 400 if it is malformed.

### 5.9 Radio list

Offered when `radio` is in `/andp/v1/info` `extensions`. The radio list carries regions, presets and communities for the
radio path. ANDP only signs, stores and passes it on; what it says is defined by ANMP.

`GET /andp/v1/radio` returns the newest radio list the relay knows, `404` if it knows none:

```json
{"list": "<JSON text>", "sig": "<b64u>"}
```

`sig = sign("andp/v1/radio", list)` by the network key, over the exact text of `list`. The list text is a JSON object
with at least:

| Field | Rule |
|---|---|
| `v` | `1`; a list with another `v` is not accepted |
| `id` | the network ID (§2) |
| `network` | the key that signed this list |
| `issued` | Unix milliseconds; strictly greater than that of the receiver's current radio list |

All other fields belong to ANMP; ANDP ignores them. A receiver accepts a radio list only if `id` equals its network ID
and `network` is a key it accepts for the network list (the current network key or its announced `next`, §5.8).
Relays pass radio lists on to each other like network lists. `POST /andp/v1/radio` with the same body offers a list:
200 if accepted, 409 if not newer, 403 if the signature fails.

## 6. Placement

For a placement key `k` (the `space` for entries, the `id` for contents) every client and relay computes the same
order over the **active** relays of the network list:

1. `rank(r) = SHA-256(bytes of "andp/v1/place\n" + k + "\n" + r.node)`, compared as unsigned big-endian.
2. Sort ascending by rank; ties by `node` (string order).
3. **Chosen:** walk the order and take relays whose `op` is not yet taken, until 3 are chosen.
4. **Spare:** all other relays, in order.
5. If a chosen relay is down (§8), its substitute is the first healthy spare that is not yet a target and whose
   `op` is not yet taken; if there is none, the first healthy spare that is not yet a target. Substitutes are
   picked in the order of the down chosen relays.

If fewer than three operators are active, fewer than three copies exist; there is no fallback. The order does not
depend on the order of the list.

## 7. Contents and orphans

- A content is written to the holders of its `id` with a `write` right in its space. Content holders verify grant
  signature and validity without state, the hash and, for client writes, the writer's daily limit
  (`writer_daily_bytes`). They do not check revocations or quota.
- An entry is written after its contents. Space holders count `quota_space_bytes` over the sizes of entries and of
  their `refs`.
- A content without expiry that no entry refers to is an **orphan**. Relays find orphans during repair (§8) and
  delete those older than `orphan_grace` (without tombstone).
- Deleting an entry does not delete its contents; they become orphans unless the client deletes them.
- References across spaces do not exist.

## 8. Repair between relays

Relays repair each other without consensus. Every relay checks at least every `repair_interval` (policy, default
60 s) which of its objects the chosen relays (§6) or their substitutes lack, and writes the missing copies there
unchanged (PUT, §5.3, with its own node key). A relay counts another as down after 10 minutes without an answer. A
relay that is no longer chosen for an object deletes its copy only after at least three chosen relays confirmed
that they hold it. Tombstones (§5.5) are passed on to all chosen relays. How relays do this among themselves is
specified in ANDP Peer.

Merge rules (no consensus):

| Case | Result |
|---|---|
| same bytes again | stored once; later `until` wins |
| tombstone known | 410 for writes; tombstone wins over any copy |
| expired | not delivered, not pushed, removed by the pruner |
| network partition | both sides accept; they converge after the partition |

## 9. Read via any relay

A client may ask any relay of the network for any object. If the relay does not hold it and the request is a
client request (peer GETs never ask further):

1. It asks up to 5 holders (chosen first) whether they hold the object, with a 5 s timeout.
2. A `gone` anywhere → 410.
3. Nobody has it → 404 with empty `holders`; if all asked holders answered, it remembers this for 30 s.
4. **Entries** (`placement: space`): → 404 with `holders`. No repair on read and no proxy; missing copies of
   entries are restored by the normal repair (§8).
5. **Contents** (`placement: object`): if the relay is itself a chosen holder, it fetches the object from a holder
   as a peer request (its own node key in `Authorization`, never the client's header), verifies hash and
   signature, stores it (repair on read) and delivers it. With request header `ANDP-Fetch: proxy` it fetches,
   verifies and delivers without storing. Otherwise → 404 with `holders`.

Clients follow a holder only if its `node` and `key` are in their own network list.

## 10. Extension: watch

Offered when `watch` is in `/andp/v1/info` `extensions`.

`POST /andp/v1/watch`, needs `list` on the space:

```json
{"space": "…", "target": {"type": "apns", "token": "<hex>", "topic": "…", "env": "production"}}
```

- The relay stores the watch for 45 days and answers 204; posting again refreshes it.
  `{"space": …, "target": …, "remove": true}` removes the watch of that target for that space.
- For `apns`, `token` is the device token as lower-case hex, `env` is `production` or `sandbox`, and `topic` must be
  an app the relay serves (relay policy, otherwise 403).
- The watch ID (§2) is computed over the raw token bytes (for `apns`: the hex-decoded token).
- On every new entry in the space the relay notifies all watches of the space, except when the write carries
  `ANDP-Notify: none` or the watch ID equals `ANDP-Watch-Skip`. Repair writes never notify.
- For `apns` the notification is an alert push with title and body from relay policy, `mutable-content: 1`,
  `collapse-id` = object id and field `o` = object id. The app fetches and decrypts the entry itself.
- **Alarm priority**: a write with `ANDP-Notify: alarm` notifies like any other, but an `apns`
  notification additionally carries `interruption-level: time-sensitive` and `sound: "alarm.caf"` in `aps`. A relay that may send critical alerts (relay policy, only after Apple granted the
  entitlement to the app) sets instead `interruption-level: critical` and
  `sound: {"critical": 1, "name": "alarm.caf", "volume": 1.0}`. `webpush` notifications are unchanged. The relay learns only that
  an alarm came, not what it says. Relays that do not know the value notify as usual (§13); a client MUST NOT
  rely on the alarm priority being applied. `none` wins over `quiet` and `alarm`, `quiet` wins over `alarm`; one header
  carries one value.
- **Quiet**: a write with `ANDP-Notify: quiet` updates devices without showing anything. An `apns` notification is a
  background push instead: `aps` is only `{"content-available": 1}`, `apns-push-type: background`, `apns-priority: 5`,
  `collapse-id` and `o` as above. `webpush` watches are not notified (browsers must show every push). `relay` watches
  (§10.2) are notified as usual. Relays that do not know the value notify as usual (§13).
- At most 32 watches per space and 64 spaces per token; the oldest drops out.

### 10.1 Target `webpush` (browsers)

Offered when `webpush` is in `extensions` (and `watch`). `/andp/v1/info` then names the relay's VAPID public key
(RFC 8292, uncompressed P-256 point, b64u) in `webpush`; all relays of a network use the same key, so one browser
subscription works at every relay.

```json
{"space": "…", "target": {"type": "webpush", "token": "<hex of the endpoint URL as UTF-8>"}}
```

- The endpoint is the push subscription's URL. It MUST be `https`, without port, user info or fragment, and its host
  MUST be a known push service of relay policy (anynear: `fcm.googleapis.com`, `*.push.services.mozilla.com`,
  `updates.push.services.mozilla.com`, `web.push.apple.com`, `*.notify.windows.com`); otherwise 400. At most 1024 bytes.
- The watch ID (§2) is computed over the raw token bytes, i.e. the endpoint URL.
- The notification is a push message without payload (RFC 8030), signed with VAPID (`Authorization: vapid t=…, k=…`),
  `TTL` one day, `Urgency: high`, `Topic` fixed per relay so that the push service keeps only the newest. The page
  shows a neutral notice and fetches new entries itself when opened. A push service answering 404 or 410 removes the target.

### 10.2 Target `relay` (stream to a home relay)

Offered when `stream` is in `extensions` (and `watch`), see §18.

```json
{"space": "…", "target": {"type": "relay", "token": "<hex of the 32-byte stream key>",
 "node": "<b64u node of the home relay>", "tag": "<b64u, 16 bytes>"}}
```

- `token` is the hex of an Ed25519 public key of the device (**stream key**), `node` the home relay that holds the
  device's stream, `tag` an opaque label of the space chosen by the device (the relay never learns more from it).
  The relay rejects the target with 400 if `node` is not a relay of its current network list, `token` is not 64
  lower-case hex characters or `tag` is not 16 bytes.
- A watch is keyed by space and token: posting it again with another `node` or `tag` replaces it.
- The watch ID (§2) is computed over the raw token bytes (the stream key), so `ANDP-Watch-Skip` works as for the other
  targets.
- On a new entry (the same cases as §10) the relay collects `{"token", "tag", "alarm"}` per `node` for at most 1 s
  and passes them to the home relay (§18.2). If `node` is the relay itself, it delivers directly.
- `relay` targets count against the limits of §10 like any other target.

## 11. Policy

Values a relay announces in `/andp/v1/info` (defaults of the anynear network in brackets): `max_object_bytes`
(50 MiB + 1 KiB), `max_until` (30 days), `inline_bytes` (64 KiB), `orphan_grace` (24 h), `quota_space_bytes`
(1 GiB), `writer_daily_bytes` (1 GiB), `cors_origins` (`*`), `repair_interval` (60 s). A relay MAY change them;
clients MUST adapt.

## 12. Transport

- Relays listen on TCP 443 with TLS 1.2 or later.
- **Apps** connect to `addr` and pin `key` (SHA-256 of the SPKI). The certificate is otherwise not checked; the
  relay presents its self-signed certificate when the client sends no SNI or an IP literal.
- **Browsers** connect to `host`. The relay presents a Web PKI certificate (Let's Encrypt) for `host` and the shared
  names of the network (for anynear: `anynear.net`), selected by SNI.
- **CORS:** relays answer preflight `OPTIONS` and set `Access-Control-Allow-Origin` (from `cors_origins`),
  `Access-Control-Allow-Headers: Authorization, Content-Type, ANDP-*` (listed explicitly),
  `Access-Control-Expose-Headers` for all `ANDP-*` response headers, `Access-Control-Allow-Methods: GET, PUT, DELETE,
  POST`.
- Rate limits per IP are relay policy; peer requests are exempt.

## 13. Evolution

Version v1 is meant to last: apps update, they are not reinstalled. Therefore:

- Unknown JSON fields, unknown headers and unknown `Authorization` parameters MUST be ignored.
- An unknown value rejects only the item that carries it, never more: an unknown `state` makes a relay inactive (§5.8),
  an unknown `placement` rejects that object, unknown rights bits reject that grant, an unknown signing domain
  rejects that signature. Unknown values in `extensions` are ignored.
- A document with an unknown `v` (network list, radio list) is not accepted; the receiver keeps its current one.
- New optional features are announced in `extensions`; clients use them only when announced.
- When the network needs newer clients, relays raise `clients.min` (§5.2).
- An incompatible change is version v2 under `/andp/v2` with domains `andp/v2/…`. Relays serve v1 and v2 side by side
  until no client in use speaks only v1.

## 14. Signing domains

| Domain | Fields | Signer |
|---|---|---|
| `andp/v1/obj` | space, id, size, ts, until, placement, refsDigest, revokes | writer |
| `andp/v1/del` | space, id, ts | deleter |
| `andp/v1/req` | METHOD, path, ts | caller |
| `andp/v1/grant` | b64u(grant body) | owner |
| `andp/v1/receipt` | space, id, until | relay node |
| `andp/v1/net` | list text | network key |
| `andp/v1/radio` | list text | network key |
| `andp/v1/place` | key, node (hashed, not signed; also the input of the weighted score, §17.4) | – |
| `andp/v1/card` | card text | relay node |

## 15. Test vectors

`vectors/andp-v1.json` holds, for fixed keys derived from `SHA-256("ANDP vectors: <label>")` as Ed25519 seeds:

- b64u strings that decoders must accept or reject (§1),
- signing bytes and signatures for every domain of §14,
- grant body CBOR, grant b64u and grant hash, and grants that must be rejected,
- refs CBOR and `refsDigest`,
- objects with their signing bytes and PUT header sets, including a revocation,
- placement orders, chosen and spare for fixed lists and keys,
- network ID, including a key rotation that keeps `id` and a list signed by the announced `next`,
- network lists with an unknown `state` and with invalid relay entries, and the active relays that remain,
- radio lists that must be accepted or rejected,
- complete `Authorization` headers, a DELETE with its tombstone, and a watch ID,
- cards (valid, tampered, unknown phase, out-of-range weight, repeated key, other network, relay not in the list), weighted
  placement scores, chosen and spare for fixed weights, `log2q32` for fixed inputs, and damaged relays with the read members that remain (§17).

Every implementation MUST pass all vectors. The reference implementation of the anynear relays generates the file;
all others only read it.

## 16. Security considerations

ANDP protects content (ciphertext) and rights. It does not protect metadata, and it does not make relays trustworthy;
it makes what they can do visible and limits it. This section is informative.

### 16.1 What a relay sees

A relay sees spaces, ids, sizes, `refs`, times, `until`, writer keys, client IP addresses and, with watch, push
tokens. A space and a writer key are public keys, not names; what links them to a person is outside ANDP. Several
relays of one operator can correlate what they see. Version v1 does not hide any of this. Applications that need more
(hidden sender, hidden header) add it inside the bytes; ANMP, for example, wraps its packets in an envelope.

A relay never sees plaintext or keys of the application. Contents can be read by anyone who knows their `id`
(§4.1), so an application MUST encrypt them and MUST NOT rely on an `id` staying secret from relays.

### 16.2 What a relay cannot do

- **Forge or change an object.** The `id` is the hash of the bytes and the metadata is signed by the writer; readers
  check both (§3, §9). A relay cannot write into a space without a grant of its owner.
- **Extend a right.** Grants are signed by the owner, carry an expiry and name the space; revocations are entries of
  the owner (§4).
- **Redirect a client.** Clients talk only to relays of a network list signed by the network key they already know,
  pin each relay's TLS key from that list (§12) and follow `holders` only if `node` and `key` are in their own
  list (§9).

### 16.3 What a faulty or malicious relay can do

- **Withhold, delay or drop** objects and tombstones it holds, refuse writes, or keep bytes after a delete or after
  `until`. Deleting is a request to honest relays, not erasure; what must stay unreadable is protected by the
  application's keys, not by deletion.
- **Answer wrongly** to `status`, to other relays or to listing (say `missing` for something it has, omit entries, claim
  `here` for bytes it lacks). A false `here` is found out when someone fetches the object, because every reader checks
  the hash.
- **Send notifications** for spaces it holds watches for, or not send them.
- **Lie in its card** (§17): announce a large `cap` to get a high weight and attract contents (§17.4), or report
  `miss` and `lost` about others. One operator alone cannot make another relay count as damaged; that takes cards of
  at least two other operators (§17.6).

Against this ANDP keeps three copies at three different operators (§6), lets every relay and every client compute the
placement itself and repairs every minute (§8); a client that still has an object can also write it again (§3 rule 2).
One dishonest operator therefore cannot make an object unavailable; three colluding chosen holders can. ANDP has no
consensus and no proof of storage: a relay that claims to hold something is found out only when a reader or a
self-check of others (`seen`, §17.1) asks for it.

### 16.4 The network key

Whoever holds the network key decides which relays belong to the network (§5.8) and what the radio list says (§5.9).
A stolen network key lets an attacker add relays and so see more metadata and withhold more objects; it does not
give access to plaintext and does not let the attacker write into spaces. The key SHOULD be kept offline and used only
to sign lists. `next` announces a successor; there is no revocation of a network key other than a list signed by the
current key or its announced `next`. If all operators are in fact one party, the three copies protect against
failures and against a single hosting provider, not against that party.

### 16.5 Abuse

Spaces and writer keys cost nothing to create, so `quota_space_bytes` and `writer_daily_bytes` (§11) limit one key,
not one person. Limits per IP address and the free-space reserve (507) are relay policy (§12); a network that is open
to anyone needs more than version v1 specifies. A grant for any grantee (no `grantee`) lets everyone who has it
write; the owner bounds the damage by expiry, by quota and by revoking it (§4.3).

Client writes are accepted only within 300 seconds of the relay's clock (§3 rule 5), which bounds replay of a captured
request; a replayed object is the same object (§3 rule 2).

### 16.6 Reporting a vulnerability

See `SECURITY.md` in the repository of this specification.

## 17. Extension: view

Offered when `view` is in `/andp/v1/info` `extensions`. The network list (§5.8) says which relays
belong to the network; with `view`, each relay also spreads a **card** that says how it takes part. Relays exchange
cards among themselves (ANDP Peer), so the network grows, shrinks and rebalances without a new network list. Clients
that do not know `view` keep using the network list alone; for them nothing changes.

### 17.1 Card

`sig = sign("andp/v1/card", card)` by the relay's node key, over the exact text of `card`. On the wire:

```json
{"card": "<JSON text>", "sig": "<b64u>"}
```

The card text:

```json
{"v": 1, "id": "<b64u network ID>", "node": "<b64u>", "ver": 1761200000001, "beat": 1761200000000,
 "phase": "active", "since": 1761113600000, "weight": 2, "cap": 536870912000, "used": 128849018880,
 "full": false, "seen": {"<b64u node>": {"ph": "join", "miss": 3, "total": 40, "at": 1761200000000}}, "sw": "v0.16.0"}
```

| Field | Rule |
|---|---|
| `v` | `1` |
| `id` | the network ID (§2) |
| `node` | the relay's node key; also the key that signs the card |
| `ver` | integer > 0; grows with every new card of this node and never goes down, not even across restarts (a relay uses at least the current Unix milliseconds) |
| `beat` | Unix milliseconds the card was made; a relay makes a new card at least every minute (heartbeat) |
| `phase` | `probe`, `join`, `active` or `leave` (§17.2); a card with another value is invalid |
| `since` | Unix milliseconds the phase began |
| `weight` | 0 … 1024 (§17.4) |
| `weights` | optional; weight mode the relay supports: `contents` or `all` (§17.4) |
| `cap`, `used` | bytes the relay offers for objects and bytes of objects it holds |
| `full` | optional; `true` while the relay accepts no new objects (free space below its reserve) |
| `conn` | optional; Unix milliseconds since when the relay has continuously received fresh cards from at least two other relays (0 or absent: not now) |
| `seen` | optional; per other relay what this relay found in its last repair round: `ph` the phase of that relay in this relay's view, `total` objects this relay holds for which that relay is a target, `miss` how many of them it lacked, `lost` how many of those it lacked although it had confirmed them `here` before (optional), `at` Unix milliseconds of the round |
| `sw` | optional; software version, for humans |

A card is valid if it parses, its fields follow this table and the signature by `node` verifies. Unknown fields are
ignored.

### 17.2 Phases and the two placements

| Phase | Gets copies (target) | Clients ask it (read) |
|---|---|---|
| `probe` | no | no |
| `join` | yes | no |
| `active` | yes | yes |
| `leave` | no | yes |

A relay without a card has the phase of its `state`: `active` → `active`, `candidate` → `probe`, `draining` → `leave`;
with an unknown state it takes no part. From one view two placements follow, both computed as in §17.4:

- **target** over the relays in `join` or `active`: repair (§8) pushes copies there;
- **read** over the relays in `active` or `leave`.

Each relay sets its own phase in its card; when and how a relay moves between phases is specified in ANDP Peer.
Clients only read the phase.

### 17.3 Cards in the network

Relays spread their cards among themselves and check each other's health (ANDP Peer). A view keeps, per node, the
valid card with the highest `ver` whose `id` is the network ID and whose `node` is in the network list (any state).
Merging in any order gives the same view. `GET /andp/v1/view` returns `{"cards": [ … ]}` with every card the relay
holds, for clients and for display.

### 17.4 Weighted placement

Each member has a weight `w` (1 … 1024). Its **score** for a placement key `k` comes from its rank of §6:

    t     = first 8 bytes of rank(r), as unsigned big-endian integer
    x     = 2^63 − (t >> 1)                      (1 … 2^63)
    score = 63·2^32 − log2q32(x)

`log2q32(x)` is log2(x) in fixed point with 32 fractional bits, computed with integer operations only, so that every
implementation gets the same bits:

    n = position of the highest set bit of x (0 … 63)
    y = x << (62 − n) if n ≤ 62, else x >> 1           (y in [2^62, 2^63), the value 1.x in Q62)
    result = n << 32
    for i = 31 down to 0:
        y = (y · y) >> 62                              (128-bit product, then the low 64 bits)
        if y ≥ 2^63: y = y >> 1; result = result | (1 << i)

The score is −log2(1 − u) for u = t / 2^64 in Q32, so it grows with the rank. Members are sorted ascending by
`score / w`, compared as `score_a · w_b < score_b · w_a` (both products fit in 64 bits), ties by rank and then by
`node`; chosen, spare and substitutes follow as in §6 steps 3–5. A relay without card has weight 1. A card with
weight 0 removes the relay from the target placement; in the read placement it counts as weight 1. With the same
weight for every member the order equals §6. A relay with weight `w` comes first for a share of keys proportional to
`w`.

**Weight of a relay:** each relay announces its weight in its card; how it derives it from `cap` and `used` is relay
policy (ANDP Peer). Clients use the weight as announced.

**Weight mode:** a card carries `weights` with the mode the relay supports: absent (none), `contents` or `all`. The
network uses the lowest mode announced by the relays in `join` or `active` (a relay without card announces none):

| Mode | Placement by weight | Placement as in §6 |
|---|---|---|
| none | – | everything |
| `contents` | contents (`placement: object`) | entries |
| `all` | everything | – |

So weights apply only once every relay that takes part supports them, and everyone computes the same mode from the same
view. Clients without `view` place as in §6; they find contents placed by weight through §9 (holders), and entries stay
where they look until the mode is `all`.

### 17.5 Stand-in for contents placed by weight

Joining relays fetch their copies from the others, and a relay hands its copies off only once the new holders
confirmed them (ANDP Peer). For clients one rule is visible:

**Stand-in for contents placed by weight:** a relay that is chosen for a content in the placement of §6 but holds it no
longer, because it lies elsewhere by weight, answers a client read like a proxy read (§9 step 5 with `ANDP-Fetch:
proxy`): it fetches the content from a holder, checks it and delivers it without storing it. So a client without
`view` finds the content at the first relay it asks and does not see a missing holder to put it back to.

### 17.6 Damaged relays

Relays check their own copies regularly and step back to `join` when they find damage (ANDP Peer).

Others do not rely on that: a relay counts as **damaged** while cards of relays of at least two operators other than
its own report `lost` for it, together at least 10 and more than 1 % of their `total`. A damaged relay in `active`
counts as `join` in both placements, whatever its own card says.

## 18. Extension: stream

Offered when `stream` is in `/andp/v1/info` `extensions`. A device in the background keeps one long-lived
connection to one relay, its **home relay**, instead of polling every space. `/andp/v1/info` carries

```json
"stream": {"ping": 180, "clients": false}
```

- `ping`: seconds between `ping` events (default 180).
- `clients`: whether apps should use the stream now. It lets the network switch the stream on and off without a new app
  release; a client that sees `false` (or no `stream` field) keeps polling.

### 18.1 GET /andp/v1/stream

Server-Sent Events (`Content-Type: text/event-stream`). The request carries `Authorization` (§4.4) signed by the
stream key; no grant is needed. The relay answers 401 if the signature is invalid, 429 or 503 when it has too many
streams (relay policy), otherwise 200 and keeps the response open.

Events, each `event: <type>` and one `data:` line with JSON, ended by an empty line:

| Event | Data | Meaning |
|---|---|---|
| `ping` | `{}` | sent at once after connecting and then every `ping` seconds |
| `new` | `{"tags": ["<b64u>", …], "alarm": true}` | spaces with these tags have new entries; `alarm` is `true` if one of the writes carried `ANDP-Notify: alarm`, and absent otherwise |
| `bye` | `{}` | the relay closes the stream (shutdown); the client reconnects after a random delay |

- At most one stream per stream key: a new stream replaces the older one, which is closed.
- The relay buffers nothing for a stream key without open stream. The client lists all its spaces once after every
  (re)connect.
- Unknown event types MUST be ignored (§13).
- A client that receives no event for two `ping` intervals considers the stream broken.

### 18.2 Between relays

A relay that holds a new entry for a `relay` watch (§10.2) tells the device's home relay, which sends the `new`
event. This hand-over between relays is part of ANDP Peer. The home relay merges notifications for the same (token, tag)
that arrive within 2 s.
