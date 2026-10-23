# SC2 reference relay (`relay/`)

This directory holds two Python packages for SolarOS Sealed Chat (SC2, protocol draft v2):

| Package | What it is |
|---|---|
| `sc2proto/` | A shared **sans-IO**, pure-Python protocol package. It covers frame codec, validation, canonical signed-byte layouts, error table, room state machine and limit helpers. It only uses `json`, `struct` and `binascii`, plus `hashlib` when present (`sc2proto.layouts.set_sha256()` lets a port without hashlib plug in its own). It does no I/O and no signing, so it can be shared by the relay, the Python test client and future ports. |
| `sc2_relay/` | The **asyncio reference relay**. It provides v2 NDJSON over TLS (`chats://`, port 7778) and plain TCP (`chat://`, port 7777, off by default), WebSocket at `/sc2`, an HTTP surface (well-known, health, metrics, read-only web view), a loopback admin API with CLI, a chatd-compatible legacy v1 hub, and SQLite storage with migrations. Its only dependency is PyNaCl, used for Ed25519 verify and sign. |

The relay is **isolated from the firmware core**: nothing outside `relay/` imports it, and it builds nothing from the C tree. The one exception is the optional C interop test, which compiles the C SC2 engine against the relay on the host. The protocol draft names `server/sc2_relay/` as the location; this phase uses the top-level `relay/` directory as requested for Phase 4.

## What the relay does (and does not) see

* **DMs** are opaque Double Ratchet envelopes. The relay checks only the routing header (`from`, `to`, sizes) and stores each envelope in a per-device queue. Queues are bounded by 7 days, 500 messages and 5 MB per device; when a queue is full, the send gets `507 inbox_full`. Envelopes are deleted on `ack`.
* **Private rooms** carry ciphertext only. Membership changes are **admin-signed commits**, which the relay verifies before applying (see the layouts below). A room has at most 32 members. A removed device gets a `room.event removed` notice in its own inbox, and routing to it stops at once. New members get **no history**: they sync from their join sequence. Sharing older messages is the opt-in client-side `room.share`.
* **Public rooms** are signed plaintext. The relay **verifies every post signature on ingest**, keeps at most 7 days or 10,000 posts per room, and accepts bodies of at most 1,024 bytes. The first time a device joins a public room it gets a notice with the `PUBLIC · not encrypted` label. Rooms come from configuration (`SC2_PUBLIC_ROOMS`); clients cannot create them unless `SC2_PUBLIC_ROOM_CREATE=any`.
* **Anti-spam** is limited to rate limits (per key, per IP, per room) and **slow mode**. Slow mode applies to young keys automatically (`SC2_SLOW_KEY_MINUTES`, optional `SC2_SLOW_UNTIL_POSTS`), and the operator can turn it on for a whole room. Nothing filters content.
* **Moderation** covers public rooms only:
  * Removals are **relay-signed** `room.mod` events. Clients verify them against the relay key published in `/.well-known/solaros-relay`.
  * Bans target a key, an IP, or both, for an operator-set duration (or indefinitely).
  * Key bans are announced as a signed `room.mod ban`; IP bans are silent.
  * Private rooms and DMs cannot be moderated by the relay, because it cannot read them.
* **Legacy v1** is chatd-compatible, for existing SolarOS gateways. It is **insecure**: no encryption and no signatures. It is on by default for self-hosting (`SC2_LEGACY_V1=true`) and lives in a separate namespace (`v1_channels` and `v1_log` tables) that is **never bridged** to SC2 rooms. The official profile turns it off; a v1 hello then gets `426 upgrade_required`.
* **Web view** is read-only. It serves HTML pages and JSON (`/api/public/<room>`) of the signed public posts, with `noindex` both as a meta tag and as an `X-Robots-Tag` header. It is on in the official profile and off by default for self-hosting.

## Running

Requirements: Python ≥ 3.9 and PyNaCl.

```sh
cd relay
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q                     # full test suite (C interop test needs gcc)

# A local relay: plain chat:// on 7777 and HTTP on 8080, data in ./data
SC2_DATA_DIR=./data SC2_PLAIN=true SC2_RELAY_ID=localhost \
SC2_ADMIN_TOKEN=dev-token python -m sc2_relay

# Or from an env file:
python -m sc2_relay --env-file config/selfhost.env --check-config   # validate only
python -m sc2_relay --env-file config/selfhost.env --print-config   # effective settings
python -m sc2_relay --env-file config/selfhost.env
```

On first start the relay creates its Ed25519 signing key at `$SC2_DATA_DIR/relay_key` (mode 0600) and its database at `$SC2_DATA_DIR/relay.sqlite3`. Migrations run automatically. **Back up `relay_key`**: clients pin the relay key, so losing it means every client must re-trust the relay.

### TLS (`chats://`)

Set `SC2_TLS_CERT` and `SC2_TLS_KEY` (PEM). The relay requires TLS 1.2 or newer. `/.well-known/solaros-relay` publishes `tls_pin` (the SHA-256 of the certificate's SubjectPublicKeyInfo), so a self-signed certificate works with `chats://host:7778#pin=sha256/<tls_pin>`. A self-signed certificate for testing:

```sh
openssl req -x509 -newkey ed25519 -nodes -days 365 -subj "/CN=chat.home.example" \
  -keyout certs/key.pem -out certs/cert.pem
```

**ACME is not built in.** If `SC2_ACME_DOMAIN` is set, the relay logs a warning and continues. Obtain and renew certificates with certbot or Caddy, then restart or reload the relay. The `SC2_ACME_DOMAIN` value is reserved for later use.

### WebSocket

`GET /sc2` with `Upgrade: websocket` carries the same v2 NDJSON frames, one text message per frame. It is served on the HTTP port, which should sit behind a TLS reverse proxy, giving `wss://host/sc2`. It is enabled by `SC2_WEBSOCKET`.

### Docker

```sh
cd relay
docker build -t sc2-relay .
cp config/selfhost.env relay.env   # edit it; mount certs at ./certs
docker compose up -d
docker compose exec relay python -m sc2_relay.admin status
```

The image runs as an unprivileged user and keeps everything persistent in the `/data` volume. It exposes 7778, 7777 and 8080. The admin API stays on 127.0.0.1:7780 *inside* the container and is not published. The compose file drops all capabilities and uses a read-only root filesystem. *(The Docker files were not built during development, because no Docker engine was available.)*

## HTTP surface (`SC2_HTTP_PORT`, default 8080)

| Path | |
|---|---|
| `/.well-known/solaros-relay` | `v`, `suites`, `relay_id`, relay signing key (`relay_key`), `limits`, `admission`, `legacy_v1`, `public_rooms`, `public_room_create`, `web_view`, `public_limits`, `tls_pin` (null without TLS). |
| `/healthz` | `ok` once the database answers. |
| `/metrics` | Prometheus text: aggregate gauges (connections, devices, rooms, queue depth) and counters. No identifiers. Disable with `SC2_METRICS=false`, or block it at the proxy. |
| `/public/`, `/public/<room>?before=<seq>` | HTML web view (if `SC2_WEB_VIEW`). |
| `/api/public/<room>?after=<seq>&limit=<≤200>` | JSON `{room, posts:[{seq, post}], mods:[room.mod], next}`: the retained signed posts (relay-removed ones omitted) plus the relay-signed moderation events, so anyone can verify them independently. |
| `/sc2` | WebSocket transport. |

The web view has its own per-IP rate limit (`SC2_WEB_RATE_PER_MIN`). It sets no cookies and sends a strict CSP with no scripts (`default-src 'none'`), plus `nosniff` and `no-referrer`. All post text is HTML-escaped.

## Admin API and CLI

The admin API listens on `SC2_ADMIN_LISTEN` (default `127.0.0.1:7780`, loopback only) and requires `Authorization: Bearer $SC2_ADMIN_TOKEN`. If the token is empty, the admin API is disabled. The admin paths do not exist on the public HTTP port.

```sh
export SC2_ADMIN_TOKEN=...
python -m sc2_relay.admin status
python -m sc2_relay.admin rooms
python -m sc2_relay.admin posts general --q spam --limit 20
python -m sc2_relay.admin remove general <ref-hex16> [--device <id>]     # relay-signed removal
python -m sc2_relay.admin ban --device <id> --duration 86400 --reason spam --remove-posts
python -m sc2_relay.admin ban --ip 203.0.113.7 --duration 3600            # silent
python -m sc2_relay.admin unban --device <id>
python -m sc2_relay.admin bans
python -m sc2_relay.admin reports [--all]; python -m sc2_relay.admin resolve <id>
python -m sc2_relay.admin slowmode general on|off
python -m sc2_relay.admin tune post_per_min=5 slow_key_minutes=30         # persisted in settings
python -m sc2_relay.admin admission code --code s3cret                    # open | code | allowlist
python -m sc2_relay.admin purge <device-id>                               # delete a device and its queues
python -m sc2_relay.admin retention                                       # run retention now
python -m sc2_relay.admin mute|unmute ...                                 # self-host only, SC2_MUTES=true
```

Bans and mutes apply to **public rooms only**. A banned key's posts get `403 banned` with `until`, and an IP ban affects every key from that address. `--remove-posts` also issues signed removals for the key's existing posts.

## Configuration

All settings are environment variables. `--env-file FILE` loads `KEY=VALUE` lines first; values already in the environment take precedence. Two profiles share one codebase:

* `SC2_PROFILE=selfhost` (default): legacy v1 on, web view off, mutes allowed.
* `SC2_PROFILE=official`: v2 only (v1 hello → `426`), web view on, no mutes. Startup refuses `SC2_LEGACY_V1=true` or `SC2_MUTES=true` under this profile.

See `config/official.env` and `config/selfhost.env`.

| Variable | Default | Meaning |
|---|---|---|
| `SC2_PROFILE` | `selfhost` | `selfhost` or `official`. |
| `SC2_RELAY_ID` | `localhost` | Relay identity, bound into auth and public-post signatures (1–255 bytes). Use the public host name. |
| `SC2_DATA_DIR` | `/data` | Holds the key and database. |
| `SC2_DB` | `$SC2_DATA_DIR/relay.sqlite3` | SQLite path override. |
| `SC2_BIND` | `0.0.0.0` | Listen address for TLS, plain and HTTP. |
| `SC2_TLS_CERT`, `SC2_TLS_KEY` | empty | PEM certificate and key. Both set enables `chats://`. |
| `SC2_TLS_PORT` | `7778` | `chats://` port. |
| `SC2_ACME_DOMAIN` | empty | Reserved. Logs a warning, because ACME is not implemented; use certbot or Caddy. |
| `SC2_PLAIN` | `false` | Enable plain `chat://`. Use on a trusted LAN only, since metadata is visible on the wire. |
| `SC2_PLAIN_PORT` | `7777` | `chat://` port. Legacy v1 clients use this or the TLS port; the relay recognises v1 by its first line. |
| `SC2_HTTP_PORT` | `8080` | HTTP port (0 disables). |
| `SC2_HTTP_TLS` | `false` | Serve HTTP with the TLS certificate. |
| `SC2_WEBSOCKET` | `true` | `/sc2` WebSocket. |
| `SC2_METRICS` | `true` | `/metrics`. |
| `SC2_TRUST_PROXY` | `false` | Take the client IP from `X-Forwarded-For` (HTTP and WS only). Turn on only behind your own proxy. |
| `SC2_ADMIN_LISTEN` | `127.0.0.1:7780` | Admin API address. |
| `SC2_ADMIN_TOKEN` | empty | Bearer token. Empty disables the admin API. |
| `SC2_ADMISSION` | `open` | `open`, `code` (`hello.admit` must equal `SC2_ADMIT_CODE`) or `allowlist`. |
| `SC2_ADMIT_CODE` | empty | Registration code. |
| `SC2_ALLOWLIST` | empty | Comma-separated 32-hex device IDs. |
| `SC2_TTL_DAYS` | `7` | Retention for inbox queues and public logs. |
| `SC2_MAX_QUEUE` | `500` | Messages per device queue. |
| `SC2_MAX_QUEUE_BYTES` | `5242880` | Bytes per device queue. |
| `SC2_OPK_MAX` | `100` | One-time prekeys stored per device. |
| `SC2_KEYS_LOW` | `5` | Send `keys.low` below this many OPKs. |
| `SC2_ROOM_MEMBERS_MAX` | `32` | Private room size cap (≤ 32). |
| `SC2_ROOMS_PER_DEVICE` | `64` | Private rooms a device may belong to. |
| `SC2_PRIVATE_LOG_MAX` | `10000` | Room log entries kept per private room (also TTL-bounded). |
| `SC2_LEGACY_V1` | `true` (selfhost), `false` (official) | chatd-compatible v1 hub. |
| `SC2_LEGACY_V1_TOKEN` | empty | Optional v1 token (< 96 bytes). |
| `SC2_V1_HISTORY` | `64` | v1 lines replayed per channel. |
| `SC2_V1_MAX_CHANNELS` | `32` | v1 channel cap. |
| `SC2_PUBLIC_ROOMS` | `general` | Configured public rooms (the `#` prefix is optional). |
| `SC2_PUBLIC_ROOM_CREATE` | `operator` | `operator` (config only) or `any`. |
| `SC2_PUBLIC_BODY_MAX` | `1024` | Public post body limit in bytes. |
| `SC2_PUBLIC_LOG_MAX` | `10000` | Posts kept per public room. |
| `SC2_WEB_VIEW` | `false` (selfhost), `true` (official) | Read-only web view. |
| `SC2_WEB_NOINDEX` | `true` | `noindex` meta and header. |
| `SC2_WEB_PAGE_SIZE` | `100` | Posts per HTML page. |
| `SC2_WEB_RATE_PER_MIN` | `120` | Web view requests per IP per minute. |
| `SC2_MUTES` | `false` | Self-host mutes (`403 muted`). Not allowed under the official profile. |
| `SC2_POST_PER_MIN` / `SC2_POST_BURST` | `10` / `5` | Public posts per key. |
| `SC2_IP_POST_PER_MIN` / `SC2_IP_POST_BURST` | `30` / `10` | Public posts per IP. |
| `SC2_ROOM_POST_PER_MIN` | `600` | Public posts per room. |
| `SC2_SLOW_KEY_MINUTES` | `10` | A key younger than this is in slow mode. |
| `SC2_SLOW_UNTIL_POSTS` | `0` | Also keep a key in slow mode until it has this many accepted posts (0 = off). |
| `SC2_SLOW_PER_MIN` / `SC2_SLOW_BURST` / `SC2_SLOW_BODY_MAX` | `2` / `1` / `256` | Slow-mode limits. |
| `SC2_SEND_PER_MIN` / `SC2_SEND_BURST` | `120` / `30` | DM and room sends per device. |
| `SC2_CLAIM_PER_MIN` | `20` | `keys.claim` per device. |
| `SC2_REGISTER_PER_HOUR` | `30` | New device registrations per IP. |
| `SC2_REPORT_PER_MIN` | `5` | Reports per device. |
| `SC2_MAX_CONNECTIONS` / `SC2_MAX_CONN_PER_IP` | `2048` / `16` | Connection caps. |
| `SC2_AUTH_TIMEOUT` | `30` | Seconds to finish hello and auth. |
| `SC2_IDLE_TIMEOUT` | `300` | Idle disconnect (clients ping). |
| `SC2_SEND_BUFFER_MAX` | `1048576` | Per-connection outbound buffer. A slow reader is disconnected beyond this. |
| `SC2_RETENTION_INTERVAL` | `60` | Seconds between retention sweeps. |
| `SC2_LOG_LEVEL` | `INFO` | Python log level. |
| `SC2_LOG_DEVICE_IDS` | `false` | Log device IDs; the default writes `<device>` instead. |

Rate and limit values marked tunable can be changed at runtime with `admin tune`, which persists them in the database. Tunable keys are `admission`, `admit_code`, `post_per_min`, `post_burst`, `ip_post_per_min`, `ip_post_burst`, `room_post_per_min`, the `slow_*` settings, `max_queue`, `max_queue_bytes`, `ttl_days`, `send_per_min`, `send_burst` and `claim_per_min`.

## Wire layouts defined in this phase

The draft leaves these byte layouts to the implementation, so this phase defines them here. They are implemented in `sc2proto/layouts.py`. The C harness in `tests/c/` builds the commit layout independently and checks it against the relay. **They still need owner sign-off and C-core parity.** `||` means concatenation; integers are big-endian; `lp8(x)` is a one-byte length followed by `x`; `n×id16` is a one-byte count followed by raw 16-byte device IDs.

* **Commit (private-room membership)**, signed by an admin's IK:
  `"SC2-COMMIT\x01" || suite u8 || room16 || prev u32 || epoch u32 || by16 || n×add16 || n×remove16 || flag u8 [|| n×admins16] || members_hash32`
  * `flag` is 1 when the commit carries a new `admins` list and 0 when the admin list is unchanged.
  * `members_hash` is the SHA-256 over the sorted raw member IDs, concatenated, after the commit is applied.
  * Wire lists must be sorted and free of duplicates.
  * `room.create` for a private room must carry the genesis commit: `prev 0`, `epoch 1`, `by` the creator, the creator in `add` and in `admins`.
  * The last admin cannot leave.
* **Moderation event**, signed by the relay key:
  `"SC2-MOD\x01" || suite u8 || lp8(relay_id) || lp8(room) || action u8 (1 remove, 2 ban) || ref8 (zeros if none) || device16 (zeros if none) || until u64 (0 = indefinite) || seq u64 || ts u64`
  * The frame is `{"type":"room.mod","room","seq","action","ref"?,"device"?,"until" (ban only),"ts","by":"relay","sig"}`.
* **Private-room invites**:
  * An admin derives `invite_key = HMAC-SHA256(secret, "SC2-INVITE\x01" || room16)` and registers it with the new client frame `{"type":"room.invite","room","key","revoke"?}`. Only admins may do this.
  * A joiner sends `room.join` with `invite = HMAC-SHA256(invite_key, "SC2-JOIN\x01" || joiner16)`.
  * A valid proof creates a `room.event join_request` for the room's admins. An admin then adds the joiner with a commit. The relay never adds members by itself.

## Security notes

* **Trust model.** The relay is a store-and-forward router. It cannot read DMs or private rooms, and it cannot forge public posts, member commits or other devices' auth. It *can* see metadata: who talks to whom and when, sizes, IPs, room membership. It can also delay or drop traffic, and it signs moderation events that clients attribute to the relay. Run it on a host you trust with that metadata.
* **Keys.** Protect `relay_key` (mode 0600, back it up offline). `SC2_ADMIN_TOKEN` must be long and random. Keep the admin API on loopback and tunnel to it over SSH if needed.
* **Plain `chat://`.** Content stays end-to-end encrypted and auth is a signature challenge, but metadata and the relay key fingerprint are exposed to the network. Use it on trusted LANs only.
* **Legacy v1 is plaintext and unauthenticated** apart from an optional shared token. It is kept for existing gateways and never bridged. Disable it (`SC2_LEGACY_V1=false`) once devices are on v2.
* **Public rooms are public.** Posts are signed plaintext and appear in the web view when enabled. Clients show the PUBLIC label and the first-join notice. `noindex` asks search engines not to index the view but does not enforce it.
* **Limits.** Every frame is size-checked before parsing (16 KiB line cap for v2) and validated strictly: canonical base64, exact field sets, bounded lists. Unauthenticated connections time out. Per-IP connection and registration caps limit floods.
* **Logs** never contain message content. Device IDs are replaced by `<device>` unless `SC2_LOG_DEVICE_IDS=true`.

## Tests

`python -m pytest -q` from `relay/` runs the suite. It needs the full repository checkout, because it imports `protocol/sc2/tools/sc2ref.py` and the C vectors and engine sources. It covers:

| Area | What it covers |
|---|---|
| End-to-end DMs | The relay driven by the Python `sc2ref` client (`protocol/sc2/tools/sc2ref.py`). |
| Private rooms | Commits, removal, size cap, no history, opt-in share, invites. |
| Public rooms | Signature verify, limits, labels, slow mode. |
| Admin and bans | Signed removals, key and IP bans. |
| Legacy v1 | chatd parity, and `426` under the official profile. |
| Web view | HTML and JSON, `noindex`. |
| Storage and config | Migrations, configuration. |
| TLS and WebSocket | TLS and WS transports. |
| Interop vectors | The C test vectors. |
| Fuzz | Raise `SC2_FUZZ_ITER` for longer runs. |
| C client | `tests/test_c_client.py` compiles a small C harness (`tests/c/`) against the firmware's SC2 engine with the host compiler and runs it against a live relay. It is skipped when gcc is missing. |
