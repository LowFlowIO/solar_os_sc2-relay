# SC2 reference relay (`relay/`)

This directory holds two Python packages for SolarOS Sealed Chat (SC2, protocol draft v2):

| Package | What it is |
|---|---|
| `sc2proto/` | A shared **sans-IO**, pure-Python protocol package. It covers frame codec, validation, canonical signed-byte layouts, error table, room state machine and limit helpers. It only uses `json`, `struct` and `binascii`, plus `hashlib` when present (`sc2proto.layouts.set_sha256()` lets a port without hashlib plug in its own). It does no I/O and no signing, so it can be shared by the relay, the Python test client and future ports. |
| `sc2_relay/` | The **asyncio reference relay**. It provides v2 NDJSON over TLS (`chats://`, port 7778) and plain TCP (`chat://`, port 7777, off by default), WebSocket at `/sc2`, an HTTP surface (well-known, health, metrics, read-only web view), a loopback admin API with CLI, a chatd-compatible legacy v1 hub, and SQLite storage with migrations. Its only dependency is PyNaCl, used for Ed25519 verify and sign. |

The relay is **isolated from the firmware core**: nothing outside `relay/` imports it, and it builds nothing from the C tree. The one exception is the optional C interop test, which compiles the C SC2 engine against the relay on the host. `relay/` is the decided location (draft §10.1, Phase 4b): the relay is a separate deployable with its own tests, kept out of the firmware tree.

## What the relay does (and does not) see

* **DMs** are opaque Double Ratchet envelopes. The relay checks only the routing header (`from`, `to`, sizes) and stores each envelope in a per-device queue. Queues are bounded by 7 days, 500 messages and 5 MB per device; when a queue is full, the send gets `507 inbox_full`. Envelopes are deleted on `ack`.
* **Private rooms** carry ciphertext only. Membership changes are **admin-signed commits**, one change per commit, chained by commit ID; the relay verifies and sequences them before applying (see the wire formats below). A room has at most 32 members. A removed device gets a `room.event removed` notice in its own inbox, and routing to it stops at once. New members get **no history**: they sync from their join sequence. Sharing older messages is the opt-in client-side `room.share`.
* **Public rooms** are signed plaintext. The relay **verifies every post signature on ingest**, keeps at most 7 days or 10,000 posts per room, and accepts bodies of at most 1,024 bytes. The first time a device joins a public room it gets a notice with the `PUBLIC · not encrypted` label. Rooms come from configuration (`SC2_PUBLIC_ROOMS`); clients cannot create them unless `SC2_PUBLIC_ROOM_CREATE=any`.
* **Anti-spam** is limited to rate limits (per key, per IP, per room) and **slow mode**. Slow mode applies to young keys automatically (`SC2_SLOW_KEY_MINUTES`, optional `SC2_SLOW_UNTIL_POSTS`), and the operator can turn it on for a whole room. Nothing filters content.
* **Moderation** covers public rooms only:
  * Removals are **relay-signed** `room.mod` events. Clients verify them against the relay key published in `/.well-known/solaros-relay`.
  * Bans target a key, an IP, or both, for an operator-set duration (or indefinitely).
  * Key bans are announced as a signed `room.mod ban`, and lifting one early as `room.mod unban`; IP bans are silent.
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

On first start the relay creates its Ed25519 signing key at `$SC2_DATA_DIR/relay_key` and its database at `$SC2_DATA_DIR/relay.sqlite3`. Migrations run automatically. **File modes do not depend on the umask:** the data directory is `0700`, and the database, its `-wal`/`-shm` files and the key are `0600`; looser modes on existing files are tightened at every start (a warning is logged if the relay does not own the file). **Back up `relay_key`**: clients pin the relay key, so losing it means every client must re-trust the relay.

### TLS (`chats://`)

Set `SC2_TLS_CERT` and `SC2_TLS_KEY` (PEM), or `SC2_ACME_DOMAIN` (below). The relay requires TLS 1.2 or newer.

**Pins are SPKI-based.** `/.well-known/solaros-relay` publishes `tls_pin`, the SHA-256 of the certificate's **SubjectPublicKeyInfo** (the public key), base64, as `sha256/<b64>`. Devices that cannot use a CA chain (self-signed relays) connect with `chats://host:7778#pin=sha256/<b64>`. Because the pin covers the key and not the certificate, a renewed certificate for the **same key** keeps every pin valid; only a new key changes it. A self-signed certificate for testing:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 \
  -subj "/CN=chat.home.example" -keyout certs/key.pem -out certs/cert.pem
```

**Hot reload.** The relay watches the two files (every `SC2_TLS_RELOAD_INTERVAL` seconds, default 60, `0` = off) and reloads them on `SIGHUP`. A changed pair is copied once, checked in a scratch TLS context (certificate parses, key matches) and only then loaded into the live context: established connections keep their session, new handshakes get the new certificate, and `tls_pin` in `/.well-known` follows. A broken or half-written pair is logged and skipped, and the old certificate stays in use (`tls_reload_failures_total` in `/metrics`, successful reloads in `tls_reloads_total`). Replace files by writing a temporary file and renaming it.

#### Let's Encrypt with Docker (cloud relays)

`docker-compose.yml` includes a `certbot` sidecar (`deploy/certbot/run.sh`):

1. Point the domain's DNS at the host and open port 80 (HTTP-01) and 7778.
2. In `relay.env` set `SC2_ACME_DOMAIN=relay.example.org` and `SC2_ACME_EMAIL=ops@example.org` (try `SC2_ACME_STAGING=true` first). Leave `SC2_TLS_CERT`/`SC2_TLS_KEY` unset: with `SC2_ACME_DOMAIN` they default to `$SC2_ACME_CERT_DIR/fullchain.pem` and `privkey.pem` (`/certs`).
3. `docker compose up -d`. certbot gets the certificate (standalone on :80; or set `SC2_ACME_WEBROOT` if a web server you already run answers `/.well-known/acme-challenge/` from a shared directory), and its deploy hook (`deploy/certbot/deploy-hook.sh`) copies the pair into the `relay-certs` volume, `0600`, owned by the relay's fixed UID/GID 10001. Until the first certificate exists the relay serves HTTP only and opens `chats://` as soon as the files appear.
4. Renewal: certbot runs `certbot renew` every 12 hours (`SC2_ACME_RENEW_INTERVAL`) and renews within 30 days of expiry. The relay hot-reloads the new pair; nothing restarts.

certbot always runs with **`--reuse-key`** (ECDSA P-256), so the SPKI pin stays the same across the 90-day renewals. Do not remove it: without it every renewal changes the pin and breaks pinned devices.

#### Plain certbot (no Docker)

```sh
sudo certbot certonly --standalone -d relay.example.org -m ops@example.org --agree-tos \
  --key-type ecdsa --elliptic-curve secp256r1 --reuse-key \
  --deploy-hook 'install -m 0600 -o sc2 -g sc2 $RENEWED_LINEAGE/privkey.pem /etc/sc2-relay/tls/privkey.pem.new &&
                 mv /etc/sc2-relay/tls/privkey.pem.new /etc/sc2-relay/tls/privkey.pem &&
                 install -m 0600 -o sc2 -g sc2 $RENEWED_LINEAGE/fullchain.pem /etc/sc2-relay/tls/fullchain.pem.new &&
                 mv /etc/sc2-relay/tls/fullchain.pem.new /etc/sc2-relay/tls/fullchain.pem &&
                 pkill -HUP -f "python -m sc2_relay" || true'
```

Then set `SC2_TLS_CERT=/etc/sc2-relay/tls/fullchain.pem` and `SC2_TLS_KEY=/etc/sc2-relay/tls/privkey.pem` (or `SC2_ACME_DOMAIN` with `SC2_ACME_CERT_DIR=/etc/sc2-relay/tls`). The distribution's `certbot.timer` (or cron `certbot renew`) does the renewals; `--reuse-key` is stored in the renewal config, and the hook copies and signals the relay. If the relay user can read `/etc/letsencrypt/live/<domain>/` you can point the two variables there directly; the watcher follows the symlinks. Use `--webroot -w <dir>` instead of `--standalone` if a web server already owns port 80.

#### Key rotation

Rotate the TLS key only when needed (suspected compromise, algorithm change). It changes the pin:

1. Generate the new key and publish the **new** pin ahead of time (announcement, project page). Devices with a CA-validated `chats://` URL need nothing; pinned devices must update their `#pin=`.
2. Rotate: `certbot renew --force-renewal --cert-name sc2-relay --new-key` (Docker: `docker compose exec certbot certbot renew --force-renewal --cert-name sc2-relay --new-key`; certbot ≥ 1.26), or replace the key and certificate by hand. Later renewals reuse the new key again.
3. The relay reloads the pair and logs `TLS key changed: SPKI pin <old> -> <new>`; `/.well-known` publishes the new pin at once.

The TLS key is separate from the relay's Ed25519 **signing** key (`relay_key`), which signs moderation events and is what clients trust for them. A TLS rotation does not touch it.

### WebSocket

`GET /sc2` with `Upgrade: websocket` carries the same v2 NDJSON frames, one text message per frame. It is served on the HTTP port, which should sit behind a TLS reverse proxy, giving `wss://host/sc2`. It is enabled by `SC2_WEBSOCKET`.

### Docker

```sh
cd relay
docker build -t sc2-relay .
cp config/official.env relay.env   # or selfhost.env; edit it (see TLS above)
docker compose up -d
docker compose exec relay python -m sc2_relay.admin status
```

The image runs as an unprivileged user with the fixed UID/GID 10001 and keeps everything persistent in the `/data` volume. It exposes 7778, 7777 and 8080. The admin API stays on 127.0.0.1:7780 *inside* the container and is not published. The compose file drops all capabilities and uses a read-only root filesystem. *(The Docker files, including the certbot sidecar, were not built or run against Let's Encrypt during development, because no Docker engine or public host was available. The deploy hook and the relay's reload path are exercised by `tests/test_tls_reload.py`.)*

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
| `SC2_ACME_DOMAIN` | empty | Let's Encrypt domain. The relay then reads `$SC2_ACME_CERT_DIR/fullchain.pem` and `privkey.pem` (unless `SC2_TLS_CERT/KEY` are set) and waits for them on first start. The certbot sidecar also reads `SC2_ACME_EMAIL`, `SC2_ACME_STAGING`, `SC2_ACME_WEBROOT` and `SC2_ACME_RENEW_INTERVAL`. |
| `SC2_ACME_CERT_DIR` | `/certs` | Where certbot's deploy hook puts the pair. |
| `SC2_TLS_RELOAD_INTERVAL` | `60` | Seconds between certificate file checks (0 = off; `SIGHUP` always reloads). |
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
| `SC2_POST_PER_MIN` / `SC2_POST_BURST` | `100000` / `100000` (official: `10` / `5`) | Public posts per key. The selfhost defaults are effectively unlimited; set real limits for an open relay. |
| `SC2_IP_POST_PER_MIN` / `SC2_IP_POST_BURST` | `100000` / `100000` (official: `30` / `10`) | Public posts per IP. |
| `SC2_ROOM_POST_PER_MIN` | `1000000` (official: `600`) | Public posts per room. |
| `SC2_SLOW_KEY_MINUTES` | `0` (official: `10`) | A key younger than this is in slow mode (0 = off). |
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

## Wire formats (draft §6.7, §7.0, §7.5, normative since Phase 4b)

The three records are fixed-size binary so a device can build and verify them with small fixed buffers; the relay does the heavier bookkeeping. They are implemented in `sc2proto/layouts.py` and `sc2proto/rooms.py` here and in `protocol/sc2/include/sc2_commit.h` and `sc2_mod.h` on the device; both sides are checked against `protocol/sc2/vectors/sc2_vectors.json` (`tests/test_interop_vectors.py`, `tests/test_c_client.py`). `‖` is concatenation; integers are big-endian.

* **Commit** (private-room membership), 130 bytes, signed as-is by an admin IK:
  `"SC2-COMMIT\x01" ‖ suite u8 ‖ room16 ‖ epoch u32 ‖ prev32 ‖ by16 ‖ op u8 ‖ target16 ‖ count u8 ‖ roster_hash32`
  * `op`: 1 create, 2 add, 3 remove, 4 promote, 5 demote, 6 rotate. **One change per commit.**
  * `epoch` is the new epoch (current + 1, genesis 1); `prev` is the previous commit's ID (`SHA-256(record)`), zero for genesis. The relay accepts only `epoch == current + 1` and `prev == head`, else `409 epoch_conflict` with `epoch` and `head`.
  * `count` and `roster_hash` describe the roster after the op: SHA-256 over the entries `device16 ‖ role u8` (1 admin, 0 member) sorted by device ID.
  * Genesis: epoch 1, zero prev, `target == by` = the creating device, count 1. Rotate: zero target. The last admin can be neither removed nor demoted; a room has at most 32 members (`SC2_ROOM_MEMBERS_MAX` or `policy.max` lower it).
  * Frames: `room.create` (private) `{type, rid, room, kind:"private", [policy], commit, sig}`; C→R `room.commit` `{type, rid, room, commit, sig}`; R→C fan-out `{type, room, seq, commit, sig}`; acks carry `epoch` and `head`, and `room.state` carries `head`. `commit` and `sig` are standard base64.
* **Moderation event** (public rooms), 122 bytes, signed by the relay key:
  `"SC2-MOD\x01" ‖ suite u8 ‖ action u8 (1 remove, 2 ban, 3 unban) ‖ room (64, UTF-8, zero padded, 1..63 bytes) ‖ seq u64 ‖ ts u64 ‖ ref8 ‖ device16 ‖ until u64`
  * `ref` only for remove (else zero); `device` always (the author for remove, the key for ban/unban); `until` only for ban, `0` = indefinite.
  * Frame, in this field order: `{type:"room.mod", room, seq, action, ts, [ref], device, [until], by:"relay", sig}`; `until` is `null` for an indefinite ban. A removal of several authors' posts emits one event per author.
* **Invites** (private rooms):
  * `invite_key = HMAC-SHA-256(secret16, "SC2-INVITE\x01" ‖ room16)`, registered by an admin with `{type:"room.invite", rid, room, key, [revoke:true]}`.
  * `room.join` carries `invite = HMAC-SHA-256(invite_key, "SC2-JOIN\x01" ‖ joiner16)`; a valid proof is acked with `status:"requested"` and creates `room.event join_request` for the admins, who add the joiner with a commit. The relay never adds members by itself.
  * The out-of-band code is `"SC2I" ‖ 1 ‖ room16 ‖ secret16 ‖ admin_id16 ‖ admin_ik32 ‖ url_len u8 ‖ url` (86..286 bytes, `admin_id = device_id(admin_ik)`, URL `chat://` or `chats://`), shown as `sc2i:` + base64. The relay never sees it.

## Security notes

* **Trust model.** The relay is a store-and-forward router. It cannot read DMs or private rooms, and it cannot forge public posts, member commits or other devices' auth. It *can* see metadata: who talks to whom and when, sizes, IPs, room membership. It can also delay or drop traffic, and it signs moderation events that clients attribute to the relay. Run it on a host you trust with that metadata.
* **Keys.** Protect `relay_key` (always 0600, back it up offline). The TLS key lives in the certbot volume or `SC2_TLS_KEY` (0600, owned by the relay user). `SC2_ADMIN_TOKEN` must be long and random. Keep the admin API on loopback and tunnel to it over SSH if needed.
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
| Private rooms | Commit chain (head/epoch conflicts, roster hash, genesis rules, last admin), removal, size cap, no history, opt-in share, invites. |
| Public rooms | Signature verify, limits, labels, slow mode. |
| Admin and bans | Signed removals, key and IP bans. |
| Legacy v1 | chatd parity, and `426` under the official profile. |
| Web view | HTML and JSON, `noindex`. |
| Storage and config | Migrations, configuration. |
| TLS and WebSocket | TLS and WS transports. |
| TLS hot reload | `--reuse-key` renewal keeps connections and the pin, key rotation publishes the new pin, broken pairs are skipped, ACME first start, the certbot deploy hook. |
| Permissions | 0700 data dir, 0600 database/WAL/SHM/key under umask 000, loose modes tightened. |
| Interop vectors | The C test vectors, including the commit chain and its bad cases, moderation records and frames, and invites. |
| Fuzz | Raise `SC2_FUZZ_ITER` for longer runs. |
| C client | `tests/test_c_client.py` compiles a small C harness (`tests/c/`) against the firmware's SC2 engine with the host compiler and runs it against a live relay. It is skipped when gcc is missing. |
