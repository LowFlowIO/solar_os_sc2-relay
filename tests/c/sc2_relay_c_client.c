/*
 * Host interop harness: two SolarOS SC2 engines (src/services/solar_os_sc2_engine.c
 * on protocol/sc2) talk to the Python reference relay over real TCP sockets.
 *
 *   sc2_relay_c_client <host> <port> <relay_id>
 *
 * Flow: hello/welcome/auth for both devices, keys.publish, keys.claim and
 * add_bundle, sealed DMs both ways (X3DH + ratchet) with inbox sync and ack,
 * a private room built with the protocol/sc2 commit API (genesis, an
 * invite registered by the admin, bob's invite proof, the admin's add commit
 * checked by bob from the relay's fan-out, then a rotate), the epoch key
 * shared over DM, sealed room messages verified by the relay, and a signed
 * public post verified by the relay and by the reader.
 * Prints "SC2-C-RELAY OK" and exits 0 on success.
 *
 * SPDX-License-Identifier: MIT
 */
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "sc2_codec.h"
#include "sc2_commit.h"
#include "sc2_crypto.h"
#include "sc2_frame.h"
#include "sc2_hash.h"
#include "sc2_identity.h"
#include "solar_os_sc2_engine.h"
#include "solar_os_sc2_selftest.h"

#define LINE_CAP 32768u

static const char *g_relay_id;

static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "sc2_relay_c_client: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}

#define CHECK(rc, what)                                                     \
    do {                                                                    \
        int rc_ = (rc);                                                     \
        if (rc_ != SC2_OK) {                                                \
            die("%s failed: %s (%d)", (what), sc2_strerror(rc_), rc_);      \
        }                                                                   \
    } while (0)

/* ---------------- host platform ---------------- */

static int urandom_fn(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    size_t got = 0;
    while (got < len) {
        ssize_t r = read(fd, out + got, len - got);
        if (r <= 0) {
            close(fd);
            return -1;
        }
        got += (size_t)r;
    }
    close(fd);
    return 0;
}

static void *h_alloc(void *ctx, size_t len)
{
    (void)ctx;
    return calloc(1, len);
}

static void h_release(void *ctx, void *ptr, size_t len)
{
    (void)ctx;
    if (ptr != NULL) {
        sc2_memzero(ptr, len);
        free(ptr);
    }
}

static uint64_t h_clock(void *ctx)
{
    (void)ctx;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

/* ---------------- line transport ---------------- */

typedef struct {
    int fd;
    char buf[LINE_CAP * 2];
    size_t len;
    const char *name;
} conn_t;

static void conn_open(conn_t *c, const char *host, const char *port, const char *name)
{
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0 || res == NULL) {
        die("cannot resolve %s:%s", host, port);
    }
    c->fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (c->fd < 0 || connect(c->fd, res->ai_addr, res->ai_addrlen) != 0) {
        die("cannot connect to %s:%s: %s", host, port, strerror(errno));
    }
    freeaddrinfo(res);
    struct timeval tv = {10, 0};
    setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    c->len = 0;
    c->name = name;
}

static void send_line(conn_t *c, const char *line, size_t len)
{
    if (write(c->fd, line, len) != (ssize_t)len || write(c->fd, "\n", 1) != 1) {
        die("%s: write failed", c->name);
    }
}

/* Next complete line (NUL terminated, newline stripped). */
static size_t recv_line(conn_t *c, char *out, size_t cap)
{
    for (;;) {
        char *nl = memchr(c->buf, '\n', c->len);
        if (nl != NULL) {
            size_t n = (size_t)(nl - c->buf);
            if (n + 1 > cap) {
                die("%s: line too long", c->name);
            }
            memcpy(out, c->buf, n);
            out[n] = '\0';
            memmove(c->buf, nl + 1, c->len - n - 1);
            c->len -= n + 1;
            return n;
        }
        if (c->len == sizeof(c->buf)) {
            die("%s: receive buffer full", c->name);
        }
        ssize_t r = read(c->fd, c->buf + c->len, sizeof(c->buf) - c->len);
        if (r <= 0) {
            die("%s: connection closed or timed out", c->name);
        }
        c->len += (size_t)r;
    }
}

/* Skip lines until one has "type":"<type>"; error frames are fatal. */
static size_t recv_type(conn_t *c, const char *type, char *out, size_t cap)
{
    char want[64];
    snprintf(want, sizeof(want), "\"type\":\"%s\"", type);
    for (;;) {
        size_t n = recv_line(c, out, cap);
        if (strstr(out, want) != NULL) {
            return n;
        }
        if (strstr(out, "\"type\":\"error\"") != NULL) {
            die("%s: relay error while waiting for %s: %s", c->name, type, out);
        }
    }
}

/* ---------------- device ---------------- */

typedef struct {
    sc2e_memstore_t *store;
    sc2e_t e;
    conn_t conn;
    sc2e_identity_info_t info;
} device_t;

static char g_line[LINE_CAP];
static char g_out[LINE_CAP];
static char g_pt[LINE_CAP];

static void device_open(device_t *d, const sc2e_test_host_t *host, const char *name)
{
    sc2e_platform_t pf;
    CHECK(sc2e_memstore_create(&d->store, host), "memstore");
    sc2e_memstore_platform(d->store, &pf);
    CHECK(sc2e_open(&d->e, &pf), "sc2e_open");
    CHECK(sc2e_identity(&d->e, &d->info), "sc2e_identity");
    d->conn.name = name;
}

static void device_connect(device_t *d, const char *host, const char *port)
{
    size_t n = 0;
    sc2_welcome_t w;
    uint8_t sig[SC2_SIG_LEN];
    conn_open(&d->conn, host, port, d->conn.name);
    CHECK(sc2_frame_hello(g_out, sizeof(g_out), &n, "solaros-c/phase4", NULL, NULL), "hello");
    send_line(&d->conn, g_out, n);
    n = recv_type(&d->conn, "welcome", g_line, sizeof(g_line));
    CHECK(sc2_frame_welcome_decode(g_line, n, &w), "welcome decode");
    if (strcmp(w.relay_id, g_relay_id) != 0 || !w.has_relay_key || w.limit_line != SC2_LINE_MAX) {
        die("unexpected welcome: %s", g_line);
    }
    CHECK(sc2_auth_sign(sig, &d->e.id, w.relay_id, strlen(w.relay_id), w.challenge), "auth sign");
    CHECK(sc2_frame_auth(g_out, sizeof(g_out), &n, "a1", d->e.id.ik_pub, sig, false), "auth frame");
    send_line(&d->conn, g_out, n);
    recv_type(&d->conn, "authed", g_line, sizeof(g_line));
    if (strstr(g_line, d->e.self_hex) == NULL) {
        die("authed for the wrong device: %s", g_line);
    }
    /* sync so the relay pushes live traffic to this session */
    n = (size_t)snprintf(g_out, sizeof(g_out), "{\"type\":\"sync\",\"rid\":\"y0\",\"inbox\":\"0\"}");
    send_line(&d->conn, g_out, n);
    recv_type(&d->conn, "sync.done", g_line, sizeof(g_line));
}

static void publish(device_t *d)
{
    size_t n = 0;
    CHECK(sc2e_keys_publish(&d->e, "k1", 8, g_out, sizeof(g_out), &n), "keys_publish");
    send_line(&d->conn, g_out, n);
    recv_type(&d->conn, "ack", g_line, sizeof(g_line));
}

static void claim(device_t *self, const device_t *peer)
{
    char dev[SC2_DEVICE_ID_HEX_LEN + 1];
    size_t n = (size_t)snprintf(g_out, sizeof(g_out), "{\"type\":\"keys.claim\",\"rid\":\"k2\",\"device\":\"%s\"}",
                                peer->e.self_hex);
    send_line(&self->conn, g_out, n);
    n = recv_type(&self->conn, "keys.bundle", g_line, sizeof(g_line));
    CHECK(sc2e_add_bundle(&self->e, g_line, n, dev), "add_bundle");
    if (strcmp(dev, peer->e.self_hex) != 0) {
        die("bundle for the wrong device");
    }
}

static void dm(device_t *from, device_t *to, const char *inner, int expect_kind)
{
    size_t n = 0, pl = 0;
    sc2e_dm_result_t res;
    CHECK(sc2e_dm_encrypt(&from->e, to->e.self_hex, "d1", inner, strlen(inner), g_out, sizeof(g_out), &n),
          "dm_encrypt");
    send_line(&from->conn, g_out, n);
    recv_type(&from->conn, "ack", g_line, sizeof(g_line));
    n = recv_type(&to->conn, "dm.msg", g_line, sizeof(g_line));
    CHECK(sc2e_dm_decrypt(&to->e, g_line, n, &res, g_pt, sizeof(g_pt), &pl), "dm_decrypt");
    if (res.kind != expect_kind || strcmp(res.from, from->e.self_hex) != 0) {
        die("unexpected DM result kind %d", res.kind);
    }
    if (expect_kind == SC2E_DM_MESSAGE && strcmp(g_pt, inner) != 0) {
        die("DM plaintext mismatch: %s", g_pt);
    }
    n = (size_t)snprintf(g_out, sizeof(g_out), "{\"type\":\"ack\",\"inbox\":\"%llu\"}", (unsigned long long)res.seq);
    send_line(&to->conn, g_out, n);
}

/* One commit on top of the admin's roster, sent as room.create (genesis) or
 * room.commit; applied locally once the relay acks it. Returns the record. */
static void room_commit(device_t *admin, sc2_roster_t *r, uint8_t op, const uint8_t target[16],
                        uint8_t rec[SC2_COMMIT_LEN])
{
    sc2_commit_t c;
    uint8_t by[16], sig[64];
    size_t n = 0;
    CHECK(sc2_hex_decode(by, 16, admin->e.self_hex, 32), "id hex");
    CHECK(sc2_commit_make(&c, r, by, op, target), "commit_make");
    CHECK(sc2_commit_encode(rec, &c), "commit_encode");
    CHECK(sc2_commit_sign(sig, rec, admin->e.id.ik_seed), "commit_sign");
    CHECK(sc2_commit_verify(sig, rec, admin->e.id.ik_pub), "commit_verify");
    if (op == SC2_COMMIT_CREATE) {
        CHECK(sc2_frame_room_create_private(g_out, sizeof(g_out), &n, "c1", r->room, rec, sig), "create frame");
    } else {
        CHECK(sc2_frame_room_commit(g_out, sizeof(g_out), &n, "c2", r->room, rec, sig), "commit frame");
    }
    send_line(&admin->conn, g_out, n);
    recv_type(&admin->conn, "ack", g_line, sizeof(g_line));
    char want[32];
    snprintf(want, sizeof(want), "\"epoch\":%u", (unsigned)c.epoch);
    if (strstr(g_line, want) == NULL) {
        die("commit not accepted: %s", g_line);
    }
    CHECK(sc2_roster_apply(r, rec), "roster_apply");
    char head[65];
    CHECK(sc2_hex_encode(head, sizeof(head), r->head, 32), "hex");
    if (strstr(g_line, head) == NULL) {
        die("relay head differs from the C commit ID: %s", g_line);
    }
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s <host> <port> <relay_id>\n", argv[0]);
        return 2;
    }
    const char *host = argv[1], *port = argv[2];
    g_relay_id = argv[3];
    sc2e_test_host_t th = {h_alloc, h_release, h_clock, {urandom_fn, NULL}, NULL};
    static device_t alice, bob;
    size_t n = 0, pl = 0;

    device_open(&alice, &th, "alice");
    device_open(&bob, &th, "bob");
    device_connect(&alice, host, port);
    device_connect(&bob, host, port);
    publish(&alice);
    publish(&bob);
    claim(&alice, &bob);
    claim(&bob, &alice);

    /* DMs both ways through the relay inbox */
    dm(&alice, &bob, "{\"t\":\"text\",\"id\":\"0123456789abcdef\",\"body\":\"hello from C\",\"ts\":1}",
       SC2E_DM_MESSAGE);
    dm(&bob, &alice, "{\"t\":\"text\",\"body\":\"hello back\"}", SC2E_DM_MESSAGE);
    dm(&alice, &bob, "{\"t\":\"text\",\"body\":\"third\"}", SC2E_DM_MESSAGE);

    /* private room: genesis, invite, join request, add commit, rotate, epoch key over DM */
    char room[SC2_DEVICE_ID_HEX_LEN + 1];
    uint8_t room_b[16], bob_id[16], rec[SC2_COMMIT_LEN];
    uint32_t epoch = 0;
    static sc2_roster_t roster;
    CHECK(sc2e_room_create(&alice.e, NULL, room, &epoch), "room_create");
    CHECK(sc2_hex_decode(room_b, 16, room, 32), "room hex");
    CHECK(sc2_hex_decode(bob_id, 16, bob.e.self_hex, 32), "id hex");
    sc2_roster_init(&roster, room_b);
    room_commit(&alice, &roster, SC2_COMMIT_CREATE, NULL, rec);
    /* invite: the admin registers HMAC(secret, room); bob proves it for his ID */
    uint8_t secret[SC2_INVITE_SECRET_LEN], ikey[SC2_INVITE_KEY_LEN], proof[32];
    urandom_fn(NULL, secret, sizeof(secret));
    CHECK(sc2_invite_key(ikey, secret, room_b), "invite_key");
    CHECK(sc2_frame_room_invite(g_out, sizeof(g_out), &n, "i1", room_b, ikey, false), "invite frame");
    send_line(&alice.conn, g_out, n);
    recv_type(&alice.conn, "ack", g_line, sizeof(g_line));
    CHECK(sc2_invite_proof(proof, ikey, bob_id), "invite_proof");
    CHECK(sc2_frame_room_join_private(g_out, sizeof(g_out), &n, "j1", room_b, proof), "join frame");
    send_line(&bob.conn, g_out, n);
    recv_type(&bob.conn, "ack", g_line, sizeof(g_line));
    if (strstr(g_line, "\"status\":\"requested\"") == NULL) {
        die("join request not accepted: %s", g_line);
    }
    recv_type(&alice.conn, "room.event", g_line, sizeof(g_line));
    if (strstr(g_line, "join_request") == NULL || strstr(g_line, bob.e.self_hex) == NULL) {
        die("join request not seen by the admin: %s", g_line);
    }
    room_commit(&alice, &roster, SC2_COMMIT_ADD, bob_id, rec);
    /* bob checks the relay's fan-out of the add with the admin's IK */
    {
        uint8_t got_room[16], got[SC2_COMMIT_LEN], got_sig[64];
        uint64_t cseq = 0;
        sc2_commit_t cc;
        n = recv_type(&bob.conn, "room.commit", g_line, sizeof(g_line));
        CHECK(sc2_frame_room_commit_decode(g_line, n, got_room, &cseq, got, got_sig), "commit fan-out");
        CHECK(sc2_commit_verify(got_sig, got, alice.e.id.ik_pub), "fan-out signature");
        CHECK(sc2_commit_decode(&cc, got), "commit_decode");
        if (memcmp(got, rec, SC2_COMMIT_LEN) != 0 || cc.op != SC2_COMMIT_ADD || memcmp(cc.target, bob_id, 16) != 0) {
            die("fan-out commit differs");
        }
    }
    /* one change per commit: a rotate after the add, then the key goes out */
    room_commit(&alice, &roster, SC2_COMMIT_ROTATE, NULL, rec);
    CHECK(sc2e_room_rotate(&alice.e, room, &epoch), "room_rotate");
    CHECK(sc2e_room_rotate(&alice.e, room, &epoch), "room_rotate");
    if (epoch != roster.epoch || roster.count != 2) {
        die("engine epoch %u, roster epoch %u", (unsigned)epoch, (unsigned)roster.epoch);
    }
    CHECK(sc2e_room_share(&alice.e, room, bob.e.self_hex, "s1", g_out, sizeof(g_out), &n), "room_share");
    send_line(&alice.conn, g_out, n);
    recv_type(&alice.conn, "ack", g_line, sizeof(g_line));
    n = recv_type(&bob.conn, "dm.msg", g_line, sizeof(g_line));
    sc2e_dm_result_t dr;
    CHECK(sc2e_dm_decrypt(&bob.e, g_line, n, &dr, g_pt, sizeof(g_pt), &pl), "epoch key DM");
    if (dr.kind != SC2E_DM_EPOCH_KEY || dr.epoch != roster.epoch || strcmp(dr.room, room) != 0) {
        die("epoch key DM not consumed");
    }
    const char *rmsg = "{\"t\":\"text\",\"body\":\"sealed room message from C\"}";
    for (int i = 0; i < 2; i++) {
        CHECK(sc2e_room_encrypt(&alice.e, room, "r1", rmsg, strlen(rmsg), g_out, sizeof(g_out), &n), "room_encrypt");
        send_line(&alice.conn, g_out, n);
        recv_type(&alice.conn, "ack", g_line, sizeof(g_line));
        n = recv_type(&bob.conn, "room.msg", g_line, sizeof(g_line));
        sc2e_room_result_t rr;
        CHECK(sc2e_room_decrypt(&bob.e, g_line, n, &rr, g_pt, sizeof(g_pt), &pl), "room_decrypt");
        if (strcmp(g_pt, rmsg) != 0 || rr.n != (uint32_t)i || rr.epoch != roster.epoch) {
            die("room message mismatch");
        }
    }

    /* public post: signed by the C engine, verified by the relay and by bob */
    n = (size_t)snprintf(g_out, sizeof(g_out), "{\"type\":\"room.join\",\"rid\":\"j\",\"room\":\"pub:general\"}");
    send_line(&alice.conn, g_out, n);
    recv_type(&alice.conn, "room.state", g_line, sizeof(g_line));
    if (strstr(g_line, "\"first_join\":true") == NULL || strstr(g_line, "not encrypted") == NULL) {
        die("first-join notice missing: %s", g_line);
    }
    send_line(&bob.conn, g_out, n);
    recv_type(&bob.conn, "room.state", g_line, sizeof(g_line));
    const char *body = "hello #general from the C engine \xc3\xa9";
    CHECK(sc2e_post_sign(&alice.e, g_relay_id, "pub:general", "Ana", body, strlen(body), 1760889600, NULL, false,
                         "p1", g_out, sizeof(g_out), &n),
          "post_sign");
    send_line(&alice.conn, g_out, n);
    recv_type(&alice.conn, "ack", g_line, sizeof(g_line));
    n = recv_type(&bob.conn, "room.pub", g_line, sizeof(g_line));
    sc2e_post_result_t pr;
    char bodybuf[2048];
    CHECK(sc2e_post_verify(g_relay_id, g_line, n, 1024, &pr, bodybuf, sizeof(bodybuf)), "post_verify");
    if (!pr.valid || strcmp(bodybuf, body) != 0 || strcmp(pr.from, alice.e.self_hex) != 0) {
        die("public post mismatch");
    }
    /* a post signed for another relay is refused with 401 bad_sig */
    CHECK(sc2e_post_sign(&alice.e, "other.relay", "pub:general", "Ana", "x", 1, 1760889601, NULL, false, "p2",
                         g_out, sizeof(g_out), &n),
          "post_sign");
    send_line(&alice.conn, g_out, n);
    recv_line(&alice.conn, g_line, sizeof(g_line));
    if (strstr(g_line, "\"code\":401") == NULL || strstr(g_line, "bad_sig") == NULL) {
        die("expected 401 bad_sig, got %s", g_line);
    }

    close(alice.conn.fd);
    close(bob.conn.fd);
    sc2e_close(&alice.e);
    sc2e_close(&bob.e);
    sc2e_memstore_destroy(alice.store);
    sc2e_memstore_destroy(bob.store);
    printf("SC2-C-RELAY OK\n");
    return 0;
}
