/*
 * Host interop harness for the device-side relay client
 * (src/services/solar_os_sc2_client.c, the sc2-sync state machine): two
 * clients, each on its own SolarOS SC2 engine, talk to the Python reference
 * relay over real TCP, the same way the firmware sc2-sync job drives them.
 *
 *   sc2_relay_sc2c_client <host> <port> <relay_id>
 *
 * Flow: hello/auth/keys.publish/sync for both; join pub:general; alice DMs
 * bob by device id (keys.claim, X3DH), bob replies; both safety numbers must
 * match; alice posts to #general and bob receives the verified post; bob
 * drops the connection, alice DMs him while he is offline, bob reconnects
 * and gets it from the inbox sync. Prints "SC2C-RELAY OK" on success.
 *
 *   sc2_relay_sc2c_client <host> <port> <relay_id> <port2> <relay_id2>
 *
 * Adds the multi-relay flow afterwards (what sc2-sync does on failover):
 * alice and bob rebuild their clients for the fallback relay (no one-time
 * prekeys there); carol, who only knows the fallback, claims alice's
 * SPK-only bundle and DMs her; alice's one-time prekeys stay untouched; bob
 * DMs alice on the fallback over the existing session; alice returns to the
 * primary and gets a DM bob left there. Prints "SC2C-MULTI OK" too.
 *
 *   sc2_relay_sc2c_client --pin <host> <port> <relay_id> <key_b64>
 *       log in with the relay key pinned; prints "PIN READY",
 *       "PIN ROTATED <new key>" first if the relay rotated, or
 *       "PIN REFUSED <reason>" (exit 0 in all three cases).
 *   sc2_relay_sc2c_client --wellknown < body
 *       parse and verify a /.well-known/solaros-relay body as the device
 *       does; prints the descriptor fields or "WELLKNOWN ERR <code>".
 *
 * SPDX-License-Identifier: MIT
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "solar_os_sc2_client.h"
#include "solar_os_sc2_engine.h"
#include "solar_os_sc2_selftest.h"

static void die(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));
static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "FAIL: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}

static int urandom_fn(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t got = 0;
    while (got < len) {
        ssize_t r = read(fd, out + got, len - got);
        if (r <= 0) { close(fd); return -1; }
        got += (size_t)r;
    }
    close(fd);
    return 0;
}
static void *h_alloc(void *ctx, size_t len) { (void)ctx; return calloc(1, len); }
static void h_release(void *ctx, void *ptr, size_t len)
{
    (void)ctx;
    if (ptr) { sc2_memzero(ptr, len); free(ptr); }
}
static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}
static uint64_t h_clock(void *ctx) { (void)ctx; return now_ms() * 1000u; }

typedef struct {
    const char *name;
    int fd;
    sc2e_memstore_t *store;
    sc2e_t e;
    sc2e_identity_info_t info;
    sc2c_t c;
    int got_dm, got_pub, got_priv, sent;
    char created[SC2_DEVICE_ID_HEX_LEN + 1];
    char invite[SC2_INVITE_TEXT_MAX];
    int key_notice;
    bool rotated;
    const char *port, *relay;
    char last_body[256];
    char last_from[SC2_DEVICE_ID_HEX_LEN + 1];
} sdev_t;

static int d_send(void *ctx, const char *line, size_t len)
{
    sdev_t *d = ctx;
    if (d->fd < 0) return -1;
    char nl = '\n';
    if (write(d->fd, line, len) != (ssize_t)len || write(d->fd, &nl, 1) != 1) return -1;
    return 0;
}
static void d_event(void *ctx, const sc2c_event_t *ev)
{
    sdev_t *d = ctx;
    switch (ev->type) {
    case SC2C_EV_MESSAGE:
        printf("[%s] msg kind=%d conv=%.12s from=%.12s name=%s replay=%d: %s\n", d->name, ev->kind, ev->conv,
               ev->from, ev->name, ev->replay, ev->body);
        snprintf(d->last_body, sizeof(d->last_body), "%s", ev->body);
        snprintf(d->last_from, sizeof(d->last_from), "%s", ev->from);
        if (ev->kind == SC2C_DM) d->got_dm++;
        if (ev->kind == SC2C_PUBLIC) d->got_pub++;
        if (ev->kind == SC2C_PRIVATE) d->got_priv++;
        break;
    case SC2C_EV_CREATED:
        printf("[%s] created %s\n", d->name, ev->conv);
        snprintf(d->created, sizeof(d->created), "%s", ev->conv);
        snprintf(d->invite, sizeof(d->invite), "%s", ev->text);
        break;
    case SC2C_EV_SENT: d->sent++; break;
    case SC2C_EV_FAILED: die("%s: send %u failed: %d %s", d->name, ev->token, ev->code, ev->text ? ev->text : "");
    case SC2C_EV_STATE: printf("[%s] state %s\n", d->name, sc2c_state_name(ev->code)); break;
    case SC2C_EV_ROOM: printf("[%s] room %s state %d\n", d->name, ev->conv, ev->code); break;
    case SC2C_EV_NOTICE:
        printf("[%s] notice %d %s\n", d->name, ev->code, ev->text ? ev->text : "");
        if (ev->code == SC2C_NOTICE_RELAY_KEY) {
            d->key_notice = 1;
            snprintf(d->last_body, sizeof(d->last_body), "%s", ev->text ? ev->text : "");
        }
        break;
    case SC2C_EV_RELAY_KEY: d->rotated = true; break;
    default: break;
    }
    fflush(stdout);
}
static sc2e_t *d_lock(void *ctx) { return &((sdev_t *)ctx)->e; }
static void d_unlock(void *ctx) { (void)ctx; }
static uint64_t d_mono(void *ctx) { (void)ctx; return now_ms(); }
static uint64_t d_wall(void *ctx) { (void)ctx; return (uint64_t)time(NULL); }

static const char *g_host;

static void d_connect(sdev_t *d)
{
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(g_host, d->port, &hints, &res) != 0 || !res) die("resolve");
    d->fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (d->fd < 0 || connect(d->fd, res->ai_addr, res->ai_addrlen) != 0) die("connect: %s", strerror(errno));
    freeaddrinfo(res);
    if (sc2c_on_connected(&d->c) != SC2_OK) die("%s: on_connected", d->name);
}
static void d_drop(sdev_t *d)
{
    close(d->fd);
    d->fd = -1;
    sc2c_on_disconnected(&d->c);
}

/* (Re)build the client for a relay, as sc2-sync's build_client() does:
 * same engine and store tag, OPKs only on the primary. */
static const uint8_t *g_pin;

static void d_client(sdev_t *d, const char *port, const char *relay, bool primary)
{
    d->port = port;
    d->relay = relay;
    sc2c_host_t h = {d_send, d_event, d_lock, d_unlock, h_alloc, h_release, d_mono, d_wall, d};
    sc2c_config_t cfg = {.tag = "t", .nick = d->name, .expect_relay = relay, .no_opks = !primary,
                         .relay_key = g_pin, .auto_admit = true, .invite_url = "chat://test.invalid:7777"};
    int rc = sc2c_init(&d->c, &h, &cfg);
    if (rc != SC2_OK) die("sc2c_init: %s", sc2_strerror(rc));
}

static void d_open(sdev_t *d, const char *name, const sc2e_test_host_t *th, const char *port, const char *relay,
                   bool primary)
{
    memset(d, 0, sizeof(*d));
    d->name = name;
    d->fd = -1;
    sc2e_platform_t pf;
    if (sc2e_memstore_create(&d->store, th) != SC2_OK) die("memstore");
    sc2e_memstore_platform(d->store, &pf);
    if (sc2e_open(&d->e, &pf) != SC2_OK) die("engine open");
    sc2e_identity(&d->e, &d->info);
    d_client(d, port, relay, primary);
}

/* Pump both connections until cond() or timeout. */
static sdev_t A, B, C;
static bool c_open;
static void pump(int (*cond)(void), const char *what)
{
    uint64_t end = now_ms() + 20000;
    while (!cond()) {
        if (now_ms() > end) die("timeout waiting for %s", what);
        sdev_t *ds[3] = {&A, &B, &C};
        struct pollfd p[3];
        for (int i = 0; i < 3; i++) {
            p[i].fd = i < 2 || c_open ? ds[i]->fd : -1;
            p[i].events = POLLIN;
            p[i].revents = 0;
        }
        poll(p, 3, 50);
        for (int i = 0; i < 3; i++) {
            if (p[i].fd < 0) continue;
            if (p[i].revents & (POLLIN | POLLHUP)) {
                uint8_t buf[1536];
                ssize_t n = read(ds[i]->fd, buf, sizeof(buf));
                if (n <= 0) die("%s: relay closed", ds[i]->name);
                int rc = sc2c_feed(&ds[i]->c, buf, (size_t)n);
                if (rc != SC2_OK) die("%s: feed: %s", ds[i]->name, sc2_strerror(rc));
            }
            if (sc2c_tick(&ds[i]->c) != SC2_OK) die("%s: tick", ds[i]->name);
        }
    }
}
static int both_ready(void) { return sc2c_ready(&A.c) && sc2c_ready(&B.c); }
static int a_ready(void) { return sc2c_ready(&A.c); }
static int b_ready(void) { return sc2c_ready(&B.c); }
static int b_dm1(void) { return B.got_dm >= 1; }
static int a_dm1(void) { return A.got_dm >= 1; }
static int b_dm2(void) { return B.got_dm >= 2; }
static int b_pub(void) { return B.got_pub >= 1; }
static int a_sent(void) { return A.sent >= 1; }
static int joined(void)
{
    const sc2c_room_t *ra = sc2c_room_get(&A.c, "pub:general"), *rb = sc2c_room_get(&B.c, "pub:general");
    return ra && rb && ra->state == SC2C_ROOM_JOINED && rb->state == SC2C_ROOM_JOINED;
}

/* Submit, retrying while keys are claimed (what the sync job does). */
static void submit(sdev_t *d, sc2c_kind_t kind, const char *target, const char *body, uint32_t token)
{
    uint64_t end = now_ms() + 15000;
    for (;;) {
        int rc = sc2c_submit(&d->c, kind, target, body, strlen(body), token, token);
        if (rc == SC2_OK) return;
        if (rc != SC2C_AGAIN) die("%s: submit: %s", d->name, sc2_strerror(rc));
        if (now_ms() > end) die("%s: submit kept returning AGAIN", d->name);
        uint64_t t = now_ms() + 200;
        while (now_ms() < t) {
            struct pollfd p = {d->fd, POLLIN, 0};
            poll(&p, 1, 20);
            if (p.revents & POLLIN) {
                uint8_t buf[1536];
                ssize_t n = read(d->fd, buf, sizeof(buf));
                if (n <= 0) die("closed");
                sc2c_feed(&d->c, buf, (size_t)n);
            }
        }
    }
}

static int c_ready(void) { return sc2c_ready(&C.c); }

/* Private room through the client, as sc2-sync drives it: Alice creates it
 * (auto-admit), Bob joins with the invite text, both post. */
static char g_room[SC2_DEVICE_ID_HEX_LEN + 1];
static int a_created(void) { return A.created[0] != '\0'; }
static int room_state(sdev_t *d, int want)
{
    const sc2c_room_t *r = sc2c_room_get(&d->c, g_room);
    return r != NULL && r->state == want;
}
static int a_room_joined(void) { return room_state(&A, SC2C_ROOM_JOINED); }
static int b_room_joined(void) { return room_state(&B, SC2C_ROOM_JOINED); }
static int b_priv1(void) { return B.got_priv >= 1; }
static int a_priv1(void) { return A.got_priv >= 1; }
static void private_room(void)
{
    if (sc2c_room_create(&A.c, g_room) != SC2_OK) die("room create");
    pump(a_created, "room created");
    if (strcmp(A.created, g_room) || strncmp(A.invite, SC2_INVITE_TEXT_PREFIX, 5)) die("created event");
    char again[SC2_INVITE_TEXT_MAX];
    if (sc2c_room_invite_text(&A.c, g_room, again, sizeof(again)) != SC2_OK || strcmp(again, A.invite))
        die("invite text again");
    if (sc2c_room_invite_text(&B.c, g_room, again, sizeof(again)) != SC2_ERR_NOT_FOUND) die("bob is no admin");
    pump(a_room_joined, "alice in her room");
    char joined_room[SC2_DEVICE_ID_HEX_LEN + 1];
    if (sc2c_room_join_invite(&B.c, "sc2i:AAAA", joined_room) == SC2_OK) die("bad invite accepted");
    if (sc2c_room_join_invite(&B.c, A.invite, joined_room) != SC2_OK || strcmp(joined_room, g_room))
        die("join with invite");
    pump(b_room_joined, "bob admitted to the private room");
    submit(&A, SC2C_PRIVATE, g_room, "private hello", 20);
    pump(b_priv1, "private post to bob");
    if (strcmp(B.last_body, "private hello") || strcmp(B.last_from, A.info.device_id)) die("private body/from");
    submit(&B, SC2C_PRIVATE, g_room, "private reply", 21);
    pump(a_priv1, "private reply to alice");
    if (strcmp(A.last_body, "private reply")) die("private reply body");
    printf("private room %s OK\n", g_room);
}
static int a_dm2(void) { return A.got_dm >= 2; }
static int a_dm3(void) { return A.got_dm >= 3; }
static int a_dm4(void) { return A.got_dm >= 4; }
static int b_sent(void) { return B.sent >= 1; }

/* Fail over to the fallback relay and come back (see the header). */
static void multi_relay(const sc2e_test_host_t *th, const char *port1, const char *relay1, const char *port2,
                        const char *relay2)
{
    const uint32_t opks = A.e.pre.opk_count;
    if (opks == 0) die("alice has no OPKs on the primary");
    sdev_t *ab[2] = {&A, &B};
    for (int i = 0; i < 2; i++) {
        d_drop(ab[i]);
        sc2c_free(&ab[i]->c);
        d_client(ab[i], port2, relay2, false);
        d_connect(ab[i]);
    }
    pump(both_ready, "login on the fallback");
    if (A.e.pre.opk_count != opks) die("fallback publish changed the OPKs");

    d_open(&C, "carol", th, port2, relay2, true);
    c_open = true;
    d_connect(&C);
    pump(c_ready, "carol login");
    sc2e_peer_info_t pi;
    submit(&C, SC2C_DM, A.info.device_id, "carol via fallback", 10);
    if (sc2e_peer_info(&C.e, A.info.device_id, &pi) != SC2_OK || !pi.known || pi.opk_available)
        die("carol should hold an SPK-only bundle for alice");
    pump(a_dm2, "carol's DM on the fallback");
    if (strcmp(A.last_body, "carol via fallback") || strcmp(A.last_from, C.info.device_id)) die("carol DM body/from");
    if (A.e.pre.opk_count != opks) die("an OPK was used on the fallback");
    submit(&B, SC2C_DM, A.info.device_id, "bob via fallback", 11);
    pump(a_dm3, "bob's DM on the fallback");
    if (strcmp(A.last_body, "bob via fallback")) die("bob fallback DM body");

    /* bob back on the primary first; alice still away */
    d_drop(&B);
    sc2c_free(&B.c);
    d_client(&B, port1, relay1, true);
    d_connect(&B);
    pump(b_ready, "bob back on the primary");
    B.sent = 0;
    submit(&B, SC2C_DM, A.info.device_id, "left on the primary", 12);
    pump(b_sent, "primary ack while alice is away");
    d_drop(&A);
    sc2c_free(&A.c);
    d_client(&A, port1, relay1, true);
    d_connect(&A);
    pump(a_dm4, "mailbox on the primary after return");
    if (strcmp(A.last_body, "left on the primary")) die("primary DM body");
    c_open = false;
    d_drop(&C);
    sc2c_free(&C.c);
    sc2e_close(&C.e);
    sc2e_memstore_destroy(C.store);
    printf("alice opks %u\n", (unsigned)A.e.pre.opk_count);
    printf("SC2C-MULTI OK\n");
}

static int pin_mode(const sc2e_test_host_t *th, const char *port, const char *relay, const char *key_b64)
{
    static uint8_t key[SC2_KEY_LEN];
    size_t got = 0;
    if (sc2_b64_decode(key, sizeof(key), &got, key_b64, strlen(key_b64)) != SC2_OK || got != SC2_KEY_LEN) die("key");
    g_pin = key;
    d_open(&A, "alice", th, port, relay, true);
    d_connect(&A);
    uint64_t end = now_ms() + 20000;
    while (!sc2c_ready(&A.c)) {
        if (now_ms() > end) die("timeout");
        struct pollfd p = {A.fd, POLLIN, 0};
        poll(&p, 1, 50);
        if (p.revents & (POLLIN | POLLHUP)) {
            uint8_t buf[1536];
            ssize_t n = read(A.fd, buf, sizeof(buf));
            if (n <= 0) die("relay closed");
            int rc = sc2c_feed(&A.c, buf, (size_t)n);
            if (rc == SC2_ERR_AUTH && A.key_notice) {
                printf("PIN REFUSED %s\n", A.last_body);
                return 0;
            }
            if (rc != SC2_OK) die("feed: %s", sc2_strerror(rc));
        }
        sc2c_tick(&A.c);
    }
    if (A.rotated) {
        char out[48];
        size_t n = 0;
        sc2_b64_encode(out, sizeof(out), &n, A.c.relay_key, SC2_KEY_LEN);
        printf("PIN ROTATED %s\n", out);
    }
    printf("PIN READY\n");
    return 0;
}

static int wellknown_mode(void)
{
    static char body[4096];
    size_t len = fread(body, 1, 1600, stdin); /* the device reads at most 1600 bytes */
    sc2_desc_t d;
    int rc = sc2_wellknown_parse(body, len, &d);
    if (rc != SC2_OK) {
        printf("WELLKNOWN ERR %d\n", rc);
        return 0;
    }
    char k[48];
    size_t n = 0;
    sc2_b64_encode(k, sizeof(k), &n, d.key, SC2_KEY_LEN);
    printf("id=%s key=%s host=%s port=%u tls=%d pin=%s fallbacks=%u\n", d.relay_id, k, d.host, (unsigned)d.port,
           d.tls, d.pin, (unsigned)d.fallback_count);
    for (unsigned i = 0; i < d.fallback_count; i++) {
        sc2_b64_encode(k, sizeof(k), &n, d.fallback[i].key, SC2_KEY_LEN);
        printf("fallback=%s %s\n", d.fallback[i].url, k);
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--wellknown") == 0) return wellknown_mode();
    if (argc == 6 && strcmp(argv[1], "--pin") == 0) {
        g_host = argv[2];
        sc2e_test_host_t th = {h_alloc, h_release, h_clock, {urandom_fn, NULL}, NULL};
        return pin_mode(&th, argv[3], argv[4], argv[5]);
    }
    if (argc != 4 && argc != 6) die("usage: %s host port relay_id [port2 relay_id2]", argv[0]);
    g_host = argv[1];
    sc2e_test_host_t th = {h_alloc, h_release, h_clock, {urandom_fn, NULL}, NULL};
    d_open(&A, "alice", &th, argv[2], argv[3], true);
    d_open(&B, "bob", &th, argv[2], argv[3], true);
    d_connect(&A);
    d_connect(&B);
    pump(both_ready, "login");
    sc2c_room_add(&A.c, "pub:general", 0);
    sc2c_room_add(&B.c, "pub:general", 0);
    pump(joined, "join #general");

    submit(&A, SC2C_DM, B.info.device_id, "hi bob, sealed", 1);
    pump(b_dm1, "bob DM");
    if (strcmp(B.last_body, "hi bob, sealed") || strcmp(B.last_from, A.info.device_id)) die("bob DM body/from");
    submit(&B, SC2C_DM, A.info.device_id, "hi alice", 2);
    pump(a_dm1, "alice DM");
    if (strcmp(A.last_body, "hi alice")) die("alice DM body");

    sc2e_safety_t sa, sb;
    if (sc2e_safety(&A.e, B.info.device_id, &sa) != SC2_OK || sc2e_safety(&B.e, A.info.device_id, &sb) != SC2_OK)
        die("safety");
    if (strcmp(sa.full_form, sb.full_form)) die("safety numbers differ");
    printf("safety %s\n", sa.short_form);

    submit(&A, SC2C_PUBLIC, "pub:general", "hello #general", 3);
    pump(b_pub, "#general post");
    if (strcmp(B.last_body, "hello #general")) die("post body");
    private_room();

    /* Offline delivery and reconnect. */
    d_drop(&B);
    submit(&A, SC2C_DM, B.info.device_id, "while you were away", 4);
    A.sent = 0;
    pump(a_sent, "relay ack while bob offline");
    uint32_t attempt = 0;
    uint32_t delay = sc2c_backoff_ms(&attempt, 12345);
    if (delay < 500 || delay > 2000 || attempt != 1) die("backoff %u", delay);
    d_connect(&B);
    pump(b_ready, "bob relogin");
    pump(b_dm2, "offline DM after reconnect");
    if (strcmp(B.last_body, "while you were away")) die("offline DM body");
    (void)a_ready;
    if (argc == 6) multi_relay(&th, argv[2], argv[3], argv[4], argv[5]);

    d_drop(&A);
    d_drop(&B);
    sc2c_free(&A.c);
    sc2c_free(&B.c);
    sc2e_close(&A.e);
    sc2e_close(&B.e);
    sc2e_memstore_destroy(A.store);
    sc2e_memstore_destroy(B.store);
    printf("SC2C-RELAY OK\n");
    return 0;
}
