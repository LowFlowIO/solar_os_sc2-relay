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
    int got_dm, got_pub, sent;
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
        break;
    case SC2C_EV_SENT: d->sent++; break;
    case SC2C_EV_FAILED: die("%s: send %u failed: %d %s", d->name, ev->token, ev->code, ev->text ? ev->text : "");
    case SC2C_EV_STATE: printf("[%s] state %s\n", d->name, sc2c_state_name(ev->code)); break;
    case SC2C_EV_ROOM: printf("[%s] room %s state %d\n", d->name, ev->conv, ev->code); break;
    case SC2C_EV_NOTICE: printf("[%s] notice %d %s\n", d->name, ev->code, ev->text ? ev->text : ""); break;
    default: break;
    }
    fflush(stdout);
}
static sc2e_t *d_lock(void *ctx) { return &((sdev_t *)ctx)->e; }
static void d_unlock(void *ctx) { (void)ctx; }
static uint64_t d_mono(void *ctx) { (void)ctx; return now_ms(); }
static uint64_t d_wall(void *ctx) { (void)ctx; return (uint64_t)time(NULL); }

static const char *g_host, *g_port, *g_relay;

static void d_connect(sdev_t *d)
{
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(g_host, g_port, &hints, &res) != 0 || !res) die("resolve");
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

static void d_open(sdev_t *d, const char *name, const sc2e_test_host_t *th)
{
    memset(d, 0, sizeof(*d));
    d->name = name;
    d->fd = -1;
    sc2e_platform_t pf;
    if (sc2e_memstore_create(&d->store, th) != SC2_OK) die("memstore");
    sc2e_memstore_platform(d->store, &pf);
    if (sc2e_open(&d->e, &pf) != SC2_OK) die("engine open");
    sc2e_identity(&d->e, &d->info);
    sc2c_host_t h = {d_send, d_event, d_lock, d_unlock, h_alloc, h_release, d_mono, d_wall, d};
    sc2c_config_t cfg = {.tag = "t", .nick = name, .expect_relay = g_relay};
    int rc = sc2c_init(&d->c, &h, &cfg);
    if (rc != SC2_OK) die("sc2c_init: %s", sc2_strerror(rc));
}

/* Pump both connections until cond() or timeout. */
static sdev_t A, B;
static void pump(int (*cond)(void), const char *what)
{
    uint64_t end = now_ms() + 20000;
    while (!cond()) {
        if (now_ms() > end) die("timeout waiting for %s", what);
        sdev_t *ds[2] = {&A, &B};
        struct pollfd p[2];
        for (int i = 0; i < 2; i++) { p[i].fd = ds[i]->fd; p[i].events = POLLIN; p[i].revents = 0; }
        poll(p, 2, 50);
        for (int i = 0; i < 2; i++) {
            if (ds[i]->fd < 0) continue;
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

int main(int argc, char **argv)
{
    if (argc != 4) die("usage: %s host port relay_id", argv[0]);
    g_host = argv[1]; g_port = argv[2]; g_relay = argv[3];
    sc2e_test_host_t th = {h_alloc, h_release, h_clock, {urandom_fn, NULL}, NULL};
    d_open(&A, "alice", &th);
    d_open(&B, "bob", &th);
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
