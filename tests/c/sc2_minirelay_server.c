/* Host TCP wrapper around the portable mini-relay (protocol/sc2 sc2_minirelay),
 * standing in for chatd: one line per frame, v1 hellos answered by a stub.
 * usage: sc2_minirelay_server relay_id [admit|-] [nolegacy]
 * Prints "PORT <n> KEY <b64>" once listening on 127.0.0.1.
 * SPDX-License-Identifier: MIT */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "sc2.h"
#include "sc2_minirelay.h"

#define NS 6
#define LMAX 20000
static int fds[NS];
static int v1[NS];
static char *lb[NS];
static size_t ll[NS];
static sc2_mr_t *mr;

static int urnd(void *ctx, uint8_t *out, size_t n)
{
    (void)ctx;
    FILE *f = fopen("/dev/urandom", "rb");
    size_t got = f ? fread(out, 1, n, f) : 0;
    if (f) fclose(f);
    return got == n ? SC2_OK : SC2_ERR_RNG;
}
static uint64_t now_s(void *ctx) { (void)ctx; return (uint64_t)time(NULL); }
static void *al(void *ctx, size_t n) { (void)ctx; return calloc(1, n); }
static void rl(void *ctx, void *p, size_t n) { (void)ctx; (void)n; free(p); }
static int tx(void *ctx, unsigned s, const char *line, size_t len)
{
    (void)ctx;
    if (fds[s] < 0) return -1;
    if (send(fds[s], line, len, MSG_NOSIGNAL) != (ssize_t)len || send(fds[s], "\n", 1, MSG_NOSIGNAL) != 1)
        return -1; /* a peer gone without a FIN yet: no SIGPIPE */
    return 0;
}
static void drop(int i)
{
    sc2_mr_close(mr, (unsigned)i);
    close(fds[i]);
    fds[i] = -1;
    v1[i] = 0;
    ll[i] = 0;
}
static void line(int i, const char *l, size_t n)
{
    if (v1[i]) {
        static const char ok[] = "{\"type\":\"error\",\"text\":\"v1 stub\",\"code\":400}\n";
        if (write(fds[i], ok, sizeof(ok) - 1) < 0) drop(i);
        return;
    }
    int rc = sc2_mr_line(mr, (unsigned)i, l, n);
    if (rc == SC2_MR_LEGACY) {
        v1[i] = 1; /* chatd hands the hello to its v1 server */
        static const char hi[] = "{\"type\":\"connected\",\"text\":\"v1 legacy\"}\n";
        if (write(fds[i], hi, sizeof(hi) - 1) < 0) drop(i);
    } else if (rc == SC2_MR_CLOSE) {
        drop(i);
    }
}
int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    uint8_t seed[32];
    if (urnd(NULL, seed, sizeof(seed)) != SC2_OK) return 2;
    sc2_mr_config_t cfg = {.relay_id = argv[1], .seed = seed, .rng = {urnd, NULL}, .now_s = now_s, .send = tx,
                           .alloc = al, .release = rl, .admit = argc > 2 && strcmp(argv[2], "-") ? argv[2] : NULL,
                           .legacy_v1 = !(argc > 3 && !strcmp(argv[3], "nolegacy")), .sessions = NS};
    if (sc2_mr_init(&mr, &cfg) != SC2_OK) return 3;
    int ls = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t al_ = sizeof(a);
    if (bind(ls, (struct sockaddr *)&a, sizeof(a)) || listen(ls, 8) || getsockname(ls, (struct sockaddr *)&a, &al_))
        return 4;
    uint8_t key[32];
    char kb[64];
    size_t kl = 0;
    sc2_mr_relay_key(mr, key);
    sc2_b64_encode(kb, sizeof(kb), &kl, key, 32);
    printf("PORT %u KEY %s SIZE %zu\n", (unsigned)ntohs(a.sin_port), kb, sc2_mr_size());
    fflush(stdout);
    for (int i = 0; i < NS; i++) {
        fds[i] = -1;
        lb[i] = malloc(LMAX);
    }
    for (;;) {
        struct pollfd p[NS + 1];
        p[0].fd = ls;
        p[0].events = POLLIN;
        for (int i = 0; i < NS; i++) {
            p[i + 1].fd = fds[i];
            p[i + 1].events = POLLIN;
            p[i + 1].revents = 0;
        }
        if (poll(p, NS + 1, 1000) < 0 && errno != EINTR) return 5;
        if (p[0].revents & POLLIN) {
            int c = accept(ls, NULL, NULL), slot = -1;
            for (int i = 0; i < NS && slot < 0; i++) if (fds[i] < 0) slot = i;
            if (slot < 0) {
                close(c);
            } else {
                fds[slot] = c;
                sc2_mr_open(mr, (unsigned)slot);
            }
        }
        for (int i = 0; i < NS; i++) {
            if (fds[i] < 0 || !(p[i + 1].revents & (POLLIN | POLLHUP))) continue;
            char buf[2048];
            ssize_t n = read(fds[i], buf, sizeof(buf));
            if (n <= 0) {
                drop(i);
                continue;
            }
            for (ssize_t k = 0; k < n && fds[i] >= 0; k++) {
                if (buf[k] == '\n') {
                    lb[i][ll[i]] = 0;
                    if (ll[i]) line(i, lb[i], ll[i]);
                    ll[i] = 0;
                } else if (ll[i] + 1 < LMAX) {
                    lb[i][ll[i]++] = buf[k];
                } else {
                    drop(i);
                }
            }
        }
    }
}
