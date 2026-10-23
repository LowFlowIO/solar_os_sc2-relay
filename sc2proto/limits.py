"""Limits, rate limiting, retention and cursor logic.

All functions take the current time from the caller (sans-IO).

SPDX-License-Identifier: MIT
"""

DAY = 86400

# Values advertised in welcome.limits.
WELCOME_LIMITS = {"line": 16384, "msg": 4096, "rooms": 64, "members": 32, "queue": 500,
                  "queue_bytes": 5242880, "ttl_days": 7}

PUBLIC_BODY_MAX = 1024          # bytes per public post body
PUBLIC_LOG_MAX = 10000          # posts per public room
PRIVATE_LOG_MAX = 10000         # messages per private room
TTL_DAYS = 7
QUEUE_MAX = 500
QUEUE_BYTES = 5 * 1024 * 1024
OPK_MAX = 100
KEYS_LOW = 5                    # keys.low below this many OPKs


class TokenBucket:
    """rate tokens per minute with a burst capacity. now is seconds (float)."""

    def __init__(self, per_min, burst, now=0.0):
        self.per_min = float(per_min)
        self.burst = float(burst)
        self.tokens = float(burst)
        self.stamp = now

    def _refill(self, now):
        if now > self.stamp:
            self.tokens = min(self.burst, self.tokens + (now - self.stamp) * self.per_min / 60.0)
            self.stamp = now

    def take(self, now, cost=1.0):
        """Returns 0 when allowed, else the wait in milliseconds."""
        self._refill(now)
        if self.tokens >= cost:
            self.tokens -= cost
            return 0
        if self.per_min <= 0:
            return 60000
        need = cost - self.tokens
        return max(1, int(need * 60000.0 / self.per_min + 0.999))

    def idle(self, now):
        self._refill(now)
        return self.tokens >= self.burst


class RateTable:
    """A set of token buckets keyed by device or IP, with lazy cleanup."""

    def __init__(self, per_min, burst, max_keys=100000):
        self.per_min = per_min
        self.burst = burst
        self.max_keys = max_keys
        self.buckets = {}

    def take(self, key, now, per_min=None, burst=None, cost=1.0):
        b = self.buckets.get(key)
        pm = self.per_min if per_min is None else per_min
        bu = self.burst if burst is None else burst
        if b is None:
            if len(self.buckets) >= self.max_keys:
                self.prune(now)
            b = TokenBucket(pm, bu, now)
            self.buckets[key] = b
        else:
            b.per_min, b.burst = float(pm), float(bu)
            b.tokens = min(b.tokens, b.burst)
        return b.take(now, cost)

    def prune(self, now):
        for k in [k for k, b in self.buckets.items() if b.idle(now)]:
            del self.buckets[k]


def expired(ts, now, ttl_days=TTL_DAYS):
    return ts < now - ttl_days * DAY


def ttl_cutoff(now, ttl_days=TTL_DAYS):
    """Items with ts below this are expired."""
    return now - ttl_days * DAY


def ring_trim(newest_seq, keep):
    """Lowest seq to keep in a log capped at `keep` entries ending at newest."""
    return max(1, newest_seq - keep + 1)


def queue_admit(count, size_bytes, item_size, max_items=QUEUE_MAX, max_bytes=QUEUE_BYTES):
    """True when one more item of item_size fits the per-device inbox."""
    return count < max_items and size_bytes + item_size <= max_bytes


def sync_window(cursor, oldest, newest, floor=1):
    """Plan a room sync.

    cursor: last seq the client has; oldest/newest: retained seq range
    (oldest None when the log is empty); floor: first seq this member may see
    (join point for private rooms, 1 otherwise).
    Returns (after, gap) where entries with seq > after are sent and gap is
    None or (from_seq, oldest_seq) for a sync.gap frame.
    """
    after = max(cursor, floor - 1)
    if oldest is None or (newest is not None and after >= newest):
        return after, None
    if after + 1 < oldest:
        return oldest - 1, (after, oldest)
    return after, None
