"""Relay configuration from environment variables (draft §8.1).

Two profiles share one codebase:
- selfhost (default): legacy v1 on, web view off, mutes allowed.
- official: v2 only (v1 hello gets 426), web view on, no mutes.
Every value can still be set explicitly; see relay/README.md for the table.

SPDX-License-Identifier: MIT
"""

import os
import re

from sc2proto import frames, is_hex, limits

_TRUE = ("1", "true", "yes", "on")
_FALSE = ("0", "false", "no", "off", "")


class ConfigError(ValueError):
    pass


def _bool(env, key, default):
    v = env.get(key)
    if v is None:
        return default
    v = v.strip().lower()
    if v in _TRUE:
        return True
    if v in _FALSE:
        return False
    raise ConfigError(key + " must be true or false, got " + repr(v))


def _int(env, key, default, lo=0, hi=1 << 62):
    v = env.get(key)
    if v is None or v.strip() == "":
        return default
    try:
        n = int(v.strip(), 10)
    except ValueError:
        raise ConfigError(key + " must be an integer, got " + repr(v))
    if n < lo or n > hi:
        raise ConfigError(key + " must be in " + str(lo) + ".." + str(hi))
    return n


def _str(env, key, default):
    v = env.get(key)
    return default if v is None else v.strip()


def _list(env, key, default):
    v = env.get(key)
    if v is None:
        return list(default)
    return [x.strip() for x in v.split(",") if x.strip()]


def _hostport(value, key):
    host, sep, port = value.rpartition(":")
    if not sep or not host:
        raise ConfigError(key + " must be host:port")
    try:
        p = int(port)
    except ValueError:
        raise ConfigError(key + " must be host:port")
    if not 0 <= p <= 65535:
        raise ConfigError(key + " port out of range")
    return host.strip("[]"), p


class Config:
    """Plain attribute bag; build with Config.from_env() or Config(**overrides)."""

    def __init__(self, **kw):
        base = Config.from_env({"SC2_PROFILE": kw.get("profile", "selfhost")}, _raw=True)
        base.update(kw)
        for k, v in base.items():
            setattr(self, k, v)
        self.validate()

    @classmethod
    def from_env(cls, env=None, _raw=False):
        env = os.environ if env is None else env
        profile = _str(env, "SC2_PROFILE", "selfhost").lower()
        if profile not in ("selfhost", "official"):
            raise ConfigError("SC2_PROFILE must be selfhost or official")
        official = profile == "official"
        c = {
            "profile": profile,
            "data_dir": _str(env, "SC2_DATA_DIR", "/data"),
            "db_path": _str(env, "SC2_DB", ""),
            "relay_id": _str(env, "SC2_RELAY_ID", "localhost"),
            "bind": _str(env, "SC2_BIND", "0.0.0.0"),
            # chats:// (TLS) and chat:// (plain) NDJSON listeners
            "tls_cert": _str(env, "SC2_TLS_CERT", ""),
            "tls_key": _str(env, "SC2_TLS_KEY", ""),
            "tls_port": _int(env, "SC2_TLS_PORT", 7778, 0, 65535),
            # Let's Encrypt via the certbot sidecar (or plain certbot): the relay only
            # reads <acme_cert_dir>/fullchain.pem and privkey.pem and hot-reloads them
            "acme_domain": _str(env, "SC2_ACME_DOMAIN", ""),
            "acme_cert_dir": _str(env, "SC2_ACME_CERT_DIR", "/certs"),
            "tls_reload_interval": _int(env, "SC2_TLS_RELOAD_INTERVAL", 60, 0, 86400),
            "plain": _bool(env, "SC2_PLAIN", False),
            "plain_port": _int(env, "SC2_PLAIN_PORT", 7777, 0, 65535),
            # HTTP: well-known, healthz, metrics, web view, wss:///sc2
            "http_port": _int(env, "SC2_HTTP_PORT", 8080, 0, 65535),
            "http_tls": _bool(env, "SC2_HTTP_TLS", False),
            "websocket": _bool(env, "SC2_WEBSOCKET", True),
            "metrics": _bool(env, "SC2_METRICS", True),
            "trust_proxy": _bool(env, "SC2_TRUST_PROXY", False),
            # admin interface (loopback + bearer token)
            "admin_listen": _str(env, "SC2_ADMIN_LISTEN", "127.0.0.1:7780"),
            "admin_token": _str(env, "SC2_ADMIN_TOKEN", ""),
            # admission and quotas
            "admission": _str(env, "SC2_ADMISSION", "open").lower(),
            "admit_code": _str(env, "SC2_ADMIT_CODE", ""),
            "allowlist": _list(env, "SC2_ALLOWLIST", []),
            "ttl_days": _int(env, "SC2_TTL_DAYS", limits.TTL_DAYS, 1, 365),
            "max_queue": _int(env, "SC2_MAX_QUEUE", limits.QUEUE_MAX, 1, 1000000),
            "max_queue_bytes": _int(env, "SC2_MAX_QUEUE_BYTES", limits.QUEUE_BYTES, 4096, 1 << 34),
            "opk_max": _int(env, "SC2_OPK_MAX", limits.OPK_MAX, 0, frames.OPK_MAX),
            "keys_low": _int(env, "SC2_KEYS_LOW", limits.KEYS_LOW, 0, frames.OPK_MAX),
            "room_members_max": _int(env, "SC2_ROOM_MEMBERS_MAX", frames.ROOM_MEMBERS_MAX, 2,
                                     frames.ROOM_MEMBERS_MAX),
            "rooms_per_device": _int(env, "SC2_ROOMS_PER_DEVICE", 64, 1, 10000),
            "private_log_max": _int(env, "SC2_PRIVATE_LOG_MAX", limits.PRIVATE_LOG_MAX, 1, 10 ** 7),
            # legacy v1 (chatd-compatible, insecure, separate namespace)
            "legacy_v1": _bool(env, "SC2_LEGACY_V1", not official),
            "legacy_v1_token": _str(env, "SC2_LEGACY_V1_TOKEN", ""),
            "v1_history": _int(env, "SC2_V1_HISTORY", 64, 0, 100000),
            "v1_max_channels": _int(env, "SC2_V1_MAX_CHANNELS", 32, 1, 10000),
            # public rooms
            "public_rooms": _list(env, "SC2_PUBLIC_ROOMS", ["general"]),
            "public_room_create": _str(env, "SC2_PUBLIC_ROOM_CREATE", "operator").lower(),
            "public_body_max": _int(env, "SC2_PUBLIC_BODY_MAX", limits.PUBLIC_BODY_MAX, 1, frames.POST_BODY_WIRE_MAX),
            "public_log_max": _int(env, "SC2_PUBLIC_LOG_MAX", limits.PUBLIC_LOG_MAX, 1, 10 ** 7),
            "web_view": _bool(env, "SC2_WEB_VIEW", official),
            "web_noindex": _bool(env, "SC2_WEB_NOINDEX", True),
            "web_page_size": _int(env, "SC2_WEB_PAGE_SIZE", 100, 1, 200),
            "web_rate_per_min": _int(env, "SC2_WEB_RATE_PER_MIN", 120, 1, 100000),
            "mutes": _bool(env, "SC2_MUTES", False),
            # anti-spam: rate limits and slow mode only (Q5)
            "post_per_min": _int(env, "SC2_POST_PER_MIN", 10, 1, 100000),
            "post_burst": _int(env, "SC2_POST_BURST", 5, 1, 100000),
            "ip_post_per_min": _int(env, "SC2_IP_POST_PER_MIN", 30, 1, 100000),
            "ip_post_burst": _int(env, "SC2_IP_POST_BURST", 10, 1, 100000),
            "room_post_per_min": _int(env, "SC2_ROOM_POST_PER_MIN", 600, 1, 1000000),
            "slow_key_minutes": _int(env, "SC2_SLOW_KEY_MINUTES", 10, 0, 100000),
            "slow_until_posts": _int(env, "SC2_SLOW_UNTIL_POSTS", 0, 0, 100000),
            "slow_per_min": _int(env, "SC2_SLOW_PER_MIN", 2, 1, 100000),
            "slow_burst": _int(env, "SC2_SLOW_BURST", 1, 1, 100000),
            "slow_body_max": _int(env, "SC2_SLOW_BODY_MAX", 256, 1, frames.POST_BODY_WIRE_MAX),
            "send_per_min": _int(env, "SC2_SEND_PER_MIN", 120, 1, 1000000),
            "send_burst": _int(env, "SC2_SEND_BURST", 30, 1, 1000000),
            "claim_per_min": _int(env, "SC2_CLAIM_PER_MIN", 20, 1, 100000),
            "register_per_hour": _int(env, "SC2_REGISTER_PER_HOUR", 30, 1, 1000000),
            "report_per_min": _int(env, "SC2_REPORT_PER_MIN", 5, 1, 100000),
            "max_connections": _int(env, "SC2_MAX_CONNECTIONS", 2048, 1, 1000000),
            "max_conn_per_ip": _int(env, "SC2_MAX_CONN_PER_IP", 16, 1, 1000000),
            "auth_timeout": _int(env, "SC2_AUTH_TIMEOUT", 30, 1, 3600),
            "idle_timeout": _int(env, "SC2_IDLE_TIMEOUT", 300, 10, 86400),
            "send_buffer_max": _int(env, "SC2_SEND_BUFFER_MAX", 1 << 20, 65536, 1 << 30),
            "retention_interval": _int(env, "SC2_RETENTION_INTERVAL", 60, 1, 86400),
            # logging
            "log_level": _str(env, "SC2_LOG_LEVEL", "INFO").upper(),
            "log_device_ids": _bool(env, "SC2_LOG_DEVICE_IDS", False),
        }
        if _raw:
            return c
        obj = cls.__new__(cls)
        for k, v in c.items():
            setattr(obj, k, v)
        obj.validate()
        return obj

    @property
    def official(self):
        return self.profile == "official"

    @property
    def database(self):
        return self.db_path or os.path.join(self.data_dir, "relay.sqlite3")

    @property
    def key_path(self):
        return os.path.join(self.data_dir, "relay_key")

    @property
    def tls_enabled(self):
        return bool(self.tls_cert and self.tls_key)

    def validate(self):
        try:
            self.public_rooms = [frames.public_room_name(r) for r in self.public_rooms]
        except ValueError as e:
            raise ConfigError("SC2_PUBLIC_ROOMS: " + str(e))
        if self.admission not in ("open", "code", "allowlist"):
            raise ConfigError("SC2_ADMISSION must be open, code or allowlist")
        if self.admission == "code" and not self.admit_code:
            raise ConfigError("SC2_ADMISSION=code needs SC2_ADMIT_CODE")
        for d in self.allowlist:
            if not is_hex(d, 32):
                raise ConfigError("SC2_ALLOWLIST entries must be 32 hex device IDs")
        if self.public_room_create not in ("operator", "any"):
            raise ConfigError("SC2_PUBLIC_ROOM_CREATE must be operator or any")
        if not self.relay_id or len(self.relay_id.encode()) > 255:
            raise ConfigError("SC2_RELAY_ID must be 1..255 bytes")
        if self.acme_domain:
            if not re.fullmatch(r"(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}",
                                self.acme_domain):
                raise ConfigError("SC2_ACME_DOMAIN must be a public DNS name")
            if not self.tls_cert and not self.tls_key:
                self.tls_cert = os.path.join(self.acme_cert_dir, "fullchain.pem")
                self.tls_key = os.path.join(self.acme_cert_dir, "privkey.pem")
        if bool(self.tls_cert) != bool(self.tls_key):
            raise ConfigError("SC2_TLS_CERT and SC2_TLS_KEY must be set together")
        if self.http_tls and not self.tls_enabled:
            raise ConfigError("SC2_HTTP_TLS needs SC2_TLS_CERT and SC2_TLS_KEY")
        if self.official:
            if self.legacy_v1:
                raise ConfigError("the official profile is v2-only: SC2_LEGACY_V1 must be false")
            if self.mutes:
                raise ConfigError("the official profile has no mutes (Q18): SC2_MUTES must be false")
        if len(self.legacy_v1_token.encode()) >= 96:
            raise ConfigError("SC2_LEGACY_V1_TOKEN must be shorter than 96 bytes")
        _hostport(self.admin_listen, "SC2_ADMIN_LISTEN")

    def admin_address(self):
        return _hostport(self.admin_listen, "SC2_ADMIN_LISTEN")

    def summary(self):
        """Non-secret settings for the startup log."""
        hidden = ("admin_token", "admit_code", "legacy_v1_token", "allowlist")
        return {k: v for k, v in sorted(vars(self).items()) if k not in hidden}
