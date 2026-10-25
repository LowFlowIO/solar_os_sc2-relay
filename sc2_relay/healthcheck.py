"""Container health check: python -m sc2_relay.healthcheck (exit 0 = healthy).

Reads the same environment as the relay and checks what it serves:
- HTTP on (SC2_HTTP_PORT): GET /healthz, over HTTPS when SC2_HTTP_TLS is set
  (certificate not verified: the check runs on loopback, not the public name);
- HTTP off: a TCP connect to the plain chat:// port, else the chats:// port;
- chats:// only and the Let's Encrypt certificate not there yet: healthy,
  since the relay is waiting for certbot rather than broken.

SPDX-License-Identifier: MIT
"""

import os
import socket
import ssl
import sys
import urllib.request

from .config import Config, ConfigError


def _host(bind):
    if bind in ("", "0.0.0.0"):
        return "127.0.0.1"
    if bind == "::":
        return "::1"
    return bind


def check(config, timeout=4.0):
    """(healthy, reason)."""
    host = _host(config.bind)
    if config.http_port:
        if config.http_tls:
            if not os.path.exists(config.tls_cert):
                return False, "SC2_HTTP_TLS is set but %s is missing" % config.tls_cert
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            scheme = "https"
        else:
            ctx, scheme = None, "http"
        url = "%s://%s:%d/healthz" % (scheme, "[%s]" % host if ":" in host else host, config.http_port)
        try:
            with urllib.request.urlopen(url, timeout=timeout, context=ctx) as r:
                return r.status == 200, "%s %d" % (url, r.status)
        except OSError as e:
            return False, "%s: %s" % (url, e)
    if config.plain:
        port = config.plain_port
    elif config.tls_enabled:
        if config.acme_domain and not (os.path.exists(config.tls_cert) and os.path.exists(config.tls_key)):
            return True, "waiting for the first certificate in %s" % os.path.dirname(config.tls_cert)
        port = config.tls_port
    else:
        return False, "no listener configured"
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "tcp %s:%d" % (host, port)
    except OSError as e:
        return False, "tcp %s:%d: %s" % (host, port, e)


def main(env=None):
    try:
        config = Config.from_env(env)
    except ConfigError as e:
        print("unhealthy: configuration: %s" % e, file=sys.stderr)
        return 1
    ok, why = check(config)
    print(("healthy: " if ok else "unhealthy: ") + why, file=sys.stdout if ok else sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
