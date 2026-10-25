#!/bin/sh
# Certbot sidecar for the SC2 relay (docker-compose service "certbot").
#
# Gets a Let's Encrypt certificate for $SC2_ACME_DOMAIN over HTTP-01 and
# renews it every 12 hours (certbot only renews within 30 days of expiry).
# --reuse-key keeps the same ECDSA P-256 key across renewals, so the SPKI pin
# that devices store as #pin= stays valid for the life of the key.
# The deploy hook copies the pair into $SC2_ACME_CERT_DIR (default /certs,
# the shared volume), the same variable the relay reads; the relay
# notices the change (SC2_TLS_RELOAD_INTERVAL) and hot-reloads it.
#
# Challenge: standalone (certbot listens on :80, publish 80:80) by default;
# set SC2_ACME_WEBROOT=/var/www/acme to answer from a web server you already
# run on :80 instead (that server must serve /.well-known/acme-challenge/
# from the same directory).
#
# SPDX-License-Identifier: MIT
set -eu

if [ -z "${SC2_ACME_DOMAIN:-}" ]; then
    # own certificates (SC2_TLS_CERT/KEY): nothing to do, stay idle so the
    # "restart: unless-stopped" policy does not loop
    echo "SC2_ACME_DOMAIN is not set; certbot sidecar idle" >&2
    trap 'exit 0' TERM INT
    while :; do sleep 86400 & wait $!; done
fi
: "${SC2_ACME_EMAIL:?set SC2_ACME_EMAIL in relay.env (Let's Encrypt account contact)}"
INTERVAL="${SC2_ACME_RENEW_INTERVAL:-43200}"
CERT_DIR="${SC2_ACME_CERT_DIR:-/certs}"
HOOKS="${SC2_HOOKS_DIR:-/hooks}"

# true/false like the relay's own settings (1/0, yes/no, on/off; empty = false)
case "$(printf '%s' "${SC2_ACME_STAGING:-}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on) STAGING=1 ;;
    0|false|no|off|"") STAGING=0 ;;
    *) echo "SC2_ACME_STAGING must be true or false, got '$SC2_ACME_STAGING'" >&2; exit 2 ;;
esac

set -- --non-interactive --agree-tos --email "$SC2_ACME_EMAIL" \
    --key-type ecdsa --elliptic-curve secp256r1 --reuse-key \
    --deploy-hook "$HOOKS/deploy-hook.sh"
if [ "$STAGING" = 1 ]; then
    set -- "$@" --staging
fi
if [ -n "${SC2_ACME_WEBROOT:-}" ]; then
    set -- "$@" --webroot -w "$SC2_ACME_WEBROOT"
else
    set -- "$@" --standalone --preferred-challenges http
fi

# First run (or a missing copy in $CERT_DIR): obtain, or reuse a still-valid lineage.
certbot certonly --keep-until-expiring --cert-name sc2-relay -d "$SC2_ACME_DOMAIN" "$@"
if [ ! -s "$CERT_DIR/fullchain.pem" ] || [ ! -s "$CERT_DIR/privkey.pem" ]; then
    RENEWED_LINEAGE=/etc/letsencrypt/live/sc2-relay "$HOOKS/deploy-hook.sh"
fi

trap 'exit 0' TERM INT
while :; do
    sleep "$INTERVAL" &
    wait $!
    certbot renew --cert-name sc2-relay "$@" || echo "certbot renew failed; retrying in ${INTERVAL}s" >&2
done
