#!/bin/sh
# Certbot sidecar for the SC2 relay (docker-compose service "certbot").
#
# Gets a Let's Encrypt certificate for $SC2_ACME_DOMAIN over HTTP-01 and
# renews it every 12 hours (certbot only renews within 30 days of expiry).
# --reuse-key keeps the same ECDSA P-256 key across renewals, so the SPKI pin
# that devices store as #pin= stays valid for the life of the key.
# The deploy hook copies the pair into the shared /certs volume; the relay
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

set -- --non-interactive --agree-tos --email "$SC2_ACME_EMAIL" \
    --key-type ecdsa --elliptic-curve secp256r1 --reuse-key \
    --deploy-hook /hooks/deploy-hook.sh
if [ -n "${SC2_ACME_STAGING:-}" ] && [ "$SC2_ACME_STAGING" != "false" ]; then
    set -- "$@" --staging
fi
if [ -n "${SC2_ACME_WEBROOT:-}" ]; then
    set -- "$@" --webroot -w "$SC2_ACME_WEBROOT"
else
    set -- "$@" --standalone --preferred-challenges http
fi

# First run (or a missing copy in /certs): obtain, or reuse a still-valid lineage.
certbot certonly --keep-until-expiring --cert-name sc2-relay -d "$SC2_ACME_DOMAIN" "$@"
if [ ! -s /certs/fullchain.pem ] || [ ! -s /certs/privkey.pem ]; then
    RENEWED_LINEAGE=/etc/letsencrypt/live/sc2-relay /hooks/deploy-hook.sh
fi

trap 'exit 0' TERM INT
while :; do
    sleep "$INTERVAL" &
    wait $!
    certbot renew --cert-name sc2-relay "$@" || echo "certbot renew failed; retrying in ${INTERVAL}s" >&2
done
