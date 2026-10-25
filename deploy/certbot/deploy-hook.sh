#!/bin/sh
# certbot --deploy-hook: copy the renewed pair into $SC2_ACME_CERT_DIR
# (default /certs), the directory the relay reads with SC2_ACME_DOMAIN.
# Files are written to a temporary name and renamed, the key first, so the
# relay never sees a half-written file (and skips a mismatched pair until
# both have landed). Both are 0600 and owned by the relay's fixed UID/GID.
#
# SPDX-License-Identifier: MIT
set -eu
SRC="${RENEWED_LINEAGE:?certbot sets RENEWED_LINEAGE}"
DST="${SC2_ACME_CERT_DIR:-/certs}"
OWNER="${SC2_RELAY_UID:-10001}:${SC2_RELAY_GID:-10001}"
umask 077
for f in privkey.pem fullchain.pem; do
    cp -L "$SRC/$f" "$DST/.$f.new"
    chown "$OWNER" "$DST/.$f.new"
    chmod 0600 "$DST/.$f.new"
    mv -f "$DST/.$f.new" "$DST/$f"
done
echo "deployed $SRC to $DST"
