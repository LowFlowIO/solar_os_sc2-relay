"""TLS helpers: server context, hot reload and the SPKI pin published in
/.well-known/solaros-relay (format "sha256/<base64>", the same form clients
accept in chats://host:7778#pin=...).

Pins are over the SubjectPublicKeyInfo, not the certificate, so a renewed
certificate for the same key (certbot --reuse-key) keeps every device pin
valid. Only a new key changes the pin.

SPDX-License-Identifier: MIT
"""

import base64
import hashlib
import os
import shutil
import ssl
import tempfile


def server_context(cert, key):
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    return ctx


def _der_item(buf, off):
    """Return (tag, header_len, content_len) of the DER item at off."""
    tag = buf[off]
    n = buf[off + 1]
    if n < 0x80:
        return tag, 2, n
    k = n & 0x7F
    if k == 0 or k > 4:
        raise ValueError("unsupported DER length")
    return tag, 2 + k, int.from_bytes(buf[off + 2:off + 2 + k], "big")


def spki_from_der(cert_der):
    """SubjectPublicKeyInfo bytes of an X.509 certificate."""
    tag, h, n = _der_item(cert_der, 0)  # Certificate
    if tag != 0x30:
        raise ValueError("not a certificate")
    off = h
    tag, h, n = _der_item(cert_der, off)  # tbsCertificate
    if tag != 0x30:
        raise ValueError("not a certificate")
    off += h
    end = off + n
    fields = []
    while off < end and len(fields) < 7:
        tag, h, n = _der_item(cert_der, off)
        fields.append((tag, off, h + n))
        off += h + n
    if fields and fields[0][0] == 0xA0:  # explicit version
        fields = fields[1:]
    # serial, signature, issuer, validity, subject, subjectPublicKeyInfo
    if len(fields) < 6 or fields[5][0] != 0x30:
        raise ValueError("certificate has no SubjectPublicKeyInfo")
    _, o, ln = fields[5]
    return bytes(cert_der[o:o + ln])


def spki_pin_pem(pem):
    """Pin of the first (leaf) certificate in a PEM chain."""
    der = ssl.PEM_cert_to_DER_cert(pem)
    return "sha256/" + base64.b64encode(hashlib.sha256(spki_from_der(der)).digest()).decode()


def spki_pin(cert_path):
    with open(cert_path, "r") as f:
        return spki_pin_pem(f.read())


def file_stamp(*paths):
    """Cheap change detector: (inode, size, mtime_ns) per path, None if missing.
    Symlinks are followed, so certbot's live/ links work too."""
    out = []
    for p in paths:
        try:
            st = os.stat(p)
            out.append((st.st_ino, st.st_size, st.st_mtime_ns))
        except OSError:
            out.append(None)
    return tuple(out)


def reload_context(ctx, cert, key):
    """Swap the certificate and key of a live server context.

    Both files are copied once into a private temporary directory so the
    validation and the live load see the same bytes even while certbot is
    rewriting them. The copy is loaded into a scratch context first; only if
    that works is it loaded into ctx. OpenSSL copies the certificate into
    each connection when the connection is created, so connections that are
    already established keep the old certificate and new handshakes get the
    new one. Returns (ctx, pin): ctx is a new context when ctx was None.
    Raises ssl.SSLError / OSError / ValueError and leaves ctx untouched on
    any problem."""
    d = tempfile.mkdtemp(prefix="sc2-tls-")
    try:
        c, k = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
        for src, dst in ((cert, c), (key, k)):
            fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as out, open(src, "rb") as inp:
                shutil.copyfileobj(inp, out)
        with open(c, "r") as f:
            pin = spki_pin_pem(f.read())
        scratch = server_context(c, k)
        if ctx is None:
            return scratch, pin
        ctx.load_cert_chain(c, k)
        return ctx, pin
    finally:
        shutil.rmtree(d, ignore_errors=True)
