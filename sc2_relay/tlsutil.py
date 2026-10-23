"""TLS helpers: server context and the SPKI pin published in
/.well-known/solaros-relay (format "sha256/<base64>", the same form clients
accept in chats://host:7778#pin=...).

SPDX-License-Identifier: MIT
"""

import base64
import hashlib
import ssl


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


def spki_pin(cert_path):
    with open(cert_path, "r") as f:
        pem = f.read()
    der = ssl.PEM_cert_to_DER_cert(pem)
    return "sha256/" + base64.b64encode(hashlib.sha256(spki_from_der(der)).digest()).decode()
