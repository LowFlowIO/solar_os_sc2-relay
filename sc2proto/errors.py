"""SC2 error codes and the exception used across sc2proto.

SPDX-License-Identifier: MIT
"""

# code -> the err strings allowed with it
ERRORS = {
    400: ("bad_request",),
    401: ("auth_required", "bad_sig"),
    403: ("forbidden", "not_member", "admit_required", "muted", "banned"),
    404: ("unknown_device", "unknown_room"),
    408: ("idle", "auth_timeout"),
    409: ("epoch_conflict", "stale_epoch", "replaced", "ambiguous_ref"),
    410: ("prekey_exhausted",),
    413: ("too_large",),
    426: ("upgrade_required",),
    429: ("rate_limited",),
    501: ("not_supported",),
    503: ("server_full", "evicted", "reconnect"),
    507: ("inbox_full",),
}

DEFAULT_TEXT = {
    "bad_request": "bad request",
    "auth_required": "authentication required",
    "bad_sig": "signature invalid",
    "forbidden": "forbidden",
    "not_member": "not a member of this room",
    "admit_required": "admission code required",
    "muted": "muted",
    "banned": "banned from public rooms",
    "unknown_device": "unknown device",
    "unknown_room": "unknown room",
    "epoch_conflict": "commit does not follow the current epoch",
    "stale_epoch": "message uses an old epoch",
    "idle": "closed after a period without activity; reconnect to continue",
    "auth_timeout": "login not completed in time",
    "replaced": "session replaced by a newer login of this device",
    "ambiguous_ref": "several authors used this message ID; include author",
    "prekey_exhausted": "no one-time prekey left; bundle has the signed prekey only",
    "too_large": "too large",
    "upgrade_required": "this relay speaks SC2 v2 only",
    "rate_limited": "slow down",
    "not_supported": "not supported by this relay",
    "server_full": "server full",
    "evicted": "relay full; this idle session was closed to admit another",
    "reconnect": "session lifetime reached; reconnect",
    "inbox_full": "recipient inbox is full",
}


class ProtocolError(Exception):
    """A protocol-level failure that maps onto one SC2 error frame.

    extra holds additional frame fields such as until, epoch or retry_ms.
    close asks the transport to close the connection after sending it.
    """

    def __init__(self, code, err, text=None, close=False, **extra):
        if code not in ERRORS or err not in ERRORS[code]:
            raise ValueError("unknown SC2 error " + str(code) + " " + str(err))
        Exception.__init__(self, text or DEFAULT_TEXT[err])
        self.code = code
        self.err = err
        self.text = text or DEFAULT_TEXT[err]
        self.close = close
        self.extra = extra

    def frame(self, rid=None):
        return error_frame(self.code, self.err, self.text, rid, **self.extra)


def error_frame(code, err, text=None, rid=None, **extra):
    if code not in ERRORS or err not in ERRORS[code]:
        raise ValueError("unknown SC2 error " + str(code) + " " + str(err))
    f = {"type": "error"}
    if rid is not None:
        f["rid"] = rid
    f["code"] = code
    f["err"] = err
    f["text"] = text or DEFAULT_TEXT[err]
    for k in extra:
        f[k] = extra[k]
    return f
