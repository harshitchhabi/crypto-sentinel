"""Reversible encodings: base64 / base32 / hex / url-safe base64.

Each ``try_*`` function returns decoded ``bytes`` on success or ``None`` if
the input is not valid for that encoding. They never raise on bad input,
which lets the analyzer fan them out cheaply.
"""

import base64
import binascii


def try_base64(data):
    """Decode standard base64. Accepts ``str`` or ``bytes``."""
    try:
        raw = data.encode() if isinstance(data, str) else data
        return base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        return None


def try_urlsafe_base64(data):
    """Decode url-safe base64 (``-`` / ``_`` alphabet)."""
    try:
        raw = data.encode() if isinstance(data, str) else data
        # pad to a multiple of 4
        raw += b"=" * (-len(raw) % 4)
        return base64.urlsafe_b64decode(raw)
    except (binascii.Error, ValueError):
        return None


def try_base32(data):
    """Decode base32."""
    try:
        raw = data.encode() if isinstance(data, str) else data
        return base64.b32decode(raw, casefold=True)
    except (binascii.Error, ValueError):
        return None


def try_hex(data):
    """Decode hex text."""
    try:
        s = data.decode() if isinstance(data, bytes) else data
        s = s.strip()
        return bytes.fromhex(s)
    except (ValueError, AttributeError):
        return None


# Map used by the analyzer to iterate over every encoding.
DECODERS = {
    "base64": try_base64,
    "urlsafe_base64": try_urlsafe_base64,
    "base32": try_base32,
    "hex": try_hex,
}
