"""XOR ciphers: single-byte and repeating-key.

The repeating-key helpers include a known-plaintext recovery: given a
crib (e.g. the first few plaintext bytes), the key bytes that produced
them fall straight out of ``ct[i] ^ pt[i]``.
"""

import itertools


def xor_bytes(data, key):
    """XOR ``data`` with a repeating ``key`` (both ``bytes``)."""
    if not key:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def single_byte_all(data):
    """Yield ``(key_byte, plaintext_bytes)`` for all 256 single-byte keys."""
    for k in range(256):
        yield k, bytes(b ^ k for b in data)


def repeating_key(data, key):
    return xor_bytes(data, key)


def key_from_known_prefix(data, known_prefix):
    """Recover the repeating-XOR key implied by a known plaintext prefix.

    If the key is no longer than ``known_prefix`` this returns the exact
    key; otherwise it returns the leading key bytes it could derive.
    """
    kp = known_prefix.encode() if isinstance(known_prefix, str) else known_prefix
    n = min(len(data), len(kp))
    return bytes(data[i] ^ kp[i] for i in range(n))


def brute_multibyte(data, max_len=2):
    """Yield ``(key, plaintext)`` for every key up to ``max_len`` bytes.

    Kept small on purpose: the full 2-byte space is 65 536 keys, which is
    cheap; longer keys should be recovered via ``key_from_known_prefix``
    rather than brute force.
    """
    for length in range(1, max_len + 1):
        for combo in itertools.product(range(256), repeat=length):
            key = bytes(combo)
            yield key, xor_bytes(data, key)
