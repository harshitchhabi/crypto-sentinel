"""Classical substitution ciphers: Caesar/ROT-n, ROT13, Atbash, Vigenere.

Functions operate on text (``str``) and only transform ASCII letters,
leaving other characters untouched. ``caesar_all`` and ``vigenere_all``
enumerate a keyspace, which the analyzer pairs with a known-prefix check.
"""

import string

_LOWER = string.ascii_lowercase
_UPPER = string.ascii_uppercase


def _shift_char(ch, n):
    if ch in _LOWER:
        return _LOWER[(_LOWER.index(ch) + n) % 26]
    if ch in _UPPER:
        return _UPPER[(_UPPER.index(ch) + n) % 26]
    return ch


def caesar(text, shift):
    """Shift every letter by ``shift`` positions."""
    return "".join(_shift_char(c, shift) for c in text)


def caesar_all(text):
    """Yield ``(shift, plaintext)`` for all 26 Caesar shifts."""
    for shift in range(26):
        yield shift, caesar(text, shift)


def rot13(text):
    return caesar(text, 13)


def atbash(text):
    """Map a->z, b->y, ... for letters; leave the rest."""
    out = []
    for c in text:
        if c in _LOWER:
            out.append(_LOWER[25 - _LOWER.index(c)])
        elif c in _UPPER:
            out.append(_UPPER[25 - _UPPER.index(c)])
        else:
            out.append(c)
    return "".join(out)


def vigenere(text, key, decrypt=True):
    """Vigenere encrypt/decrypt ``text`` with alphabetic ``key``."""
    if not key:
        return text
    key = [ord(k.lower()) - 97 for k in key if k.isalpha()]
    if not key:
        return text
    out = []
    ki = 0
    for c in text:
        if c.isalpha():
            k = key[ki % len(key)]
            out.append(_shift_char(c, -k if decrypt else k))
            ki += 1
        else:
            out.append(c)
    return "".join(out)


def vigenere_all(text, wordlist):
    """Yield ``(key, plaintext)`` for each candidate key in ``wordlist``."""
    for key in wordlist:
        yield key, vigenere(text, key, decrypt=True)
