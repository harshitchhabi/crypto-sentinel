"""Textbook-RSA helpers for weak-parameter attacks.

These target the classic CTF mistakes: a modulus small enough to factor,
and a low public exponent on an un-padded short message. They are not a
general RSA break and make no attempt against well-chosen parameters.
"""

import math


def integer_nth_root(x, n):
    """Return ``floor(x ** (1/n))`` exactly, plus whether it is exact."""
    if x < 0:
        raise ValueError("negative radicand")
    if x == 0:
        return 0, True
    lo, hi = 0, 1 << ((x.bit_length() // n) + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** n <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo, lo ** n == x


def factor_small(n, limit=10_000_000):
    """Trial-divide ``n`` up to ``limit``; return a prime factor or None."""
    if n % 2 == 0:
        return 2
    i = 3
    while i <= limit and i * i <= n:
        if n % i == 0:
            return i
        i += 2
    return None


def fermat_factor(n, max_iters=1_000_000):
    """Fermat factorisation: fast when the two primes are close."""
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_iters):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1
    return None


def decrypt_with_factors(c, e, p, q):
    """Recover ``m`` and its bytes from ciphertext ``c`` given ``p, q``."""
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    length = (m.bit_length() + 7) // 8
    return m, m.to_bytes(length, "big")


def low_exponent_root(c, e):
    """If ``m ** e < n`` the message is just the exact e-th root of c."""
    root, exact = integer_nth_root(c, e)
    if exact:
        length = (root.bit_length() + 7) // 8
        return root.to_bytes(max(length, 1), "big")
    return None
