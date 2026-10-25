"""Hash identification and small-dictionary reversal.

Hashes are one-way, so "reversal" only means checking a candidate
wordlist against the digest. ``identify`` guesses the algorithm from the
digest length / shape; ``crack`` tries a wordlist.
"""

import hashlib

# digest hex-length -> plausible algorithms
_BY_LENGTH = {
    32: ["md5"],
    40: ["sha1"],
    56: ["sha224"],
    64: ["sha256"],
    96: ["sha384"],
    128: ["sha512"],
}


def identify(digest_hex):
    """Return candidate algorithm names for a hex digest."""
    s = digest_hex.strip().lower()
    if not all(c in "0123456789abcdef" for c in s):
        return []
    return _BY_LENGTH.get(len(s), [])


def crack(digest_hex, wordlist, algorithms=None):
    """Return the word whose hash matches ``digest_hex``, or None.

    ``algorithms`` defaults to those guessed from the digest length.
    """
    target = digest_hex.strip().lower()
    algos = algorithms or identify(target) or list(_BY_LENGTH.values())
    algos = [a for group in algos for a in ([group] if isinstance(group, str) else group)]
    for word in wordlist:
        raw = word.encode() if isinstance(word, str) else word
        for algo in algos:
            if hashlib.new(algo, raw).hexdigest() == target:
                return word
    return None
