"""Orchestration: throw every applicable module at an unknown blob and
report which one yields plaintext starting with a known prefix.

The entry point is :func:`solve_with_hint`. It is deliberately
prefix-driven: in a CTF you usually know a few leading plaintext bytes
(here, ``msbj``), and that crib is what lets us recognise a win and, for
XOR, recover the key outright.
"""

import base64
import json
import os

from . import encoding, classical, xor, aes_ecb


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _as_bytes(prefix):
    return prefix.encode() if isinstance(prefix, str) else prefix


def _matches(candidate, prefix_bytes):
    """True if ``candidate`` (bytes or str) starts with ``prefix_bytes``."""
    if candidate is None:
        return False
    if isinstance(candidate, str):
        try:
            candidate = candidate.encode()
        except UnicodeEncodeError:
            return False
    return candidate.startswith(prefix_bytes)


def _looks_like_pqc_envelope(obj):
    return isinstance(obj, dict) and "kem_cipher" in obj and "ciphertext" in obj


# a tiny built-in wordlist for Vigenere/key guesses; callers can pass more
_DEFAULT_WORDS = ["key", "secret", "password", "crypto", "sentinel", "vit"]


# ---------------------------------------------------------------------------
# PQC envelope path
# ---------------------------------------------------------------------------

def _identify_pqc(obj):
    """Report the scheme implied by the envelope's field sizes."""
    sizes = {k: len(base64.b64decode(v)) for k, v in obj.items() if isinstance(v, str)}
    kem = {768: "ML-KEM-512", 1088: "ML-KEM-768", 1568: "ML-KEM-1024"}
    sig = {2420: "ML-DSA-44", 3309: "ML-DSA-65", 4627: "ML-DSA-87"}
    return {
        "field_sizes": sizes,
        "kem": kem.get(sizes.get("kem_cipher"), "unknown-KEM"),
        "signature": sig.get(sizes.get("signature"), "unknown-signature"),
        "aead": "AES-256-GCM" if sizes.get("nonce") == 12 and sizes.get("auth_tag") == 16 else "unknown-AEAD",
    }


def _try_pqc_decrypt(obj, prefix_bytes, aes_key):
    """Finish the envelope if we already hold the symmetric AES-GCM key.

    The KEM shared secret cannot be recovered from public data alone; this
    runs only when ``aes_key`` (32 bytes) is supplied out of band.
    """
    if aes_key is None:
        return None
    nonce = base64.b64decode(obj["nonce"])
    tag = base64.b64decode(obj["auth_tag"])
    ct = base64.b64decode(obj["ciphertext"])
    pt = aes_ecb.decrypt_gcm(ct, aes_key, nonce, tag)
    if pt is not None and _matches(pt, prefix_bytes):
        return pt
    return None


# ---------------------------------------------------------------------------
# classical / encoded path
# ---------------------------------------------------------------------------

def _try_classical_blob(raw, prefix_bytes, wordlist, attempts):
    """Run encodings, classical ciphers and XOR against a raw blob."""
    # 1. plain encodings
    for name, decoder in encoding.DECODERS.items():
        out = decoder(raw)
        attempts.append(f"encoding:{name}")
        if _matches(out, prefix_bytes):
            return f"encoding:{name}", out

    # text view for classical ciphers
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = None

    if text is not None:
        for shift, out in classical.caesar_all(text):
            attempts.append(f"classical:caesar(shift={shift})")
            if _matches(out, prefix_bytes):
                return f"classical:caesar(shift={shift})", out
        atb = classical.atbash(text)
        attempts.append("classical:atbash")
        if _matches(atb, prefix_bytes):
            return "classical:atbash", atb
        for key, out in classical.vigenere_all(text, wordlist):
            attempts.append(f"classical:vigenere(key={key})")
            if _matches(out, prefix_bytes):
                return f"classical:vigenere(key={key})", out

    # 2. single-byte XOR
    for k, out in xor.single_byte_all(raw):
        attempts.append(f"xor:single(0x{k:02x})")
        if _matches(out, prefix_bytes):
            return f"xor:single(0x{k:02x})", out

    # 3. repeating-key XOR recovered from the known prefix
    recovered = xor.key_from_known_prefix(raw, prefix_bytes)
    if recovered:
        out = xor.xor_bytes(raw, recovered)
        attempts.append(f"xor:repeating(key_from_prefix={recovered.hex()})")
        if _matches(out, prefix_bytes):
            return f"xor:repeating(key=0x{recovered.hex()})", out

    return None, None


# ---------------------------------------------------------------------------
# public entry point
# ---------------------------------------------------------------------------

def solve_with_hint(filepath, known_prefix, aes_key=None, wordlist=None):
    """Load ``filepath`` and try every applicable module against it.

    For each attempt the decrypted output is checked against
    ``known_prefix``. The first method whose output starts with the prefix
    is reported as the winner.

    Parameters
    ----------
    filepath : str
        File to decrypt.
    known_prefix : str | bytes
        Known leading plaintext (e.g. ``"msbj"``).
    aes_key : bytes, optional
        A recovered 32-byte AES-GCM key. Only relevant for a hybrid PQC
        envelope, whose symmetric key cannot be derived from public data.
    wordlist : list[str], optional
        Candidate keys for Vigenere and similar guess-based attacks.

    Returns
    -------
    dict with keys:
        success    : bool
        method     : str | None   -- the winning method, if any
        plaintext  : bytes | None
        container  : str          -- 'pqc-envelope' or 'raw-blob'
        details    : dict         -- scheme identification / diagnostics
        attempts   : list[str]    -- every method tried, in order
    """
    prefix_bytes = _as_bytes(known_prefix)
    wordlist = wordlist or _DEFAULT_WORDS
    attempts = []

    with open(filepath, "rb") as fh:
        raw = fh.read()

    # Is it a structured (PQC) envelope?
    obj = None
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        obj = None

    if _looks_like_pqc_envelope(obj):
        details = _identify_pqc(obj)
        attempts.append(f"pqc:identify({details['kem']}+{details['aead']})")
        pt = _try_pqc_decrypt(obj, prefix_bytes, aes_key)
        if pt is not None:
            attempts.append("pqc:aead-decrypt")
            return {
                "success": True,
                "method": f"PQC envelope ({details['kem']} + {details['aead']})",
                "plaintext": pt,
                "container": "pqc-envelope",
                "details": details,
                "attempts": attempts,
            }
        # No key -> we can identify but not break it.
        details["blocked_on"] = (
            "KEM private (decapsulation) key required: the AES-256-GCM key "
            "is derived from " + details["kem"] + " and cannot be recovered "
            "from public fields or the known prefix."
        )
        return {
            "success": False,
            "method": None,
            "plaintext": None,
            "container": "pqc-envelope",
            "details": details,
            "attempts": attempts,
        }

    # Otherwise treat it as a raw/encoded blob and run the attack modules.
    method, pt = _try_classical_blob(raw, prefix_bytes, wordlist, attempts)
    return {
        "success": pt is not None,
        "method": method,
        "plaintext": pt,
        "container": "raw-blob",
        "details": {"size": len(raw)},
        "attempts": attempts,
    }
