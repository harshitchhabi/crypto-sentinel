"""Orchestration: throw every applicable module at an unknown blob and
report which one yields plaintext starting with a known prefix.

The entry point is :func:`solve_with_hint`. It is deliberately
prefix-driven: in a CTF you usually know a few leading plaintext bytes
(here, ``msbj``), and that crib is what lets us recognise a win and, for
XOR, recover the key outright.
"""

import base64
import hashlib
import json

from . import encoding, classical, xor, aes_ecb, hashes, rsa, pqc


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


def _is_likely_plaintext(data):
    """True if ``data`` looks like readable ASCII text/flag rather than XOR noise."""
    if not data:
        return False
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    if (printable / len(data)) < 0.90:
        return False
    natural = sum(
        1 for b in data
        if (48 <= b <= 57) or (65 <= b <= 90) or (97 <= b <= 122)
        or b in b" {}_-.,:;!?'\"\n\r\t"
    )
    return (natural / len(data)) >= 0.85


def _smallest_period(key_bytes):
    """Return the shortest repeating period of ``key_bytes``."""
    n = len(key_bytes)
    for period in range(1, n + 1):
        repeated = (key_bytes[:period] * ((n // period) + 1))[:n]
        if repeated == key_bytes:
            return key_bytes[:period]
    return key_bytes


def _looks_like_pqc_envelope(obj):
    return isinstance(obj, dict) and "kem_cipher" in obj and "ciphertext" in obj


def _looks_like_rsa_envelope(obj):
    return isinstance(obj, dict) and "c" in obj and "e" in obj


# a tiny built-in wordlist for Vigenere/key/hash guesses; callers can pass more
_DEFAULT_WORDS = ["key", "secret", "password", "crypto", "sentinel", "vit", "msbj"]


# ---------------------------------------------------------------------------
# PQC envelope path
# ---------------------------------------------------------------------------

def _identify_pqc(obj):
    """Report the scheme implied by the envelope's field sizes."""
    sizes = {}
    for k, v in obj.items():
        if isinstance(v, str):
            try:
                sizes[k] = len(base64.b64decode(v))
            except Exception:
                sizes[k] = -1
    kem = {768: "ML-KEM-512", 1088: "ML-KEM-768", 1568: "ML-KEM-1024"}
    sig = {2420: "ML-DSA-44", 3309: "ML-DSA-65", 4627: "ML-DSA-87"}
    return {
        "field_sizes": sizes,
        "kem": kem.get(sizes.get("kem_cipher"), "unknown-KEM"),
        "signature": sig.get(sizes.get("signature"), "unknown-signature"),
        "aead": "AES-256-GCM" if sizes.get("nonce") == 12 and sizes.get("auth_tag") == 16 else "unknown-AEAD",
    }


def _try_pqc_decrypt(obj, prefix_bytes, aes_key=None, kem_private=None, attempts=None):
    """Finish the envelope if we hold either ``aes_key`` or ``kem_private``."""
    try:
        nonce = base64.b64decode(obj["nonce"])
        tag = base64.b64decode(obj["auth_tag"])
        ct = base64.b64decode(obj["ciphertext"])
        kem_ct = base64.b64decode(obj["kem_cipher"])
    except Exception:
        return None, None

    candidate_keys = []
    if aes_key is not None:
        candidate_keys.append(("aes_key", aes_key))
    if kem_private is not None:
        try:
            shared = kem_private.decapsulate(kem_ct)
            candidate_keys.append(("kdf=raw", shared))
            candidate_keys.append(("kdf=hkdf", pqc.hkdf_sha256(shared, 32, salt=None, info=b"pqenc")))
            candidate_keys.append(("kdf=hkdf-empty", pqc.hkdf_sha256(shared, 32, salt=None, info=b"")))
        except Exception as exc:
            if attempts is not None:
                attempts.append(f"pqc:kem-decapsulate-error({exc})")

    for label, k in candidate_keys:
        if attempts is not None:
            attempts.append(f"pqc:aead-decrypt({label})")
        pt = aes_ecb.decrypt_gcm(ct, k, nonce, tag)
        if pt is not None and (_matches(pt, prefix_bytes) or not prefix_bytes):
            return pt, label
    return None, None


# ---------------------------------------------------------------------------
# classical / encoded / XOR / hash / RSA / AES-ECB path
# ---------------------------------------------------------------------------

def _try_ciphers_on_bytes(raw, prefix_bytes, wordlist, attempts, stage_prefix="", allow_heuristic_xor=False):
    """Run classical ciphers, XOR, hashes, and AES-ECB against ``raw``."""
    tag = f"{stage_prefix}->" if stage_prefix else ""

    # text view for classical ciphers & hash cracking
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = None

    if text is not None:
        stripped = text.strip()
        # Hash identification & dictionary reversal
        algos = hashes.identify(stripped)
        if algos:
            attempts.append(f"{tag}hashes:crack({'/'.join(algos)})")
            candidates = list(wordlist) + [
                (prefix_bytes.decode("utf-8", "ignore") + w) for w in wordlist
            ]
            cracked = hashes.crack(stripped, candidates, algorithms=algos)
            if cracked is not None and _matches(cracked, prefix_bytes):
                return f"{tag}hashes:crack({algos[0]})", cracked.encode()

        for shift, out in classical.caesar_all(text):
            attempts.append(f"{tag}classical:caesar(shift={shift})")
            if _matches(out, prefix_bytes):
                return f"{tag}classical:caesar(shift={shift})", out.encode()
        atb = classical.atbash(text)
        attempts.append(f"{tag}classical:atbash")
        if _matches(atb, prefix_bytes):
            return f"{tag}classical:atbash", atb.encode()
        for key, out in classical.vigenere_all(text, wordlist):
            attempts.append(f"{tag}classical:vigenere(key={key})")
            if _matches(out, prefix_bytes):
                return f"{tag}classical:vigenere(key={key})", out.encode()

    # Single-byte XOR
    for k, out in xor.single_byte_all(raw):
        attempts.append(f"{tag}xor:single(0x{k:02x})")
        if _matches(out, prefix_bytes):
            return f"{tag}xor:single(0x{k:02x})", out

    # Repeating-key XOR recovered from the known prefix.
    recovered = xor.key_from_known_prefix(raw, prefix_bytes)
    if recovered:
        minimal_key = _smallest_period(recovered)
        is_periodic = len(minimal_key) < len(recovered)
        if is_periodic or allow_heuristic_xor:
            out = xor.xor_bytes(raw, minimal_key)
            attempts.append(f"{tag}xor:repeating(key_from_prefix={minimal_key.hex()})")
            remainder = out[len(prefix_bytes):]
            is_valid = is_periodic or (
                len(remainder) > 0 and _is_likely_plaintext(remainder)
            )
            if _matches(out, prefix_bytes) and is_valid:
                return f"{tag}xor:repeating(key=0x{minimal_key.hex()})", out

    # AES-ECB dictionary key trial (if blob is a multiple of 16 bytes)
    if len(raw) >= 16 and len(raw) % 16 == 0:
        for word in wordlist:
            wbytes = word.encode() if isinstance(word, str) else word
            key_candidates = [
                wbytes.ljust(16, b"\x00")[:16],
                hashlib.sha256(wbytes).digest(),
            ]
            for k in key_candidates:
                attempts.append(f"{tag}aes_ecb:key({word},{len(k)*8})")
                pt = aes_ecb.decrypt_ecb(raw, k, unpad=True)
                if pt is not None and _matches(pt, prefix_bytes):
                    return f"{tag}aes_ecb(key={word})", pt

    return None, None


def _try_classical_blob(raw, prefix_bytes, wordlist, attempts):
    """Run encodings (1- and 2-layer), classical ciphers, XOR, hashes, and AES-ECB."""
    decoded_layers = []
    for name, decoder in encoding.DECODERS.items():
        out = decoder(raw)
        attempts.append(f"encoding:{name}")
        if out is not None:
            if _matches(out, prefix_bytes):
                return f"encoding:{name}", out
            decoded_layers.append((f"encoding:{name}", out))

    # Try deterministic ciphers directly on the raw blob
    method, pt = _try_ciphers_on_bytes(
        raw, prefix_bytes, wordlist, attempts, allow_heuristic_xor=False
    )
    if pt is not None:
        return method, pt

    # Try a second pass on any successfully decoded outer encoding layer
    for stage_name, decoded_bytes in decoded_layers:
        for inner_name, decoder in encoding.DECODERS.items():
            out2 = decoder(decoded_bytes)
            attempts.append(f"{stage_name}->encoding:{inner_name}")
            if out2 is not None and _matches(out2, prefix_bytes):
                return f"{stage_name}->encoding:{inner_name}", out2
        method, pt = _try_ciphers_on_bytes(
            decoded_bytes, prefix_bytes, wordlist, attempts,
            stage_prefix=stage_name, allow_heuristic_xor=True,
        )
        if pt is not None:
            return method, pt

    # Finally, try heuristic full-prefix-length XOR key recovery on raw bytes
    recovered = xor.key_from_known_prefix(raw, prefix_bytes)
    if recovered:
        minimal_key = _smallest_period(recovered)
        if len(minimal_key) == len(recovered):
            out = xor.xor_bytes(raw, minimal_key)
            attempts.append(f"xor:repeating(key_from_prefix={minimal_key.hex()})")
            remainder = out[len(prefix_bytes):]
            if _matches(out, prefix_bytes) and len(remainder) > 0 and _is_likely_plaintext(remainder):
                return f"xor:repeating(key=0x{minimal_key.hex()})", out

    return None, None


def _try_rsa_envelope(obj, prefix_bytes, attempts):
    """Try textbook RSA attacks (low-e root, small factor, Fermat) on a JSON dict."""
    c = int(obj["c"])
    e = int(obj["e"])
    n = int(obj["n"]) if "n" in obj else None

    attempts.append("rsa:low_exponent_root")
    pt = rsa.low_exponent_root(c, e)
    if pt is not None and _matches(pt, prefix_bytes):
        return "rsa:low_exponent_root", pt

    if n is not None:
        attempts.append("rsa:factor_small")
        p = rsa.factor_small(n)
        if p:
            _, pt = rsa.decrypt_with_factors(c, e, p, n // p)
            if _matches(pt, prefix_bytes):
                return "rsa:factor_small", pt

        attempts.append("rsa:fermat_factor")
        factors = rsa.fermat_factor(n)
        if factors:
            _, pt = rsa.decrypt_with_factors(c, e, factors[0], factors[1])
            if _matches(pt, prefix_bytes):
                return "rsa:fermat_factor", pt

    return None, None


# ---------------------------------------------------------------------------
# public entry point
# ---------------------------------------------------------------------------

def solve_with_hint(filepath, known_prefix, aes_key=None, kem_private=None, wordlist=None):
    """Load ``filepath`` and try every applicable module against it.

    For each attempt the decrypted output is checked against
    ``known_prefix``. The first method whose output starts with the prefix
    is reported as the winner.
    """
    prefix_bytes = _as_bytes(known_prefix)
    wordlist = wordlist or _DEFAULT_WORDS
    attempts = []

    with open(filepath, "rb") as fh:
        raw = fh.read()

    # Is it a structured JSON envelope (PQC or RSA)?
    obj = None
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        obj = None

    if _looks_like_pqc_envelope(obj):
        details = _identify_pqc(obj)
        attempts.append(f"pqc:identify({details['kem']}+{details['aead']})")
        pt, kdf_label = _try_pqc_decrypt(
            obj, prefix_bytes, aes_key=aes_key, kem_private=kem_private, attempts=attempts
        )
        if pt is not None:
            return {
                "success": True,
                "method": f"PQC envelope ({details['kem']} + {details['aead']}, {kdf_label})",
                "plaintext": pt,
                "container": "pqc-envelope",
                "details": details,
                "attempts": attempts,
            }
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

    if _looks_like_rsa_envelope(obj):
        method, pt = _try_rsa_envelope(obj, prefix_bytes, attempts)
        return {
            "success": pt is not None,
            "method": method,
            "plaintext": pt,
            "container": "rsa-envelope",
            "details": {"has_n": "n" in obj},
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
