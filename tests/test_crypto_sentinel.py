"""Comprehensive unit and integration test suite for crypto-sentinel."""

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

from crypto_engine import (
    aes_ecb,
    analyzer,
    classical,
    encoding,
    hashes,
    pqc,
    rsa,
    xor,
)
import generate
import inspect_pqenc


class TestCryptoEngine(unittest.TestCase):
    def test_encodings_with_whitespace(self):
        self.assertEqual(encoding.try_base64("  bXNiag==\n"), b"msbj")
        self.assertEqual(encoding.try_urlsafe_base64("bXNiag\n"), b"msbj")
        self.assertEqual(encoding.try_base32("NVZWE2I=\n"), b"msbi")
        self.assertEqual(encoding.try_hex("  6d73626a \n"), b"msbj")
        self.assertIsNone(encoding.try_base64(""))
        self.assertIsNone(encoding.try_hex("zzzz"))

    def test_classical_ciphers(self):
        ct = classical.caesar("msbj_secret_flag", 7)
        self.assertEqual(classical.caesar(ct, -7), "msbj_secret_flag")
        self.assertEqual(classical.rot13(classical.rot13("msbj_rot13")), "msbj_rot13")
        self.assertEqual(classical.atbash(classical.atbash("msbj_atbash")), "msbj_atbash")
        vig = classical.vigenere("msbj_vigenere", "sentinel", decrypt=False)
        self.assertEqual(classical.vigenere(vig, "sentinel", decrypt=True), "msbj_vigenere")

    def test_xor_and_no_false_positive_on_random_bytes(self):
        # Genuine repeating-key XOR with readable plaintext should succeed
        pt = b"msbj{repeating_xor_test_message_in_ascii}"
        ct = xor.xor_bytes(pt, b"XY")
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(ct)
            path = tf.name
        try:
            res = analyzer.solve_with_hint(path, "msbj")
            self.assertTrue(res["success"])
            self.assertEqual(res["plaintext"], pt)
        finally:
            os.unlink(path)

        # High-entropy non-printable binary blob must NOT trigger a false-positive XOR win
        garbage = bytes(range(128, 256))
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(garbage)
            gpath = tf.name
        try:
            res_g = analyzer.solve_with_hint(gpath, "msbj")
            self.assertFalse(res_g["success"])
        finally:
            os.unlink(gpath)

    def test_multi_layer_encoding_and_cipher(self):
        # Base64-wrapped Caesar cipher
        inner = classical.caesar("msbj{layered_flag}", 5).encode()
        outer = base64.b64encode(inner)
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(outer)
            path = tf.name
        try:
            res = analyzer.solve_with_hint(path, "msbj")
            self.assertTrue(res["success"])
            self.assertIn("encoding:base64->classical:caesar", res["method"])
            self.assertEqual(res["plaintext"], b"msbj{layered_flag}")
        finally:
            os.unlink(path)

    def test_rsa_and_hashes_integration(self):
        # Hash crack via analyzer
        digest = hashlib.sha256(b"msbj_secret").hexdigest().encode()
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(digest)
            hpath = tf.name
        try:
            res = analyzer.solve_with_hint(hpath, "msbj", wordlist=["_secret"])
            self.assertTrue(res["success"])
            self.assertEqual(res["plaintext"], b"msbj_secret")
        finally:
            os.unlink(hpath)

        # RSA envelope via analyzer
        m = int.from_bytes(b"msbj_rsa", "big")
        p, q, e = 1000003, 1000033, 65537
        # Use low-e attack vector
        env = {"c": m ** 3, "e": 3}
        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            json.dump(env, tf)
            rpath = tf.name
        try:
            res = analyzer.solve_with_hint(rpath, "msbj")
            self.assertTrue(res["success"])
            self.assertEqual(res["plaintext"], b"msbj_rsa")
        finally:
            os.unlink(rpath)

    def test_safe_key_reader_preserves_whitespace_prefixed_raw_keys(self):
        # 64-byte raw seed starting with 0x20 (space) and ending with 0x0a (newline)
        raw_seed = b" " + (b"A" * 62) + b"\n"
        self.assertEqual(len(raw_seed), 64)
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(raw_seed)
            kpath = tf.name
        try:
            loaded = pqc.read_key_bytes(kpath)
            self.assertEqual(loaded, raw_seed)
        finally:
            os.unlink(kpath)

    def test_pqc_roundtrip_and_expanded_key_support(self):
        kem_priv = pqc.MLKEM1024PrivateKey.generate()
        kem_pub = kem_priv.public_key()
        sig_priv = pqc.MLDSA87PrivateKey.generate()

        msg = b"msbj{post_quantum_round_trip_verified}"
        env = generate.encrypt_envelope(msg, kem_pub, sig_priv, kdf="hkdf")

        # 1. Decrypt using 64-byte seed
        seed_priv = pqc.MLKEM1024PrivateKey.from_private_bytes(kem_priv.private_bytes_raw())
        pt1, sig_ok1 = generate.decrypt_envelope(env, seed_priv, kdf="auto")
        self.assertEqual(pt1, msg)
        self.assertTrue(sig_ok1)

        # 2. Decrypt using 3168-byte expanded private key
        expanded_raw = kem_priv.expanded_private_bytes_raw()
        self.assertEqual(len(expanded_raw), 3168)
        exp_priv = pqc.MLKEM1024PrivateKey.from_private_bytes(expanded_raw)
        pt2, sig_ok2 = generate.decrypt_envelope(env, exp_priv, kdf="auto")
        self.assertEqual(pt2, msg)
        self.assertTrue(sig_ok2)

    def test_cli_entrypoints(self):
        repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for script_args in [
            ["inspect_pqenc.py", "pass.txt.pqenc"],
            ["solve.py", "pass.txt.pqenc", "msbj"],
            ["generate.py", "selftest"],
            ["generate.py", "selftest", "--kdf", "hkdf"],
        ]:
            proc = subprocess.run(
                [sys.executable] + script_args,
                cwd=repo_dir,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=f"{script_args} failed:\n{proc.stderr}\n{proc.stdout}")


if __name__ == "__main__":
    unittest.main()
