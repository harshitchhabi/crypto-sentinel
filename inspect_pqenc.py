#!/usr/bin/env python3
"""Quick, dependency-free inspection of an unknown encrypted blob.

Reads a file as raw bytes and reports:
  * file size
  * a hex dump of the first 64 bytes (hex + printable ASCII gutter)
  * a heuristic guess at the on-disk shape: base64 text, hex text,
    JSON text, raw binary, or plain/other text.

The point is to look before we pick an attack: the structure of the file
tells us which module in crypto_engine could possibly apply.
"""

import json
import string
import sys


def hexdump(data, width=16):
    """Return a classic offset / hex / ascii dump of ``data``."""
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        hexpart = f"{hexpart:<{width * 3 - 1}}"
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hexpart}  |{asciipart}|")
    return "\n".join(lines)


def guess_format(data):
    """Best-effort classification of the blob's outer shape.

    Returns a short string describing the most likely encoding so the
    caller knows what they are dealing with before decrypting.
    """
    if not data:
        return "empty file"

    # Decide first whether the bytes are even text.
    text_bytes = set(range(32, 127)) | {9, 10, 13}
    printable_ratio = sum(1 for b in data if b in text_bytes) / len(data)
    if printable_ratio < 0.90:
        return "raw binary (non-text bytes present)"

    stripped = data.strip()

    # JSON? (our envelope format)
    if stripped[:1] in (b"{", b"["):
        try:
            json.loads(stripped.decode("utf-8", "replace"))
            return "JSON text (structured container)"
        except (ValueError, UnicodeDecodeError):
            pass

    sample = stripped.decode("ascii", "replace")

    # Hex text?
    hex_alphabet = set(string.hexdigits)
    if len(sample) >= 2 and len(sample) % 2 == 0 and all(c in hex_alphabet for c in sample):
        return "hex text (even length, all hex digits)"

    # Base64 text?
    b64_alphabet = set(string.ascii_letters + string.digits + "+/=\n\r")
    if all(c in b64_alphabet for c in sample) and len(sample.replace("\n", "").replace("\r", "")) % 4 == 0:
        return "base64 text"

    return "plain/other text"


def inspect(path):
    with open(path, "rb") as fh:
        data = fh.read()

    print(f"file:        {path}")
    print(f"size:        {len(data)} bytes")
    print(f"format guess: {guess_format(data)}")
    print()
    print("first 64 bytes:")
    print(hexdump(data[:64]))


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "pass.txt.pqenc"
    inspect(target)
