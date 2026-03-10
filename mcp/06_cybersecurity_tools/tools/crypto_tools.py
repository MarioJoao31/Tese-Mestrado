"""
crypto_tools.py
---------------
MCP tool functions for cryptographic analysis and secure coding helpers.

Tools:
  - identify_hash_type    : Guess hash algorithm from hex digest length/pattern.
  - hash_text             : Hash a string with a chosen algorithm.
  - analyze_password      : Advanced password-strength and breach-pattern check.
  - generate_secure_token : Produce a cryptographically random token.
  - check_encoding        : Detect and decode common text encodings.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import secrets
import string
from urllib.parse import unquote

from mcp.server.fastmcp import FastMCP

_mcp = FastMCP("crypto-tools")

# ---------------------------------------------------------------------------
# Known hash lengths (hex digits)
# ---------------------------------------------------------------------------

_HASH_BY_LENGTH: dict[int, list[str]] = {
    8:  ["CRC-32"],
    32: ["MD5", "MD4", "NTLM"],
    40: ["SHA-1", "RIPEMD-160"],
    56: ["SHA-224"],
    64: ["SHA-256", "SHA-3-256", "BLAKE2s"],
    96: ["SHA-384"],
    128: ["SHA-512", "SHA-3-512", "BLAKE2b"],
}

_HASH_ALGORITHMS: set[str] = {"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_256", "sha3_512", "blake2s", "blake2b"}

# Common weak/leaked passwords (indicative list for educational demo)
_COMMON_PASSWORDS: frozenset[str] = frozenset({
    "password", "123456", "password1", "qwerty", "abc123", "letmein",
    "monkey", "1234567890", "iloveyou", "sunshine", "princess", "admin",
    "welcome", "shadow", "master", "dragon", "pass", "test", "root",
})


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@_mcp.tool()
def identify_hash_type(hash_value: str) -> str:
    """
    Attempt to identify the hashing algorithm used to produce a hex digest.

    Args:
        hash_value: Hexadecimal hash string (e.g. "5d41402abc4b2a76b9719d911017c592").

    Returns:
        JSON with possible algorithm candidates and security notes.
    """
    h = hash_value.strip().lower()
    if not re.match(r"^[0-9a-f]+$", h):
        # Could be Base64-encoded hash or bcrypt, etc.
        special: list[str] = []
        if h.startswith("$2") and len(h) == 60:
            special = ["bcrypt (password hash)"]
        elif re.match(r"^\$argon2", h):
            special = ["Argon2 (password hash)"]
        elif re.match(r"^\$pbkdf2", h):
            special = ["PBKDF2 (password hash)"]
        elif re.match(r"^[0-9a-z+/]+=*$", h, re.IGNORECASE):
            special = ["Base64-encoded value (decode first)"]

        return json.dumps({
            "input": hash_value,
            "format": "non-hex",
            "candidates": special or ["Unknown / non-standard format"],
            "security_notes": [],
        })

    candidates = _HASH_BY_LENGTH.get(len(h), [])
    security_notes: list[str] = []

    if "MD5" in candidates or "MD4" in candidates or "NTLM" in candidates:
        security_notes.append("MD5/NTLM are cryptographically broken – do not use for security purposes.")
    if "SHA-1" in candidates:
        security_notes.append("SHA-1 is deprecated; migrate to SHA-256 or stronger.")
    if "CRC-32" in candidates:
        security_notes.append("CRC-32 is a checksum, NOT a cryptographic hash – not suitable for security use.")

    return json.dumps(
        {
            "input_length": len(h),
            "candidates": candidates if candidates else ["No known algorithm for this length"],
            "security_notes": security_notes,
            "recommendation": (
                "Use SHA-256, SHA-3-256, or BLAKE2 for general hashing; "
                "use bcrypt/Argon2/PBKDF2 for password storage."
            ),
        },
        indent=2,
    )


@_mcp.tool()
def hash_text(text: str, algorithm: str = "sha256", as_base64: bool = False) -> str:
    """
    Compute a cryptographic hash of the provided text.

    Args:
        text:      The input text to hash (UTF-8 encoded).
        algorithm: Hash algorithm name: md5, sha1, sha224, sha256, sha384, sha512,
                   sha3_256, sha3_512, blake2s, blake2b. Default: sha256.
        as_base64: If True, return the digest Base64-encoded instead of hex.

    Returns:
        JSON with the digest and algorithm metadata.
    """
    alg = algorithm.lower().strip()
    if alg not in _HASH_ALGORITHMS:
        return json.dumps({
            "error": f"Unsupported algorithm '{alg}'. Supported: {sorted(_HASH_ALGORITHMS)}",
        })

    warnings: list[str] = []
    if alg in ("md5", "sha1"):
        warnings.append(f"{alg.upper()} is cryptographically weak. Use SHA-256 or stronger.")

    try:
        if alg == "blake2s":
            digest_bytes = hashlib.new("blake2s", text.encode("utf-8")).digest()
        elif alg == "blake2b":
            digest_bytes = hashlib.new("blake2b", text.encode("utf-8")).digest()
        else:
            digest_bytes = hashlib.new(alg, text.encode("utf-8")).digest()
    except ValueError as exc:
        return json.dumps({"error": str(exc)})

    digest = base64.b64encode(digest_bytes).decode() if as_base64 else digest_bytes.hex()

    return json.dumps(
        {
            "algorithm": alg,
            "encoding": "base64" if as_base64 else "hex",
            "digest": digest,
            "input_length": len(text),
            "warnings": warnings,
        },
        indent=2,
    )


@_mcp.tool()
def analyze_password(password: str) -> str:
    """
    Perform an advanced password strength analysis.

    Checks: length, character diversity, common patterns, keyboard walks,
    repeated characters, and known breached passwords.

    Args:
        password: The password string to analyse (not logged or stored).

    Returns:
        JSON with per-criterion scores, an overall strength rating, and
        specific improvement suggestions.
    """
    criteria: dict[str, bool] = {
        "min_length_8":    len(password) >= 8,
        "min_length_12":   len(password) >= 12,
        "min_length_16":   len(password) >= 16,
        "has_uppercase":   bool(re.search(r"[A-Z]", password)),
        "has_lowercase":   bool(re.search(r"[a-z]", password)),
        "has_digits":      bool(re.search(r"\d", password)),
        "has_special":     bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]", password)),
        "no_common_word":  password.lower() not in _COMMON_PASSWORDS,
        "no_sequential":   not bool(re.search(r"(012|123|234|345|456|567|678|789|890|abc|bcd|cde|qwer|asdf|zxcv)", password.lower())),
        "no_repeated_chars": not bool(re.search(r"(.)\1{2,}", password)),
    }

    entropy_chars = 0
    if criteria["has_lowercase"]:
        entropy_chars += 26
    if criteria["has_uppercase"]:
        entropy_chars += 26
    if criteria["has_digits"]:
        entropy_chars += 10
    if criteria["has_special"]:
        entropy_chars += 32
    import math
    entropy_bits = math.log2(entropy_chars ** len(password)) if entropy_chars > 0 else 0

    score = sum(criteria.values())
    if score <= 4:
        strength = "VERY WEAK"
        color = "red"
    elif score <= 6:
        strength = "WEAK"
        color = "orange"
    elif score <= 8:
        strength = "MODERATE"
        color = "yellow"
    elif score <= 9:
        strength = "STRONG"
        color = "green"
    else:
        strength = "VERY STRONG"
        color = "blue"

    suggestions: list[str] = []
    if not criteria["min_length_12"]:
        suggestions.append("Increase length to at least 12 characters (16+ recommended).")
    if not criteria["has_special"]:
        suggestions.append("Add special characters (e.g. !, @, #, $, %).")
    if not criteria["has_uppercase"]:
        suggestions.append("Include at least one uppercase letter.")
    if not criteria["has_digits"]:
        suggestions.append("Include at least one digit.")
    if not criteria["no_common_word"]:
        suggestions.append("Avoid common passwords that appear in breach databases.")
    if not criteria["no_sequential"]:
        suggestions.append("Avoid sequential patterns like '123' or 'qwer'.")
    if not criteria["no_repeated_chars"]:
        suggestions.append("Avoid repeating characters (e.g. 'aaa').")

    return json.dumps(
        {
            "strength": strength,
            "color_indicator": color,
            "score": f"{score}/{len(criteria)}",
            "estimated_entropy_bits": round(entropy_bits, 1),
            "criteria": criteria,
            "suggestions": suggestions,
            "warning": "Do not submit real passwords to any tool or API.",
        },
        indent=2,
    )


@_mcp.tool()
def generate_secure_token(length: int = 32, format: str = "hex") -> str:
    """
    Generate a cryptographically secure random token using Python's secrets module.

    Args:
        length: Desired token length in bytes (2–128). For hex output the string
                will be 2× this length. Default: 32.
        format: Output format – "hex", "base64", "urlsafe_base64", or "alphanumeric".

    Returns:
        JSON with the generated token and metadata.
    """
    if not 2 <= length <= 128:
        return json.dumps({"error": "Length must be between 2 and 128 bytes."})

    fmt = format.lower().strip()
    if fmt == "hex":
        token = secrets.token_hex(length)
        display_len = length * 2
    elif fmt == "base64":
        token = base64.b64encode(secrets.token_bytes(length)).decode()
        display_len = len(token)
    elif fmt in ("urlsafe_base64", "urlsafe"):
        token = secrets.token_urlsafe(length)
        display_len = len(token)
    elif fmt == "alphanumeric":
        alphabet = string.ascii_letters + string.digits
        token = "".join(secrets.choice(alphabet) for _ in range(length))
        display_len = length
    else:
        return json.dumps({"error": f"Unknown format '{fmt}'. Use hex, base64, urlsafe_base64, or alphanumeric."})

    return json.dumps(
        {
            "token": token,
            "format": fmt,
            "byte_length": length,
            "string_length": display_len,
            "entropy_bits": length * 8,
            "usage_notes": [
                "Use as API keys, session tokens, CSRF tokens, or password-reset links.",
                "Never reuse tokens or derive them from predictable values.",
                "Store tokens with a one-way hash (e.g. SHA-256) server-side.",
            ],
        },
        indent=2,
    )


@_mcp.tool()
def check_encoding(data: str) -> str:
    """
    Detect and attempt to decode common encodings often used to obfuscate payloads.

    Checks: Base64, URL encoding, hex strings, and HTML entities.

    Args:
        data: The potentially encoded string to inspect.

    Returns:
        JSON with detected encoding type(s) and decoded value(s).
    """
    results: list[dict] = []

    # Base64
    try:
        padded = data + "=" * (-len(data) % 4)
        decoded_bytes = base64.b64decode(padded, validate=True)
        decoded_str = decoded_bytes.decode("utf-8", errors="replace")
        results.append({
            "encoding": "Base64",
            "decoded": decoded_str,
            "note": "Standard Base64",
        })
    except (binascii.Error, ValueError):
        pass

    # URL encoding
    url_decoded = unquote(data)
    if url_decoded != data:
        results.append({
            "encoding": "URL encoding",
            "decoded": url_decoded,
            "note": "Percent-encoded characters decoded",
        })

    # Hex string
    hex_clean = re.sub(r"[\s\\x]", "", data.lower())
    if re.match(r"^[0-9a-f]+$", hex_clean) and len(hex_clean) % 2 == 0:
        try:
            hex_decoded = bytes.fromhex(hex_clean).decode("utf-8", errors="replace")
            results.append({
                "encoding": "Hex",
                "decoded": hex_decoded,
                "note": "Hexadecimal byte string",
            })
        except ValueError:
            pass

    # HTML entity decoding
    import html
    html_decoded = html.unescape(data)
    if html_decoded != data:
        results.append({
            "encoding": "HTML entities",
            "decoded": html_decoded,
            "note": "HTML entity characters unescaped",
        })

    security_notes: list[str] = []
    if results:
        for r in results:
            dec = r.get("decoded", "")
            if re.search(r"<script|onerror|javascript:|eval\(|exec\(", dec, re.IGNORECASE):
                security_notes.append(f"Decoded {r['encoding']} value contains suspicious script content.")

    return json.dumps(
        {
            "original": data,
            "detections": results,
            "security_notes": security_notes,
            "no_encoding_detected": len(results) == 0,
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
CRYPTO_TOOLS = [
    identify_hash_type,
    hash_text,
    analyze_password,
    generate_secure_token,
    check_encoding,
]
