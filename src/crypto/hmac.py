# Goal: Implement HMAC-SHA256 for message authentication.

"""
HMAC-SHA256.

This module uses our SHA-256 implementation with a secret key.
It will be used later in the handshake and in HKDF.
"""

from src.crypto.sha256 import sha256


BLOCK_SIZE = 64
DIGEST_SIZE = 32


def _normalize_key(key: bytes) -> bytes:
    """
    Prepare the key to be exactly one SHA-256 block.

    If the key is too long, hash it.
    If it is too short, pad it with zeros.
    """
    if len(key) > BLOCK_SIZE:
        key = sha256(key)

    if len(key) < BLOCK_SIZE:
        key = key + b"\x00" * (BLOCK_SIZE - len(key))

    return key


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """
    Compute HMAC using SHA-256.

    HMAC uses two padded versions of the key:
    - inner pad
    - outer pad
    """
    normalized_key = _normalize_key(key)

    inner_pad = bytes(byte ^ 0x36 for byte in normalized_key)
    outer_pad = bytes(byte ^ 0x5c for byte in normalized_key)

    inner_hash = sha256(inner_pad + message)
    return sha256(outer_pad + inner_hash)


def hmac_sha256_hex(key: bytes, message: bytes) -> str:
    """
    Return HMAC-SHA256 as a hexadecimal string.
    """
    return hmac_sha256(key, message).hex()


def verify_hmac_sha256(key: bytes, message: bytes, tag: bytes) -> bool:
    """
    Verify an HMAC tag.

    The comparison does not stop early, so it is safer than normal ==.
    """
    if len(tag) != DIGEST_SIZE:
        return False

    expected = hmac_sha256(key, message)

    result = 0
    for x, y in zip(expected, tag):
        result |= x ^ y

    return result == 0