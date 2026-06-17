# Goal: Combine ChaCha20 encryption with Poly1305 authentication.

"""
ChaCha20-Poly1305 AEAD.

This module encrypts plaintext with ChaCha20 and authenticates both
ciphertext and AAD using Poly1305.
"""

from src.crypto.chacha20 import chacha20_block, chacha20_encrypt
from src.crypto.poly1305 import poly1305_mac


TAG_SIZE = 16


def _pad16(data: bytes) -> bytes:
    """
    Return zero padding until the length becomes a multiple of 16.
    """
    remainder = len(data) % 16

    if remainder == 0:
        return b""

    return b"\x00" * (16 - remainder)


def _poly1305_key_gen(key: bytes, nonce: bytes) -> bytes:
    """
    Generate the one-time Poly1305 key using ChaCha20 block 0.

    In ChaCha20-Poly1305, counter 0 is used only for the MAC key.
    Message encryption starts from counter 1.
    """
    return chacha20_block(key, 0, nonce)[:32]


def _build_mac_data(aad: bytes, ciphertext: bytes) -> bytes:
    """
    Build the exact data authenticated by Poly1305.

    Poly1305 authenticates:
    AAD || padding || ciphertext || padding || lengths
    """
    return (
        aad
        + _pad16(aad)
        + ciphertext
        + _pad16(ciphertext)
        + len(aad).to_bytes(8, "little")
        + len(ciphertext).to_bytes(8, "little")
    )


def _constant_time_equal(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings without stopping early.
    """
    if len(a) != len(b):
        return False

    result = 0

    for x, y in zip(a, b):
        result |= x ^ y

    return result == 0


def chacha20_poly1305_encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes = b"",
) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext and return ciphertext with authentication tag.
    """
    if len(key) != 32:
        raise ValueError("AEAD key must be 32 bytes")

    if len(nonce) != 12:
        raise ValueError("AEAD nonce must be 12 bytes")

    poly_key = _poly1305_key_gen(key, nonce)
    ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)

    mac_data = _build_mac_data(aad, ciphertext)
    tag = poly1305_mac(mac_data, poly_key)

    return ciphertext, tag


def chacha20_poly1305_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes = b"",
) -> bytes:
    """
    Verify the tag, then decrypt the ciphertext.

    If the tag is wrong, the message must be rejected.
    """
    if len(tag) != TAG_SIZE:
        raise ValueError("AEAD tag must be 16 bytes")

    poly_key = _poly1305_key_gen(key, nonce)
    mac_data = _build_mac_data(aad, ciphertext)
    expected_tag = poly1305_mac(mac_data, poly_key)

    if not _constant_time_equal(expected_tag, tag):
        raise ValueError("Invalid authentication tag")

    return chacha20_encrypt(key, 1, nonce, ciphertext)