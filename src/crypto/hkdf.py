# Goal: Implement HKDF using HMAC-SHA256 to derive session keys.

"""
HKDF key derivation.

This module takes input key material and derives secure output keys.
It will be used later after X25519 to create separate session keys.
"""

from src.crypto.hmac import hmac_sha256, DIGEST_SIZE


def hkdf_extract(salt: bytes | None, input_key_material: bytes) -> bytes:
    """
    HKDF extract step.

    This step compresses the input key material into a fixed-size PRK.
    PRK means pseudorandom key.
    """
    if salt is None or len(salt) == 0:
        salt = b"\x00" * DIGEST_SIZE

    return hmac_sha256(salt, input_key_material)


def hkdf_expand(pseudorandom_key: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF expand step.

    This step expands the PRK into the number of bytes we need.
    """
    if len(pseudorandom_key) != DIGEST_SIZE:
        raise ValueError("PRK must be 32 bytes for HMAC-SHA256")

    if length < 0:
        raise ValueError("Length must not be negative")

    if length > 255 * DIGEST_SIZE:
        raise ValueError("Length is too large for HKDF-SHA256")

    output = b""
    previous_block = b""
    counter = 1

    while len(output) < length:
        data = previous_block + info + bytes([counter])
        previous_block = hmac_sha256(pseudorandom_key, data)
        output += previous_block
        counter += 1

    return output[:length]


def hkdf(
    input_key_material: bytes,
    length: int,
    salt: bytes | None = None,
    info: bytes = b"",
) -> bytes:
    """
    Full HKDF: extract then expand.
    """
    prk = hkdf_extract(salt, input_key_material)
    return hkdf_expand(prk, info, length)