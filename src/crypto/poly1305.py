# Goal: Implement Poly1305 MAC to detect message tampering.

"""
Poly1305 message authentication code.

This module creates a 16-byte authentication tag for a message.
Later, ChaCha20 and Poly1305 will be combined into ChaCha20-Poly1305 AEAD.
"""


P = (1 << 130) - 5
TAG_SIZE = 16


def _clamp_r(r: bytes) -> int:
    """
    Clamp the r part of the Poly1305 key.

    Clamping clears some bits as required by Poly1305.
    This makes the multiplication safe for the Poly1305 design.
    """
    if len(r) != 16:
        raise ValueError("r must be 16 bytes")

    r_list = bytearray(r)

    r_list[3] &= 15
    r_list[7] &= 15
    r_list[11] &= 15
    r_list[15] &= 15

    r_list[4] &= 252
    r_list[8] &= 252
    r_list[12] &= 252

    return int.from_bytes(r_list, "little")


def poly1305_mac(message: bytes, key: bytes) -> bytes:
    """
    Compute a 16-byte Poly1305 tag.

    key is 32 bytes:
    - first 16 bytes: r
    - second 16 bytes: s
    """
    if len(key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes")

    r = _clamp_r(key[:16])
    s = int.from_bytes(key[16:], "little")

    accumulator = 0

    for block_start in range(0, len(message), 16):
        block = message[block_start:block_start + 16]

        # Poly1305 adds a 1 byte after each block before converting it to an integer.
        n = int.from_bytes(block + b"\x01", "little")

        accumulator = (accumulator + n) % P
        accumulator = (accumulator * r) % P

    tag_number = (accumulator + s) % (1 << 128)
    return tag_number.to_bytes(TAG_SIZE, "little")


def verify_poly1305_tag(message: bytes, key: bytes, tag: bytes) -> bool:
    """
    Verify that the given tag matches the message and key.
    """
    if len(tag) != TAG_SIZE:
        return False

    expected_tag = poly1305_mac(message, key)
    return expected_tag == tag