# Goal: Implement X25519 key exchange to create a shared secret.

"""
X25519 key exchange.

This module uses scalar multiplication on Curve25519.
It will be used in the handshake so both sides can derive the same shared secret.
"""

from secrets import token_bytes


P = (1 << 255) - 19
A24 = 121665
KEY_SIZE = 32
BASE_POINT = bytes([9]) + b"\x00" * 31


def generate_private_key() -> bytes:
    """
    Generate a random 32-byte private key.

    The key is clamped later inside x25519().
    """
    return token_bytes(KEY_SIZE)


def _clamp_scalar(scalar: bytes) -> int:
    """
    Clamp the scalar as required by X25519.

    Clamping changes some bits before scalar multiplication.
    """
    if len(scalar) != KEY_SIZE:
        raise ValueError("X25519 scalar must be 32 bytes")

    scalar_bytes = bytearray(scalar)

    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 127
    scalar_bytes[31] |= 64

    return int.from_bytes(scalar_bytes, "little")


def _decode_u_coordinate(u_coordinate: bytes) -> int:
    """
    Convert the public u-coordinate from bytes to an integer.
    """
    if len(u_coordinate) != KEY_SIZE:
        raise ValueError("X25519 u-coordinate must be 32 bytes")

    u_bytes = bytearray(u_coordinate)

    # X25519 ignores the top bit of the last byte.
    u_bytes[31] &= 127

    return int.from_bytes(u_bytes, "little")


def _conditional_swap(swap: int, first: int, second: int) -> tuple[int, int]:
    """
    Swap two values when swap is 1.

    This follows the style used in the Montgomery ladder.
    """
    mask = -swap
    temp = mask & (first ^ second)

    first ^= temp
    second ^= temp

    return first, second


def x25519(scalar: bytes, u_coordinate: bytes) -> bytes:
    """
    Compute X25519 scalar multiplication.

    scalar: private key bytes
    u_coordinate: other side public key bytes
    returns: 32-byte shared secret or public key
    """
    k = _clamp_scalar(scalar)
    x1 = _decode_u_coordinate(u_coordinate)

    x2 = 1
    z2 = 0
    x3 = x1
    z3 = 1
    swap = 0

    # Montgomery ladder, from bit 254 down to bit 0.
    for bit_index in range(254, -1, -1):
        current_bit = (k >> bit_index) & 1

        swap ^= current_bit
        x2, x3 = _conditional_swap(swap, x2, x3)
        z2, z3 = _conditional_swap(swap, z2, z3)
        swap = current_bit

        a = (x2 + z2) % P
        aa = (a * a) % P
        b = (x2 - z2) % P
        bb = (b * b) % P
        e = (aa - bb) % P

        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = (d * a) % P
        cb = (c * b) % P

        x3 = ((da + cb) * (da + cb)) % P
        z3 = (x1 * (da - cb) * (da - cb)) % P

        x2 = (aa * bb) % P
        z2 = (e * (aa + A24 * e)) % P

    x2, x3 = _conditional_swap(swap, x2, x3)
    z2, z3 = _conditional_swap(swap, z2, z3)

    # Convert projective coordinates back to affine x-coordinate.
    result = (x2 * pow(z2, P - 2, P)) % P

    return result.to_bytes(KEY_SIZE, "little")


def public_key_from_private(private_key: bytes) -> bytes:
    """
    Create a public key from a private key using the standard base point.
    """
    return x25519(private_key, BASE_POINT)


def shared_secret(private_key: bytes, peer_public_key: bytes) -> bytes:
    """
    Create a shared secret using our private key and the peer public key.
    """
    return x25519(private_key, peer_public_key)