# Goal: Implement SHA-256 hash function used later by HMAC and HKDF.

"""
SHA-256 hash function.

This module takes any byte message and returns a 32-byte digest.
It will be used later to build HMAC-SHA256 and HKDF.
"""


MASK_32 = 0xffffffff
BLOCK_SIZE = 64
DIGEST_SIZE = 32


K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]


INITIAL_HASH = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
]


def _right_rotate(value: int, shift: int) -> int:
    """
    Rotate a 32-bit number to the right.
    """
    value &= MASK_32
    return (value >> shift) | ((value << (32 - shift)) & MASK_32)


def _choice(x: int, y: int, z: int) -> int:
    """
    Choose bits from y or z based on x.
    """
    return (x & y) ^ (~x & z)


def _majority(x: int, y: int, z: int) -> int:
    """
    Return the majority bit among x, y, and z.
    """
    return (x & y) ^ (x & z) ^ (y & z)


def _big_sigma0(x: int) -> int:
    """
    First large sigma function used in the compression loop.
    """
    return _right_rotate(x, 2) ^ _right_rotate(x, 13) ^ _right_rotate(x, 22)


def _big_sigma1(x: int) -> int:
    """
    Second large sigma function used in the compression loop.
    """
    return _right_rotate(x, 6) ^ _right_rotate(x, 11) ^ _right_rotate(x, 25)


def _small_sigma0(x: int) -> int:
    """
    First small sigma function used to build the message schedule.
    """
    return _right_rotate(x, 7) ^ _right_rotate(x, 18) ^ (x >> 3)


def _small_sigma1(x: int) -> int:
    """
    Second small sigma function used to build the message schedule.
    """
    return _right_rotate(x, 17) ^ _right_rotate(x, 19) ^ (x >> 10)


def _pad_message(message: bytes) -> bytes:
    """
    Pad the message so its length becomes a multiple of 64 bytes.
    """
    message_bit_length = len(message) * 8

    padded = message + b"\x80"

    while len(padded) % BLOCK_SIZE != 56:
        padded += b"\x00"

    padded += message_bit_length.to_bytes(8, "big")
    return padded


def _process_block(block: bytes, hash_values: list[int]) -> list[int]:
    """
    Process one 64-byte block and update the hash state.
    """
    if len(block) != BLOCK_SIZE:
        raise ValueError("SHA-256 block must be 64 bytes")

    words = [
        int.from_bytes(block[i:i + 4], "big")
        for i in range(0, BLOCK_SIZE, 4)
    ]

    for i in range(16, 64):
        new_word = (
            _small_sigma1(words[i - 2])
            + words[i - 7]
            + _small_sigma0(words[i - 15])
            + words[i - 16]
        ) & MASK_32
        words.append(new_word)

    a, b, c, d, e, f, g, h = hash_values

    for i in range(64):
        temp1 = (
            h
            + _big_sigma1(e)
            + _choice(e, f, g)
            + K[i]
            + words[i]
        ) & MASK_32

        temp2 = (_big_sigma0(a) + _majority(a, b, c)) & MASK_32

        h = g
        g = f
        f = e
        e = (d + temp1) & MASK_32
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & MASK_32

    return [
        (hash_values[0] + a) & MASK_32,
        (hash_values[1] + b) & MASK_32,
        (hash_values[2] + c) & MASK_32,
        (hash_values[3] + d) & MASK_32,
        (hash_values[4] + e) & MASK_32,
        (hash_values[5] + f) & MASK_32,
        (hash_values[6] + g) & MASK_32,
        (hash_values[7] + h) & MASK_32,
    ]


def sha256(message: bytes) -> bytes:
    """
    Compute SHA-256 digest for a byte message.
    """
    padded = _pad_message(message)
    hash_values = INITIAL_HASH.copy()

    for block_start in range(0, len(padded), BLOCK_SIZE):
        block = padded[block_start:block_start + BLOCK_SIZE]
        hash_values = _process_block(block, hash_values)

    return b"".join(value.to_bytes(4, "big") for value in hash_values)


def sha256_hex(message: bytes) -> str:
    """
    Return SHA-256 digest as a hexadecimal string.
    """
    return sha256(message).hex()