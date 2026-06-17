# Goal: Implement the ChaCha20 stream cipher used to encrypt and decrypt messages.

"""
ChaCha20 stream cipher.

This module creates the ChaCha20 keystream and XORs it with data.
The same function is used for encryption and decryption.
"""

from typing import List


MASK_32 = 0xffffffff
CHACHA20_CONSTANT = b"expand 32-byte k"


def rotate_left(value: int, shift: int) -> int:
    """
    Rotate a 32-bit number to the left.

    ChaCha20 uses rotation to mix bits inside each word.
    """
    value &= MASK_32
    return ((value << shift) & MASK_32) | (value >> (32 - shift))


def little_endian_to_word(data: bytes) -> int:
    """
    Convert 4 bytes into one 32-bit word using little-endian order.

    ChaCha20 treats the key, nonce, and constants as 32-bit words.
    """
    if len(data) != 4:
        raise ValueError("A word must be exactly 4 bytes")

    return int.from_bytes(data, "little")


def word_to_little_endian(word: int) -> bytes:
    """
    Convert one 32-bit word back into 4 little-endian bytes.
    """
    return (word & MASK_32).to_bytes(4, "little")


def quarter_round(state: List[int], a: int, b: int, c: int, d: int) -> None:
    """
    Mix four words from the ChaCha20 state.

    This is the main operation in ChaCha20.
    It uses addition mod 2^32, XOR, and bit rotation.
    """
    state[a] = (state[a] + state[b]) & MASK_32
    state[d] ^= state[a]
    state[d] = rotate_left(state[d], 16)

    state[c] = (state[c] + state[d]) & MASK_32
    state[b] ^= state[c]
    state[b] = rotate_left(state[b], 12)

    state[a] = (state[a] + state[b]) & MASK_32
    state[d] ^= state[a]
    state[d] = rotate_left(state[d], 8)

    state[c] = (state[c] + state[d]) & MASK_32
    state[b] ^= state[c]
    state[b] = rotate_left(state[b], 7)


def _bytes_to_words(data: bytes) -> List[int]:
    """
    Split bytes into a list of 32-bit little-endian words.
    """
    if len(data) % 4 != 0:
        raise ValueError("Data length must be a multiple of 4")

    return [
        little_endian_to_word(data[i:i + 4])
        for i in range(0, len(data), 4)
    ]


def _serialize_words(words: List[int]) -> bytes:
    """
    Convert a list of 32-bit words into bytes.
    """
    return b"".join(word_to_little_endian(word) for word in words)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """
    Generate one 64-byte ChaCha20 keystream block.

    The state has 16 words:
    - 4 constant words
    - 8 key words
    - 1 counter word
    - 3 nonce words
    """
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes")

    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonce must be 12 bytes")

    if not 0 <= counter <= MASK_32:
        raise ValueError("Counter must be a 32-bit integer")

    constants = _bytes_to_words(CHACHA20_CONSTANT)
    key_words = _bytes_to_words(key)
    nonce_words = _bytes_to_words(nonce)

    initial_state = constants + key_words + [counter] + nonce_words
    working_state = initial_state.copy()

    # ChaCha20 uses 20 rounds.
    # Each loop below does 2 rounds: one column round and one diagonal round.
    for _ in range(10):
        # Column round
        quarter_round(working_state, 0, 4, 8, 12)
        quarter_round(working_state, 1, 5, 9, 13)
        quarter_round(working_state, 2, 6, 10, 14)
        quarter_round(working_state, 3, 7, 11, 15)

        # Diagonal round
        quarter_round(working_state, 0, 5, 10, 15)
        quarter_round(working_state, 1, 6, 11, 12)
        quarter_round(working_state, 2, 7, 8, 13)
        quarter_round(working_state, 3, 4, 9, 14)

    # Add the original state to the mixed state.
    final_state = [
        (working_state[i] + initial_state[i]) & MASK_32
        for i in range(16)
    ]

    return _serialize_words(final_state)


def chacha20_encrypt(key: bytes, counter: int, nonce: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt or decrypt data with ChaCha20.

    ChaCha20 produces a keystream.
    Encryption: plaintext XOR keystream = ciphertext.
    Decryption: ciphertext XOR keystream = plaintext.
    """
    ciphertext = bytearray()
    block_counter = counter

    for block_start in range(0, len(plaintext), 64):
        if block_counter > MASK_32:
            raise ValueError("ChaCha20 counter overflow")

        keystream = chacha20_block(key, block_counter, nonce)
        block = plaintext[block_start:block_start + 64]

        encrypted_block = bytes(
            block[i] ^ keystream[i]
            for i in range(len(block))
        )

        ciphertext.extend(encrypted_block)
        block_counter += 1

    return bytes(ciphertext)