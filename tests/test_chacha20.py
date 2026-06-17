from src.crypto.chacha20 import quarter_round, chacha20_block, chacha20_encrypt


def test_quarter_round():
    state = [
        0x11111111,
        0x01020304,
        0x9b8d6f43,
        0x01234567,
    ]

    quarter_round(state, 0, 1, 2, 3)

    assert state == [
        0xea2a92f4,
        0xcb1cf8ce,
        0x4581472e,
        0x5881c4bb,
    ]


def test_chacha20_block():
    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    )
    counter = 1
    nonce = bytes.fromhex("000000090000004a00000000")

    expected = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e"
    )

    assert chacha20_block(key, counter, nonce) == expected


def test_chacha20_encrypt_and_decrypt():
    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
    )
    nonce = bytes.fromhex("000000090000004a00000000")
    plaintext = b"Hello Majd, this is ChaCha20 test."

    ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)
    decrypted = chacha20_encrypt(key, 1, nonce, ciphertext)

    assert decrypted == plaintext
    assert ciphertext != plaintext