import pytest

from src.crypto.aead import (
    chacha20_poly1305_encrypt,
    chacha20_poly1305_decrypt,
)


def test_chacha20_poly1305_official_vector():
    key = bytes.fromhex(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
    )

    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")

    plaintext = (
        b"Ladies and Gentlemen of the class of '99: "
        b"If I could offer you only one tip for the future, "
        b"sunscreen would be it."
    )

    expected_ciphertext = bytes.fromhex(
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116"
    )

    expected_tag = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")

    ciphertext, tag = chacha20_poly1305_encrypt(key, nonce, plaintext, aad)

    assert ciphertext == expected_ciphertext
    assert tag == expected_tag


def test_chacha20_poly1305_decrypt_success():
    key = bytes.fromhex(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
    )
    nonce = bytes.fromhex("070000004041424344454647")
    aad = b"header data"
    plaintext = b"secret message"

    ciphertext, tag = chacha20_poly1305_encrypt(key, nonce, plaintext, aad)
    decrypted = chacha20_poly1305_decrypt(key, nonce, ciphertext, tag, aad)

    assert decrypted == plaintext


def test_chacha20_poly1305_rejects_modified_ciphertext():
    key = bytes.fromhex(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
    )
    nonce = bytes.fromhex("070000004041424344454647")
    aad = b"header data"
    plaintext = b"secret message"

    ciphertext, tag = chacha20_poly1305_encrypt(key, nonce, plaintext, aad)

    modified_ciphertext = bytearray(ciphertext)
    modified_ciphertext[0] ^= 1

    with pytest.raises(ValueError):
        chacha20_poly1305_decrypt(
            key,
            nonce,
            bytes(modified_ciphertext),
            tag,
            aad,
        )


def test_chacha20_poly1305_rejects_modified_aad():
    key = bytes.fromhex(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
    )
    nonce = bytes.fromhex("070000004041424344454647")
    aad = b"header data"
    plaintext = b"secret message"

    ciphertext, tag = chacha20_poly1305_encrypt(key, nonce, plaintext, aad)

    with pytest.raises(ValueError):
        chacha20_poly1305_decrypt(
            key,
            nonce,
            ciphertext,
            tag,
            b"changed header",
        )